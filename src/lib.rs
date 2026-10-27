//! kete — encrypted keyed storage over a manifestus vault.
//!
//! *kete* (te reo Māori): a woven basket — the opaque bag you put things into.
//!
//! The shared storage adapter for the passless app stack. Each app opens a dual-ring manifestus vault and reads/writes values by logical string key; kete optionally encrypts each value with a per-key ChaCha20-Poly1305 key and addresses it by a per-key derived 32-byte handle. Callers (photon's `contacts.rs`, idiosync's archive, ...) only ever see logical keys and plaintext. The vault is scoped by a 32-byte `secret`: pass `tohu::device::device_secret()` to bind it to this machine, or a portable secret to make a vault that travels.
//!
//! Extracted from photon's `src/storage/{flat,mod}.rs`. The only behavioural change is parameterization: `App { id, dir }` replaces photon's baked-in `"photon"` / `"Photon"` constants. With `App { id: "photon", dir: "Photon" }` the KDF contexts (`photon.storage.encryption.v0` / `.entry.v0`) and the `tohu::vault_path_name("photon", …)` filename are reproduced exactly, so existing photon vaults remain readable.
//!
//! Crash model (inherited from manifestus): power loss at ANY byte boundary is normal operation. Every block self-validates; the committed generation defines exactly which writes exist; the rollback fence keeps the last 4 generations restorable. Open replicates divergent mirrors block-level (verified, never a file copy) before composing them.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
#[cfg(not(target_os = "ferros"))]
use manifestus::{FileDev, Mirror, Vault, HOST_RING_LOG2, verified_replicate};
use rand::RngCore;

#[cfg(target_os = "ferros")]
mod ferros;

/// Shadow-ring filename suffix used when XDG config_dir == data_dir (macOS): both rings live in the same directory but with distinct names, keeping the dual-ring invariant intact across platforms.
#[cfg(not(target_os = "ferros"))]
const VAULT_SHADOW_SUFFIX: &str = ".shadow";

/// Initial tract size: 4096 blocks = 16MB per mirror file. Deliberately small — a vault starts small and growth is one fallocate + commit.
#[cfg(not(target_os = "ferros"))]
const INITIAL_TRACT_BLOCKS: u64 = 4096;

/// Identifies the calling application. `id` feeds the `tohu::vault_path_name` filename and the per-key KDF context strings; `dir` is the XDG subdirectory the dual rings live under. Both are stable per app — changing either orphans that app's existing vaults.
#[derive(Clone, Copy)]
pub struct App<'a> {
    pub id: &'a str,
    pub dir: &'a str,
}

// ============================================================================ Error ======================================================================

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Crypto(String),
    Parse(String),
    /// Vault-layer error from the manifestus backend.
    Vault(String),
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

impl From<String> for StorageError {
    fn from(s: String) -> Self {
        StorageError::Vault(s)
    }
}

impl From<manifestus::Error> for StorageError {
    fn from(e: manifestus::Error) -> Self {
        StorageError::Vault(e.to_string())
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO: {}", e),
            StorageError::Crypto(s) => write!(f, "Crypto: {}", s),
            StorageError::Parse(s) => write!(f, "Parse: {}", s),
            StorageError::Vault(s) => write!(f, "Vault: {}", s),
        }
    }
}

impl std::error::Error for StorageError {}

// ============================================================================ Shared encryption ==========================================================

/// Encrypt with XChaCha20-Poly1305 + a fresh 24-byte random nonce. Output layout is `[nonce: 24B] || [ciphertext + 16B auth tag]`. One call site for the whole stack so a future change (algorithm bump, AAD scheme) lands in one place.
///
/// The 192-bit nonce (2026-08-18 migration from ChaCha20-Poly1305's 96-bit) removes the birthday bound on random nonces entirely: a fleet may seal unbounded values under one key with no collision concern. [`decrypt_bytes`] still reads the legacy 12-byte-nonce format, so vaults upgrade lazily on each value's next write.
pub fn encrypt_bytes(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// The logical-string entry address, exposed for inspection tooling beside [`derive_addr_key`].
pub fn derive_entry_addr(app_id: &str, key: &str) -> [u8; 32] {
    blake3::derive_key(&format!("{}.storage.entry.v0", app_id), key.as_bytes())
}

/// A domain-scoped entry address (photon's `vault_key` shape): same context, input = domain bytes ‖ 32-byte scope.
pub fn derive_scoped_addr(app_id: &str, domain: &str, scope: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 32);
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(scope);
    blake3::derive_key(&format!("{}.storage.entry.v0", app_id), &input)
}

/// The per-address AEAD key derivation, exposed for inspection tooling (keteinfo, photon-settings-inspect) that opens COPIED ring files outside a FlatStorage — the one derivation, never duplicated.
pub fn derive_addr_key(app_id: &str, addr: &[u8; 32], vault_seed: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
    let context = [addr.as_slice(), vault_seed.as_slice(), secret.as_slice()].concat();
    blake3::derive_key(&format!("{}.storage.encryption.v0", app_id), &context)
}

/// Decrypt a blob produced by [`encrypt_bytes`]: XChaCha20-Poly1305, [nonce:24][ct+tag]. The pre-2026-08-18 12-byte-nonce ChaCha reader was dropped 2026-10-17 (Nick: "Ditch the old!") - a value still in that form fails like any undecryptable entry, and the fleet copy replaces it.
pub fn decrypt_bytes(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    // WHY/PROOF: the blob is read back from the vault file and may be any length — under 24 bytes split_at would panic, and under 40 there is no room for a nonce and a tag.
    if blob.len() < 24 + 16 {
        return Err(format!("ciphertext too short: {} bytes (need ≥ 40 for a nonce + tag)", blob.len()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(24);
    let nonce = XNonce::try_from(nonce_bytes).expect("split_at(24) gives exactly a 24-byte nonce");
    XChaCha20Poly1305::new(key.into())
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "decrypt failed (XChaCha20-Poly1305)".to_string())
}

// ============================================================================ The librarian ==============================================================

/// One message to the librarian — the vault-owner thread. Every op carries its own reply channel; mutations reply after the write is durable, so the sync wrappers below preserve durable-on-return exactly.
enum VaultOp {
    Get {
        addr: [u8; 32],
        reply: std::sync::mpsc::Sender<Result<Option<Vec<u8>>, String>>,
    },
    Put {
        addr: [u8; 32],
        stored: Vec<u8>,
        reply: std::sync::mpsc::Sender<Result<(), String>>,
    },
    Delete {
        addr: [u8; 32],
        reply: std::sync::mpsc::Sender<Result<(), String>>,
    },
    /// Many put-or-delete ops from ONE caller, applied in order under (usually) one manifestus commit — the transaction shape rārangi's transact posts so its apply phase stops paying one commit per write. `Some(stored)` = put (already encrypted by the caller), `None` = delete.
    Batch {
        items: Vec<([u8; 32], Option<Vec<u8>>)>,
        reply: std::sync::mpsc::Sender<Result<(), String>>,
    },
    Degraded {
        reply: std::sync::mpsc::Sender<bool>,
    },
    /// Every live entry address — the migration enumeration (see [`FlatStorage::live_addrs`]).
    Keys {
        reply: std::sync::mpsc::Sender<Result<Vec<[u8; 32]>, String>>,
    },
    /// The engine's physique (generation, tract occupancy, live set) — display-grade, answered from RAM.
    Stats {
        reply: std::sync::mpsc::Sender<manifestus::VaultStats>,
    },
}

/// What the librarian needs to reopen its vault with the pruning repair open, when a lazy open's walk refuses (see [`FlatStorage::open`]).
#[cfg(not(target_os = "ferros"))]
struct Reopen {
    paths: [PathBuf; 2],
    blocks: u64,
    lost: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(not(target_os = "ferros"))]
impl Reopen {
    /// The repair open over the same files, its losses named in the log and counted.
    fn repair(&self, refusal: &manifestus::Error) -> Result<Vault<FileDev, FileDev>, StorageError> {
        log::warn!("kete: vault open refused ({refusal}) — retrying with the pruning repair open");
        let a = FileDev::create(&self.paths[0], self.blocks)?;
        let b = FileDev::create(&self.paths[1], self.blocks)?;
        let (v, report) = Vault::open_repairing(Mirror::new(a, b).with_events(Box::new(LogSink)), HOST_RING_LOG2, eagle_now(), manifestus::DeletePolicy::UnlinkOnly)?;
        self.lost.fetch_add(report.dangling.len(), std::sync::atomic::Ordering::Relaxed);
        log::warn!(
            "kete: repair open succeeded — {} stale pointer(s) unlinked, {} dangling pointer(s) pruned (those values are LOST)",
            report.stale.len(),
            report.dangling.len()
        );
        // NAME EVERY LOSS (field 2026-09-03, Leviathan: 43 pruned pointers whose identities were gone forever the moment this log line printed only a count). lba + hash + key + reason is the entire forensic record of what died — without it there is no way to even say WHICH conversations lost rows.
        for d in &report.dangling {
            log::warn!(
                "kete: pruned dangling — lba {} hash {} key {} route {}: {}",
                d.lba,
                hex_prefix(&d.hash),
                d.key.as_ref().map_or("?".to_string(), |k| hex_prefix(k)),
                hex_prefix(&d.route),
                d.reason
            );
        }
        for s in &report.stale {
            log::info!("kete: unlinked stale — lba {} hash {} route {} (fast-deleted, no data behind it)", s.lba, hex_prefix(&s.hash), hex_prefix(&s.route));
        }
        Ok(v)
    }

    /// One step of the vault's walk; a refusal the repair walk can survive reopens with it in place. True once settled.
    fn step(&self, vault: &mut Vault<FileDev, FileDev>) -> Result<bool, String> {
        match vault.settle_step() {
            Ok(done) => Ok(done),
            Err(e @ (manifestus::Error::Seal | manifestus::Error::Corrupt(_))) => {
                *vault = self.repair(&e).map_err(|e| e.to_string())?;
                Ok(true)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The walk to its end — what a write, an enumeration of the live set's numbers, waits for.
    fn settle(&self, vault: &mut Vault<FileDev, FileDev>) -> Result<(), String> {
        let t = std::time::Instant::now();
        let was = vault.settled();
        while !self.step(vault)? {}
        if !was {
            log::info!("kete: vault walk finished in {} ms, ahead of a write", t.elapsed().as_millis());
        }
        Ok(())
    }
}

/// The librarian: the ONE thread that owns the manifestus engine — no mutex exists, so a blocked reader is structurally impossible rather than a per-call-site discipline.
/// The old shape (engine under a Mutex, every thread calling in) meant an innocent read queued behind whichever persist worker held the lock thru a whole encrypted table write — the 2026-08-15 field lag (400-1794ms UI stalls on a per-tick avatar probe).
/// Reads go first: before each mutation the mailbox is drained and every queued Get is answered, so a read waits for at most the ONE write already on the platter, never a queue of them. Writes can theoretically starve under a sustained read flood, but read floods are boot-shaped and brief while writes coalesce upstream — the trade is deliberate.
/// The thread exits when every sender drops (recv errs), dropping the engine; manifestus is crash-safe at any byte boundary, so no explicit flush handshake is needed.
/// After a lazy open the walk that finds what is live runs here a step (a thousand index blocks) at a time whenever the mailbox is empty, so reads never wait for it; a write that arrives first finishes it.
#[cfg(not(target_os = "ferros"))]
fn librarian(mut vault: Vault<FileDev, FileDev>, rx: std::sync::mpsc::Receiver<VaultOp>, reopen: Reopen) {
    let mut pending: std::collections::VecDeque<VaultOp> = std::collections::VecDeque::new();
    let walk_started = std::time::Instant::now();
    loop {
        // Idle: a step of the walk while it is unfinished, else block for one op. Busy: drain whatever queued while the last op ran.
        if pending.is_empty() {
            if !vault.settled() {
                match rx.try_recv() {
                    Ok(op) => pending.push_back(op),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        match reopen.step(&mut vault) {
                            Ok(true) => log::info!("kete: vault walk finished {} ms after the open", walk_started.elapsed().as_millis()),
                            Ok(false) => {}
                            // Left unsettled: the next write tries again and carries the error to its caller.
                            Err(e) => {
                                log::warn!("kete: vault walk failed ({e}) — the next write retries it");
                                match rx.recv() {
                                    Ok(op) => pending.push_back(op),
                                    Err(_) => return,
                                }
                            }
                        }
                        continue;
                    }
                }
            } else {
                match rx.recv() {
                    Ok(op) => pending.push_back(op),
                    Err(_) => return,
                }
            }
        }
        while let Ok(op) = rx.try_recv() {
            pending.push_back(op);
        }
        // Answer every queued read (their mutual order preserved), then GATHER every queued mutation into one ordered batch and land it under (usually) one commit. GROUP COMMIT, SAFE FORM (2026-09-02; the 2026-08-21 revert's homework got done in manifestus): the reverted 1944ebe starved the rollback fence because a batch's appends piled up before ONE commit and the fence only slides on commit — manifestus's put ladder now commits MID-LADDER on Fenced (that IS how the fence rises, vault.rs put_no_commit), so a batch degrades toward commit-per-write under fence pressure and never past it. The batch is drained-and-committed within this cycle, never held open across cycles. The flush is size-independent (~900ms on busy BTRFS, 53 bytes = 22KB), so N ops under one commit turn N flushes into one — the 2026-09-02 field day measured 2-5s PER 322-byte put with every vault caller serialized behind it.
        let mut batch: Vec<([u8; 32], Option<Vec<u8>>)> = Vec::new();
        let mut replies: Vec<std::sync::mpsc::Sender<Result<(), String>>> = Vec::new();
        while let Some(op) = pending.pop_front() {
            match op {
                VaultOp::Get { addr, reply } => {
                    let _ = reply.send(vault.get(&addr).map_err(|e| e.to_string()));
                }
                VaultOp::Degraded { reply } => {
                    let _ = reply.send(vault.degraded());
                }
                VaultOp::Keys { reply } => {
                    let _ = reply.send(vault.live_keys().map_err(|e| e.to_string()));
                }
                VaultOp::Stats { reply } => {
                    // The live set's numbers are the walk's: finish it (best-effort; an unsettled vault reports what it knows).
                    let _ = reopen.settle(&mut vault);
                    let _ = reply.send(vault.engine_stats());
                }
                VaultOp::Put { addr, stored, reply } => {
                    batch.push((addr, Some(stored)));
                    replies.push(reply);
                }
                VaultOp::Delete { addr, reply } => {
                    batch.push((addr, None));
                    replies.push(reply);
                }
                VaultOp::Batch { items, reply } => {
                    batch.extend(items);
                    replies.push(reply);
                }
            }
        }
        if !batch.is_empty() {
            let t = std::time::Instant::now();
            let ops = batch.len();
            let bytes: usize = batch.iter().map(|(_, v)| v.as_ref().map_or(0, |b| b.len())).sum();
            let r = reopen.settle(&mut vault).and_then(|()| apply_growing(&mut vault, &batch));
            let ms = t.elapsed().as_millis();
            if ms > 200 {
                log::warn!(
                    "kete: SLOW commit — {} op(s), {} bytes in {}ms (every vault caller blocked behind it)",
                    ops, bytes, ms
                );
            } else if ops > 1 {
                log::info!("kete: group commit — {} op(s), {} bytes in {}ms", ops, bytes, ms);
            }
            // One shared verdict: the batch is one commit, so its ops share one fate. A per-op verdict would be a lie — a mid-ladder heartbeat may have landed a prefix early, but "early" is still durable, and an error means the caller must treat its op as unwritten either way.
            for reply in replies {
                let _ = reply.send(r.clone());
            }
            // The batch's callers are answered; reclaim belongs here, between batches, not inside the next caller's commit.
            reclaim_while_idle(&mut vault, &rx, &mut pending);
        }
    }
}

/// RECLAIM AT THE IDLE EDGE: after a batch's replies are out, while the mailbox stays empty, step the vault's reap ahead one bounded window at a time.
/// The edge is the batch completing; the stops are the first queued op (taken into `pending`, served next), the vault saying it is comfortable, or one full lap of the reap cursor in this idle stretch — no timer anywhere.
/// Field 2026-10-21 (Emma's new phone taking in 256 KiB attachment chunks): with reclaim only inside commits, whichever chunk met the shortage paid the reap, the rescue and the grow — single-op commits of 3.3 s and 5.7 s with every vault caller blocked behind them.
/// A live-heavy tract (reaping cannot pay its way) grows here instead, ahead of the batch that would otherwise grow inside its own commit.
#[cfg(not(target_os = "ferros"))]
fn reclaim_while_idle(
    vault: &mut Vault<FileDev, FileDev>,
    rx: &std::sync::mpsc::Receiver<VaultOp>,
    pending: &mut std::collections::VecDeque<VaultOp>,
) {
    let lap_end = vault.engine_stats().reap + vault.tract_blocks();
    loop {
        match rx.try_recv() {
            Ok(op) => {
                pending.push_back(op);
                return;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if vault.engine_stats().reap >= lap_end {
            return;
        }
        match vault.reclaim_ahead(eagle_now()) {
            Ok(manifestus::Reclaim::Reaped) => {}
            Ok(manifestus::Reclaim::LiveHeavy) => {
                // PROOF: a tract counts blocks on a real device, far below 2^63, and manifestus doubles it the same way.
                let target = vault.tract_blocks() * 2;
                log::info!(
                    "kete: tract live-heavy at the idle edge — growing {} -> {} blocks ahead of the next batch",
                    vault.tract_blocks(),
                    target
                );
                if let Err(e) = vault.grow(target, eagle_now()) {
                    log::warn!("kete: idle grow failed ({e}) — the next batch's ladder grows instead");
                }
                return;
            }
            Ok(_) => return,
            Err(e) => {
                log::warn!("kete: idle reclaim failed ({e}) — the commit ladders still reclaim inline");
                return;
            }
        }
    }
}

/// Growth-aware batch apply (subsumed the old single-op `put_growing` when the librarian went batch-only): pre-size once for the batch's SUMMED payload, then land the whole ordered op list via `apply_batch` (one commit, mixed puts+deletes), doubling thru TractFull with the same bounded backstop. Order is preserved end to end — callers whose last op is their cleanup edge (rārangi's WAL retire) rely on it.
#[cfg(not(target_os = "ferros"))]
fn apply_growing(
    vault: &mut Vault<FileDev, FileDev>,
    items: &[([u8; 32], Option<Vec<u8>>)],
) -> Result<(), String> {
    const EST_PAYLOAD_PER_BLOCK: u64 = 3072;
    let total: u64 = items.iter().map(|(_, v)| v.as_ref().map_or(0, |b| b.len() as u64)).sum();
    let needed = (total / EST_PAYLOAD_PER_BLOCK) + 64;
    let floor = vault.live_blocks() as u64 + needed;
    let mut target = vault.tract_blocks();
    while target < floor {
        // PROOF: floor is the live blocks plus this batch, far below 2^63, so doubling from a real tract reaches it first.
        target *= 2;
    }
    if target > vault.tract_blocks() {
        log::info!(
            "kete: pre-sizing tract for a {}-byte batch — growing {} -> {} blocks",
            total,
            vault.tract_blocks(),
            target
        );
        vault
            .grow(target, eagle_now())
            .map_err(|e| format!("vault grow: {e}"))?;
    }
    let refs: Vec<(&[u8; 32], Option<&[u8]>)> = items
        .iter()
        .map(|(a, v)| (a, v.as_deref()))
        .collect();
    for _ in 0..40 {
        match vault.apply_batch(&refs, eagle_now()) {
            Err(manifestus::Error::TractFull) => {
                // PROOF: a tract counts blocks on a real device, far below 2^63, and manifestus doubles it the same way.
                let target = vault.tract_blocks() * 2;
                log::info!(
                    "kete: tract full of live data — growing {} -> {} blocks (batch)",
                    vault.tract_blocks(),
                    target
                );
                vault
                    .grow(target, eagle_now())
                    .map_err(|e| format!("vault grow: {e}"))?;
            }
            r => return r.map_err(|e| e.to_string()),
        }
    }
    Err("vault grow loop exhausted — growth is not sticking (batch)".to_string())
}

// ============================================================================ FlatStorage ================================================================

/// All of an app's vault I/O goes thru this struct. Initialized once with the app namespace + handle + secret; the dual-ring vault is opened (or formatted) during construction. Callers see only logical keys; vault internals + per-key encryption are managed below.
/// The engine itself lives on the librarian thread (see [`librarian`]); this struct holds the mailbox. The Mutex around the Sender exists only because std's Sender is !Sync — it guards a sub-microsecond `send`, never IO.
pub struct FlatStorage {
    /// `App::id` — feeds `vault_path_name` and the per-key KDF context strings.
    app_id: String,
    /// The IDENTITY seed, when one exists. Per-identity vaults (`new`) carry it from construction; a device-first vault (open_device*) starts None and gains it via [`set_identity`](Self::set_identity) at attest — Nick's key model 2026-08-20: entries are keyed hash(thing|device) pre-attest and hash(thing|device|person) after.
    identity: Mutex<Option<[u8; 32]>>,
    /// The 32-byte secret the vault is bound to — mixed into both the vault filename and every per-key encryption key. `tohu::device::device_secret()` locks the vault to this machine; any portable secret (passphrase-derived, identity key) makes a vault that opens on any machine holding that secret.
    secret: [u8; 32],
    /// The librarian's mailbox.
    ops: Mutex<std::sync::mpsc::Sender<VaultOp>>,
    /// STORED-bytes read cache, sorted by address for binary search (ciphertext for encrypted vaults — RAM stays as sealed as disk): reads served from here NEVER touch the librarian, so no read ever waits behind a running commit. The 2026-08-21 field capture showed commits at 1-10s under disk load and every UI hitch was a read stuck behind one (render `pre 3772ms`, conversation-open stalls). Write path inserts BEFORE posting (read-your-own-writes — a racing reader sees the value that is about to be durable); delete removes; `None` caches known-absence so repeated misses skip the round-trip too. Bounded: past CACHE_CAP_BYTES the whole cache clears (readers fall thru to the librarian — pure correctness, cold speed).
    read_cache: Mutex<Vec<([u8; 32], Option<Vec<u8>>)>>,
    /// Mirrors diverged at open and were replicated back into agreement.
    healed_at_open: bool,
    /// Values LOST by the repair fallback: the strict open (or its walk, stepped by the librarian after a lazy open) refused (torn/reused block behind a committed pointer) and `open_repairing` pruned that many dangling pointers to boot at all; counted when the walk meets it, which may be after the open returned. 0 = nothing lost (clean open, or repair found only stale no-data pointers). Callers surface this to the user — a silent prune is how "storage degraded" turns into a mystery.
    repaired_lost_values: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Whether values are encrypted (per-key ChaCha20-Poly1305) before storage. False = plaintext: the vault still gives integrity + durability (manifestus BLAKE3-seals every block), values are just stored as-is and stay inspectable on disk (e.g. `vsfinfo` on a VSF value). The caller's choice — a plaintext vault is not leaked-file-safe.
    encrypt: bool,
}

impl FlatStorage {
    /// Post one op to the librarian and wait for its reply — the shared shape of every sync wrapper. A dead librarian (all-senders-dropped teardown racing a call, or a panicked thread) surfaces as a Vault error, the same failure class the old poisoned mutex produced, minus the poisoning.
    fn post<R>(&self, op: VaultOp, reply_rx: std::sync::mpsc::Receiver<R>) -> Result<R, StorageError> {
        self.ops
            .lock()
            .map_err(|_| StorageError::Vault("vault mailbox lock poisoned".to_string()))?
            .send(op)
            .map_err(|_| StorageError::Vault("vault thread gone".to_string()))?;
        reply_rx
            .recv()
            .map_err(|_| StorageError::Vault("vault thread gone".to_string()))
    }
}

impl FlatStorage {
    /// Open an encrypted vault (per-key ChaCha20-Poly1305), keyed on `secret`. `secret` is mixed into both the filename and every value's key, so the same `(app, seed, secret)` reproduces the same vault and decryption anywhere. Pass `tohu::device::device_secret()` to lock the vault to this machine; pass a portable secret (passphrase-derived, identity key) for a vault you can move to or open on another machine.
    pub fn new(app: App, vault_seed: [u8; 32], secret: [u8; 32]) -> Result<Self, StorageError> {
        let filename = tohu::vault_path_name(app.id, &vault_seed, &secret);
        Self::open(app, filename, Some(vault_seed), secret, true)
    }

    /// Open a vault that stores values in **plaintext** — same addressing, durability, and integrity (manifestus still BLAKE3-seals every block), but no per-key encryption, so values stay inspectable on disk. Use for data that isn't secret; do NOT use for secrets (a plaintext vault file is readable by anyone who can read it). `secret` still scopes the vault path (machine-bound or portable, your choice).
    pub fn new_plaintext(app: App, vault_seed: [u8; 32], secret: [u8; 32]) -> Result<Self, StorageError> {
        let filename = tohu::vault_path_name(app.id, &vault_seed, &secret);
        Self::open(app, filename, Some(vault_seed), secret, false)
    }

    /// Open the vault as the ONE process-wide shared engine for its file — every `open_shared` of the same `(app, seed, secret)` returns the same `Arc<FlatStorage>`, so all threads serialize on one engine and one in-RAM state.
    ///
    /// This is the constructor apps must use for any vault reachable from more than one call site: two `new()` engines on the same file are two independent in-RAM states racing the same mirrors — engine A commits, engine B (stale) reads blocks A rewrote → "seal verification failed" mid-session, and B's next commit writes its stale state to BOTH mirrors (read-back-verify checks disk==RAM, not that RAM was right), corrupting the vault at rest. This is exactly how photon's resume-engine + attest-worker-engine pair destroyed a live vault (2026-07-12).
    ///
    /// The registry holds `Weak` refs: a vault fully dropped by every holder closes normally and a later `open_shared` reopens it fresh.
    pub fn open_shared(app: App, vault_seed: [u8; 32], secret: [u8; 32]) -> Result<Arc<Self>, StorageError> {
        static OPEN_VAULTS: Mutex<Vec<(String, Weak<FlatStorage>)>> = Mutex::new(Vec::new());

        let filename = tohu::vault_path_name(app.id, &vault_seed, &secret);
        let mut reg = OPEN_VAULTS
            .lock()
            .map_err(|e| StorageError::Io(std::io::Error::other(format!("vault registry lock: {}", e))))?;
        // Drop dead entries, then look for a live engine on this file.
        reg.retain(|(_, w)| w.strong_count() > 0);
        if let Some((_, w)) = reg.iter().find(|(f, _)| *f == filename) {
            if let Some(live) = w.upgrade() {
                return Ok(live);
            }
        }
        // Held across the open on purpose: a second thread racing this open must wait and receive the same engine, never construct its own.
        let vault = Arc::new(Self::open(app, filename.clone(), Some(vault_seed), secret, true)?);
        reg.push((filename, Arc::downgrade(&vault)));
        Ok(vault)
    }

    /// Open the ONE device vault — exists from FIRST LAUNCH, named from the device secret alone (tohu::device_vault_path_name), no identity required. Device-scope entries (`*_device` methods) work immediately; identity-scope entries unlock via [`set_identity`](Self::set_identity) at attest. Same process-wide shared-engine registry as [`open_shared`](Self::open_shared).
    pub fn open_device_shared(app: App, device_secret: [u8; 32]) -> Result<Arc<Self>, StorageError> {
        static OPEN_DEVICE_VAULTS: Mutex<Vec<(String, Weak<FlatStorage>)>> = Mutex::new(Vec::new());
        let filename = tohu::device_vault_path_name(app.id, &device_secret);
        let mut reg = OPEN_DEVICE_VAULTS
            .lock()
            .map_err(|e| StorageError::Io(std::io::Error::other(format!("vault registry lock: {}", e))))?;
        reg.retain(|(_, w)| w.strong_count() > 0);
        if let Some((_, w)) = reg.iter().find(|(f, _)| *f == filename) {
            if let Some(live) = w.upgrade() {
                return Ok(live);
            }
        }
        let vault = Arc::new(Self::open(app, filename.clone(), None, device_secret, true)?);
        reg.push((filename, Arc::downgrade(&vault)));
        Ok(vault)
    }

    /// Install the identity seed at attest — identity-scope entries become readable/writable from here on. Idempotent; a DIFFERENT identity than the one already set is refused (one identity per device, D2).
    pub fn set_identity(&self, identity_seed: [u8; 32]) -> Result<(), StorageError> {
        let mut g = self
            .identity
            .lock()
            .map_err(|_| StorageError::Vault("identity lock poisoned".to_string()))?;
        match *g {
            Some(existing) if existing != identity_seed => Err(StorageError::Crypto(
                "vault already bound to a different identity (one identity per device)".to_string(),
            )),
            _ => {
                *g = Some(identity_seed);
                Ok(())
            }
        }
    }

    /// The identity this vault currently serves, if attested.
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.identity.lock().ok().and_then(|g| *g)
    }

    /// On ferros: this process's vault scope, through the kernel (`ferros.rs`); `filename`, which tells one vault from another on a host, becomes a key prefix inside the scope.
    #[cfg(target_os = "ferros")]
    fn open(app: App, filename: String, identity: Option<[u8; 32]>, secret: [u8; 32], encrypt: bool) -> Result<Self, StorageError> {
        let store = ferros::KernelStore::open(&filename).ok_or_else(|| StorageError::Vault("ferros: this process holds no vault scope (spawn it with --store)".to_string()))?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("kete-librarian".to_string())
            .spawn(move || ferros::librarian(store, rx))
            .map_err(StorageError::Io)?;
        Ok(Self {
            app_id: app.id.to_string(),
            identity: Mutex::new(identity),
            secret,
            ops: Mutex::new(tx),
            read_cache: Mutex::new(Vec::new()),
            healed_at_open: false,
            repaired_lost_values: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            encrypt,
        })
    }

    #[cfg(not(target_os = "ferros"))]
    fn open(app: App, filename: String, identity: Option<[u8; 32]>, secret: [u8; 32], encrypt: bool) -> Result<Self, StorageError> {
        let paths = vault_paths(app.dir, &filename)?;

        for p in &paths {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let blocks = (1u64 << HOST_RING_LOG2) + INITIAL_TRACT_BLOCKS;
        let opened = std::time::Instant::now();
        let mut a = FileDev::create(&paths[0], blocks)?;
        let mut b = FileDev::create(&paths[1], blocks)?;

        // Converge divergent mirrors (stale restore, missed writes, fresh second file) BEFORE composing them — block-level, verified, idempotent.
        // The heal is best-effort by definition: its live walk is strict, so a torn block behind a committed pointer aborts it — and that same tear is exactly what the repair-open below survives. A replicate failure must never block boot (field 2026-08-25: it front-ran the open and made the whole vault unbootable).
        let healed = match verified_replicate(&mut a, &mut b, HOST_RING_LOG2) {
            Ok(h) => h,
            Err(e) => {
                log::warn!("kete: mirror replicate failed ({e}) — skipping the heal, the open path decides");
                manifestus::Replicated::default()
            }
        };
        let healed_at_open = healed != manifestus::Replicated::default();
        let replicated_ms = opened.elapsed().as_millis();
        if healed_at_open {
            log::info!(
                "kete: mirrors diverged at open — replicated {} spine + {} tract blocks",
                healed.spine_copied,
                healed.tract_copied
            );
        }

        // Strict open first, LAZY (2026-10-25): the head is read here and the index walk that finds what is live is stepped on the librarian between requests (see `librarian`), so the open costs the same at any size — the walk read one leaf per entry, 1.3 s at eight thousand on a desktop SSD, before the app's first read. Its refusals (a torn or reused block behind a committed pointer — a kill mid-flush, a fence-era relocation gone bad) now come from the walk, and the librarian meets them with the repair open; one met here takes it at once. Field 2026-08-25: the Mac's device vault died "seal verification failed" on every boot for half an hour when ONE dangling pointer would have pruned. The repair path commits the pruned index, so the cost is exactly the already-lost values, counted and surfaced — never the vault.
        let lost = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reopen = Reopen { paths: paths.clone(), blocks, lost: lost.clone() };
        // UnlinkOnly (see manifestus::DeletePolicy): kete's host profile runs on files over CoW filesystems and vendor-FTL flash — delete is space reclamation, the boot-gated vault key is the security boundary. The ZeroIsErase arm belongs to a future kete-on-owned-NAND profile (ferros on hardware we command), which must choose it consciously at ITS open site.
        let vault = match Vault::open_lazy(Mirror::new(a, b).with_events(Box::new(LogSink)), HOST_RING_LOG2, eagle_now(), manifestus::DeletePolicy::UnlinkOnly) {
            Ok(v) => v,
            Err(e @ (manifestus::Error::Seal | manifestus::Error::Corrupt(_))) => reopen.repair(&e)?,
            Err(e) => return Err(e.into()),
        };
        // What an open costs, by part: the mirrors' resync, then the engine's own open (its index walk).
        log::info!("kete: vault open in {} ms ({} ms resyncing the mirrors{}), its walk to follow between requests", opened.elapsed().as_millis(), replicated_ms, if healed_at_open { ", which had diverged" } else { "" });
        // Hand the engine to its librarian — from here on, only that thread touches manifestus.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("kete-librarian".to_string())
            .spawn(move || librarian(vault, rx, reopen))
            .map_err(|e| StorageError::Io(e))?;
        Ok(Self {
            app_id: app.id.to_string(),
            identity: Mutex::new(identity),
            secret,
            ops: Mutex::new(tx),
            read_cache: Mutex::new(Vec::new()),
            healed_at_open,
            repaired_lost_values: lost,
            encrypt,
        })
    }

    /// Read-cache size ceiling (sum of cached value bytes). The whole vault is tens of MB in practice, so a warm session fits; a bulk-content future (avatars, attachments) hits the cap and clears — correctness never depends on residency.
    const CACHE_CAP_BYTES: usize = 64 * 1024 * 1024;

    /// Insert/replace a cache entry, clearing the whole cache first if it would exceed the cap.
    fn cache_put(&self, addr: [u8; 32], stored: Option<Vec<u8>>) {
        if let Ok(mut c) = self.read_cache.lock() {
            let incoming = stored.as_ref().map_or(0, |v| v.len());
            let held: usize = c.iter().map(|(_, v)| v.as_ref().map_or(0, |b| b.len())).sum();
            if held + incoming > Self::CACHE_CAP_BYTES {
                c.clear();
            }
            match c.binary_search_by(|(a, _)| a.cmp(&addr)) {
                Ok(i) => c[i].1 = stored,
                Err(i) => c.insert(i, (addr, stored)),
            }
        }
    }

    /// The cached stored bytes at `addr` (`Some(None)` = known absent), by binary search over the address-sorted cache.
    fn cache_get(c: &[([u8; 32], Option<Vec<u8>>)], addr: &[u8; 32]) -> Option<Option<Vec<u8>>> {
        c.binary_search_by(|(a, _)| a.cmp(addr)).ok().map(|i| c[i].1.clone())
    }

    /// Write data under a logical **string** key. Hashes the key to a 32-byte vault address (so the string never reaches disk), then delegates to [`write_addr`](Self::write_addr). For callers whose key is genuinely a string (table/pk/seq, e.g. rārangi). Callers that already hold a 32-byte address (a seed, a conversation id) should use [`write_addr`](Self::write_addr) directly rather than text-encoding it first.
    pub fn write(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        self.write_addr(&self.derive_entry_key(key), data)
    }

    /// Read the value for a logical **string** key. See [`write`](Self::write) for when to use this vs. [`read_addr`](Self::read_addr).
    pub fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_addr(&self.derive_entry_key(key))
    }

    /// Remove a logical **string** key. See [`write`](Self::write) for when to use this vs. [`delete_addr`](Self::delete_addr).
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.delete_addr(&self.derive_entry_key(key))
    }

    /// Write data at a caller-supplied 32-byte vault **address**. For callers who already hold the address as bytes (an identity seed, a conversation id) — no text-encoding round-trip. Encrypts with the per-address ChaCha20-Poly1305 key; durable on return (a spine generation references the new state on at least one verified mirror). The address is the AEAD key input, so a value written here reads back identically whether reached via this method or via [`write`](Self::write) with a string that hashes to the same address.
    /// Encrypt runs HERE on the caller's thread — the librarian only does vault IO, so a big value's AEAD work never delays anyone else's op.
    pub fn write_addr(&self, addr: &[u8; 32], data: &[u8]) -> Result<(), StorageError> {
        let stored = if self.encrypt {
            encrypt_bytes(data, &self.derive_enc_key_for_addr(addr)?).map_err(StorageError::Crypto)?
        } else {
            data.to_vec()
        };
        // Cache BEFORE posting: read-your-own-writes — a reader racing this write sees the value about to become durable instead of stalling behind the commit.
        self.cache_put(*addr, Some(stored.clone()));
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Put { addr: *addr, stored, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// Read the value at a 32-byte vault **address**. Returns `None` if absent. Every block on the path is hash-verified by manifestus.
    /// Reads jump the librarian's queued writes (see [`librarian`]), so this waits for at most one in-flight write — never a persist burst. Decrypt runs on the caller's thread.
    pub fn read_addr(&self, addr: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        // Cache first — a hit never touches the librarian, so no read waits behind a running commit (the 2026-08-21 hitches). Decrypt still runs per read; RAM holds only stored bytes.
        let cached = self.read_cache.lock().ok().and_then(|c| Self::cache_get(&c, addr));
        let stored = match cached {
            Some(hit) => hit,
            None => {
                let (reply, reply_rx) = std::sync::mpsc::channel();
                let fetched = self
                    .post(VaultOp::Get { addr: *addr, reply }, reply_rx)?
                    .map_err(StorageError::Vault)?;
                self.cache_put(*addr, fetched.clone());
                fetched
            }
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        if !self.encrypt {
            return Ok(Some(stored));
        }
        let plaintext =
            decrypt_bytes(&stored, &self.derive_enc_key_for_addr(addr)?).map_err(StorageError::Crypto)?;
        Ok(Some(plaintext))
    }

    /// Remove the value at a 32-byte vault **address**. Blocks zeroed on both mirrors immediately; the plow reaps the slots.
    pub fn delete_addr(&self, addr: &[u8; 32]) -> Result<(), StorageError> {
        // Known-absent in the cache immediately (same read-your-own-writes rule as write_addr).
        self.cache_put(*addr, None);
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Delete { addr: *addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// Apply MANY put-or-delete addr ops IN ORDER as one librarian batch — (usually) ONE manifestus commit for the lot, instead of one durable round-trip per op. `Some(data)` = put, `None` = delete. This is the transaction shape for rārangi's transact: its apply phase [row puts + catalog + superroot + WAL retire] rode 4-5 serial commits per row before this (the 2026-09-02 field day's 40s message sends); posted as one Batch it is one flush. Encrypt runs on the caller's thread per the write_addr law; every entry hits the read cache before posting (read-your-own-writes). Durable on return. NOT all-or-nothing under fence pressure (a heartbeat commit can land a prefix early — never out of order); callers needing atomicity anchor on their own journal, exactly as rārangi's WAL does.
    pub fn apply_addr_batch(
        &self,
        items: Vec<([u8; 32], Option<Vec<u8>>)>,
    ) -> Result<(), StorageError> {
        if items.is_empty() {
            return Ok(());
        }
        let mut stored_items: Vec<([u8; 32], Option<Vec<u8>>)> = Vec::with_capacity(items.len());
        for (addr, value) in items {
            match value {
                Some(data) => {
                    let stored = if self.encrypt {
                        encrypt_bytes(&data, &self.derive_enc_key_for_addr(&addr)?)
                            .map_err(StorageError::Crypto)?
                    } else {
                        data
                    };
                    self.cache_put(addr, Some(stored.clone()));
                    stored_items.push((addr, Some(stored)));
                }
                None => {
                    self.cache_put(addr, None);
                    stored_items.push((addr, None));
                }
            }
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Batch { items: stored_items, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// The 32-byte vault address a logical **string** key maps to — for callers (rārangi) that batch string-keyed and addr-keyed ops thru [`apply_addr_batch`](Self::apply_addr_batch) and need the derivation without a write.
    pub fn entry_addr(&self, key: &str) -> [u8; 32] {
        self.derive_entry_key(key)
    }

    /// This vault's identity seed — callers use it as the `scope` for self/global entries. Panics only if called on a device vault before [`set_identity`](Self::set_identity); legacy per-identity vaults always carry it. New code should prefer [`identity()`](Self::identity).
    pub fn vault_seed(&self) -> [u8; 32] {
        self.identity().expect("vault_seed() before set_identity on a device vault")
    }

    /// DEVICE-scope string-key ops — readable from first launch, before any identity exists: the pre-attest state (binding marker, boot settings, reboot capsule, opt-in flags) that used to sprawl as loose files.
    pub fn write_device(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let addr = self.derive_device_entry_key(key);
        let stored = if self.encrypt {
            encrypt_bytes(data, &self.derive_device_enc_key_for_addr(&addr)).map_err(StorageError::Crypto)?
        } else {
            data.to_vec()
        };
        self.cache_put(addr, Some(stored.clone()));
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Put { addr, stored, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// DEVICE-scope read — see [`write_device`](Self::write_device).
    pub fn read_device(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let addr = self.derive_device_entry_key(key);
        let cached = self.read_cache.lock().ok().and_then(|c| Self::cache_get(&c, &addr));
        let stored = match cached {
            Some(hit) => hit,
            None => {
                let (reply, reply_rx) = std::sync::mpsc::channel();
                let fetched = self
                    .post(VaultOp::Get { addr, reply }, reply_rx)?
                    .map_err(StorageError::Vault)?;
                self.cache_put(addr, fetched.clone());
                fetched
            }
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        if !self.encrypt {
            return Ok(Some(stored));
        }
        let plaintext = decrypt_bytes(&stored, &self.derive_device_enc_key_for_addr(&addr))
            .map_err(StorageError::Crypto)?;
        Ok(Some(plaintext))
    }

    /// DEVICE-scope read of a BULK value ([`write_device_bulk`](Self::write_device_bulk)): straight from the librarian, never the read cache, and nothing added to it. A value written through the cache still reads as cached.
    pub fn read_device_bulk(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let addr = self.derive_device_entry_key(key);
        let cached = self.read_cache.lock().ok().and_then(|c| Self::cache_get(&c, &addr));
        let stored = match cached {
            Some(hit) => hit,
            None => {
                let (reply, reply_rx) = std::sync::mpsc::channel();
                self.post(VaultOp::Get { addr, reply }, reply_rx)?.map_err(StorageError::Vault)?
            }
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        if !self.encrypt {
            return Ok(Some(stored));
        }
        let plaintext = decrypt_bytes(&stored, &self.derive_device_enc_key_for_addr(&addr)).map_err(StorageError::Crypto)?;
        Ok(Some(plaintext))
    }

    /// DEVICE-scope write of many BULK values as one librarian batch, kept OUT of the read cache: values the caller holds itself and reads back rarely (Mahere's downloaded map cells, Nick 2026-10-25), which through the cache would fill it past its cap and clear everyone's entries with it. A cached entry at one of the keys is dropped, never left stale. Durable on return; until then a read may answer from before the write (the librarian answers queued reads first), so a caller that must read its own writes holds them until this returns.
    pub fn write_device_bulk(&self, entries: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut items: Vec<([u8; 32], Option<Vec<u8>>)> = Vec::with_capacity(entries.len());
        for (key, data) in entries {
            let addr = self.derive_device_entry_key(key);
            let stored = if self.encrypt {
                encrypt_bytes(data, &self.derive_device_enc_key_for_addr(&addr)).map_err(StorageError::Crypto)?
            } else {
                data.clone()
            };
            items.push((addr, Some(stored)));
        }
        if let Ok(mut c) = self.read_cache.lock() {
            for (addr, _) in &items {
                if let Ok(i) = c.binary_search_by(|(a, _)| a.cmp(addr)) {
                    c.remove(i);
                }
            }
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Batch { items, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// DEVICE-scope read by ADDRESS (from [`live_addrs`](Self::live_addrs)): the value decrypted as a device-scope entry, for an app taking stock of what its vault holds when it no longer knows every key (Mahere 2026-10-19). An identity-scope value at that address does not decrypt and reads as an error.
    pub fn read_device_addr(&self, addr: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let (reply, reply_rx) = std::sync::mpsc::channel();
        let stored = self.post(VaultOp::Get { addr: *addr, reply }, reply_rx)?.map_err(StorageError::Vault)?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        if !self.encrypt {
            return Ok(Some(stored));
        }
        decrypt_bytes(&stored, &self.derive_device_enc_key_for_addr(addr)).map(Some).map_err(StorageError::Crypto)
    }

    /// Delete MANY values by ADDRESS as one librarian batch (usually one commit): [`delete_device_batch`](Self::delete_device_batch) for addresses found by [`live_addrs`](Self::live_addrs) rather than by key.
    pub fn delete_addr_batch(&self, addrs: &[[u8; 32]]) -> Result<(), StorageError> {
        if addrs.is_empty() {
            return Ok(());
        }
        for a in addrs {
            self.cache_put(*a, None);
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Batch { items: addrs.iter().map(|a| (*a, None)).collect(), reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// DEVICE-scope delete — see [`write_device`](Self::write_device).
    pub fn delete_device(&self, key: &str) -> Result<(), StorageError> {
        let addr = self.derive_device_entry_key(key);
        self.cache_put(addr, None);
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Delete { addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// DEVICE-scope delete of MANY keys as one librarian batch — (usually) one manifestus commit for the lot instead of one durable round trip per key (Mahere 2026-10-18: moving its cell cache, hundreds of thousands of entries, out of the vault). An absent key is a no-op, as for [`delete_device`](Self::delete_device). Durable on return.
    pub fn delete_device_batch(&self, keys: &[String]) -> Result<(), StorageError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut items: Vec<([u8; 32], Option<Vec<u8>>)> = Vec::with_capacity(keys.len());
        for key in keys {
            let addr = self.derive_device_entry_key(key);
            self.cache_put(addr, None);
            items.push((addr, None));
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Batch { items, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// DEVICE-scope write of MANY keys as one librarian batch — (usually) one manifestus commit for the lot instead of one durable round trip per key (Mahere 2026-10-25: a view's cells arrive by the hundred). Encrypted on the caller's thread and visible to reads at once, as for [`write_device`](Self::write_device). Durable on return.
    pub fn write_device_batch(&self, entries: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut items: Vec<([u8; 32], Option<Vec<u8>>)> = Vec::with_capacity(entries.len());
        for (key, data) in entries {
            let addr = self.derive_device_entry_key(key);
            let stored = if self.encrypt {
                encrypt_bytes(data, &self.derive_device_enc_key_for_addr(&addr)).map_err(StorageError::Crypto)?
            } else {
                data.clone()
            };
            self.cache_put(addr, Some(stored.clone()));
            items.push((addr, Some(stored)));
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Batch { items, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// Device-scope entry ADDRESS — a distinct context from the identity-scope entry address, so the two scopes can never collide on a storage slot even for an identical logical key.
    fn derive_device_entry_key(&self, key: &str) -> [u8; 32] {
        blake3::derive_key(&format!("{}.storage.entry.device.v1", self.app_id), key.as_bytes())
    }

    // ======================================================================== Enumeration + raw reads =====================================

    /// Every live entry ADDRESS in the vault, enumerated from the committed trie — complete by construction (manifestus leaves carry their keys), zero domain knowledge needed.
    pub fn live_addrs(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Keys { reply }, reply_rx)?.map_err(StorageError::Vault)
    }

    /// The engine's physique — one librarian message, answered from RAM (the Settings vault page's read).
    pub fn vault_stats(&self) -> Result<manifestus::VaultStats, StorageError> {
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Stats { reply }, reply_rx)
    }

    /// The raw STORED bytes at an address — ciphertext and all, no decrypt: a presence probe that needs no key (photon's blob checks).
    pub fn read_stored(&self, addr: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Get { addr: *addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// How many values the repair-open fallback pruned to boot this vault (0 = clean open or no data lost). Callers surface a nonzero count — the loss already happened; hiding it is the only way to make it worse.
    pub fn repaired_lost_values(&self) -> usize {
        self.repaired_lost_values.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True if the mirrors diverged at open (and were healed) or a mirror died mid-session.
    pub fn degraded(&self) -> bool {
        if self.healed_at_open || self.repaired_lost_values() > 0 {
            return true;
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Degraded { reply }, reply_rx).unwrap_or(true)
    }

    // ======================================================================== Internal key derivation ================================================

    /// Per-address AEAD key, IDENTITY scope: hash(thing|person|device). Errors when no identity is set (pre-attest): identity-scope data cannot exist before an identity does.
    fn derive_enc_key_for_addr(&self, addr: &[u8; 32]) -> Result<[u8; 32], StorageError> {
        let identity = self.identity().ok_or_else(|| {
            StorageError::Crypto("identity not set — pre-attest entries use the *_device methods".to_string())
        })?;
        Ok(derive_addr_key(&self.app_id, addr, &identity, &self.secret))
    }

    /// Per-address AEAD key, DEVICE scope: hash(thing|device) — readable from first launch, before any identity exists. Distinct KDF context keeps the two scopes disjoint even at an identical address.
    fn derive_device_enc_key_for_addr(&self, addr: &[u8; 32]) -> [u8; 32] {
        let context = [addr.as_slice(), self.secret.as_slice()].concat();
        blake3::derive_key(&format!("{}.storage.encryption.device.v1", self.app_id), &context)
    }

    /// Fixed 32-byte vault entry address for a logical string key. The vault file is already per-(app, handle, device), so no identity material is mixed here — only the app domain + the key.
    fn derive_entry_key(&self, key: &str) -> [u8; 32] {
        derive_entry_addr(&self.app_id, key)
    }
}

// ============================================================================ Vault path resolution ======================================================

/// Vault dir override — platform-neutral (generalized 2026-08-20 from the Android-only version). Two callers: the Android JNI shim (dirs::config_dir() doesn't resolve there; app-private dirs come from the Java side) and TESTS (a test that forgets this writes real 17MB vault rings into the developer's live config dir — the "eight vaults, recent timestamps" field mystery). Tuple is `(primary, shadow)`.
static VAULT_DIRS_OVERRIDE: Mutex<Option<(String, String)>> = Mutex::new(None);

/// Inject the dual-ring vault directories. Android: the JNI shim wires it from native init, before any storage op. Tests: point at a tempdir FIRST — never let a test touch the real config dir.
pub fn set_vault_dirs_override(primary: String, shadow: String) {
    if let Ok(mut g) = VAULT_DIRS_OVERRIDE.lock() {
        *g = Some((primary, shadow));
    }
}

/// Back-compat alias for the JNI shim's existing call site.
#[cfg(target_os = "android")]
pub fn set_android_vault_dirs(primary: String, shadow: String) {
    set_vault_dirs_override(primary, shadow);
}

/// The injected `(primary, shadow)` vault directories, if set. Exposed so a device-clean can wipe the ACTUAL vault dirs on Android — `dirs::config_dir()` doesn't resolve there, so a wipe that walked it would silently no-op.
pub fn android_vault_dirs() -> Option<(String, String)> {
    VAULT_DIRS_OVERRIDE.lock().ok().and_then(|g| g.clone())
}

/// Resolve the two ring paths for the given per-handle filename. Files live under `<config_dir>/<dir>/<filename>.vsf` and `<data_dir>/<dir>/<filename>.vsf`. On Linux + Windows the XDG split gives different directories. On macOS `config_dir()` and `data_dir()` collide; the shadow then shares the directory with `<filename>.shadow.vsf`. On Android the dirs come from the JNI shim.
/// The two physical ring-file paths a vault occupies (config-dir + data-dir, or the shadow-suffixed pair when they coincide), for a given app + vault seed + secret. Exposed so inspection tools (`keteinfo`) can open the same files `FlatStorage` would, without re-deriving the (android-vs-desktop, config-vs-data) path logic. Same inputs as [`FlatStorage::new`].
#[cfg(not(target_os = "ferros"))]
pub fn vault_ring_paths(app: App, vault_seed: &[u8; 32], secret: &[u8; 32]) -> Result<[PathBuf; 2], StorageError> {
    let filename = tohu::vault_path_name(app.id, vault_seed, secret);
    vault_paths(app.dir, &filename)
}

#[cfg(not(target_os = "ferros"))]
fn vault_paths(dir: &str, filename: &str) -> Result<[PathBuf; 2], StorageError> {
    let primary_name = format!("{}.vsf", filename);
    let shadow_name = format!("{}{}.vsf", filename, VAULT_SHADOW_SUFFIX);

    // The override wins on EVERY platform: Android requires it (no XDG dirs), tests use it to stay out of the developer's real config dir.
    let override_dirs = VAULT_DIRS_OVERRIDE
        .lock()
        .map_err(|e| StorageError::Io(std::io::Error::other(format!("vault-dir lock: {}", e))))?
        .clone();
    if let Some(dirs) = override_dirs {
        let primary_dir = PathBuf::from(&dirs.0).join(dir);
        let shadow_dir = if dirs.1.is_empty() {
            primary_dir.clone()
        } else {
            PathBuf::from(&dirs.1).join(dir)
        };
        let primary = primary_dir.join(&primary_name);
        let shadow = if primary_dir == shadow_dir {
            shadow_dir.join(&shadow_name)
        } else {
            shadow_dir.join(&primary_name)
        };
        return Ok([primary, shadow]);
    }

    #[cfg(target_os = "android")]
    {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Android vault dirs not set — JNI shim must call set_android_vault_dirs",
        )));
    }

    #[cfg(not(target_os = "android"))]
    {
        let primary_dir = dirs::config_dir()
            .ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "config directory not found",
                ))
            })?
            .join(dir);
        let shadow_dir = dirs::data_dir().unwrap_or_else(|| primary_dir.clone()).join(dir);

        let primary = primary_dir.join(&primary_name);
        let shadow = if primary_dir == shadow_dir {
            shadow_dir.join(&shadow_name)
        } else {
            shadow_dir.join(&primary_name)
        };

        Ok([primary, shadow])
    }
}

/// First 8 bytes of a 32-byte identifier as lowercase hex — enough to correlate across logs without dumping whole hashes.
#[cfg(not(target_os = "ferros"))]
fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{:02x}", b)).collect()
}

/// The engine's event sink, routed to the log — closes manifestus's "emit-site wiring is the follow-up pass" TODO for the host profile. Every survivable engine event (verify retries, mirror degradation, averted live-laps) becomes a visible log line instead of dying in the NullSink.
#[cfg(not(target_os = "ferros"))]
struct LogSink;

#[cfg(not(target_os = "ferros"))]
impl manifestus::EventSink for LogSink {
    fn emit(&mut self, event: manifestus::StorageEvent) {
        match event {
            // The lap guard fired: an append was about to destroy a block the committed index still references. The value survived — but the clean invariant was broken upstream, and every one of these is a would-have-been dangling pointer (Leviathan's 43, 2026-09-03). LOUD.
            manifestus::StorageEvent::LiveLapAverted { lba } => {
                log::error!("kete: LIVE-LAP AVERTED at lba {} — an append targeted a referenced block and was refused; the value survives, but the clean invariant was broken upstream (report this log)", lba)
            }
            manifestus::StorageEvent::MirrorDegraded => log::warn!("kete: mirror degraded — secondary dropped for the session, running unmirrored"),
            other => log::info!("kete: storage event {:?}", other),
        }
    }
}

/// The commit stamp (`now`) manifestus writes into every spine entry as VSF `e6`: Eagle time in oscillations, which is what that type IS.
/// It was Unix seconds (2026-10-25: every vault commit read as about 1.2 s after the Eagle landed); manifestus only asks that a generation's stamp exceed the head's, and real oscillations (~2.6e18) exceed every Unix second ever stored (~1.7e9), so existing vaults keep that order across the change.
#[cfg(not(target_os = "ferros"))]
fn eagle_now() -> i64 {
    vsf::eagle_time_oscillations()
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: App = App {
        id: "kete-test",
        dir: "kete-test",
    };

    /// Every disk-touching test routes thru the tempdir override — a test that forgets writes REAL vault rings into the developer's home (the "eight vaults, recent timestamps" field mystery, 2026-08-20). Process-global: all tests in one run share one tmp root, but the root is per-PID so a PREVIOUS run's vault files never leak into this run's "fresh vault" assumptions (the identity-gate test found last run's entries and correctly refused to read them pre-identity).
    fn isolate() {
        let root = std::env::temp_dir().join(format!("kete-tests-{}", std::process::id()));
        static CLEAN: std::sync::Once = std::sync::Once::new();
        CLEAN.call_once(|| {
            let _ = std::fs::remove_dir_all(&root); // pid-reuse insurance — once per process, BEFORE any test writes; sibling tests only ever see the fresh root
        });
        set_vault_dirs_override(
            root.join("cfg").to_string_lossy().into_owned(),
            root.join("data").to_string_lossy().into_owned(),
        );
    }

    /// Repair-open fallback (field 2026-08-25): a torn/reused block behind a committed pointer made the strict open refuse the WHOLE vault with "seal verification failed" on every boot. The fallback prunes the dangling pointer and boots. Torn = the newest nonzero tract block corrupted in BOTH mirrors (identical tears — a kill mid-flush hits both sides; a one-sided tear is already healed by verified_replicate before this path is reached).
    #[test]
    fn torn_live_block_opens_via_repair_fallback() {
        isolate();
        let identity = [0xE1u8; 32];
        let secret = [0xE2u8; 32];
        {
            let v = FlatStorage::new(APP, identity, secret).unwrap();
            for i in 0..6u8 {
                v.write(&format!("key/{i}"), &[i; 900]).unwrap();
            }
        } // librarian + files closed

        let paths = vault_ring_paths(APP, &identity, &secret).unwrap();
        // The FIRST nonzero block past the ring region is the oldest live VALUE doc (fresh vault, no wrap — values and index versions append in write order, so the lowest tract block is key/0's data, not the index root). Tear its body (past the seal header) in BOTH files: a value tear is surgical, an index-root tear would cost the whole tree.
        let bytes = std::fs::read(&paths[0]).unwrap();
        let block = 4096usize;
        let tract_first = 1usize << HOST_RING_LOG2;
        let torn = (tract_first..bytes.len() / block)
            .find(|i| bytes[i * block..(i + 1) * block].iter().any(|b| *b != 0))
            .expect("a nonzero tract block exists");
        for p in &paths {
            use std::io::{Seek, Write};
            let mut f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
            f.seek(std::io::SeekFrom::Start((torn * block + block - 8) as u64)).unwrap();
            f.write_all(&[0xA5u8; 8]).unwrap();
        }

        // Reopen (lazily): the walk refuses (Seal) where it meets the tear — at the latest before the first write lands — the fallback prunes and reopens, and the vault WORKS: fresh writes land, surviving keys read.
        let v = FlatStorage::new(APP, identity, secret).unwrap();
        v.write("post-repair", b"alive").unwrap();
        assert!(v.repaired_lost_values() >= 1, "the torn live block must have cost at least one pruned pointer");
        assert!(v.degraded(), "a repair-open with losses reports degraded");
        assert_eq!(v.read("post-repair").unwrap(), Some(b"alive".to_vec()));
        let mut survivors = 0;
        for i in 0..6u8 {
            if let Ok(Some(val)) = v.read(&format!("key/{i}")) {
                assert_eq!(val, vec![i; 900]);
                survivors += 1;
            }
        }
        assert!(survivors >= 1, "pruning is surgical — the tear must not take the whole vault");
        drop(v);

        // THE REPAIR MUST STICK (field 2026-08-25): the Mac re-pruned the SAME 84 danglings on every boot — the repair commit was a no-op on disk, so the vault re-repaired forever and every mid-session put kept failing. A second reopen must be CLEAN.
        let v2 = FlatStorage::new(APP, identity, secret).unwrap();
        // A write finishes the lazy walk: past it, a repair would have been counted.
        v2.write("second boot", b"clean").unwrap();
        assert_eq!(
            v2.repaired_lost_values(),
            0,
            "the pruned index must be durable — a second boot needing the same repair means the repair never landed"
        );
        assert_eq!(v2.read("post-repair").unwrap(), Some(b"alive".to_vec()));
    }

    #[test]
    fn encrypt_round_trip() {
        let key = [9u8; 32];
        let pt = b"the quick brown fox";
        let blob = encrypt_bytes(pt, &key).unwrap();
        assert_eq!(&blob[..24].len(), &24); // 24-byte XChaCha nonce prefix
        assert_ne!(&blob[24..], &pt[..]); // ciphertext is not the plaintext
        assert_eq!(decrypt_bytes(&blob, &key).unwrap(), pt);
        assert!(decrypt_bytes(&blob, &[8u8; 32]).is_err()); // wrong key fails the AEAD tag
    }

    /// A value sealed under the pre-2026-08-18 ChaCha20-Poly1305 (12-byte nonce) format no longer opens: the read-both reader was dropped.
    #[test]
    fn refuses_legacy_12byte_nonce_format() {
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let key = [7u8; 32];
        let pt = b"a pre-migration vault value";
        let nonce_bytes = [0x42u8; 12];
        let ct = ChaCha20Poly1305::new((&key).into())
            .encrypt(&Nonce::from(nonce_bytes), &pt[..])
            .unwrap();
        let mut legacy = nonce_bytes.to_vec();
        legacy.extend_from_slice(&ct);
        // The reader is gone (2026-10-17): the right key, the old format — refused, never a second parser.
        assert!(decrypt_bytes(&legacy, &key).is_err());
    }

    #[test]
    fn vault_round_trip() {
        isolate();
        let store = FlatStorage::new(APP, [0x11; 32], [3u8; 32]).unwrap();
        assert!(store.read("k").unwrap().is_none());
        store.write("k", b"value").unwrap();
        assert_eq!(store.read("k").unwrap().as_deref(), Some(&b"value"[..]));
        store.write("k", b"updated").unwrap();
        assert_eq!(store.read("k").unwrap().as_deref(), Some(&b"updated"[..]));
        store.delete("k").unwrap();
        assert!(store.read("k").unwrap().is_none());
    }

    /// The batch API: mixed puts+deletes land in order thru one librarian post, read back correctly (thru the cache AND cold from disk), and entry_addr matches the string-key derivation so batched string ops hit the same rows as write/read.
    #[test]
    fn addr_batch_round_trip_and_entry_addr_parity() {
        isolate();
        let seed = [0x2Bu8; 32];
        let secret = [7u8; 32];
        {
            let store = FlatStorage::new(APP, seed, secret).unwrap();
            store.write("doomed", b"to-be-batch-deleted").unwrap();
            let a1 = store.entry_addr("row/one");
            let a2 = store.entry_addr("row/two");
            let doomed = store.entry_addr("doomed");
            store
                .apply_addr_batch(vec![
                    (a1, Some(b"first".to_vec())),
                    (doomed, None),
                    (a2, Some(b"second".to_vec())),
                ])
                .unwrap();
            // entry_addr parity: the string-key read path resolves the batched addr write.
            assert_eq!(store.read("row/one").unwrap().as_deref(), Some(&b"first"[..]));
            assert_eq!(store.read("row/two").unwrap().as_deref(), Some(&b"second"[..]));
            assert!(store.read("doomed").unwrap().is_none(), "batched delete landed");
        }
        // Cold reopen: the batch was durable, not a cache artifact.
        let store = FlatStorage::new(APP, seed, secret).unwrap();
        assert_eq!(store.read("row/one").unwrap().as_deref(), Some(&b"first"[..]));
        assert_eq!(store.read("row/two").unwrap().as_deref(), Some(&b"second"[..]));
        assert!(store.read("doomed").unwrap().is_none());
    }

    #[test]
    fn secret_separates_vaults() {
        // Same app + seed, different device secret → a different vault file, so one device's data is invisible to the other.
        isolate();
        let a = FlatStorage::new(APP, [0x22; 32], [1u8; 32]).unwrap();
        a.write("secret", b"hunter2").unwrap();
        let b = FlatStorage::new(APP, [0x22; 32], [2u8; 32]).unwrap();
        assert!(b.read("secret").unwrap().is_none());
    }

    #[test]
    fn a_full_tract_grows_instead_of_dying() {
        // Write well past the 16MB initial tract with values that stay LIVE (distinct addresses, no deletes) — the plow can reclaim nothing, so without the growth path every write past the lap dies with TractFull (the 2026-08-16 photon field failure). Read a sample back across the growth boundary.
        isolate();
        let store = FlatStorage::new(APP, [0x55; 32], [6u8; 32]).unwrap();
        let chunk = vec![0xCD_u8; 256 * 1024];
        for i in 0u8..96 {
            let addr = [i; 32];
            store.write_addr(&addr, &chunk).unwrap();
        }
        for i in [0u8, 47, 95] {
            let got = store.read_addr(&[i; 32]).unwrap().expect("value survives growth");
            assert_eq!(got.len(), chunk.len());
            assert!(got.iter().all(|b| *b == 0xCD));
        }
    }

    #[test]
    fn concurrent_writers_and_readers_hold_read_your_writes() {
        // The librarian serializes ops without a shared mutex; each thread's own write-then-read must still see its write (the sync wrapper's durable-on-return makes this ordering, not luck). Four threads hammer disjoint keys around a fat value that keeps the librarian busy.
        isolate();
        let store = std::sync::Arc::new(FlatStorage::new(APP, [0x44; 32], [5u8; 32]).unwrap());
        let fat = vec![0xAB_u8; 512 * 1024];
        let handles: Vec<_> = (0u8..4)
            .map(|t| {
                let store = std::sync::Arc::clone(&store);
                let fat = fat.clone();
                std::thread::spawn(move || {
                    for i in 0u8..8 {
                        let addr = [t * 64 + i; 32];
                        let value = if i % 2 == 0 { fat.clone() } else { vec![t, i] };
                        store.write_addr(&addr, &value).unwrap();
                        assert_eq!(store.read_addr(&addr).unwrap().as_deref(), Some(&value[..]));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn device_vault_scopes_and_identity_gate() {
        isolate();
        let dev = [0x66u8; 32];
        {
            let v = FlatStorage::open_device_shared(APP, dev).unwrap();
            // Device scope works from first launch, before any identity exists.
            v.write_device("binding", b"party-id-bytes").unwrap();
            assert_eq!(v.read_device("binding").unwrap().as_deref(), Some(&b"party-id-bytes"[..]));
            // Identity scope is GATED until attest — a pre-identity WRITE refuses instead of silently mis-keying; a pre-identity read of an ABSENT key is just absent (no key derivation happens until a value exists).
            assert!(v.write("contacts", b"x").is_err());
            assert!(v.read("contacts").unwrap().is_none());
            // Attest: identity lands, identity scope opens, a DIFFERENT identity is refused (D2).
            v.set_identity([0x77u8; 32]).unwrap();
            v.write("contacts", b"alice").unwrap();
            assert_eq!(v.read("contacts").unwrap().as_deref(), Some(&b"alice"[..]));
            assert!(v.set_identity([0x78u8; 32]).is_err());
            assert_eq!(v.vault_seed(), [0x77u8; 32]);
        }
        // Reopen: same file (device-named), device entries persist, identity entries readable again after set_identity.
        let v = FlatStorage::open_device_shared(APP, dev).unwrap();
        assert_eq!(v.read_device("binding").unwrap().as_deref(), Some(&b"party-id-bytes"[..]));
        v.set_identity([0x77u8; 32]).unwrap();
        assert_eq!(v.read("contacts").unwrap().as_deref(), Some(&b"alice"[..]));
        // The two scopes never collide even on an identical key string.
        v.write_device("contacts", b"device-side").unwrap();
        assert_eq!(v.read("contacts").unwrap().as_deref(), Some(&b"alice"[..]));
        assert_eq!(v.read_device("contacts").unwrap().as_deref(), Some(&b"device-side"[..]));
    }

    /// A batch of device-scope deletes removes every key it names, leaves the rest, takes absent keys in stride, and holds across a reopen.
    #[test]
    fn device_batch_delete() {
        isolate();
        let dev = [0x5au8; 32];
        {
            let v = FlatStorage::open_device_shared(APP, dev).unwrap();
            for i in 0..40 {
                v.write_device(&format!("cell {i}"), &[i as u8; 300]).unwrap();
            }
            let gone: Vec<String> = (0..30).map(|i| format!("cell {i}")).chain(["never written".to_string()]).collect();
            v.delete_device_batch(&gone).unwrap();
            assert!(v.read_device("cell 0").unwrap().is_none());
            assert_eq!(v.read_device("cell 35").unwrap().as_deref(), Some(&[35u8; 300][..]));
        }
        let v = FlatStorage::open_device_shared(APP, dev).unwrap();
        assert!((0..30).all(|i| v.read_device(&format!("cell {i}")).unwrap().is_none()));
        assert!((30..40).all(|i| v.read_device(&format!("cell {i}")).unwrap().is_some()));
    }

    /// Bulk values round-trip, hold across a reopen, replace a cached value without leaving it stale, and stay out of the read cache; a batch of ordinary device writes reads back too.
    #[test]
    fn device_bulk_and_batch_writes() {
        isolate();
        let dev = [0x6bu8; 32];
        {
            let v = FlatStorage::open_device_shared(APP, dev).unwrap();
            v.write_device("setting", b"old").unwrap();
            v.write_device_batch(&[("a".to_string(), vec![1; 50]), ("b".to_string(), vec![2; 50])]).unwrap();
            let cells: Vec<(String, Vec<u8>)> = (0..20).map(|i| (format!("cell {i}"), vec![i as u8; 9000])).chain([("setting".to_string(), b"new".to_vec())]).collect();
            v.write_device_bulk(&cells).unwrap();
            assert_eq!(v.read_device("setting").unwrap().as_deref(), Some(&b"new"[..]), "a bulk write leaves no stale cached value");
            assert_eq!(v.read_device_bulk("cell 7").unwrap().as_deref(), Some(&[7u8; 9000][..]));
            assert_eq!(v.read_device("b").unwrap().as_deref(), Some(&[2u8; 50][..]));
            let cached: usize = v.read_cache.lock().unwrap().iter().map(|(_, x)| x.as_ref().map_or(0, |b| b.len())).sum();
            assert!(cached < 9000, "bulk values are not cached ({cached} bytes held)");
        }
        let v = FlatStorage::open_device_shared(APP, dev).unwrap();
        assert!((0..20).all(|i| v.read_device_bulk(&format!("cell {i}")).unwrap().as_deref() == Some(&[i as u8; 9000][..])));
        assert_eq!(v.read_device("a").unwrap().as_deref(), Some(&[1u8; 50][..]));
    }

    /// Every live address reads back as its device-scope value, and a batch delete by address removes exactly those.
    #[test]
    fn device_values_by_address() {
        isolate();
        let v = FlatStorage::open_device_shared(APP, [0x4du8; 32]).unwrap();
        for i in 0..12 {
            v.write_device(&format!("entry {i}"), &[i as u8; 50]).unwrap();
        }
        let addrs = v.live_addrs().unwrap();
        assert_eq!(addrs.len(), 12);
        let mut seen: Vec<u8> = addrs.iter().map(|a| v.read_device_addr(a).unwrap().unwrap()[0]).collect();
        seen.sort();
        assert_eq!(seen, (0..12).collect::<Vec<u8>>());
        let odd: Vec<[u8; 32]> = addrs.iter().copied().filter(|a| v.read_device_addr(a).unwrap().unwrap()[0] % 2 == 1).collect();
        v.delete_addr_batch(&odd).unwrap();
        assert_eq!(v.live_addrs().unwrap().len(), 6);
        assert!(v.read_device("entry 3").unwrap().is_none());
        assert!(v.read_device("entry 4").unwrap().is_some());
    }

    #[test]
    fn plaintext_round_trip() {
        isolate();
        let store = FlatStorage::new_plaintext(APP, [0x33; 32], [4u8; 32]).unwrap();
        store.write("k", b"in the clear").unwrap();
        assert_eq!(store.read("k").unwrap().as_deref(), Some(&b"in the clear"[..]));
        store.delete("k").unwrap();
        assert!(store.read("k").unwrap().is_none());
    }
}
