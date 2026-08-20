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
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use manifestus::{FileDev, Mirror, Vault, HOST_RING_LOG2, verified_replicate};
use rand::RngCore;

/// Shadow-ring filename suffix used when XDG config_dir == data_dir (macOS): both rings live in the same directory but with distinct names, keeping the dual-ring invariant intact across platforms.
const VAULT_SHADOW_SUFFIX: &str = ".shadow";

/// Initial tract size: 4096 blocks = 16MB per mirror file. Deliberately small — a vault starts small and growth is one fallocate + commit.
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

/// Decrypt a blob produced by [`encrypt_bytes`]. Reads the current XChaCha20-Poly1305 (24-byte nonce) format first, then falls back to the legacy ChaCha20-Poly1305 (12-byte nonce) format for values written before the 2026-08-18 migration. The Poly1305 tag is the disambiguator — a wrong-width attempt fails authentication (2^-128 spurious-pass), so no version byte is needed; a value re-writes into the new format on its next `write`. AEAD failure under BOTH formats (wrong key, tamper, truncation) flows thru as a stringified error.
///
/// MIGRATION: drop the legacy branch once every fleet vault has been fully rewritten (a few versions out) — the birthday-bound-erasing 24-byte nonce is the only format we mint now.
pub fn decrypt_bytes(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    // Current: XChaCha20-Poly1305, [nonce:24][ct+tag].
    if blob.len() >= 24 + 16 {
        let (nonce_bytes, ciphertext) = blob.split_at(24);
        if let Ok(nonce) = XNonce::try_from(nonce_bytes) {
            if let Ok(pt) = XChaCha20Poly1305::new(key.into()).decrypt(&nonce, ciphertext) {
                return Ok(pt);
            }
        }
    }
    // Legacy: ChaCha20-Poly1305, [nonce:12][ct+tag].
    if blob.len() >= 12 + 16 {
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        if let Ok(nonce) = Nonce::try_from(nonce_bytes) {
            if let Ok(pt) = ChaCha20Poly1305::new(key.into()).decrypt(&nonce, ciphertext) {
                return Ok(pt);
            }
        }
        return Err("decrypt failed under both XChaCha and legacy ChaCha formats".to_string());
    }
    Err(format!(
        "ciphertext too short: {} bytes (need ≥ 28 for a legacy nonce + tag)",
        blob.len()
    ))
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
    Degraded {
        reply: std::sync::mpsc::Sender<bool>,
    },
}

/// The librarian: the ONE thread that owns the manifestus engine — no mutex exists, so a blocked reader is structurally impossible rather than a per-call-site discipline.
/// The old shape (engine under a Mutex, every thread calling in) meant an innocent read queued behind whichever persist worker held the lock thru a whole encrypted table write — the 2026-08-15 field lag (400-1794ms UI stalls on a per-tick avatar probe).
/// Reads go first: before each mutation the mailbox is drained and every queued Get is answered, so a read waits for at most the ONE write already on the platter, never a queue of them. Writes can theoretically starve under a sustained read flood, but read floods are boot-shaped and brief while writes coalesce upstream — the trade is deliberate.
/// The thread exits when every sender drops (recv errs), dropping the engine; manifestus is crash-safe at any byte boundary, so no explicit flush handshake is needed.
fn librarian(mut vault: Vault<FileDev, FileDev>, rx: std::sync::mpsc::Receiver<VaultOp>) {
    let mut pending: std::collections::VecDeque<VaultOp> = std::collections::VecDeque::new();
    loop {
        // Idle: block for one op. Busy: drain whatever queued while the last op ran.
        if pending.is_empty() {
            match rx.recv() {
                Ok(op) => pending.push_back(op),
                Err(_) => return,
            }
        }
        while let Ok(op) = rx.try_recv() {
            pending.push_back(op);
        }
        // Answer every queued read (their mutual order preserved), then perform ONE mutation and re-drain — a read arriving mid-write jumps every still-queued write.
        let mut mutation: Option<VaultOp> = None;
        while let Some(op) = pending.pop_front() {
            match op {
                VaultOp::Get { addr, reply } => {
                    let _ = reply.send(vault.get(&addr).map_err(|e| e.to_string()));
                }
                VaultOp::Degraded { reply } => {
                    let _ = reply.send(vault.degraded());
                }
                m => {
                    mutation = Some(m);
                    break;
                }
            }
        }
        match mutation {
            Some(VaultOp::Put { addr, stored, reply }) => {
                let _ = reply.send(put_growing(&mut vault, &addr, &stored));
            }
            Some(VaultOp::Delete { addr, reply }) => {
                let _ = reply.send(vault.delete(&addr, unix_now()).map(|_| ()).map_err(|e| e.to_string()));
            }
            _ => {}
        }
    }
}

/// Put with the designed-but-never-wired growth path: manifestus's put already runs the plow before conceding, so TractFull means the tract is genuinely full of LIVE data — double it (fallocate + commit, fence-conservative per `Vault::grow`) and retry once. Doubling amortizes: a vault that filled once will fill again.
/// This was the missing link behind photon's 2026-08-16 field failure: a 16MB-initial vault filled and every settings/phonebook/zoom persist died with "tract full" — 304 dropped writes in one session log — because nothing ever called grow.
fn put_growing(
    vault: &mut Vault<FileDev, FileDev>,
    addr: &[u8; 32],
    stored: &[u8],
) -> Result<(), String> {
    match vault.put(addr, stored, unix_now()) {
        Err(manifestus::Error::TractFull) => {
            let target = vault.tract_blocks().saturating_mul(2);
            log::info!(
                "kete: tract full of live data — growing {} -> {} blocks",
                vault.tract_blocks(),
                target
            );
            vault
                .grow(target, unix_now())
                .map_err(|e| format!("vault grow: {e}"))?;
            vault.put(addr, stored, unix_now()).map_err(|e| e.to_string())
        }
        r => r.map_err(|e| e.to_string()),
    }
}

// ============================================================================ FlatStorage ================================================================

/// All of an app's vault I/O goes thru this struct. Initialized once with the app namespace + handle + secret; the dual-ring vault is opened (or formatted) during construction. Callers see only logical keys; vault internals + per-key encryption are managed below.
/// The engine itself lives on the librarian thread (see [`librarian`]); this struct holds the mailbox. The Mutex around the Sender exists only because std's Sender is !Sync — it guards a sub-microsecond `send`, never IO.
pub struct FlatStorage {
    /// `App::id` — feeds `vault_path_name` and the per-key KDF context strings.
    app_id: String,
    /// The IDENTITY seed, when one exists. Legacy per-identity vaults carry it from construction; a device-first vault (open_device*) starts None and gains it via [`set_identity`](Self::set_identity) at attest — Nick's key model 2026-08-20: entries are keyed hash(thing|device) pre-attest and hash(thing|device|person) after.
    identity: Mutex<Option<[u8; 32]>>,
    /// The 32-byte secret the vault is bound to — mixed into both the vault filename and every per-key encryption key. `tohu::device::device_secret()` locks the vault to this machine; any portable secret (passphrase-derived, identity key) makes a vault that opens on any machine holding that secret.
    secret: [u8; 32],
    /// The librarian's mailbox.
    ops: Mutex<std::sync::mpsc::Sender<VaultOp>>,
    /// Mirrors diverged at open and were replicated back into agreement.
    healed_at_open: bool,
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

    fn open(app: App, filename: String, identity: Option<[u8; 32]>, secret: [u8; 32], encrypt: bool) -> Result<Self, StorageError> {
        let paths = vault_paths(app.dir, &filename)?;

        for p in &paths {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let blocks = (1u64 << HOST_RING_LOG2) + INITIAL_TRACT_BLOCKS;
        let mut a = FileDev::create(&paths[0], blocks)?;
        let mut b = FileDev::create(&paths[1], blocks)?;

        // Converge divergent mirrors (stale restore, missed writes, fresh second file) BEFORE composing them — block-level, verified, idempotent.
        let healed = verified_replicate(&mut a, &mut b, HOST_RING_LOG2)?;
        let healed_at_open = healed != manifestus::Replicated::default();
        if healed_at_open {
            log::info!(
                "kete: mirrors diverged at open — replicated {} spine + {} tract blocks",
                healed.spine_copied,
                healed.tract_copied
            );
        }

        let vault = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, unix_now())?;
        // Hand the engine to its librarian — from here on, only that thread touches manifestus.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("kete-librarian".to_string())
            .spawn(move || librarian(vault, rx))
            .map_err(|e| StorageError::Io(e))?;
        Ok(Self {
            app_id: app.id.to_string(),
            identity: Mutex::new(identity),
            secret,
            ops: Mutex::new(tx),
            healed_at_open,
            encrypt,
        })
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
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Put { addr: *addr, stored, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// Read the value at a 32-byte vault **address**. Returns `None` if absent. Every block on the path is hash-verified by manifestus.
    /// Reads jump the librarian's queued writes (see [`librarian`]), so this waits for at most one in-flight write — never a persist burst. Decrypt runs on the caller's thread.
    pub fn read_addr(&self, addr: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let (reply, reply_rx) = std::sync::mpsc::channel();
        let stored = self
            .post(VaultOp::Get { addr: *addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)?;
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
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Delete { addr: *addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)
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
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Put { addr, stored, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// DEVICE-scope read — see [`write_device`](Self::write_device).
    pub fn read_device(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let addr = self.derive_device_entry_key(key);
        let (reply, reply_rx) = std::sync::mpsc::channel();
        let stored = self
            .post(VaultOp::Get { addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)?;
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

    /// DEVICE-scope delete — see [`write_device`](Self::write_device).
    pub fn delete_device(&self, key: &str) -> Result<(), StorageError> {
        let addr = self.derive_device_entry_key(key);
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Delete { addr, reply }, reply_rx)?
            .map_err(StorageError::Vault)
    }

    /// Device-scope entry ADDRESS — a distinct context from the identity-scope entry address, so the two scopes can never collide on a storage slot even for an identical logical key.
    fn derive_device_entry_key(&self, key: &str) -> [u8; 32] {
        blake3::derive_key(&format!("{}.storage.entry.device.v1", self.app_id), key.as_bytes())
    }

    /// True if the mirrors diverged at open (and were healed) or a mirror died mid-session.
    pub fn degraded(&self) -> bool {
        if self.healed_at_open {
            return true;
        }
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.post(VaultOp::Degraded { reply }, reply_rx).unwrap_or(true)
    }

    // ======================================================================== Internal key derivation ================================================

    /// Per-address AEAD key, IDENTITY scope: hash(thing|person|device) — the exact derivation legacy per-identity vaults used, so migrated values decrypt unchanged. Errors when no identity is set (pre-attest): identity-scope data cannot exist before an identity does.
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
pub fn vault_ring_paths(app: App, vault_seed: &[u8; 32], secret: &[u8; 32]) -> Result<[PathBuf; 2], StorageError> {
    let filename = tohu::vault_path_name(app.id, vault_seed, secret);
    vault_paths(app.dir, &filename)
}

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

/// Caller-clock timestamp (`now`) for manifestus commit metadata. Unix seconds — manifestus never interprets it; it exists for GC policy and debugging.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: App = App {
        id: "kete-test",
        dir: "kete-test",
    };

    /// Every disk-touching test routes thru the tempdir override — a test that forgets writes REAL vault rings into the developer's home (the "eight vaults, recent timestamps" field mystery, 2026-08-20). Idempotent and process-global: all tests share one tmp root.
    fn isolate() {
        let root = std::env::temp_dir().join("kete-tests");
        set_vault_dirs_override(
            root.join("cfg").to_string_lossy().into_owned(),
            root.join("data").to_string_lossy().into_owned(),
        );
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

    /// A value sealed under the LEGACY ChaCha20-Poly1305 (12-byte nonce) format must still open — the
    /// read-both migration path. Synthesizes a legacy blob directly (the old encrypt is gone).
    #[test]
    fn decrypts_legacy_12byte_nonce_format() {
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let key = [7u8; 32];
        let pt = b"a pre-migration vault value";
        let nonce_bytes = [0x42u8; 12];
        let ct = ChaCha20Poly1305::new((&key).into())
            .encrypt(&Nonce::from(nonce_bytes), &pt[..])
            .unwrap();
        let mut legacy = nonce_bytes.to_vec();
        legacy.extend_from_slice(&ct);
        assert_eq!(decrypt_bytes(&legacy, &key).unwrap(), pt);
        // And the wrong key still fails under the legacy branch too.
        assert!(decrypt_bytes(&legacy, &[1u8; 32]).is_err());
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
                        let addr = [t.wrapping_mul(64).wrapping_add(i); 32];
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
