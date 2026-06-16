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
use std::sync::Mutex;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
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

/// Encrypt with ChaCha20-Poly1305 + a fresh 12-byte random nonce. Output layout is `[nonce: 12B] || [ciphertext + 16B auth tag]`. One call site for the whole stack so a future change (algorithm bump, AAD scheme) lands in one place.
pub fn encrypt_bytes(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_bytes`]. AEAD failure (wrong key, tamper, truncation) flows thru as a stringified error.
pub fn decrypt_bytes(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 + 16 {
        return Err(format!(
            "ciphertext too short: {} bytes (need ≥ 28 for nonce + auth tag)",
            blob.len()
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| "invalid nonce length".to_string())?;
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(&nonce, ciphertext).map_err(|e| e.to_string())
}

// ============================================================================ FlatStorage ================================================================

/// All of an app's vault I/O goes thru this struct. Initialized once with the app namespace + handle + secret; the dual-ring vault is opened (or formatted) during construction. Callers see only logical keys; vault internals + per-key encryption are managed below.
pub struct FlatStorage {
    /// `App::id` — feeds `vault_path_name` and the per-key KDF context strings.
    app_id: String,
    /// Frozen v0 handle_seed (`tohu::handle_seed(handle)`). The vault's name/address seed and one input to each per-key encryption key.
    handle_seed: [u8; 32],
    /// The 32-byte secret the vault is bound to — mixed into both the vault filename and every per-key encryption key. `tohu::device::device_secret()` locks the vault to this machine; any portable secret (passphrase-derived, identity key) makes a vault that opens on any machine holding that secret.
    secret: [u8; 32],
    /// The manifestus engine. Mutex so future multi-threaded callers Just Work.
    vault: Mutex<Vault<FileDev, FileDev>>,
    /// Mirrors diverged at open and were replicated back into agreement.
    healed_at_open: bool,
    /// Whether values are encrypted (per-key ChaCha20-Poly1305) before storage. False = plaintext: the vault still gives integrity + durability (manifestus BLAKE3-seals every block), values are just stored as-is and stay inspectable on disk (e.g. `vsfinfo` on a VSF value). The caller's choice — a plaintext vault is not leaked-file-safe.
    encrypt: bool,
}

impl FlatStorage {
    /// Open an encrypted vault (per-key ChaCha20-Poly1305), keyed on `secret`. `secret` is mixed into both the filename and every value's key, so the same `(app, handle, secret)` reproduces the same vault and decryption anywhere. Pass `tohu::device::device_secret()` to lock the vault to this machine; pass a portable secret (passphrase-derived, identity key) for a vault you can move to or open on another machine.
    pub fn new(app: App, handle: &str, secret: [u8; 32]) -> Result<Self, StorageError> {
        Self::open(app, tohu::handle_seed(handle), secret, true)
    }

    /// Like [`new`](Self::new) but takes the already-derived vault seed (`tohu::handle_seed`) directly, so a caller that has the seed (e.g. a resumed session) opens the vault without the handle string.
    pub fn new_with_seed(app: App, vault_seed: [u8; 32], secret: [u8; 32]) -> Result<Self, StorageError> {
        Self::open(app, vault_seed, secret, true)
    }

    /// Open a vault that stores values in **plaintext** — same addressing, durability, and integrity (manifestus still BLAKE3-seals every block), but no per-key encryption, so values stay inspectable on disk. Use for data that isn't secret; do NOT use for secrets (a plaintext vault file is readable by anyone who can read it). `secret` still scopes the vault path (machine-bound or portable, your choice).
    pub fn new_plaintext(app: App, handle: &str, secret: [u8; 32]) -> Result<Self, StorageError> {
        Self::open(app, tohu::handle_seed(handle), secret, false)
    }

    /// Plaintext variant of [`new_with_seed`](Self::new_with_seed).
    pub fn new_plaintext_with_seed(app: App, vault_seed: [u8; 32], secret: [u8; 32]) -> Result<Self, StorageError> {
        Self::open(app, vault_seed, secret, false)
    }

    fn open(app: App, vault_seed: [u8; 32], secret: [u8; 32], encrypt: bool) -> Result<Self, StorageError> {
        let filename = tohu::vault_path_name(app.id, &vault_seed, &secret);
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
        Ok(Self {
            app_id: app.id.to_string(),
            handle_seed: vault_seed,
            secret,
            vault: Mutex::new(vault),
            healed_at_open,
            encrypt,
        })
    }

    /// Write data under a logical key. Encrypts with the per-key ChaCha20-Poly1305 key; durable on return (a spine generation references the new state on at least one verified mirror).
    pub fn write(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let stored = if self.encrypt {
            encrypt_bytes(data, &self.derive_enc_key(key)).map_err(StorageError::Crypto)?
        } else {
            data.to_vec()
        };
        let entry_key = self.derive_entry_key(key);

        let mut vault = self
            .vault
            .lock()
            .map_err(|_| StorageError::Vault("FlatStorage mutex poisoned".to_string()))?;
        vault.put(&entry_key, &stored, unix_now())?;
        Ok(())
    }

    /// Read the value for a logical key. Returns `None` if absent. Every block on the path is hash-verified by manifestus.
    pub fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let entry_key = self.derive_entry_key(key);
        let mut vault = self
            .vault
            .lock()
            .map_err(|_| StorageError::Vault("FlatStorage mutex poisoned".to_string()))?;
        let Some(stored) = vault.get(&entry_key)? else {
            return Ok(None);
        };
        if !self.encrypt {
            return Ok(Some(stored));
        }
        let plaintext = decrypt_bytes(&stored, &self.derive_enc_key(key)).map_err(StorageError::Crypto)?;
        Ok(Some(plaintext))
    }

    /// Remove a logical key. Blocks zeroed on both mirrors immediately; the plow reaps the slots.
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        let entry_key = self.derive_entry_key(key);
        let mut vault = self
            .vault
            .lock()
            .map_err(|_| StorageError::Vault("FlatStorage mutex poisoned".to_string()))?;
        vault.delete(&entry_key, unix_now())?;
        Ok(())
    }

    /// True if the mirrors diverged at open (and were healed) or a mirror died mid-session.
    pub fn degraded(&self) -> bool {
        self.healed_at_open
            || self.vault.lock().map(|mut v| v.degraded()).unwrap_or(true)
    }

    // ======================================================================== Internal key derivation ================================================

    /// Per-key AEAD key: domain-separated by app, bound to the handle + the vault `secret`. For `app_id == "photon"` with `secret = device_secret`, this is byte-identical to photon's original `derive_key("photon.storage.encryption.v0", key ++ handle_seed ++ device_secret)`.
    fn derive_enc_key(&self, key: &str) -> [u8; 32] {
        let context = [
            key.as_bytes(),
            self.handle_seed.as_slice(),
            self.secret.as_slice(),
        ]
        .concat();
        blake3::derive_key(&format!("{}.storage.encryption.v0", self.app_id), &context)
    }

    /// Fixed 32-byte vault entry address for a logical key. The vault file is already per-(app, handle, device), so no identity material is mixed here — only the app domain + the key.
    fn derive_entry_key(&self, key: &str) -> [u8; 32] {
        blake3::derive_key(&format!("{}.storage.entry.v0", self.app_id), key.as_bytes())
    }
}

// ============================================================================ Vault path resolution ======================================================

/// Android vault dir override — populated once at startup from the host's JNI shim. `dirs::config_dir()` doesn't resolve on Android; the right scope is the app-private dirs Java side hands us. Tuple is `(primary, shadow)`.
#[cfg(target_os = "android")]
static ANDROID_VAULT_DIRS: Mutex<Option<(String, String)>> = Mutex::new(None);

/// Inject the Android dual-ring vault directories. Must be called before any storage operation. The JNI shim wires it from native init.
#[cfg(target_os = "android")]
pub fn set_android_vault_dirs(primary: String, shadow: String) {
    if let Ok(mut g) = ANDROID_VAULT_DIRS.lock() {
        *g = Some((primary, shadow));
    }
}

/// Resolve the two ring paths for the given per-handle filename. Files live under `<config_dir>/<dir>/<filename>.vsf` and `<data_dir>/<dir>/<filename>.vsf`. On Linux + Windows the XDG split gives different directories. On macOS `config_dir()` and `data_dir()` collide; the shadow then shares the directory with `<filename>.shadow.vsf`. On Android the dirs come from the JNI shim.
fn vault_paths(dir: &str, filename: &str) -> Result<[PathBuf; 2], StorageError> {
    let primary_name = format!("{}.vsf", filename);
    let shadow_name = format!("{}{}.vsf", filename, VAULT_SHADOW_SUFFIX);

    #[cfg(target_os = "android")]
    {
        let dirs = ANDROID_VAULT_DIRS
            .lock()
            .map_err(|e| StorageError::Io(std::io::Error::other(format!("vault-dir lock: {}", e))))?
            .clone()
            .ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Android vault dirs not set — JNI shim must call set_android_vault_dirs",
                ))
            })?;
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

    #[test]
    fn encrypt_round_trip() {
        let key = [9u8; 32];
        let pt = b"the quick brown fox";
        let blob = encrypt_bytes(pt, &key).unwrap();
        assert_ne!(&blob[12..], &pt[..]); // ciphertext is not the plaintext
        assert_eq!(decrypt_bytes(&blob, &key).unwrap(), pt);
        assert!(decrypt_bytes(&blob, &[8u8; 32]).is_err()); // wrong key fails the AEAD tag
    }

    #[test]
    fn vault_round_trip() {
        let store = FlatStorage::new(APP, "kete-smoke", [3u8; 32]).unwrap();
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
        // Same app + handle, different device secret → a different vault file, so one device's data is invisible to the other.
        let a = FlatStorage::new(APP, "kete-devbind", [1u8; 32]).unwrap();
        a.write("secret", b"hunter2").unwrap();
        let b = FlatStorage::new(APP, "kete-devbind", [2u8; 32]).unwrap();
        assert!(b.read("secret").unwrap().is_none());
    }

    #[test]
    fn plaintext_round_trip() {
        let store = FlatStorage::new_plaintext(APP, "kete-plain", [4u8; 32]).unwrap();
        store.write("k", b"in the clear").unwrap();
        assert_eq!(store.read("k").unwrap().as_deref(), Some(&b"in the clear"[..]));
        store.delete("k").unwrap();
        assert!(store.read("k").unwrap().is_none());
    }
}
