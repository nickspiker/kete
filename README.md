<p align="center">
  <img src="kete.png" alt="kete" width="400"/>
</p>

# kete

**Encrypted keyed storage — a woven basket: put anything in, lock it with any key, carry it anywhere.**

*kete* (te reo Māori): a woven basket — the opaque bag you put things into.

`kete` is a small keyed store: `put` / `get` / `delete` values by string key, optionally encrypted per-key with ChaCha20-Poly1305, stored durably and crash-proof in a [manifestus](https://crates.io/crates/manifestus) dual-ring vault. It's a tool, not a policy — you decide what goes in, where it lives, and what key locks it.

You hand it three things: an `app` namespace, a `name`, and a 32-byte `secret`. The vault's filename and every per-key encryption key derive from those. **The interesting one is the secret, and choosing it is the whole point** — it's what binds (or doesn't bind) the vault to a machine, a password, or an identity. kete just does the derivation, encryption, and durable storage; the security posture is whatever your secret is.

## The secret is the lever

Same vault, one parameter, three postures:

- **Machine-bound.** Pass [`tohu`](https://crates.io/crates/tohu)'s `device_secret()` (a machine fingerprint) and the vault only opens on this machine — a copied or backed-up file won't decrypt elsewhere.
- **Portable.** Pass a passphrase-derived key, or a recoverable identity key, and the same vault opens on any machine that has the secret. Move it, sync it, restore it on new hardware; confidentiality rests on the secret, not the hardware.
- **Plaintext.** `new_plaintext` skips encryption entirely (the secret then only scopes the path) — durable and integrity-checked but readable on disk, e.g. `vsfinfo` on a VSF value. For data that isn't secret.

kete is agnostic: it derives a per-key key from `(key, name seed, secret)` and gets out of the way.

## What it gives you

- **Per-key encryption (optional, on by default).** Each logical key gets its own ChaCha20-Poly1305 key via BLAKE3 over the key string + the name seed + your secret. Distinct key per entry; the secret you supply decides portability.
- **Durable + crash-proof.** Values land in a manifestus vault: mirrored 4KB block devices, a generation ring, write-verify-then-mirror. Power loss at any byte boundary is normal operation, not a corruption event. Every block is BLAKE3-sealed, so integrity holds even in plaintext mode.
- **Opaque addressing.** A logical key is hashed to a 32-byte vault address. The directory holds opaque names; the filesystem leaks nothing about contents.
- **Point-lookup only.** `get` / `put` / `delete`, no iteration — the non-enumerable model of the vault underneath. Layer your own index on top if you need to scan.

## Usage

```rust
use kete::{App, FlatStorage};

// `id` namespaces the vault filename + KDF contexts; `dir` is the on-disk subdirectory.
const APP: App = App { id: "myapp", dir: "MyApp" };

// The secret is yours to choose. This one binds the vault to this machine; swap it
// for a passphrase-derived or identity key to make the vault portable.
let secret = tohu::device::device_secret()?;
let store = FlatStorage::new(APP, "alice", secret)?;

store.write("contacts/index", b"...bytes (VSF or anything)...")?;
let got = store.read("contacts/index")?;   // Option<Vec<u8>>
store.delete("contacts/index")?;

if store.degraded() {
    // a mirror was missing/diverged at open, or died mid-session — surface it
}
```

`new_with_seed` opens the vault straight from a cached name seed (skip the handle string on a resumed session); `new_plaintext` / `new_plaintext_with_seed` are the unencrypted variants. The raw `encrypt_bytes` / `decrypt_bytes` helpers (ChaCha20-Poly1305, `[nonce ‖ ciphertext+tag]`) are exposed for the same wire format outside the vault.

## Security model

Your security posture is your secret's posture — kete imposes none of its own. A machine-bound secret makes a leaked or backed-up vault file useless on another machine; a portable secret makes it as safe as that secret is kept; plaintext mode has integrity but no confidentiality. In every case manifestus guarantees integrity (every block BLAKE3-sealed). What no file-based scheme defends on a desktop is same-user malware — a process with your UID has your files and can recompute whatever your code can; that's the Unix model, and the endgame is a hardware-isolated secret.

Built for the passless app stack (photon, idiosync, …), but it's a general tool — use it for whatever you like.

## License

MIT OR Apache-2.0, at your option.
