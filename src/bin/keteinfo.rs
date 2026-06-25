//! `keteinfo` — the decrypting companion to manifestus's `vaultinfo`.
//!
//! `vaultinfo` decodes the manifestus on-disk structure (rings, tree, seals) but shows values as opaque sizes — manifestus holds only ciphertext. `keteinfo` adds the kete layer: given the vault's `(app, vault_seed, secret)` it opens the `FlatStorage`, and for each LOGICAL key supplied it derives the entry key, fetches the value, derives the per-key ChaCha20-Poly1305 key, and decrypts — printing plaintext.
//!
//! WHY logical keys (not on-disk hashes): the on-disk 32-byte key is `BLAKE3.derive_key("...entry.v0", logical_key)` — one-way. You cannot decrypt a value from the vault file alone; you need the original logical string the app `put()` under (plus the seed + secret that gate the enc key). So this tool takes the app's own logical keys.
//!
//! Two forms:
//!   keteinfo FILE                                  # structural only — same as `vaultinfo FILE`
//!   keteinfo --app ID --dir DIR --seed HEX --secret HEX [KEY...]
//!                                                  # derive ring paths, inspect structure, decrypt each KEY

use std::env;
use std::process::ExitCode;

use kete::{App, FlatStorage, vault_ring_paths};
use manifestus::host::FileDev;
use manifestus::inspect::{inspect, InspectOptions};

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() || argv.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        return ExitCode::from(if argv.is_empty() { 1 } else { 0 });
    }

    let mut app_id: Option<String> = None;
    let mut app_dir: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut secret_hex: Option<String> = None;
    let mut file: Option<String> = None;
    let mut keys: Vec<String> = Vec::new();

    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--app" => app_id = it.next().cloned(),
            "--dir" => app_dir = it.next().cloned(),
            "--seed" => seed_hex = it.next().cloned(),
            "--secret" => secret_hex = it.next().cloned(),
            s if s.starts_with("--") => {
                eprintln!("keteinfo: unknown option {s}");
                print_usage();
                return ExitCode::from(1);
            }
            // A path-shaped arg is the file; everything else is a logical key.
            s if looks_like_path(s) && file.is_none() => file = Some(s.to_string()),
            s => keys.push(s.to_string()),
        }
    }

    // Structural-only form: a bare FILE, no seed.
    if seed_hex.is_none() && secret_hex.is_none() {
        let Some(path) = file else {
            eprintln!("keteinfo: give a FILE (structural) or --app/--dir/--seed/--secret (decrypt)");
            print_usage();
            return ExitCode::from(1);
        };
        return structural_only(&path);
    }

    // Decrypt form: need app + dir + seed + secret.
    let (Some(id), Some(dir), Some(sh), Some(xh)) = (app_id, app_dir, seed_hex, secret_hex) else {
        eprintln!("keteinfo: decrypt form needs all of --app --dir --seed --secret");
        print_usage();
        return ExitCode::from(1);
    };
    let Some(seed) = parse_hex32(&sh) else {
        eprintln!("keteinfo: --seed must be 64 hex chars (32 bytes)");
        return ExitCode::from(1);
    };
    let Some(secret) = parse_hex32(&xh) else {
        eprintln!("keteinfo: --secret must be 64 hex chars (32 bytes)");
        return ExitCode::from(1);
    };

    let app = App { id: &id, dir: &dir };

    // Structural pass on the derived primary ring file.
    let paths = match vault_ring_paths(app, &seed, &secret) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("keteinfo: deriving ring paths: {e}");
            return ExitCode::from(1);
        }
    };
    println!("vault rings:");
    for p in &paths {
        println!("  {}", p.display());
    }
    println!();
    if let Ok(mut dev) = FileDev::open(&paths[0]) {
        if let Ok(report) = inspect(&mut dev, InspectOptions::default()) {
            print!("{}", report.render(InspectOptions::default()));
            println!();
        }
    } else {
        eprintln!("keteinfo: primary ring {} not found — was the vault ever written?", paths[0].display());
        return ExitCode::from(1);
    }

    // Decrypt pass.
    if keys.is_empty() {
        println!("(no logical keys given — structure shown above; pass keys to decrypt values)");
        return ExitCode::from(0);
    }
    let storage = match FlatStorage::new(app, seed, secret) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("keteinfo: opening vault: {e}");
            return ExitCode::from(1);
        }
    };
    println!("--- decrypted values ---");
    let mut any_fail = false;
    for key in &keys {
        match storage.read(key) {
            Ok(Some(bytes)) => {
                println!("  key {key:?} => {} bytes", bytes.len());
                match std::str::from_utf8(&bytes) {
                    Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') => {
                        println!("    {s}");
                    }
                    _ => println!("    (binary; first 32 bytes hex: {})", hex_preview(&bytes)),
                }
            }
            Ok(None) => {
                println!("  key {key:?} => (not present)");
            }
            Err(e) => {
                println!("  key {key:?} => DECRYPT/READ FAILED: {e}");
                any_fail = true;
            }
        }
    }

    if any_fail {
        ExitCode::from(2)
    } else {
        ExitCode::from(0)
    }
}

fn structural_only(path: &str) -> ExitCode {
    let mut dev = match FileDev::open(std::path::Path::new(path)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("keteinfo: cannot open {path}: {e}");
            return ExitCode::from(1);
        }
    };
    match inspect(&mut dev, InspectOptions::default()) {
        Ok(report) => {
            print!("{}", report.render(InspectOptions::default()));
            if report.all_checks_pass() {
                ExitCode::from(0)
            } else {
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!("keteinfo: inspect failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// Path-shaped: contains a separator or a `.vsf` extension. Logical keys are app strings (handles, etc.) without these by convention; ambiguous cases go to `file` only if `file` is still empty.
fn looks_like_path(s: &str) -> bool {
    s.contains('/') || s.contains('\\') || s.ends_with(".vsf")
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_preview(b: &[u8]) -> String {
    b.iter().take(32).map(|x| format!("{x:02x}")).collect()
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  keteinfo FILE                                          # structural only (like vaultinfo)");
    eprintln!("  keteinfo --app ID --dir DIR --seed HEX --secret HEX [KEY...]   # decrypt logical KEYs");
    eprintln!();
    eprintln!("  --app ID      the app namespace (e.g. \"photon\")");
    eprintln!("  --dir DIR     the XDG subdir the rings live under");
    eprintln!("  --seed HEX    vault_seed (tohu::handle_seed), 64 hex chars");
    eprintln!("  --secret HEX  the secret (device_secret or portable), 64 hex chars");
    eprintln!("  KEY...        LOGICAL string keys the app wrote (NOT the on-disk hash — that's one-way)");
    eprintln!();
    eprintln!("Structure comes from manifestus::inspect; decryption from the kete per-key ChaCha20-Poly1305.");
}
