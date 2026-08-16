//! `keteinfo` — the decrypting companion to manifestus's `vaultinfo`.
//!
//! `vaultinfo` decodes the manifestus on-disk structure (rings, tree, seals) but shows values as opaque sizes — manifestus holds only ciphertext. `keteinfo` adds the kete layer: given the vault's `(app, vault_seed, secret)` it derives entry addresses (logical string keys, photon-style domain-scoped entries, or raw addresses), fetches, decrypts, and RENDERS — a value that parses as a VSF document prints thru the real VSF inspector.
//!
//! WHY logical keys (not on-disk hashes): the on-disk 32-byte key is `BLAKE3.derive_key("...entry.v0", input)` — one-way. You cannot decrypt a value from the vault file alone; you need the inputs the app derived with (plus the seed + secret that gate the enc key).
//!
//! SAFETY: decrypt mode always copies the ring files to tmp and opens the COPIES — a second engine on live rings is the 2026-07-12 corruption (two in-RAM states racing the same mirrors), so a running app is never raced and never sees this tool.
//!
//! Forms:
//!   keteinfo FILE                                  # structural only — same as `vaultinfo FILE`
//!   keteinfo --app ID --dir DIR --seed HEX|session --secret HEX|device [KEY...] [--domain NAME [--scope HEX]] [--addr HEX]

use std::env;
use std::process::ExitCode;

use kete::{decrypt_bytes, derive_addr_key, derive_entry_addr, derive_scoped_addr, vault_ring_paths, App};
use manifestus::host::FileDev;
use manifestus::inspect::{inspect, InspectOptions};
use manifestus::{verified_replicate, Mirror, Vault, HOST_RING_LOG2};

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
    let mut domains: Vec<String> = Vec::new();
    let mut addrs: Vec<String> = Vec::new();
    let mut scope_hex: Option<String> = None;

    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--app" => app_id = it.next().cloned(),
            "--dir" => app_dir = it.next().cloned(),
            "--seed" => seed_hex = it.next().cloned(),
            "--secret" => secret_hex = it.next().cloned(),
            "--domain" => {
                if let Some(d) = it.next() {
                    domains.push(d.clone());
                }
            }
            "--addr" => {
                if let Some(a) = it.next() {
                    addrs.push(a.clone());
                }
            }
            "--scope" => scope_hex = it.next().cloned(),
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
    // `--seed session` / `--secret device`: pull from the live tohu session and the hardware fingerprint — the exact values the app itself would use, no hex juggling.
    let seed = if sh == "session" {
        match tohu::session() {
            Some(s) => s.vault_seed,
            None => {
                eprintln!("keteinfo: --seed session but no live tohu session (attest once this boot, or pass hex)");
                return ExitCode::from(1);
            }
        }
    } else {
        match parse_hex32(&sh) {
            Some(s) => s,
            None => {
                eprintln!("keteinfo: --seed must be 64 hex chars or the word `session`");
                return ExitCode::from(1);
            }
        }
    };
    let secret = if xh == "device" {
        match tohu::device::device_secret() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("keteinfo: --secret device but the device secret is unavailable: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        match parse_hex32(&xh) {
            Some(s) => s,
            None => {
                eprintln!("keteinfo: --secret must be 64 hex chars or the word `device`");
                return ExitCode::from(1);
            }
        }
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

    // Gather the entries to decrypt.
    let mut items: Vec<(String, [u8; 32])> = Vec::new();
    for key in &keys {
        items.push((format!("key {key:?}"), derive_entry_addr(&id, key)));
    }
    let scope = match &scope_hex {
        Some(h) => match parse_hex32(h) {
            Some(s) => s,
            None => {
                eprintln!("keteinfo: --scope must be 64 hex chars");
                return ExitCode::from(1);
            }
        },
        // The common scope is the vault's own seed (self/global entries: settings, the contact index, our own avatar).
        None => seed,
    };
    for d in &domains {
        items.push((format!("domain {d:?}"), derive_scoped_addr(&id, d, &scope)));
    }
    for a in &addrs {
        match parse_hex32(a) {
            Some(x) => items.push((format!("addr {}…", &a[..16]), x)),
            None => {
                eprintln!("keteinfo: --addr must be 64 hex chars");
                return ExitCode::from(1);
            }
        }
    }
    if items.is_empty() {
        println!("(nothing to decrypt — pass logical KEYs, --domain NAME, or --addr HEX)");
        return ExitCode::from(0);
    }

    // COPY-FIRST: the engine below opens tmp copies, never the live rings.
    let tmp = std::env::temp_dir().join(format!("keteinfo-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&tmp) {
        eprintln!("keteinfo: tmp dir: {e}");
        return ExitCode::from(1);
    }
    let copies = [tmp.join("ring-a.vsf"), tmp.join("ring-b.vsf")];
    for (src, dst) in paths.iter().zip(copies.iter()) {
        if let Err(e) = std::fs::copy(src, dst) {
            eprintln!("keteinfo: copying {} for safe inspection: {e}", src.display());
            return ExitCode::from(1);
        }
    }
    let vault = (|| -> Result<Vault<FileDev, FileDev>, String> {
        let mut a = FileDev::open(&copies[0]).map_err(|e| e.to_string())?;
        let mut b = FileDev::open(&copies[1]).map_err(|e| e.to_string())?;
        verified_replicate(&mut a, &mut b, HOST_RING_LOG2).map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Vault::open(Mirror::new(a, b), HOST_RING_LOG2, now).map_err(|e| e.to_string())
    })();
    let mut vault = match vault {
        Ok(v) => v,
        Err(e) => {
            eprintln!("keteinfo: opening copied rings: {e}");
            return ExitCode::from(1);
        }
    };

    println!("--- decrypted values (from copies under {}) ---", tmp.display());
    let mut any_fail = false;
    for (label, addr) in &items {
        match vault.get(addr) {
            Ok(Some(stored)) => {
                let plain = match decrypt_bytes(&stored, &derive_addr_key(&id, addr, &seed, &secret)) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("  {label} => DECRYPT FAILED: {e}");
                        any_fail = true;
                        continue;
                    }
                };
                println!("  {label} => {} bytes", plain.len());
                render_value(&plain);
            }
            Ok(None) => println!("  {label} => (not present)"),
            Err(e) => {
                println!("  {label} => READ FAILED: {e}");
                any_fail = true;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    if any_fail {
        ExitCode::from(2)
    } else {
        ExitCode::from(0)
    }
}

/// A decrypted value renders as what it IS: a VSF document thru the real inspector, printable text as text, anything else as hex.
fn render_value(plain: &[u8]) {
    const VSF_MAGIC: [u8; 4] = [0x52, 0xC3, 0x85, 0x3C];
    if plain.starts_with(&VSF_MAGIC) {
        match vsf::inspect::inspect_vsf_plain(plain) {
            Ok(report) => {
                for line in report.lines() {
                    println!("    {line}");
                }
                return;
            }
            Err(e) => println!("    (VSF magic but inspect failed: {e})"),
        }
    }
    match std::str::from_utf8(plain) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') => {
            println!("    {s}");
        }
        _ => println!("    (binary; first 32 bytes hex: {})", hex_preview(plain)),
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
    eprintln!("  keteinfo --app ID --dir DIR --seed HEX|session --secret HEX|device [KEY...] [--domain NAME] [--addr HEX]");
    eprintln!();
    eprintln!("  --app ID      the app namespace (e.g. \"photon\")");
    eprintln!("  --dir DIR     the XDG subdir the rings live under");
    eprintln!("  --seed HEX    vault_seed (identity_seed), 64 hex chars — or `session` for the live tohu session");
    eprintln!("  --secret HEX  the secret, 64 hex chars — or `device` for this machine's fingerprint secret");
    eprintln!("  KEY...        LOGICAL string keys the app wrote (NOT the on-disk hash — that's one-way)");
    eprintln!("  --domain NAME domain-scoped entry (photon vault_key shape); scope = --scope HEX or the seed");
    eprintln!("  --addr HEX    a raw 32-byte entry address");
    eprintln!("  decrypt mode always operates on COPIES of the rings — a running app is never raced");
}
