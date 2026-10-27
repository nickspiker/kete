//! kete on ferros: the kernel's vault behind `FlatStorage`, no files anywhere. A process holds a Store capability for one scope of the device vault (the kernel hands it at spawn: `--store photon`), and this backend keeps every entry of every vault kete opens inside that scope, under a short prefix per vault (the first eight hex digits of BLAKE3 over the vault's name, the name a host would have used as a filename) and the entry's 32-byte address in base64url — 52 of the 64 bytes a key may have. Values go through the kernel's STORE syscall in 4 KiB pieces (KERNEL.md, syscall 13: set, staged pieces, delete, list); the librarian thread serves `VaultOp`s one by one, a batch in order — the kernel commits each put, so a batch is not atomic here.
//!
//! The syscall and the arc registers are inlined (three dozen lines) rather than taken from ferros_sys: kete is published, and a path dependency on the ferros tree is not.

use std::sync::mpsc::Receiver;

use crate::VaultOp;

const STORE: u64 = 13;
const ERR: u64 = u64::MAX;
const NOTHING: u64 = u64::MAX - 1;
const PIECE: usize = 4096;

#[inline(always)]
fn svc(n: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let r: u64;
    unsafe { core::arch::asm!("svc #0", inlateout("x0") a0 => r, in("x1") a1, in("x2") a2, in("x3") a3, in("x4") a4, in("x8") n, options(nostack)) };
    r
}

/// The arc base (x28, the kernel's, never written by compiled code on this target).
#[inline(always)]
fn arc_base() -> u64 {
    let b: u64;
    unsafe { core::arch::asm!("mov {}, x28", out(reg) b, options(nomem, nostack, preserves_flags)) };
    b
}

#[inline(always)]
fn off<T: ?Sized>(p: *const T) -> u64 {
    (p as *const u8 as u64).wrapping_sub(arc_base())
}

/// The grants page is arc offset 0: a u32 count, then 32-byte tokens; slot 0 is the console.
fn grant_count() -> u64 {
    unsafe { (arc_base() as *const u32).read_volatile() as u64 }
}

fn cap(slot: u64) -> u64 {
    4 + 32 * slot
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64(addr: &[u8; 32]) -> String {
    let mut out = String::with_capacity(43);
    let mut bits: u32 = 0;
    let mut n = 0;
    for &b in addr {
        bits = (bits << 8) | b as u32;
        n += 8;
        while n >= 6 {
            n -= 6;
            out.push(B64[((bits >> n) & 63) as usize] as char);
        }
    }
    if n > 0 {
        out.push(B64[((bits << (6 - n)) & 63) as usize] as char);
    }
    out
}

fn unb64(s: &str) -> Option<[u8; 32]> {
    if s.len() != 43 {
        return None;
    }
    let mut out = [0u8; 32];
    let (mut bits, mut n, mut i) = (0u32, 0, 0);
    for c in s.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            if i < 32 {
                out[i] = ((bits >> n) & 255) as u8;
                i += 1;
            }
        }
    }
    (i == 32).then_some(out)
}

/// One vault of kete's inside the process's scope.
pub(crate) struct KernelStore {
    cap: u64,
    prefix: String,
}

impl KernelStore {
    /// Find the Store grant among the process's grants (the kernel answers ERR to a list on any other kind) and name this vault's prefix from `name`.
    pub(crate) fn open(name: &str) -> Option<Self> {
        let mut probe = [0u8; 8];
        let cap = (1..grant_count().min(64)).map(cap).find(|&c| svc(STORE, c, 16 | 2 | 8 << 8, off(b"".as_ptr()), 0, off(probe.as_mut_ptr())) != ERR)?;
        let h = blake3::hash(name.as_bytes()).to_hex();
        Some(KernelStore { cap, prefix: format!("{}.", &h[..8]) })
    }

    fn key(&self, addr: &[u8; 32]) -> String {
        format!("{}{}", self.prefix, b64(addr))
    }

    pub(crate) fn get(&self, addr: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let key = self.key(addr);
        let mut out = Vec::new();
        let mut buf = [0u8; PIECE];
        loop {
            let r = svc(STORE, self.cap, 2 | (PIECE as u64) << 8 | (out.len() as u64) << 32, off(key.as_ptr()), key.len() as u64, off(buf.as_mut_ptr()));
            if r == NOTHING {
                return Ok(None);
            }
            if r == ERR {
                return Err(format!("ferros store: read of {key} refused"));
            }
            let total = r as usize;
            let n = PIECE.min(total - out.len().min(total));
            out.extend_from_slice(&buf[..n]);
            if out.len() >= total {
                return Ok(Some(out));
            }
        }
    }

    pub(crate) fn put(&self, addr: &[u8; 32], value: &[u8]) -> Result<(), String> {
        let key = self.key(addr);
        if value.is_empty() {
            return (svc(STORE, self.cap, 1, off(key.as_ptr()), key.len() as u64, off(value.as_ptr())) == 0).then_some(()).ok_or_else(|| format!("ferros store: write of {key} refused"));
        }
        let pieces = value.len().div_ceil(PIECE);
        for (i, piece) in value.chunks(PIECE).enumerate() {
            let more = if i + 1 < pieces { 4 } else { 0 };
            if svc(STORE, self.cap, 1 | 2 | more | (piece.len() as u64) << 8 | ((i * PIECE) as u64) << 32, off(key.as_ptr()), key.len() as u64, off(piece.as_ptr())) != 0 {
                return Err(format!("ferros store: write of {key} refused at piece {i}"));
            }
        }
        Ok(())
    }

    pub(crate) fn delete(&self, addr: &[u8; 32]) -> Result<(), String> {
        let key = self.key(addr);
        match svc(STORE, self.cap, 8, off(key.as_ptr()), key.len() as u64, 0) {
            0 | NOTHING => Ok(()),
            _ => Err(format!("ferros store: delete of {key} refused")),
        }
    }

    /// Every address this vault holds: the scope's listing, filtered to the prefix.
    pub(crate) fn keys(&self) -> Result<Vec<[u8; 32]>, String> {
        let mut listing = Vec::new();
        let mut buf = [0u8; PIECE];
        loop {
            let r = svc(STORE, self.cap, 16 | 2 | (PIECE as u64) << 8 | (listing.len() as u64) << 32, off(b"".as_ptr()), 0, off(buf.as_mut_ptr()));
            if r == ERR || r == NOTHING {
                return Err("ferros store: listing refused".to_string());
            }
            let total = r as usize;
            let n = PIECE.min(total - listing.len().min(total));
            listing.extend_from_slice(&buf[..n]);
            if listing.len() >= total {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&listing).lines().filter_map(|l| l.strip_prefix(self.prefix.as_str())).filter_map(unb64).collect())
    }
}

/// The librarian on ferros: each op straight to the kernel, a batch in order.
pub(crate) fn librarian(store: KernelStore, rx: Receiver<VaultOp>) {
    while let Ok(op) = rx.recv() {
        match op {
            VaultOp::Get { addr, reply } => {
                let _ = reply.send(store.get(&addr));
            }
            VaultOp::Put { addr, stored, reply } => {
                let _ = reply.send(store.put(&addr, &stored));
            }
            VaultOp::Delete { addr, reply } => {
                let _ = reply.send(store.delete(&addr));
            }
            VaultOp::Batch { items, reply } => {
                let mut r = Ok(());
                for (addr, v) in &items {
                    r = match v {
                        Some(v) => store.put(addr, v),
                        None => store.delete(addr),
                    };
                    if r.is_err() {
                        break;
                    }
                }
                let _ = reply.send(r);
            }
            VaultOp::Keys { reply } => {
                let _ = reply.send(store.keys());
            }
            VaultOp::Degraded { reply } => {
                let _ = reply.send(false);
            }
            // No engine physique to report: the reply sender drops and the caller sees the vault thread decline.
            VaultOp::Stats { .. } => {}
        }
    }
}
