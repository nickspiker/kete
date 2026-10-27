//! kete on ferros: the kernel's vault behind `FlatStorage`, no files anywhere. A process holds a Store capability for one scope of the device vault (the kernel hands it at spawn: `--store photon`), and this backend keeps every entry there by the 32-byte address kete already derives for it — the address goes to the kernel as those bytes (SYS_STORE bit 5), nothing encoded, nothing named; the kernel scopes it and keeps the scope's address list for `live_keys`. Values travel in 4 KiB pieces (KERNEL.md, syscall 13). The librarian thread serves `VaultOp`s one by one, a batch in order — the kernel commits each put, so a batch is not atomic here.
//!
//! The identity vault's and the device vault's addresses never meet: kete derives them under different keys (`derive_entry_key`, `derive_device_entry_key`), so one scope holds both.
//!
//! The syscall and the arc registers are inlined (two dozen lines) rather than taken from ferros_sys: kete is published, and a path dependency on the ferros tree is not.

use std::sync::mpsc::Receiver;

use crate::VaultOp;

const STORE: u64 = 13;
const ERR: u64 = u64::MAX;
const NOTHING: u64 = u64::MAX - 1;
const PIECE: usize = 4096;
/// SYS_STORE x1 bits.
const SET: u64 = 1;
const AT: u64 = 2;
const MORE: u64 = 4;
const DELETE: u64 = 8;
const LIST: u64 = 16;
const ADDR: u64 = 32;

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

/// The process's vault scope.
pub(crate) struct KernelStore {
    cap: u64,
}

impl KernelStore {
    /// Find the Store grant among the process's grants (the kernel answers ERR to a listing on any other kind).
    pub(crate) fn open() -> Option<Self> {
        let mut probe = [0u8; 8];
        let cap = (1..grant_count().min(64)).map(cap).find(|&c| svc(STORE, c, ADDR | LIST | AT | 8 << 8, off(b"".as_ptr()), 0, off(probe.as_mut_ptr())) != ERR)?;
        Some(KernelStore { cap })
    }

    /// A large value or the listing, piece by piece.
    fn read_all(&self, flags: u64, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let mut out = Vec::new();
        let mut buf = [0u8; PIECE];
        loop {
            let r = svc(STORE, self.cap, flags | AT | (PIECE as u64) << 8 | (out.len() as u64) << 32, off(key.as_ptr()), key.len() as u64, off(buf.as_mut_ptr()));
            if r == NOTHING {
                return Ok(None);
            }
            if r == ERR {
                return Err("ferros store: read refused".to_string());
            }
            let total = r as usize;
            let n = PIECE.min(total - out.len().min(total));
            out.extend_from_slice(&buf[..n]);
            if out.len() >= total {
                return Ok(Some(out));
            }
        }
    }

    pub(crate) fn get(&self, addr: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        self.read_all(ADDR, addr)
    }

    pub(crate) fn put(&self, addr: &[u8; 32], value: &[u8]) -> Result<(), String> {
        if value.len() <= PIECE {
            return (svc(STORE, self.cap, ADDR | SET | (value.len() as u64) << 8, off(addr.as_ptr()), 32, off(value.as_ptr())) == 0).then_some(()).ok_or_else(|| "ferros store: write refused".to_string());
        }
        let pieces = value.len().div_ceil(PIECE);
        for (i, piece) in value.chunks(PIECE).enumerate() {
            let more = if i + 1 < pieces { MORE } else { 0 };
            if svc(STORE, self.cap, ADDR | SET | AT | more | (piece.len() as u64) << 8 | ((i * PIECE) as u64) << 32, off(addr.as_ptr()), 32, off(piece.as_ptr())) != 0 {
                return Err(format!("ferros store: write refused at piece {i}"));
            }
        }
        Ok(())
    }

    pub(crate) fn delete(&self, addr: &[u8; 32]) -> Result<(), String> {
        match svc(STORE, self.cap, ADDR | DELETE, off(addr.as_ptr()), 32, 0) {
            0 | NOTHING => Ok(()),
            _ => Err("ferros store: delete refused".to_string()),
        }
    }

    /// Every address this scope holds.
    pub(crate) fn keys(&self) -> Result<Vec<[u8; 32]>, String> {
        let listing = self.read_all(ADDR | LIST, b"")?.unwrap_or_default();
        Ok(listing.chunks_exact(32).map(|c| c.try_into().unwrap()).collect())
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
