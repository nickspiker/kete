# Many reads in one call

Status: the host side is built (branch `batch-read`, 2026-11-20); the ferros op below is a proposal for the ferros session to agree before anyone builds it.

## The API

```rust
pub fn read_addr_batch(&self, addrs: &[[u8; 32]]) -> Result<Vec<Option<Vec<u8>>>, StorageError>
```

- One answer per address, in the order given: exactly what `read_addr` returns for it (`None` when absent). An address may repeat; an empty list returns an empty list without touching the librarian.
- Err when any address would make `read_addr` fail. When several would fail differently, the vault's errors come before the decrypt ones.
- Read-your-own-writes holds as for `read_addr`: the read cache answers first, and a miss queued behind a write is answered from the librarian's gathered batch (LIB-16).
- What it costs once per call instead of once per address: the read cache's lock (one lookup pass, one fill pass under the same fill rule), the trip through the librarian's mailbox (one `VaultOp::GetMany`), the identity lock for the decrypt pass on the caller's thread.
- First caller: Photon's row loader (`rows_load.rs`, a page of `1 << 7` rows), which today calls `rarangi::Db::get_addr` (= `read_addr`) per row. `read_addr_batch` on the same `FlatStorage` with `rarangi::keys::row_addr` addresses is the drop-in.

## What a batch saves on the host

Measured 2026-11-20 (`read_batch_timing`, an ignored test: 2340 rows of 256 to 511 bytes, written sixteen to a commit beside a rewritten catalog value, each read cold from a fresh open as at launch; the median of eight alternating rounds, release build):

| Where the vault lies | Walk | 2340 × `read_addr` | `read_addr_batch`, pages of 128 | Gain |
|---|---|---|---|---|
| SATA SSD, btrfs over dm-crypt (O_DIRECT) | settled | 588.8 ms (252 µs a row) | 574.5 ms (246 µs a row) | 1.02× |
| same | still walking | 1157.7 ms (495 µs a row) | 1067.5 ms (456 µs a row) | 1.08× |
| tmpfs (O_DIRECT refused, page cache) | settled | 101.3 ms (43 µs a row) | 77.8 ms (33 µs a row) | 1.30× |
| same | still walking | 118.4 ms (51 µs a row) | 89.3 ms (38 µs a row) | 1.33× |

The disk's rounds are noisy (a loop of `read_addr` ran 1018 to 4414 ms while walking, the batch 991 to 1223 ms); the medians are what the table gives. An earlier run on the same disk gave 1.06× settled and 1.44× walking.

What the numbers say:

- The mailbox and the locks were about 10 µs a row; the batch removes them.
- The rest is manifestus's own `get`, one key at a time: about 30 µs a row in software (each index node's seal and decode on the way down), and on a real disk about 220 µs a row more. FileDev opens O_DIRECT, so every block outside the mirror's 1024-block cache is a device read (about 110 µs on this stack, manifestus host.rs `READERS`). A cold open reads every index node a row passes and the row's leaf: about two device reads a row.
- Asking the engine in address order (so neighbouring walks share nodes in the cache) measured no faster (in two runs of the test on the disk, settled: 604 ms sorted, 565 ms as asked), so the librarian asks in the caller's order.
- A batch cannot do better on the host without manifestus: kete sees only `Vault::get` (the walk and the leaf read together). A `Vault::get_many` in manifestus could walk the index once for all keys a level at a time, as `walk_tree_step` already walks it at open: each shared node read and decoded once, and the level's blocks read together (`Tract::read_many`). That cuts the software half on any device and the device half where reads overlap (UFS, NVMe). It will not cut this desktop's device half much: manifestus measured that btrfs over dm-crypt on a SATA SSD serves overlapping reads no faster (host.rs, 2026-10-25). Fewer reads would: the open's walk already reads every node and leaf (`walk_tree_step`) and keeps none of them.

## The ferros op (proposal, not built)

Today kete on ferros reads a row with one `SYS_STORE` get (raw address, ADDR bit 32): the kernel stamps it with the scope's domain keys and forwards it to the vault process, which serves it and replies. On the Pro that is about 0.53 ms a row, 1245 ms for Photon's launch, nearly all of it the round trip, the stamp and the hand-offs, once per row. Until this op exists, kete's ferros librarian answers a `GetMany` with one get per address (`ferros.rs`), the first refusal ending it.

### The call

`SYS_STORE` (13) from the caller, as a raw-address get with one new bit:

- x1: ADDR (32) | MANY (64, new), the reply buffer's length in bits 8 to 31 (at most what the vault serves for a get, `STORE_GET_MAX`, 1 MiB);
- x2, x3: the request document's offset and length (at most `STORE_MAX`, 256 KiB, one transfer);
- x4: the reply buffer.

The kernel stamps it as it stamps a raw-address get today (one domain: the scope's class for an address name), op `VOP_GET_MANY = 7`, the name empty, the rest `[reply length u32 LE][the request document]`. It copies the document as it copies a set's bytes and does not parse it.

A kernel from before ignores bit 64, reads the name as at most 97 bytes, finds it is not 32, and answers ERR. A vault process from before answers op 7 with ERR (`serve`'s `_ => ERR`). kete's ferros backend takes the first ERR to a `GET_MANY` as "not served here", remembers it (as `SIZES` steps down a refused size), and reads one get per address from then on.

### The request: a complete VSF document

`RÅ<` header with version, its length, an Eagle-time creation stamp (`ef6`) and the provenance hash `hp` over the whole; then one section:

```
[get_many
  (addr: ht, ht, ht, …)
]
```

- `addr`: one field, one `ht` value per address, 32 bytes each, in the order the caller wants them answered. `ht` (a thing: what stays the same while its content changes) is what a vault address is: the slot's name across every value written to it; `hp` would claim one content and `hb` a file's rolling state.
- The vault refuses the whole call (ERR) for a document that does not verify, a value that is not a 32-byte `ht`, or more addresses than the cap. Repeats are answered each time. An empty field is answered with an empty reply (kete never sends one).

**The cap: `1 << 7` addresses a call.**
WHY: the count is the caller's word, and the vault process serves one request at a time on its serving thread, so a batch holds every other process's store calls (the display's reads, the identity service's sync every 4 s) for all its lookups.
PROOF it is needed: the transfer bound alone does not bound the work. An `ht` value is 32 bytes and a few of marker and length, so one 256 KiB transfer carries about 7000 addresses, fifty-five pages of Photon's, which at the Pro's per-get cost (0.53 ms, an upper bound: it includes the round trip this op removes) would hold the vault for up to about 3.7 s.
128 is Photon's page and holds the vault at most about 68 ms by the same bound. The ferros session should set the final figure from the vault process's own per-lookup time, so that a batch holds the serving thread no longer than a 1 MiB bulk get already does. kete sends at most the cap a call and splits a longer list.

### The reply: a complete VSF document

The syscall's value: the reply document's whole length, or ERR (the refusals above, the person's domain while no one is unlocked, no vault process). The bytes: the document, at most the caller's buffer.

```
[got
  [entry (addr: ht) (state: u) (value: v'b' …)]   state 1
  [entry (addr: ht) (state: u)]                   state 0 or 3
  [entry (addr: ht) (state: u) (size: u)]         state 2
  …
]
```

One nested `entry` section per address answered, in request order. Each carries:

- `addr`: the address it answers (`ht`). The caller matches each answer by it, never by position.
- `state`: what the address holds (`u`, a typed kind, never a marker in the bytes):
  - 0: absent (a get's NOTHING);
  - 1: present, `value` follows;
  - 2: present but larger than this reply has room for, `size` follows; the caller reads it alone with the plain get (kete's `read_all`, in 1 MiB transfers);
  - 3: refused, its read failed (a seal or a corrupt block; the vault's console says why, as for a get today). kete fails the batch with "ferros store: read refused", as a get's refusal fails `read_addr`.
- `value`: `v'b'`, the stored bytes exactly as a get returns them (kete's own sealed value).
- `size`: `u`, the value's whole length.

### How a reply is bounded and how a list is finished

- A reply is at most the caller's buffer, at most 1 MiB: the vault process's reply buffer today (`out`, `STORE_GET_MAX` and 4 KiB).
- The vault answers the addresses in order while each entry fits in what is left. The first entry that does not fit ends the reply, unless it is the first: then it is answered with state 2, so every reply answers at least one address.
- The answered entries are always a prefix of the request. The caller asks again with the addresses from the first one not answered. The vault keeps nothing between calls (unlike the export, which holds its document): there is nothing to wipe at a lock, and a caller that stops asking leaves nothing behind.
- A page of Photon's rows (128 of a few hundred bytes, each with kete's 40 bytes of nonce and tag) is about 64 KiB: one call.

### What it saves on ferros

Per call instead of per row: one `SYS_STORE`, one stamp (the domain keys derived once), one forward and one reply, one wake of the vault process and of the caller. The lookups themselves stay one per address in `ferros_store` (a small row is inline in its head: one manifestus get and the head's seal). The vault side could later walk the index once for all addresses and read their leaves in one `read_gathered`, the same one-pass lookup the host lacks above.
