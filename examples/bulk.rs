//! Bulk timing: a device vault filled with cell-sized values, then opened cold and read back.
//! bulk <dir> fill <n> <kb> [batch] [first key] | open <n>: n values of kb KB written (one commit each, or `batch` to a write_device_batch), keys "cell <first + i>"; open then reads every seventh back.
use std::time::Instant;
struct L;
impl log::Log for L {
    fn enabled(&self, _: &log::Metadata) -> bool { true }
    fn log(&self, r: &log::Record) { eprintln!("[{}] {}", r.level(), r.args()); }
    fn flush(&self) {}
}
fn main() {
    log::set_logger(&L).ok();
    log::set_max_level(log::LevelFilter::Info);
    let a: Vec<String> = std::env::args().collect();
    let dir = &a[1];
    kete::set_vault_dirs_override(format!("{dir}/vault"), format!("{dir}/vault-shadow"));
    let t = Instant::now();
    let v = kete::FlatStorage::open_device_shared(kete::App { id: "bulk", dir: "bulk" }, [7; 32]).unwrap();
    eprintln!("open {:.3} s", t.elapsed().as_secs_f32());
    let mut x = 0x1234_5678u64;
    let mut val = |kb: usize| -> Vec<u8> { (0..kb * 1024).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x as u8 }).collect() };
    if a[2] == "fill" {
        let (n, kb): (usize, usize) = (a[3].parse().unwrap(), a[4].parse().unwrap());
        let batch: usize = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(1);
        let from: usize = a.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
        let t = Instant::now();
        let mut i = 0;
        while i < n {
            if batch == 1 {
                v.write_device(&format!("cell {}", from + i), &val(kb)).unwrap();
                i += 1;
            } else {
                let items: Vec<(String, Vec<u8>)> = (i..(i + batch).min(n)).map(|j| (format!("cell {}", from + j), val(kb))).collect();
                i += items.len();
                v.write_device_batch(&items).unwrap();
            }
        }
        eprintln!("{n} written, {:.2} ms each", t.elapsed().as_secs_f32() * 1000.0 / n as f32);
    } else {
        let n: usize = a[3].parse().unwrap();
        let t = Instant::now();
        let mut got = 0usize;
        for i in (0..n).step_by(7) {
            got += v.read_device(&format!("cell {i}")).unwrap().map_or(0, |b| b.len());
        }
        eprintln!("read {} KB in {:.3} s ({} reads)", got >> 10, t.elapsed().as_secs_f32(), n.div_ceil(7));
    }
}
