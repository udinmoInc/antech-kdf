//! Minimal verify loop for Linux `perf stat` (side-channel PMU).

use antech_kdf::{hash_with_config, verify, AntechConfig};
use std::hint::black_box;

fn main() {
    let cfg = AntechConfig::builder().memory_kib(1024).build().unwrap();
    let encoded = hash_with_config(b"perf_probe_password", &cfg).unwrap();
    for _ in 0..5 {
        black_box(verify(b"perf_probe_password", &encoded).unwrap());
    }
}
