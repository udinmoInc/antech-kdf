//! Defender verification latency benchmarks.

use crate::candidates::{ResearchKdf, ResearchParams, VariantK1, VariantK2};
use std::time::Instant;

pub fn measure_defender_latencies() -> (f64, f64) {
    let k1 = VariantK1::new();
    let k2 = VariantK2::new();
    let dummy_params = ResearchParams::default();
    let pwd = b"benchmark_password_test";
    let salt = [0x77u8; 16];

    let _ = k1.derive(pwd, &salt, &dummy_params);
    let t0 = Instant::now();
    for _ in 0..3 {
        let _ = k1.derive(pwd, &salt, &dummy_params);
    }
    let k1_lat_ms = (t0.elapsed().as_secs_f64() * 1000.0) / 3.0;

    let _ = k2.derive(pwd, &salt, &dummy_params);
    let t1 = Instant::now();
    for _ in 0..3 {
        let _ = k2.derive(pwd, &salt, &dummy_params);
    }
    let k2_lat_ms = (t1.elapsed().as_secs_f64() * 1000.0) / 3.0;

    (k1_lat_ms, k2_lat_ms)
}
