//! Quick v5 defender + packed_prefetch scaling microbench.

use antech_kdf::{hash_with_config_and_salt, AntechConfig, GraphKind};
use antech_kdf_research::compute_memory_v4::attacker_opt::{
    derive_packed_prefetch, PackedScratch,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() {
    let cfg = AntechConfig::builder()
        .memory_mib(16)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    let salt = b"v5_cost_salt_16b";

    // Defender latency
    let mut samples = Vec::new();
    for i in 0..40 {
        let pw = format!("def_{i}");
        let t0 = Instant::now();
        let _ = hash_with_config_and_salt(pw.as_bytes(), salt, &cfg).unwrap();
        samples.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "defender_ms p50={:.1} p95={:.1} p99={:.1} mean={:.1}",
        percentile(&samples, 50.0),
        percentile(&samples, 95.0),
        percentile(&samples, 99.0),
        samples.iter().sum::<f64>() / samples.len() as f64
    );

    // Packed prefetch scaling
    let window = Duration::from_millis(1200);
    let warmup = Duration::from_millis(300);
    for &threads in &[1usize, 2, 4, 8, 16, 32] {
        let counter = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicU64::new(0));
        // warmup
        {
            let mut scratch = PackedScratch::new();
            let end = Instant::now() + warmup;
            let mut i = 0u64;
            while Instant::now() < end {
                let pw = format!("w_{i}");
                let _ = derive_packed_prefetch(pw.as_bytes(), salt, &cfg, &mut scratch);
                i += 1;
            }
        }
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for t in 0..threads {
                let counter = Arc::clone(&counter);
                let stop = Arc::clone(&stop);
                let cfg = cfg;
                s.spawn(move || {
                    let mut scratch = PackedScratch::new();
                    let mut i = t as u64;
                    while stop.load(Ordering::Relaxed) == 0 {
                        let pw = format!("a_{i}");
                        let _ = derive_packed_prefetch(pw.as_bytes(), salt, &cfg, &mut scratch);
                        counter.fetch_add(1, Ordering::Relaxed);
                        i += threads as u64;
                    }
                });
            }
            std::thread::sleep(window);
            stop.store(1, Ordering::Relaxed);
        });
        let gps = counter.load(Ordering::Relaxed) as f64 / t0.elapsed().as_secs_f64();
        println!("packed_prefetch threads={threads} gps={gps:.2}");
    }
}
