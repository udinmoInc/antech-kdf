//! CPU attacker scaling for v4 (same methodology as v3 / Argon2id H2H).

use super::config::CPU_WORKER_COUNTS;
use crate::candidates::cand_004::{ResearchKdf, ResearchParams};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerRecord {
    pub variant: String,
    pub memory_mib: usize,
    pub threads: usize,
    pub guesses_per_sec: f64,
    pub latency_ms_per_guess: f64,
    pub speedup_vs_1: f64,
    pub parallel_efficiency: f64,
    pub total_guesses: u64,
    pub duration_secs: f64,
}

fn corpus() -> Vec<Vec<u8>> {
    (0..256u32)
        .map(|i| format!("v4_attacker_candidate_{:04}", i).into_bytes())
        .collect()
}

const SALT: &[u8] = b"v4_attacker_salt_16";

pub fn measure_attacker(
    kdf: &dyn ResearchKdf,
    params: &ResearchParams,
    threads: usize,
    duration: Duration,
) -> (f64, u64, f64) {
    let passwords = corpus();
    let counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    std::thread::scope(|s| {
        for t in 0..threads {
            let counter = Arc::clone(&counter);
            let passwords = &passwords;
            s.spawn(move || {
                let mut local = 0u64;
                let mut idx = t;
                let end = Instant::now() + duration;
                while Instant::now() < end {
                    let pw = &passwords[idx % passwords.len()];
                    let _ = kdf.derive(pw, SALT, params);
                    local += 1;
                    idx = idx.wrapping_add(threads);
                }
                counter.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    let total = counter.load(Ordering::Relaxed);
    (total as f64 / elapsed, total, elapsed)
}

pub fn evaluate_scaling(
    kdf: &dyn ResearchKdf,
    params: &ResearchParams,
    duration: Duration,
    memory_mib: usize,
) -> Vec<AttackerRecord> {
    let mut records = Vec::new();
    let mut base_gps = 0.0f64;

    for &threads in &CPU_WORKER_COUNTS {
        let (gps, total, elapsed) = measure_attacker(kdf, params, threads, duration);
        if threads == 1 {
            base_gps = gps.max(1e-9);
        }
        let speedup = gps / base_gps;
        let efficiency = gps / (base_gps * threads as f64);
        records.push(AttackerRecord {
            variant: kdf.name().to_string(),
            memory_mib,
            threads,
            guesses_per_sec: gps,
            latency_ms_per_guess: if gps > 0.0 { 1000.0 / gps } else { 0.0 },
            speedup_vs_1: speedup,
            parallel_efficiency: efficiency,
            total_guesses: total,
            duration_secs: elapsed,
        });
    }
    records
}
