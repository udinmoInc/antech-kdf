//! Strongest practical CPU attackers against canonical CombinedFrontier (research-only).

use crate::compute_memory_v4::attacker_opt::{
    derive_packed_dual, derive_packed_noring, derive_packed_prefetch, derive_packed_ring,
    PackedScratch, NUM_BLOCKS_16MIB,
};
use antech_kdf_core::engine::AntechEngine;
use antech_kdf_types::{AntechConfig, GraphKind};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAttackerRow {
    pub strategy: String,
    pub memory_mib: usize,
    pub threads: usize,
    pub gps: f64,
    pub correct: bool,
    pub kind: String, // MEASURED
    pub notes: String,
}

fn cfg_mib(mib: usize) -> AntechConfig {
    AntechConfig::builder()
        .memory_mib(mib)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap()
}

pub fn verify_packed_matches_engine(password: &[u8], salt: &[u8]) -> bool {
    let cfg = cfg_mib(16);
    assert_eq!(cfg.num_blocks(), NUM_BLOCKS_16MIB);
    let mut scratch = PackedScratch::new();
    let eng = AntechEngine::new().derive(password, salt, &cfg).unwrap();
    let a = derive_packed_prefetch(password, salt, &cfg, &mut scratch);
    a.as_slice() == eng.as_slice()
}

fn measure_engine(threads: usize, duration: Duration, salt: &[u8]) -> f64 {
    let cfg = cfg_mib(16);
    let counter = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..threads {
            let counter = Arc::clone(&counter);
            let salt = salt.to_vec();
            s.spawn(move || {
                let end = Instant::now() + duration;
                let mut i = t as u64;
                while Instant::now() < end {
                    let pw = format!("eng_cpu_{i}");
                    let _ = AntechEngine::new().derive(pw.as_bytes(), &salt, &cfg);
                    counter.fetch_add(1, Ordering::Relaxed);
                    i = i.wrapping_add(threads as u64);
                }
            });
        }
    });
    counter.load(Ordering::Relaxed) as f64 / duration.as_secs_f64().max(1e-9)
}

fn measure_packed(strategy: &str, threads: usize, duration: Duration, salt: &[u8]) -> f64 {
    let cfg = cfg_mib(16);
    let counter = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..threads {
            let counter = Arc::clone(&counter);
            let salt = salt.to_vec();
            let strategy = strategy.to_string();
            s.spawn(move || {
                let mut scratch = PackedScratch::new();
                let mut scratch_b = PackedScratch::new();
                let end = Instant::now() + duration;
                let mut i = t as u64;
                while Instant::now() < end {
                    let pw = format!("eng_cpu_{i}");
                    match strategy.as_str() {
                        "packed_prefetch" => {
                            let _ =
                                derive_packed_prefetch(pw.as_bytes(), &salt, &cfg, &mut scratch);
                        }
                        "packed_ring" => {
                            let _ = derive_packed_ring(pw.as_bytes(), &salt, &cfg, &mut scratch);
                        }
                        "packed_noring" => {
                            let _ = derive_packed_noring(pw.as_bytes(), &salt, &cfg, &mut scratch);
                        }
                        "packed_dual" => {
                            let pw2 = format!("eng_cpu_dual_{i}");
                            let _ = derive_packed_dual(
                                pw.as_bytes(),
                                pw2.as_bytes(),
                                &salt,
                                &cfg,
                                &mut scratch,
                                &mut scratch_b,
                            );
                            // Dual counts as 2 guesses
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    i = i.wrapping_add(threads as u64);
                }
            });
        }
    });
    counter.load(Ordering::Relaxed) as f64 / duration.as_secs_f64().max(1e-9)
}

/// Bake-off strongest CPU strategies at 16 MiB. Duration per cell is short by default.
pub fn run_cpu_attacker_campaign(duration: Duration) -> Vec<CpuAttackerRow> {
    let salt = b"eng_cpu_salt_16b!";
    let correct = verify_packed_matches_engine(b"eng_correctness", salt);
    let threads_list = [1usize, 2, 4, 8, 16, 32];
    let strategies = [
        "production_engine",
        "packed_ring",
        "packed_noring",
        "packed_prefetch",
        "packed_dual",
    ];
    let mut rows = Vec::new();
    let avx = cfg!(target_feature = "avx2") || is_x86_feature_detected_avx2();
    for &threads in &threads_list {
        if threads
            > std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                * 2
        {
            // Still attempt; OS will oversubscribe.
        }
        for strat in &strategies {
            let gps = if *strat == "production_engine" {
                measure_engine(threads, duration, salt)
            } else {
                measure_packed(strat, threads, duration, salt)
            };
            rows.push(CpuAttackerRow {
                strategy: (*strat).into(),
                memory_mib: 16,
                threads,
                gps,
                correct,
                kind: "MEASURED".into(),
                notes: format!(
                    "avx2_compile_or_runtime={avx}; packed uses u64 layout+prefetch; dual=2walks"
                ),
            });
        }
    }
    rows
}

fn is_x86_feature_detected_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

pub fn strongest_row(rows: &[CpuAttackerRow]) -> Option<&CpuAttackerRow> {
    rows.iter()
        .filter(|r| r.correct && r.gps.is_finite())
        .max_by(|a, b| {
            a.gps
                .partial_cmp(&b.gps)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}
