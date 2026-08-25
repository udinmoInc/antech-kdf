//! Configurable long-duration stress of hash/verify + resource scheduler.

use antech_kdf::{hash_with_config, verify};
use antech_kdf_core::scheduler_stats;
use antech_kdf_types::AntechConfig;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressRow {
    pub duration_secs: u64,
    pub concurrency: usize,
    pub memory_kib: usize,
    pub hashes: u64,
    pub verifies: u64,
    pub errors: u64,
    pub gps: f64,
    pub final_active_permits: u64,
    pub final_queue_depth: u64,
    pub scheduler_idle: bool,
    pub kind: String,
    pub notes: String,
}

pub fn stress_durations_from_env() -> Vec<u64> {
    match std::env::var("ANTECH_STRESS_SECS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => vec![10, 30], // default short; full set: 10,30,60,300 via env
    }
}

pub fn stress_conc_from_env() -> Vec<usize> {
    match std::env::var("ANTECH_STRESS_CONC") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => {
            let n = std::thread::available_parallelism()
                .map(|x| x.get())
                .unwrap_or(4);
            let mut v = vec![1usize, n.min(10), n.min(32)];
            v.sort_unstable();
            v.dedup();
            v
        }
    }
}

pub fn run_stress_campaign() -> Vec<StressRow> {
    let durs = stress_durations_from_env();
    let concs = stress_conc_from_env();
    let mut rows = Vec::new();
    let cfg = AntechConfig::builder().memory_kib(1024).build().unwrap();
    for &secs in &durs {
        for &conc in &concs {
            rows.push(run_one(secs, conc, &cfg));
        }
    }
    rows
}

fn run_one(secs: u64, concurrency: usize, cfg: &AntechConfig) -> StressRow {
    let duration = Duration::from_secs(secs);
    let hashes = Arc::new(AtomicU64::new(0));
    let verifies = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for t in 0..concurrency {
            let hashes = Arc::clone(&hashes);
            let verifies = Arc::clone(&verifies);
            let errors = Arc::clone(&errors);
            let cfg = *cfg;
            s.spawn(move || {
                let end = Instant::now() + duration;
                let mut i = t as u64;
                while Instant::now() < end {
                    let pw = format!("stress_{i}");
                    match hash_with_config(pw.as_bytes(), &cfg) {
                        Ok(h) => {
                            hashes.fetch_add(1, Ordering::Relaxed);
                            match verify(pw.as_bytes(), &h) {
                                Ok(true) => {
                                    verifies.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(false) | Err(_) => {
                                    errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if verify(b"wrong", &h).unwrap_or(true) {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    i = i.wrapping_add(concurrency as u64);
                }
            });
        }
    });
    let elapsed = t0.elapsed().as_secs_f64().max(1e-9);
    let h = hashes.load(Ordering::Relaxed);
    let stats = scheduler_stats();
    StressRow {
        duration_secs: secs,
        concurrency,
        memory_kib: cfg.memory.as_kib(),
        hashes: h,
        verifies: verifies.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        gps: h as f64 / elapsed,
        final_active_permits: stats.active_jobs as u64,
        final_queue_depth: stats.waiting_jobs as u64,
        scheduler_idle: stats.active_jobs == 0 && stats.waiting_jobs == 0,
        kind: "MEASURED".into(),
        notes: "1 MiB cfg for density; set ANTECH_STRESS_SECS / ANTECH_STRESS_CONC for full matrix"
            .into(),
    }
}
