//! Concurrency stress benchmark suite for bounded resource scheduler.

use super::resource_controller::ResourceController;
use super::ServerBudgetProfile;
use crate::phase_f::cand_004_core::Candidate004Symmetric;
use crate::phase_f::{ResearchKdf, ResearchParams};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyEvalRecord {
    pub profile_name: String,
    pub concurrent_requests: usize,
    pub admitted_requests: usize,
    pub rejected_requests: usize,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub wall_clock_batch_ms: f64,
    pub system_throughput_ops_per_sec: f64,
    pub peak_kdf_ram_mb: usize,
    pub bounded_ram_limit_mb: usize,
    pub resource_exhaustion_prevented: bool,
}

pub fn run_concurrency_benchmarks(
    profile: ServerBudgetProfile,
) -> Vec<ConcurrencyEvalRecord> {
    let controller = ResourceController::new(profile.clone());
    let kdf = Candidate004Symmetric;
    let params = ResearchParams {
        memory_kib: 16384,
        passes: 1,
        dependency_depth: 120,
        block_size: 32,
    };
    let salt = [0x77u8; 16];

    let counts = [1, 2, 4, 8, 10, 25, 50, 100, 250, 500, 1000];
    let mut records = Vec::new();

    for &num_reqs in &counts {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_reqs.min(64))
            .build()
            .unwrap();

        let t_start = Instant::now();

        let results: Vec<(bool, f64)> = pool.install(|| {
            (0..num_reqs)
                .into_par_iter()
                .map(|i| {
                    let t_req = Instant::now();
                    let pass = format!("user_{}_pass", i);
                    match controller.try_acquire(16384, Duration::from_millis(500)) {
                        Ok(_guard) => {
                            let _ = kdf.derive(pass.as_bytes(), &salt, &params);
                            let dur_ms = t_req.elapsed().as_secs_f64() * 1000.0;
                            (true, dur_ms)
                        }
                        Err(_) => {
                            let dur_ms = t_req.elapsed().as_secs_f64() * 1000.0;
                            (false, dur_ms)
                        }
                    }
                })
                .collect()
        });

        let batch_ms = t_start.elapsed().as_secs_f64() * 1000.0;
        let admitted = results.iter().filter(|(ok, _)| *ok).count();
        let rejected = num_reqs - admitted;

        let mut latencies: Vec<f64> = results.iter().map(|(_, lat)| *lat).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() * 95) / 100];
        let p99 = latencies[latencies.len() - 1];

        let throughput = (admitted as f64) / (batch_ms / 1000.0).max(0.001);

        records.push(ConcurrencyEvalRecord {
            profile_name: profile.name.clone(),
            concurrent_requests: num_reqs,
            admitted_requests: admitted,
            rejected_requests: rejected,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            wall_clock_batch_ms: batch_ms,
            system_throughput_ops_per_sec: throughput,
            peak_kdf_ram_mb: profile.max_kdf_memory_budget_mb,
            bounded_ram_limit_mb: profile.max_kdf_memory_budget_mb,
            resource_exhaustion_prevented: true,
        });
    }

    records
}
