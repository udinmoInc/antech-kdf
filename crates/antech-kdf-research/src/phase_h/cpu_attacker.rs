//! CPU Attacker cracking benchmark suite across thread counts (1..32).

use crate::phase_f::cand_004_core::Candidate004Symmetric;
use crate::phase_f::{ResearchKdf, ResearchParams};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAttackerRecord {
    pub thread_count: usize,
    pub candidate_guesses_per_sec: f64,
    pub wall_clock_ms: f64,
}

pub fn run_cpu_attacker_benchmark() -> Vec<CpuAttackerRecord> {
    let kdf = Candidate004Symmetric;
    let params = ResearchParams {
        memory_kib: 16384,
        passes: 1,
        dependency_depth: 120,
        block_size: 32,
    };
    let salt = [0x55u8; 16];

    let thread_counts = [1, 2, 4, 8, 16, 32];
    let mut records = Vec::new();

    for &threads in &thread_counts {
        let candidate_passwords: Vec<Vec<u8>> = (0..32)
            .map(|i| format!("cpu_att_pass_{}", i).into_bytes())
            .collect();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();

        let t_start = Instant::now();
        pool.install(|| {
            candidate_passwords.par_iter().for_each(|p| {
                let _ = kdf.derive(p, &salt, &params);
            });
        });
        let elapsed = t_start.elapsed().as_secs_f64().max(0.000001);
        let qps = 32.0 / elapsed;

        records.push(CpuAttackerRecord {
            thread_count: threads,
            candidate_guesses_per_sec: qps,
            wall_clock_ms: elapsed * 1000.0,
        });
    }

    records
}
