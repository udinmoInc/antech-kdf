//! CPU attacker multi-core parallel scaling (real timed derives).

use super::config::CPU_WORKER_COUNTS;
use crate::candidates::cand_004::{ResearchKdf, ResearchParams};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAttackerRecord {
    pub variant: String,
    pub threads: usize,
    pub total_guesses: u64,
    pub duration_secs: f64,
    pub guesses_per_sec: f64,
    pub scaling_efficiency: f64,
}

pub struct CpuAttackerEngine;

impl CpuAttackerEngine {
    pub fn evaluate_scaling(
        kdf: &dyn ResearchKdf,
        params: &ResearchParams,
        threads_list: &[usize],
        duration: Duration,
    ) -> Vec<CpuAttackerRecord> {
        let workers = if threads_list.is_empty() {
            &CPU_WORKER_COUNTS[..]
        } else {
            threads_list
        };

        let mut records = Vec::new();
        let mut baseline_gns = 0.0f64;

        for &num_threads in workers {
            let counter = Arc::new(AtomicU64::new(0));
            let start = Instant::now();

            std::thread::scope(|s| {
                for t_idx in 0..num_threads {
                    let counter_clone = Arc::clone(&counter);
                    let password = format!("attacker_pwd_{}", t_idx).into_bytes();
                    let salt = b"attacker_salt_16".to_vec();

                    s.spawn(move || {
                        let mut local_count = 0u64;
                        let end_time = Instant::now() + duration;
                        while Instant::now() < end_time {
                            let _ = kdf.derive(&password, &salt, params);
                            local_count += 1;
                        }
                        counter_clone.fetch_add(local_count, Ordering::Relaxed);
                    });
                }
            });

            let elapsed = start.elapsed().as_secs_f64().max(0.001);
            let total_guesses = counter.load(Ordering::Relaxed);
            let guesses_per_sec = total_guesses as f64 / elapsed;

            if num_threads == 1 {
                baseline_gns = guesses_per_sec.max(0.001);
            }

            let scaling_efficiency = guesses_per_sec / (baseline_gns * num_threads as f64);

            records.push(CpuAttackerRecord {
                variant: kdf.name().to_string(),
                threads: num_threads,
                total_guesses,
                duration_secs: elapsed,
                guesses_per_sec,
                scaling_efficiency,
            });
        }

        records
    }
}
