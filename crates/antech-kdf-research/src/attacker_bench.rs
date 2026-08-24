//! Real CPU multi-core attacker candidate-password evaluation benchmark.

use rayon::prelude::*;
use std::time::Instant;

/// Output result from real CPU attacker cracking benchmark.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RealAttackerBenchResult {
    pub algorithm: String,
    pub worker_threads: usize,
    pub total_guesses_evaluated: usize,
    pub elapsed_ms: f64,
    pub measured_guesses_per_sec: f64,
    pub median_ms_per_guess: f64,
    pub multicore_scaling_efficiency: f64,
}

/// Runs empirical multi-core CPU candidate-password evaluation across 1..16 threads.
pub fn run_real_attacker_benchmarks() -> Vec<RealAttackerBenchResult> {
    let worker_counts = [1, 2, 4, 8, 16];
    let candidate_passwords: Vec<String> = (0..200)
        .map(|i| format!("candidate_password_{}", i))
        .collect();
    let target_hash = antech_kdf::hash("candidate_password_199").unwrap();

    let mut results = Vec::new();
    let mut baseline_single_cpu_qps = 1.0;

    for &workers in &worker_counts {
        let pool = match rayon::ThreadPoolBuilder::new().num_threads(workers).build() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let t0 = Instant::now();

        pool.install(|| {
            candidate_passwords.par_iter().for_each(|pass| {
                let _ = antech_kdf::verify(pass, &target_hash);
            });
        });

        let elapsed = t0.elapsed();
        let total_guesses = candidate_passwords.len();
        let elapsed_sec = elapsed.as_secs_f64().max(0.000001);
        let qps = (total_guesses as f64) / elapsed_sec;
        let median_ms = (elapsed.as_secs_f64() * 1000.0) / (total_guesses as f64);

        if workers == 1 {
            baseline_single_cpu_qps = qps;
        }

        let expected_linear_qps = baseline_single_cpu_qps * (workers as f64);
        let efficiency = if expected_linear_qps > 0.0 {
            (qps / expected_linear_qps) * 100.0
        } else {
            0.0
        };

        results.push(RealAttackerBenchResult {
            algorithm: "antech-kdf-placeholder".to_string(),
            worker_threads: workers,
            total_guesses_evaluated: total_guesses,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            measured_guesses_per_sec: qps,
            median_ms_per_guess: median_ms,
            multicore_scaling_efficiency: efficiency,
        });
    }

    results
}
