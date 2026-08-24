//! Research-only memory bandwidth churn laboratory harness.
//!
//! Evaluates whether high-frequency memory churn over a small working set can maintain high memory bus throughput.

use std::time::Instant;
use zeroize::Zeroizing;

/// Research experiment configuration for bandwidth churn test.
#[derive(Debug, Clone)]
pub struct ChurnExperimentParams {
    pub working_set_kib: usize,
    pub passes: usize,
    pub churn_rate_multiplier: usize,
    pub read_write_ratio: f32,
}

/// Output measurement from bandwidth churn experiment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChurnExperimentResult {
    pub working_set_kib: usize,
    pub passes: usize,
    pub elapsed_ms: f64,
    pub total_bytes_churned: u64,
    pub measured_bandwidth_mb_per_sec: f64,
}

/// Executes bandwidth churn experiment over temporary working buffer.
pub fn run_churn_experiment(params: &ChurnExperimentParams) -> ChurnExperimentResult {
    let size_bytes = params.working_set_kib * 1024;
    let mut buffer = Zeroizing::new(vec![0u8; size_bytes]);

    // Initialize buffer
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = ((i & 0xFF) ^ 0xAA) as u8;
    }

    let t0 = Instant::now();
    let mut acc: u8 = 0x55;

    for pass in 0..params.passes {
        let pass_byte = (pass & 0xFF) as u8;
        for i in 0..buffer.len() {
            // High-frequency pseudo-random memory read/write pass
            acc = buffer[i].wrapping_add(acc).wrapping_add(pass_byte).rotate_left(1);
            buffer[i] = acc;
        }
    }

    let elapsed = t0.elapsed();
    let total_bytes = (size_bytes as u64) * (params.passes as u64) * 2; // Reads + Writes
    let elapsed_sec = elapsed.as_secs_f64().max(0.000001);
    let bw_mb_s = (total_bytes as f64 / 1_048_576.0) / elapsed_sec;

    ChurnExperimentResult {
        working_set_kib: params.working_set_kib,
        passes: params.passes,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        total_bytes_churned: total_bytes,
        measured_bandwidth_mb_per_sec: bw_mb_s,
    }
}
