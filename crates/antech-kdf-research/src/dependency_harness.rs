//! Research experiment comparing independent work vs strict sequential dependencies.

use std::time::Instant;

/// Result output from dependency graph experiment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DependencyExperimentResult {
    pub mode: String,
    pub buffer_size_kib: usize,
    pub iterations: usize,
    pub elapsed_ms: f64,
    pub ops_per_sec: f64,
}

/// Executes independent work experiment (parallelizable elements).
pub fn run_independent_work(buffer_kib: usize, iterations: usize) -> DependencyExperimentResult {
    let size = buffer_kib * 1024;
    let mut buffer = vec![0u8; size];

    let t0 = Instant::now();
    for it in 0..iterations {
        let val = (it & 0xFF) as u8;
        for i in 0..buffer.len() {
            buffer[i] = buffer[i].wrapping_add(val);
        }
    }
    let elapsed = t0.elapsed();

    let total_ops = (size as f64) * (iterations as f64);
    let sec = elapsed.as_secs_f64().max(0.000001);

    DependencyExperimentResult {
        mode: "independent_work".to_string(),
        buffer_size_kib: buffer_kib,
        iterations,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        ops_per_sec: total_ops / sec,
    }
}

/// Executes strict sequential dependency work (element i depends on element i-1).
pub fn run_sequential_dependency_work(buffer_kib: usize, iterations: usize) -> DependencyExperimentResult {
    let size = buffer_kib * 1024;
    let mut buffer = vec![0u8; size];

    let t0 = Instant::now();
    for _ in 0..iterations {
        for i in 1..buffer.len() {
            let prev = buffer[i - 1];
            buffer[i] = buffer[i].rotate_left(3) ^ prev;
        }
    }
    let elapsed = t0.elapsed();

    let total_ops = (size as f64) * (iterations as f64);
    let sec = elapsed.as_secs_f64().max(0.000001);

    DependencyExperimentResult {
        mode: "sequential_dependency_work".to_string(),
        buffer_size_kib: buffer_kib,
        iterations,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        ops_per_sec: total_ops / sec,
    }
}
