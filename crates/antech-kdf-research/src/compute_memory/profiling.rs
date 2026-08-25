//! Defender execution profiling with multi-sample latency percentiles.

use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProfile {
    pub variant: String,
    pub memory_mib: usize,
    pub defender_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub cpu_cycles: u64,
    pub cpu_instructions: u64,
    pub integer_ops: u64,
    pub dependency_stalls: u64,
    pub memory_ops: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub l2_cache_misses: u64,
    pub l3_cache_misses: u64,
    pub dram_bytes_moved: u64,
    pub dram_bandwidth_gbps: f64,
    pub cpu_cycles_per_guess: u64,
    pub dram_bytes_per_guess: u64,
    pub attacker_guesses_per_sec: f64,
    pub compute_security_efficiency: f64,
}

impl ExecutionProfile {
    /// Measure `samples` timed runs of `f` and estimate secondary metrics from the
    /// known algorithmic structure (depth/passes/block touches). Cycle/cache
    /// counters are structural estimates when HW PMUs are unavailable.
    pub fn measure<F>(
        variant_name: &str,
        memory_mib: usize,
        depth: u32,
        passes: u32,
        mix_rounds: u32,
        samples: usize,
        mut f: F,
    ) -> Self
    where
        F: FnMut(),
    {
        let samples = samples.max(1);
        let mut latencies_ms = Vec::with_capacity(samples);
        for _ in 0..samples {
            let start = Instant::now();
            f();
            latencies_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let defender_latency_ms = latencies_ms.iter().sum::<f64>() / samples as f64;
        let p50_latency_ms = percentile(&latencies_ms, 0.50);
        let p95_latency_ms = percentile(&latencies_ms, 0.95);

        let total_bytes_allocated = (memory_mib as u64) * 1024 * 1024;
        // Dual parent read + dest write per step.
        let memory_ops = (depth as u64) * (passes as u64) * 3;
        let bytes_read = (depth as u64) * (passes as u64) * 2 * 32;
        let bytes_written = (depth as u64) * (passes as u64) * 32;

        let integer_ops = (depth as u64) * (passes as u64) * (mix_rounds as u64) * 12;
        // Segment fill: ~1 SHA-256 per 1 KiB + ARX expand, plus transition work.
        let fill_segments = total_bytes_allocated / 1024;
        let cpu_instructions = fill_segments * 80 + integer_ops + memory_ops * 4;
        let cpu_cycles = (cpu_instructions as f64 * 1.12) as u64;
        let dependency_stalls = (depth as u64) * (passes as u64) * 2;

        let l2_cache_misses = (memory_ops as f64 * 0.10) as u64;
        let l3_cache_misses = if memory_mib <= 16 {
            (memory_ops as f64 * 0.02) as u64
        } else {
            (memory_ops as f64 * 0.05) as u64
        };

        // Moderate DRAM: one pass over the buffer at fill + sparse misses in the walk.
        let dram_bytes_moved = total_bytes_allocated + (l3_cache_misses * 64);
        let elapsed_secs = (defender_latency_ms / 1000.0).max(1e-6);
        let dram_bandwidth_gbps =
            (dram_bytes_moved as f64 / (1024.0 * 1024.0 * 1024.0)) / elapsed_secs;

        let cpu_guesses_per_sec = 1.0 / elapsed_secs;
        let compute_security_efficiency =
            (cpu_cycles as f64) / (total_bytes_allocated as f64 / 1024.0);

        Self {
            variant: variant_name.to_string(),
            memory_mib,
            defender_latency_ms,
            p50_latency_ms,
            p95_latency_ms,
            cpu_cycles,
            cpu_instructions,
            integer_ops,
            dependency_stalls,
            memory_ops,
            bytes_read,
            bytes_written,
            l2_cache_misses,
            l3_cache_misses,
            dram_bytes_moved,
            dram_bandwidth_gbps,
            cpu_cycles_per_guess: cpu_cycles,
            dram_bytes_per_guess: dram_bytes_moved,
            attacker_guesses_per_sec: cpu_guesses_per_sec,
            compute_security_efficiency,
        }
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
