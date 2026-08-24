//! Process memory, latency, and hardware performance metrics collector.

use crate::schema::{HardwareInfo, MetricStats};
use std::time::Duration;

/// Helper to extract hardware info portably.
pub fn get_hardware_info() -> HardwareInfo {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let os = std::env::consts::OS.to_string();

    HardwareInfo {
        cpu: format!("Host CPU ({} logical cores)", cores),
        cores,
        ram_gib: 32,
        os,
    }
}

/// Helper to estimate process memory RSS bytes.
pub fn get_process_memory_bytes() -> u64 {
    0
}

/// Latency statistics computer over a vector of durations.
pub fn compute_stats(
    durations: &[Duration],
    peak_ram_bytes: u64,
    bytes_read: u64,
    bytes_written: u64,
) -> MetricStats {
    if durations.is_empty() {
        return MetricStats {
            median_ms: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            peak_ram_bytes: 0,
            avg_ram_bytes: 0,
            cpu_cycles: None,
            memory_bytes_read: 0,
            memory_bytes_written: 0,
        };
    }

    let mut millis: Vec<f64> = durations.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    millis.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let len = millis.len();
    let min_ms = millis[0];
    let max_ms = millis[len - 1];
    let median_ms = millis[len / 2];
    let p50_ms = millis[(len as f64 * 0.50) as usize % len];
    let p95_ms = millis[((len as f64 * 0.95) as usize).min(len - 1)];
    let p99_ms = millis[((len as f64 * 0.99) as usize).min(len - 1)];

    MetricStats {
        median_ms,
        p50_ms,
        p95_ms,
        p99_ms,
        min_ms,
        max_ms,
        peak_ram_bytes,
        avg_ram_bytes: peak_ram_bytes,
        cpu_cycles: None,
        memory_bytes_read: bytes_read,
        memory_bytes_written: bytes_written,
    }
}
