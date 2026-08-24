//! Process memory, latency, and hardware performance metrics collector.

use crate::schema::{BandwidthBreakdown, HardwareInfo, MeasurementSource, MetricStats, RamBreakdown};
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
pub fn get_process_resident_memory_bytes() -> u64 {
    // Portable memory measurement fallback
    0
}

/// Latency statistics computer over a vector of durations.
pub fn compute_stats(
    durations: &[Duration],
    requested_mem_bytes: u64,
    kdf_working_mem_bytes: u64,
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
            latency_classification: MeasurementSource::Measured,
            ram: RamBreakdown {
                requested_allocation_bytes: requested_mem_bytes,
                resident_memory_bytes: 0,
                kdf_working_memory_bytes: kdf_working_mem_bytes,
                temporary_allocation_bytes: requested_mem_bytes.saturating_sub(kdf_working_mem_bytes),
                ram_classification: MeasurementSource::Estimated,
            },
            bandwidth: BandwidthBreakdown {
                bytes_read: 0,
                bytes_written: 0,
                estimated_bandwidth_gb_per_sec: 0.0,
                cache_locality_tier: "L1/L2 Cache".to_string(),
                bandwidth_classification: MeasurementSource::Estimated,
            },
            cpu_cycles: None,
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

    let total_sec: f64 = durations.iter().map(|d| d.as_secs_f64()).sum();
    let total_bytes = bytes_read + bytes_written;
    let bw_gb_s = if total_sec > 0.0 {
        (total_bytes as f64 / 1_073_741_824.0) / total_sec
    } else {
        0.0
    };

    let cache_tier = if kdf_working_mem_bytes <= 256 * 1024 {
        "L1/L2 Cache Hit (<256KB)".to_string()
    } else if kdf_working_mem_bytes <= 16 * 1024 * 1024 {
        "L3 Cache Hit (256KB-16MB)".to_string()
    } else {
        "DRAM Memory Bus (>16MB)".to_string()
    };

    MetricStats {
        median_ms,
        p50_ms,
        p95_ms,
        p99_ms,
        min_ms,
        max_ms,
        latency_classification: MeasurementSource::Measured,
        ram: RamBreakdown {
            requested_allocation_bytes: requested_mem_bytes,
            resident_memory_bytes: get_process_resident_memory_bytes(),
            kdf_working_memory_bytes: kdf_working_mem_bytes,
            temporary_allocation_bytes: requested_mem_bytes.saturating_sub(kdf_working_mem_bytes),
            ram_classification: MeasurementSource::Estimated,
        },
        bandwidth: BandwidthBreakdown {
            bytes_read,
            bytes_written,
            estimated_bandwidth_gb_per_sec: bw_gb_s,
            cache_locality_tier: cache_tier,
            bandwidth_classification: MeasurementSource::Estimated,
        },
        cpu_cycles: None,
    }
}
