//! JSON & CSV schema data structures for Phase B validation audit & research results.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Measurement source classification tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasurementSource {
    /// Directly measured from hardware/OS counters or high-res timers.
    Measured,
    /// Calculated from deterministic algorithm specification or memory access model.
    Estimated,
    /// Analytical mathematical model.
    Modeled,
    /// Synthetic workload simulation.
    Simulated,
    /// Metric cannot be measured on host environment.
    Unavailable,
}

impl fmt::Display for MeasurementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Hardware profile specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu: String,
    pub cores: usize,
    pub ram_gib: u64,
    pub os: String,
}

/// Execution run metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub iterations: u32,
    pub warmup_iterations: u32,
}

/// Detailed memory breakdown distinguishing allocation tiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RamBreakdown {
    pub requested_allocation_bytes: u64,
    pub resident_memory_bytes: u64,
    pub kdf_working_memory_bytes: u64,
    pub temporary_allocation_bytes: u64,
    pub ram_classification: MeasurementSource,
}

/// Detailed bandwidth breakdown distinguishing cache tiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthBreakdown {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub estimated_bandwidth_gb_per_sec: f64,
    pub cache_locality_tier: String,
    pub bandwidth_classification: MeasurementSource,
}

/// Detailed defender performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStats {
    pub median_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub latency_classification: MeasurementSource,
    pub ram: RamBreakdown,
    pub bandwidth: BandwidthBreakdown,
    pub cpu_cycles: Option<u64>,
}

/// Raw individual un-aggregated measurement entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBenchmarkRecord {
    pub algorithm: String,
    pub iteration: u32,
    pub duration_us: u64,
    pub timestamp_epoch_ms: u64,
}

/// Single benchmark measurement output matching JSON research schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub algorithm: String,
    pub version: String,
    pub parameters: String,
    pub hardware: HardwareInfo,
    pub run: RunInfo,
    pub metrics: MetricStats,
}

/// Flat record for CSV exporter compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvBenchmarkRecord {
    pub algorithm: String,
    pub version: String,
    pub parameters: String,
    pub cpu: String,
    pub cores: usize,
    pub ram_gib: u64,
    pub os: String,
    pub iterations: u32,
    pub warmup_iterations: u32,
    pub median_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub latency_classification: String,
    pub requested_allocation_bytes: u64,
    pub resident_memory_bytes: u64,
    pub kdf_working_memory_bytes: u64,
    pub ram_classification: String,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub estimated_bandwidth_gb_per_sec: f64,
    pub cache_locality_tier: String,
    pub bandwidth_classification: String,
}

impl From<&BenchmarkResult> for CsvBenchmarkRecord {
    fn from(b: &BenchmarkResult) -> Self {
        Self {
            algorithm: b.algorithm.clone(),
            version: b.version.clone(),
            parameters: b.parameters.clone(),
            cpu: b.hardware.cpu.clone(),
            cores: b.hardware.cores,
            ram_gib: b.hardware.ram_gib,
            os: b.hardware.os.clone(),
            iterations: b.run.iterations,
            warmup_iterations: b.run.warmup_iterations,
            median_ms: b.metrics.median_ms,
            p50_ms: b.metrics.p50_ms,
            p95_ms: b.metrics.p95_ms,
            p99_ms: b.metrics.p99_ms,
            min_ms: b.metrics.min_ms,
            max_ms: b.metrics.max_ms,
            latency_classification: b.metrics.latency_classification.to_string(),
            requested_allocation_bytes: b.metrics.ram.requested_allocation_bytes,
            resident_memory_bytes: b.metrics.ram.resident_memory_bytes,
            kdf_working_memory_bytes: b.metrics.ram.kdf_working_memory_bytes,
            ram_classification: b.metrics.ram.ram_classification.to_string(),
            bytes_read: b.metrics.bandwidth.bytes_read,
            bytes_written: b.metrics.bandwidth.bytes_written,
            estimated_bandwidth_gb_per_sec: b.metrics.bandwidth.estimated_bandwidth_gb_per_sec,
            cache_locality_tier: b.metrics.bandwidth.cache_locality_tier.clone(),
            bandwidth_classification: b.metrics.bandwidth.bandwidth_classification.to_string(),
        }
    }
}

/// Bandwidth record for CSV export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthRecord {
    pub algorithm: String,
    pub parameters: String,
    pub memory_bytes_read: u64,
    pub memory_bytes_written: u64,
    pub total_bandwidth_bytes: u64,
    pub estimated_bandwidth_gb_per_sec: f64,
    pub median_latency_ms: f64,
    pub cache_locality_tier: String,
    pub bandwidth_classification: String,
}

/// Concurrency scaling measurement entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyResult {
    pub algorithm: String,
    pub concurrent_requests: usize,
    pub total_peak_ram_bytes: u64,
    pub ram_per_request_bytes: u64,
    pub per_request_median_ms: f64,
    pub per_request_p95_ms: f64,
    pub per_request_p99_ms: f64,
    pub wall_clock_batch_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub queueing_delay_ms: f64,
    pub failure_count: usize,
    pub latency_classification: MeasurementSource,
}

/// Attacker cost model measurement entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerModelResult {
    pub algorithm: String,
    pub parameters: String,
    pub ram_per_guess_bytes: u64,
    pub compute_per_guess_ops: u64,
    pub bandwidth_per_guess_bytes: u64,
    pub single_cpu_guesses_per_sec: f64,
    pub multicore_16c_guesses_per_sec: f64,
    pub gpu_simulated_parallel_guesses_per_sec: f64,
    pub max_practical_parallelism: u64,
    pub memory_bus_bottleneck: String,
    pub cpu_throughput_classification: MeasurementSource,
    pub gpu_throughput_classification: MeasurementSource,
}
