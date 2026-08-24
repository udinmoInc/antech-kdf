//! JSON & CSV schema data structures for benchmark results.

use serde::{Deserialize, Serialize};

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

/// Detailed defender performance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStats {
    pub median_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub peak_ram_bytes: u64,
    pub avg_ram_bytes: u64,
    pub cpu_cycles: Option<u64>,
    pub memory_bytes_read: u64,
    pub memory_bytes_written: u64,
}

/// Single benchmark measurement output matching required JSON research schema.
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
    pub peak_ram_bytes: u64,
    pub avg_ram_bytes: u64,
    pub memory_bytes_read: u64,
    pub memory_bytes_written: u64,
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
            peak_ram_bytes: b.metrics.peak_ram_bytes,
            avg_ram_bytes: b.metrics.avg_ram_bytes,
            memory_bytes_read: b.metrics.memory_bytes_read,
            memory_bytes_written: b.metrics.memory_bytes_written,
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
    pub median_latency_ms: f64,
}

/// Concurrency scaling measurement entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyResult {
    pub algorithm: String,
    pub concurrent_requests: usize,
    pub total_peak_ram_bytes: u64,
    pub ram_per_request_bytes: u64,
    pub median_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub queueing_delay_ms: f64,
    pub failure_count: usize,
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
}
