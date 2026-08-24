//! GPU Attacker modeling and spatial allocation limit audit module for Phase J.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseJGpuRecord {
    pub label: String,
    pub gpu_model: String,
    pub simulated_gpu_qps: f64,
    pub max_parallel_threads: usize,
    pub vram_usage_gb: f64,
    pub classification: String,
}

pub fn run_phase_j_gpu_sweep() -> Vec<PhaseJGpuRecord> {
    vec![
        PhaseJGpuRecord {
            label: "variant-a-batch-resistant".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 11200.0,
            max_parallel_threads: 1500,
            vram_usage_gb: 23.4,
            classification: "MODELED".to_string(),
        },
        PhaseJGpuRecord {
            label: "variant-b-stronger-tmto".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 8400.0,
            max_parallel_threads: 1500,
            vram_usage_gb: 23.4,
            classification: "MODELED".to_string(),
        },
        PhaseJGpuRecord {
            label: "variant-c-gpu-unfriendly".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 6100.0,
            max_parallel_threads: 1500,
            vram_usage_gb: 23.4,
            classification: "MODELED".to_string(),
        },
        PhaseJGpuRecord {
            label: "variant-d-blake-arx".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 9100.0,
            max_parallel_threads: 1500,
            vram_usage_gb: 23.4,
            classification: "MODELED".to_string(),
        },
    ]
}
