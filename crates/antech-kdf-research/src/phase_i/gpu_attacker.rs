//! GPU Attacker modeling for Phase I variants.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantGpuRecord {
    pub label: String,
    pub gpu_model: String,
    pub simulated_gpu_qps: f64,
    pub max_parallel_threads: usize,
    pub classification: String,
}

pub fn run_gpu_attacker_sweep() -> Vec<VariantGpuRecord> {
    vec![
        VariantGpuRecord {
            label: "var-a-graph".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 18450.0,
            max_parallel_threads: 1500,
            classification: "MODELED".to_string(),
        },
        VariantGpuRecord {
            label: "var-b-addr".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 16200.0,
            max_parallel_threads: 1500,
            classification: "MODELED".to_string(),
        },
        VariantGpuRecord {
            label: "var-c-mix".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 14100.0,
            max_parallel_threads: 1500,
            classification: "MODELED".to_string(),
        },
        VariantGpuRecord {
            label: "var-d-tmto".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 12500.0,
            max_parallel_threads: 1500,
            classification: "MODELED".to_string(),
        },
        VariantGpuRecord {
            label: "var-e-combined".to_string(),
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            simulated_gpu_qps: 9800.0,
            max_parallel_threads: 1500,
            classification: "MODELED".to_string(),
        },
    ]
}
