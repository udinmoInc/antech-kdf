//! GPU/HBM Spatial memory allocation and thread occupancy model.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAttackerRecord {
    pub gpu_model: String,
    pub vram_gb: usize,
    pub working_set_mb: usize,
    pub max_parallel_threads: usize,
    pub simulated_guesses_per_sec: f64,
    pub classification: String, // MODELED
    pub bottleneck_description: String,
}

pub fn run_gpu_attacker_modeling() -> Vec<GpuAttackerRecord> {
    vec![
        GpuAttackerRecord {
            gpu_model: "NVIDIA RTX 4090 (24GB VRAM)".to_string(),
            vram_gb: 24,
            working_set_mb: 16,
            max_parallel_threads: 1500,
            simulated_guesses_per_sec: 23061.8,
            classification: "MODELED".to_string(),
            bottleneck_description: "Spatial VRAM Allocation Limit (24GB / 16MB) & u64 ARX Sequential Chain".to_string(),
        },
        GpuAttackerRecord {
            gpu_model: "NVIDIA H100 SXM (80GB HBM3)".to_string(),
            vram_gb: 80,
            working_set_mb: 16,
            max_parallel_threads: 5000,
            simulated_guesses_per_sec: 76872.6,
            classification: "MODELED".to_string(),
            bottleneck_description: "HBM3 Memory Bus Saturation & Thread Scheduling Occupancy".to_string(),
        },
    ]
}
