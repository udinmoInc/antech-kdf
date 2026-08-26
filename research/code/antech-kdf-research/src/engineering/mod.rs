//! Engineering-complete research infrastructure (attackers, multitarget, side-channel,
//! ASIC/FPGA models, stress, hardware metadata). Does **not** change the production KDF.

pub mod asic_fpga;
pub mod cpu_attacker;
pub mod hardware;
pub mod multitarget_eng;
pub mod property;
pub mod production_correctness;
pub mod production_stress;
pub mod side_channel;
pub mod stress;

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareMeta {
    pub os: String,
    pub arch: String,
    pub cpu_brand: String,
    pub logical_cpus: usize,
    pub hostname_hash: String,
    pub cuda_available: bool,
    pub gpu_name: Option<String>,
    pub notes: String,
}

pub fn ensure_eng_dirs(root: &Path) -> std::io::Result<()> {
    for sub in [
        "cpu-attacker",
        "gpu-attacker",
        "multitarget",
        "side-channel",
        "asic-fpga",
        "hardware",
        "fuzz",
        "stress",
        "reference",
        "build",
    ] {
        std::fs::create_dir_all(root.join(sub))?;
    }
    Ok(())
}
