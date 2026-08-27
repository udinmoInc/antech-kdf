//! Antech KDF Research Crate.
//!
//! Current campaigns: `compute_memory_v4` (attackers / benches around canonical core),
//! `cryptanalysis`, `engineering`.
//!
//! Historical v2/v3 engines live under `research/archive/code/` for reproducibility.
//! Canonical digests always come from `antech_kdf_core::AntechEngine`.

pub mod attackers;
pub mod baselines;
pub mod benchmarks;
pub mod candidates;
pub mod compute_memory;
pub mod compute_memory_v4;
pub mod cryptanalysis;
pub mod engineering;
pub mod multitarget;
pub mod resource_controller;
pub mod tmto;

use std::path::Path;

/// Runs the current research benchmark suite (canonical core + attackers).
pub fn run_research_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    compute_memory_v4::run_compute_memory_v4_suite(&target_dir.join("compute-memory-v4"))?;
    Ok(())
}
