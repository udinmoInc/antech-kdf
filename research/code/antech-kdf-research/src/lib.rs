//! Antech KDF Research Crate.
//!
//! Current campaigns: `compute_memory_v4`, `cryptanalysis`, `engineering`.
//! Historical engines (`compute_memory`, `compute_memory_v3`) remain for archive reproduction.

pub mod attackers;
pub mod baselines;
pub mod benchmarks;
pub mod candidates;
pub mod compute_memory;
pub mod compute_memory_v3;
pub mod compute_memory_v4;
pub mod cryptanalysis;
pub mod engineering;
pub mod multitarget;
pub mod resource_controller;
pub mod tmto;

use std::path::Path;

/// Runs the current (v4) research benchmark suite.
pub fn run_research_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    compute_memory_v4::run_compute_memory_v4_suite(&target_dir.join("compute-memory-v4"))?;
    Ok(())
}
