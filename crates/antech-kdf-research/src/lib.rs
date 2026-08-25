//! Antech KDF Research Crate.

pub mod attackers;
pub mod baselines;
pub mod benchmarks;
pub mod candidates;
pub mod compute_memory;
pub mod compute_memory_v3;
pub mod compute_memory_v4;
pub mod multitarget;
pub mod resource_controller;
pub mod tmto;

use std::path::Path;

/// Runs the complete Antech KDF research benchmark suite.
pub fn run_research_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    benchmarks::run_research_benchmark_suite(target_dir)?;
    compute_memory::run_compute_memory_suite(&target_dir.join("compute-memory"))?;
    compute_memory_v3::run_compute_memory_v3_suite(&target_dir.join("compute-memory-v3"))?;
    compute_memory_v4::run_compute_memory_v4_suite(&target_dir.join("compute-memory-v4"))?;
    Ok(())
}

