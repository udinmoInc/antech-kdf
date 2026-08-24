//! Antech KDF Research Laboratory Crate.

pub mod baselines;
pub mod benchmarks;
pub mod candidate004;
pub mod cpu_attacker;
pub mod gpu_attacker;
pub mod multitarget;
pub mod resource_controller;
pub mod tmto;
pub mod variant_k1;
pub mod variant_k2;

use std::path::Path;

/// Runs the complete Antech KDF research benchmark suite and exports comparison deliverables.
pub fn run_research_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    benchmarks::run_research_benchmark_suite(target_dir)
}
