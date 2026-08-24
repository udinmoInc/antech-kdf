//! Antech KDF Research Crate.

pub mod attackers;
pub mod baselines;
pub mod benchmarks;
pub mod candidates;
pub mod multitarget;
pub mod resource_controller;
pub mod tmto;

use std::path::Path;

/// Runs the complete Antech KDF research benchmark suite.
pub fn run_research_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    benchmarks::run_research_benchmark_suite(target_dir)
}
