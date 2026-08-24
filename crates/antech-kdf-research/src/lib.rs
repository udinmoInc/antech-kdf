//! Antech KDF Baseline Research & Laboratory Suite.

pub mod attacker;
pub mod baselines;
pub mod churn_harness;
pub mod concurrency;
pub mod dependency_harness;
pub mod exporter;
pub mod metrics;
pub mod schema;

use std::path::Path;

/// Runs the complete baseline benchmark suite, concurrency tests, attacker modeling,
/// and exports all CSV/JSON/Markdown deliverables.
pub fn run_full_research_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Argon2id baseline matrix ===");
    let mut baselines = baselines::run_argon2id_matrix(1, 3);

    println!("=== Running scrypt baseline matrix ===");
    baselines.extend(baselines::run_scrypt_matrix(1, 3));

    println!("=== Running bcrypt baseline matrix ===");
    baselines.extend(baselines::run_bcrypt_matrix(1, 3));

    println!("=== Running PBKDF2 baseline matrix ===");
    baselines.extend(baselines::run_pbkdf2_matrix(1, 3));

    println!("=== Running defender login concurrency benchmarks (1..1000 threads) ===");
    let concurrency = concurrency::run_concurrency_benchmarks();

    println!("=== Running offline attacker cost modeling ===");
    let attacker_models = attacker::run_attacker_cost_models();

    println!("=== Exporting deliverables to {:?} ===", target_dir);
    exporter::export_all_results(target_dir, &baselines, &concurrency, &attacker_models)?;

    println!("Research laboratory run complete. Results written to {:?}", target_dir);
    Ok(())
}
