//! Antech KDF Baseline Research & Laboratory Suite.

pub mod attacker;
pub mod attacker_bench;
pub mod baselines;
pub mod candidates;
pub mod churn_harness;
pub mod concurrency;
pub mod dependency_harness;
pub mod exporter;
pub mod metrics;
pub mod optimizations;
pub mod phase_c_exporter;
pub mod phase_c_runner;
pub mod phase_d_exporter;
pub mod phase_d_runner;
pub mod phase_e;
pub mod phase_e_exporter;
pub mod phase_e_runner;
pub mod schema;

use std::path::Path;

/// Runs the complete Phase B baseline laboratory benchmark suite.
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

    println!("=== Running real CPU multicore attacker cracking benchmarks (1..16 workers) ===");
    let real_attacker_results = attacker_bench::run_real_attacker_benchmarks();
    println!("Real CPU Attacker Benchmark Results: {:?}", real_attacker_results.len());

    println!("=== Running offline attacker cost modeling ===");
    let attacker_models = attacker::run_attacker_cost_models();

    println!("=== Exporting deliverables to {:?} ===", target_dir);
    exporter::export_all_results(target_dir, &baselines, &concurrency, &attacker_models)?;

    println!("Research laboratory run complete. Results written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase C candidate research laboratory suite.
pub fn run_phase_c_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase C Candidate Research Laboratory (Candidates 001..008) ===");
    let results = phase_c_runner::run_phase_c_suite();

    println!("=== Exporting Phase C deliverables to {:?} ===", target_dir);
    phase_c_exporter::export_phase_c_results(target_dir, &results)?;

    println!("Phase C research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase D optimization & adversarial audit laboratory suite.
pub fn run_phase_d_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase D Candidate 004 Optimization & Adversarial Audit Laboratory ===");
    let results = phase_d_runner::run_phase_d_suite();

    println!("=== Exporting Phase D deliverables to {:?} ===", target_dir);
    phase_d_exporter::export_phase_d_results(target_dir, &results)?;

    println!("Phase D research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase E cost-asymmetric research laboratory suite.
pub fn run_phase_e_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase E Cost-Asymmetric Research Laboratory (Candidates E1..E6) ===");
    let results = phase_e_runner::run_phase_e_suite();

    println!("=== Exporting Phase E deliverables to {:?} ===", target_dir);
    phase_e_exporter::export_phase_e_results(target_dir, &results)?;

    println!("Phase E research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}
