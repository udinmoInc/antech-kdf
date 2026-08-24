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
pub mod phase_e1_exporter;
pub mod phase_e1_runner;
pub mod phase_e_exporter;
pub mod phase_e_runner;
pub mod phase_f;
pub mod phase_f_exporter;
pub mod phase_f_runner;
pub mod phase_g;
pub mod phase_g_exporter;
pub mod phase_g_runner;
pub mod phase_h;
pub mod phase_h_exporter;
pub mod phase_h_runner;
pub mod phase_i;
pub mod phase_i_exporter;
pub mod phase_i_runner;
pub mod phase_i_verifier;
pub mod phase_j;
pub mod phase_j_exporter;
pub mod phase_j_runner;
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

/// Runs the full Phase E.1 Candidate-E4 prior-art, cryptanalysis & novelty audit laboratory suite.
pub fn run_phase_e1_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase E.1 Candidate-E4 Prior-Art & Cryptanalysis Audit Laboratory ===");
    let results = phase_e1_runner::run_phase_e1_suite();

    println!("=== Exporting Phase E.1 deliverables to {:?} ===", target_dir);
    phase_e1_exporter::export_phase_e1_results(target_dir, &results)?;

    println!("Phase E.1 research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase F Candidate-004 formalization and research laboratory suite.
pub fn run_phase_f_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase F Candidate-004 Formalization & Research Laboratory ===");
    let results = phase_f_runner::run_phase_f_suite();

    println!("=== Exporting Phase F deliverables to {:?} ===", target_dir);
    phase_f_exporter::export_phase_f_results(target_dir, &results)?;

    println!("Phase F research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase G Attacker-Cost Equalization laboratory suite.
pub fn run_phase_g_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase G Candidate-004 Attacker-Cost Equalization Laboratory ===");
    let results = phase_g_runner::run_phase_g_suite();

    println!("=== Exporting Phase G deliverables to {:?} ===", target_dir);
    phase_g_exporter::export_phase_g_results(target_dir, &results)?;

    println!("Phase G research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase H Production-Constraint research laboratory suite.
pub fn run_phase_h_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase H Production-Constraint Research Laboratory ===");
    let results = phase_h_runner::run_phase_h_suite();

    println!("=== Exporting Phase H deliverables to {:?} ===", target_dir);
    phase_h_exporter::export_phase_h_results(target_dir, &results)?;

    println!("Phase H research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase I Candidate-004 research laboratory suite.
pub fn run_phase_i_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase I Candidate-004 Target Matching Research Laboratory ===");
    let results = phase_i_runner::run_phase_i_suite();

    println!("=== Exporting Phase I deliverables to {:?} ===", target_dir);
    phase_i_exporter::export_phase_i_results(target_dir, &results)?;

    println!("Phase I research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the Phase I Variant E Deep-DAG verification suite.
pub fn run_phase_i_verification(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase I Variant E Deep-DAG Verification Suite ===");
    phase_i_verifier::run_phase_i_verification(target_dir)?;
    println!("Phase I verification complete. Deliverables written to {:?}", target_dir);
    Ok(())
}

/// Runs the full Phase J research laboratory suite.
pub fn run_phase_j_suite(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running Phase J Latency / Attacker-Cost Bottleneck Research Laboratory ===");
    let results = phase_j_runner::run_phase_j_suite();

    println!("=== Exporting Phase J deliverables to {:?} ===", target_dir);
    phase_j_exporter::export_phase_j_results(target_dir, &results)?;

    println!("Phase J research complete. Deliverables written to {:?}", target_dir);
    Ok(())
}
