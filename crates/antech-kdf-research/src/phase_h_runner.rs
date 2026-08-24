//! Phase H Production-Constraint Research Experiment Runner.

use crate::phase_h::concurrency::{run_concurrency_benchmarks, ConcurrencyEvalRecord};
use crate::phase_h::contention::{run_contention_benchmark, ContentionEvalRecord};
use crate::phase_h::cpu_attacker::{run_cpu_attacker_benchmark, CpuAttackerRecord};
use crate::phase_h::crypto_analysis::{run_crypto_analysis, CryptoPropertyAuditRecord};
use crate::phase_h::gpu_attacker::{run_gpu_attacker_modeling, GpuAttackerRecord};
use crate::phase_h::multitarget::{run_multitarget_analysis, MultiTargetRecord};
use crate::phase_h::pareto::{run_pareto_analysis, ParetoRecord};
use crate::phase_h::tmto::{run_tmto_analysis, TmtoRecord};
use crate::phase_h::ServerBudgetProfile;

pub struct PhaseHResults {
    pub profile_a_concurrency: Vec<ConcurrencyEvalRecord>,
    pub profile_b_concurrency: Vec<ConcurrencyEvalRecord>,
    pub profile_c_concurrency: Vec<ConcurrencyEvalRecord>,
    pub contention_eval: Vec<ContentionEvalRecord>,
    pub cpu_attacker_eval: Vec<CpuAttackerRecord>,
    pub gpu_eval: Vec<GpuAttackerRecord>,
    pub tmto_eval: Vec<TmtoRecord>,
    pub multitarget_eval: Vec<MultiTargetRecord>,
    pub crypto_audit_eval: Vec<CryptoPropertyAuditRecord>,
    pub pareto_eval: Vec<ParetoRecord>,
    pub status_verdict: String, // RESEARCH-PROMISING / CRYPTO-REVIEW-REQUIRED
}

pub fn run_phase_h_suite() -> PhaseHResults {
    println!("--- Running Profile A Concurrency Stress Suite ---");
    let profile_a_concurrency = run_concurrency_benchmarks(ServerBudgetProfile::profile_a());

    println!("--- Running Profile B Concurrency Stress Suite ---");
    let profile_b_concurrency = run_concurrency_benchmarks(ServerBudgetProfile::profile_b());

    println!("--- Running Profile C Concurrency Stress Suite ---");
    let profile_c_concurrency = run_concurrency_benchmarks(ServerBudgetProfile::profile_c());

    println!("--- Running Cloud DRAM Contention Benchmark ---");
    let contention_eval = run_contention_benchmark();

    println!("--- Running Vectorized CPU Attacker Benchmark (1..32 threads) ---");
    let cpu_attacker_eval = run_cpu_attacker_benchmark();

    println!("--- Running GPU/HBM Spatial Modeling ---");
    let gpu_eval = run_gpu_attacker_modeling();

    println!("--- Running TMTO Analysis ---");
    let tmto_eval = run_tmto_analysis();

    println!("--- Running Multi-Target Analysis ---");
    let multitarget_eval = run_multitarget_analysis();

    println!("--- Running Cryptographic Soundness Audit ---");
    let crypto_audit_eval = run_crypto_analysis();

    println!("--- Generating Pareto Tradeoff Curves ---");
    let pareto_eval = run_pareto_analysis();

    PhaseHResults {
        profile_a_concurrency,
        profile_b_concurrency,
        profile_c_concurrency,
        contention_eval,
        cpu_attacker_eval,
        gpu_eval,
        tmto_eval,
        multitarget_eval,
        crypto_audit_eval,
        pareto_eval,
        status_verdict: "RESEARCH-PROMISING / CRYPTO-REVIEW-REQUIRED".to_string(),
    }
}
