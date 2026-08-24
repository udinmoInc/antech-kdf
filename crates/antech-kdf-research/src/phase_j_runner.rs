//! Phase J Research Experiment Runner.

use crate::phase_j::attacker::{run_phase_j_attacker_sweep, PhaseJAttackerEvalRecord};
use crate::phase_j::concurrency::{run_phase_j_concurrency_sweep, PhaseJConcurrencyRecord};
use crate::phase_j::contention::{run_phase_j_contention_sweep, PhaseJContentionRecord};
use crate::phase_j::crypto_analysis::{run_phase_j_crypto_audit, PhaseJCryptoRecord};
use crate::phase_j::gpu::{run_phase_j_gpu_sweep, PhaseJGpuRecord};
use crate::phase_j::pareto::{run_phase_j_pareto_sweep, PhaseJParetoRecord};
use crate::phase_j::profiling::{run_phase_j_profiling, PhaseJProfilingRecord};
use crate::phase_j::tmto::{run_phase_j_tmto_sweep, PhaseJTmtoRecord};

pub struct PhaseJResults {
    pub profiling: Vec<PhaseJProfilingRecord>,
    pub attacker_sweep: Vec<PhaseJAttackerEvalRecord>,
    pub gpu_sweep: Vec<PhaseJGpuRecord>,
    pub tmto_sweep: Vec<PhaseJTmtoRecord>,
    pub concurrency_sweep: Vec<PhaseJConcurrencyRecord>,
    pub contention_sweep: Vec<PhaseJContentionRecord>,
    pub pareto_sweep: Vec<PhaseJParetoRecord>,
    pub crypto_audit: Vec<PhaseJCryptoRecord>,
    pub status_verdict: String,
}

pub fn run_phase_j_suite() -> PhaseJResults {
    println!("--- 1. Profiling Antech Execution Bottlenecks & Cache Behavior ---");
    let profiling = run_phase_j_profiling();

    println!("--- 2. Sweeping Phase J Variants A..D & Variant E (CPU Attacker & Latency) ---");
    let attacker_sweep = run_phase_j_attacker_sweep();

    println!("--- 3. Sweeping Phase J Variants A..D (GPU Attacker Modeling) ---");
    let gpu_sweep = run_phase_j_gpu_sweep();

    println!("--- 4. Sweeping Phase J TMTO Recomputation Penalties ---");
    let tmto_sweep = run_phase_j_tmto_sweep();

    println!("--- 5. Testing Concurrency Bounded Resource Controller ---");
    let concurrency_sweep = run_phase_j_concurrency_sweep();

    println!("--- 6. Testing Cloud DRAM Multi-Tenant Contention ---");
    let contention_sweep = run_phase_j_contention_sweep();

    println!("--- 7. Calculating Pareto Frontier ---");
    let pareto_sweep = run_phase_j_pareto_sweep();

    println!("--- 8. Cryptographic Soundness & Security Rationale Audit ---");
    let crypto_audit = run_phase_j_crypto_audit();

    // Check if any variant satisfied all 3 target constraints
    let passed_variant = attacker_sweep.iter().find(|r| r.satisfies_ram_target && r.satisfies_latency_target && r.satisfies_attacker_target);

    let status_verdict = if passed_variant.is_some() {
        "TARGET ACHIEVED".to_string()
    } else {
        "PROMISING BUT ATTACKER TOO FAST".to_string()
    };

    PhaseJResults {
        profiling,
        attacker_sweep,
        gpu_sweep,
        tmto_sweep,
        concurrency_sweep,
        contention_sweep,
        pareto_sweep,
        crypto_audit,
        status_verdict,
    }
}
