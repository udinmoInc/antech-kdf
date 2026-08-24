//! Benchmark helper functions for Phase J.

use super::attacker::run_phase_j_attacker_sweep;
use super::attacker::PhaseJAttackerEvalRecord;

pub fn run_all_benchmarks() -> Vec<PhaseJAttackerEvalRecord> {
    run_phase_j_attacker_sweep()
}
