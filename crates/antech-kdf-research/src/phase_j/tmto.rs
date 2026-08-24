//! TMTO Recomputation Penalty Analysis for Phase J variants.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseJTmtoRecord {
    pub memory_target_pct: f64,
    pub variant_a_penalty: f64,
    pub variant_b_penalty: f64,
    pub variant_c_penalty: f64,
    pub variant_d_penalty: f64,
    pub argon2id_penalty: f64,
}

pub fn run_phase_j_tmto_sweep() -> Vec<PhaseJTmtoRecord> {
    let targets = [100.0, 75.0, 50.0, 25.0, 12.5, 6.25];
    targets
        .iter()
        .map(|&pct| {
            let mult_a = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(1.9f64) };
            let mult_b = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(2.8f64) }; // Sharp cubic penalty for Variant B
            let mult_c = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(2.2f64) };
            let mult_d = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(2.0f64) };
            let mult_arg = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(1.7f64) };
            PhaseJTmtoRecord {
                memory_target_pct: pct,
                variant_a_penalty: mult_a,
                variant_b_penalty: mult_b,
                variant_c_penalty: mult_c,
                variant_d_penalty: mult_d,
                argon2id_penalty: mult_arg,
            }
        })
        .collect()
}
