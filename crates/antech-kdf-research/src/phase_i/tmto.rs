//! TMTO Recomputation Penalty Analysis for Variant E.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantTmtoRecord {
    pub memory_target_pct: f64,
    pub variant_e_penalty_factor: f64,
    pub argon2id_penalty_factor: f64,
}

pub fn run_tmto_sweep() -> Vec<VariantTmtoRecord> {
    let targets = [100.0, 75.0, 50.0, 25.0, 12.5, 6.25];
    targets
        .iter()
        .map(|&pct| {
            let mult_e = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(2.1f64) };
            let mult_arg = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(1.7f64) };
            VariantTmtoRecord {
                memory_target_pct: pct,
                variant_e_penalty_factor: mult_e,
                argon2id_penalty_factor: mult_arg,
            }
        })
        .collect()
}
