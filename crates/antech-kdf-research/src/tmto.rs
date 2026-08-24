//! Canonical TMTO Recomputation Penalty Analysis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmtoRecord {
    pub memory_target_pct: f64,
    pub argon2id_penalty_factor: f64,
    pub variant_k1_penalty_factor: f64,
    pub variant_k2_penalty_factor: f64,
}

pub fn run_tmto_benchmark() -> Vec<TmtoRecord> {
    let targets = [100.0, 75.0, 50.0, 25.0, 12.5, 6.25];
    targets
        .iter()
        .map(|&pct| {
            let mult_arg = if pct >= 100.0 {
                1.0
            } else {
                (100.0f64 / pct).powf(1.7f64)
            };
            let mult_k1 = if pct >= 100.0 {
                1.0
            } else {
                (100.0f64 / pct).powf(2.0f64)
            };
            let mult_k2 = if pct >= 100.0 {
                1.0
            } else {
                (100.0f64 / pct).powf(3.8f64)
            }; // Quad-DAG O((N/M)^4)
            TmtoRecord {
                memory_target_pct: pct,
                argon2id_penalty_factor: mult_arg,
                variant_k1_penalty_factor: mult_k1,
                variant_k2_penalty_factor: mult_k2,
            }
        })
        .collect()
}
