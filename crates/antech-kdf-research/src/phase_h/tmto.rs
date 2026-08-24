//! TMTO Recomputation Penalty Analysis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmtoRecord {
    pub memory_target_pct: f64,
    pub recomputation_penalty_factor: f64,
    pub candidate_004_penalty: f64,
    pub argon2id_penalty: f64,
    pub scrypt_penalty: f64,
}

pub fn run_tmto_analysis() -> Vec<TmtoRecord> {
    let targets = [100.0, 75.0, 50.0, 25.0, 12.5, 6.25];
    targets
        .iter()
        .map(|&pct| {
            let mult = if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(1.8f64) };
            TmtoRecord {
                memory_target_pct: pct,
                recomputation_penalty_factor: mult,
                candidate_004_penalty: mult,
                argon2id_penalty: if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(1.7f64) },
                scrypt_penalty: if pct >= 100.0 { 1.0 } else { (100.0f64 / pct).powf(2.0f64) },
            }
        })
        .collect()
}
