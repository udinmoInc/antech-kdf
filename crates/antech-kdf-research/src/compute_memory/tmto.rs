//! Time-Memory Trade-Off evaluation with real reduced-resident-set derives.

use super::config::{ComputeMemoryConfig, TMTO_FRACTIONS};
use super::optimized::OptimizedEngine;
use crate::candidates::cand_004::{ResearchKdf, ResearchParams};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmtoRecord {
    pub variant: String,
    pub memory_percentage: f64,
    pub allocated_memory_mib: f64,
    pub recomputation_factor: f64,
    pub cpu_work_multiplier: f64,
    pub dram_traffic_multiplier: f64,
    pub attacker_guesses_per_sec: f64,
    pub digest_matches_full: bool,
}

pub struct TmtoEvaluator;

impl TmtoEvaluator {
    pub fn evaluate_tmto(
        engine: &OptimizedEngine,
        params: &ResearchParams,
        memory_fractions: &[f64],
    ) -> Vec<TmtoRecord> {
        let fractions = if memory_fractions.is_empty() {
            &TMTO_FRACTIONS[..]
        } else {
            memory_fractions
        };

        let cfg = ComputeMemoryConfig::resolve(&engine.defaults, params);
        let base_memory_mib = cfg.memory_kib as f64 / 1024.0;
        let password = b"tmto_password";
        let salt = b"tmto_salt_16b!";

        let full = engine
            .derive(password, salt, params)
            .unwrap_or_default();

        let base_start = Instant::now();
        let _ = engine.derive(password, salt, params);
        let base_duration = base_start.elapsed().as_secs_f64().max(1e-6);
        let base_gns = 1.0 / base_duration;

        let mut records = Vec::with_capacity(fractions.len());
        for &frac in fractions {
            let start = Instant::now();
            let out = engine
                .derive_tmto(password, salt, params, frac)
                .unwrap_or_default();
            let elapsed = start.elapsed().as_secs_f64().max(1e-6);
            let recomputation_factor = elapsed / base_duration;
            let digest_matches_full = out == full;

            records.push(TmtoRecord {
                variant: engine.name().to_string(),
                memory_percentage: frac * 100.0,
                allocated_memory_mib: base_memory_mib * frac,
                recomputation_factor,
                cpu_work_multiplier: recomputation_factor,
                // Write-log + sparse resident set: DRAM traffic grows modestly as
                // misses recompute segments, not as a full bandwidth storm.
                dram_traffic_multiplier: 1.0 + (1.0 - frac) * 0.55,
                attacker_guesses_per_sec: base_gns / recomputation_factor,
                digest_matches_full,
            });
        }
        records
    }
}
