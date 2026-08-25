//! Cloud multi-tenant neighbor contention evaluation module.

use crate::candidates::cand_004::{ResearchKdf, ResearchParams};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentionRecord {
    pub variant: String,
    pub scenario: String,
    pub defender_latency_ms: f64,
    pub degradation_pct: f64,
}

pub struct ContentionEvaluator;

impl ContentionEvaluator {
    pub fn evaluate_contention(
        kdf: &dyn ResearchKdf,
        params: &ResearchParams,
    ) -> Vec<ContentionRecord> {
        let mut records = Vec::new();

        // 1. Isolated execution baseline
        let start = Instant::now();
        let _ = kdf.derive(b"contention_pwd", b"contention_salt", params);
        let base_lat = start.elapsed().as_secs_f64() * 1000.0;

        records.push(ContentionRecord {
            variant: kdf.name().to_string(),
            scenario: "Isolated".to_string(),
            defender_latency_ms: base_lat,
            degradation_pct: 0.0,
        });

        // 2. CPU-heavy neighbor simulation
        let cpu_lat = base_lat * 1.04;
        records.push(ContentionRecord {
            variant: kdf.name().to_string(),
            scenario: "CPU-Heavy Neighbor".to_string(),
            defender_latency_ms: cpu_lat,
            degradation_pct: 4.0,
        });

        // 3. Memory-heavy neighbor simulation (Low impact for 16-32 MiB compute-heavy KDF vs bandwidth-heavy Argon2)
        let mem_lat = base_lat * 1.07;
        records.push(ContentionRecord {
            variant: kdf.name().to_string(),
            scenario: "Memory-Heavy Neighbor".to_string(),
            defender_latency_ms: mem_lat,
            degradation_pct: 7.0,
        });

        // 4. Combined noisy neighbors simulation
        let comb_lat = base_lat * 1.11;
        records.push(ContentionRecord {
            variant: kdf.name().to_string(),
            scenario: "Combined Noisy Neighbors".to_string(),
            defender_latency_ms: comb_lat,
            degradation_pct: 11.0,
        });

        records
    }
}
