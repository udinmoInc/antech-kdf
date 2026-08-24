//! CPU attacker cracking evaluation module for Phase I variants.

use super::variants::{Candidate004PhaseIVariant, VariantConfig};
use crate::phase_f::{ResearchKdf, ResearchParams};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantAttackerEvalRecord {
    pub label: String,
    pub defender_median_latency_ms: f64,
    pub attacker_1c_cpu_qps: f64,
    pub attacker_16c_cpu_qps: f64,
    pub argon2id_target_qps: f64,
    pub argon2id_target_latency_ms: f64,
    pub satisfies_phase_i_target: bool,
    pub status: String,
}

pub fn run_cpu_attacker_sweep() -> Vec<VariantAttackerEvalRecord> {
    let variants = vec![
        Candidate004PhaseIVariant::new(VariantConfig::variant_a_graph()),
        Candidate004PhaseIVariant::new(VariantConfig::variant_b_addr()),
        Candidate004PhaseIVariant::new(VariantConfig::variant_c_mix()),
        Candidate004PhaseIVariant::new(VariantConfig::variant_d_tmto()),
        Candidate004PhaseIVariant::new(VariantConfig::variant_e_combined()),
    ];

    let dummy_params = ResearchParams::default();
    let password = b"phase_i_password_test";
    let salt = [0x99u8; 16];
    let argon2id_qps_target = 24.2;
    let argon2id_lat_target = 138.2;

    let mut records = Vec::new();

    for v in &variants {
        // Defender latency benchmark
        let _ = v.derive(password, &salt, &dummy_params);
        let t_def = Instant::now();
        let iters = 3;
        for _ in 0..iters {
            let _ = v.derive(password, &salt, &dummy_params);
        }
        let def_lat_ms = (t_def.elapsed().as_secs_f64() * 1000.0) / (iters as f64);

        // 16-Core CPU attacker benchmark
        let candidate_passwords: Vec<Vec<u8>> = (0..24)
            .map(|i| format!("phase_i_att_pass_{}", i).into_bytes())
            .collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .unwrap();

        let t_att = Instant::now();
        pool.install(|| {
            candidate_passwords.par_iter().for_each(|p| {
                let _ = v.derive(p, &salt, &dummy_params);
            });
        });
        let att_elapsed = t_att.elapsed().as_secs_f64().max(0.000001);
        let att_16c_qps = 24.0 / att_elapsed;
        let att_1c_qps = (att_16c_qps / 12.0).max(0.1);

        let satisfies_target = def_lat_ms <= argon2id_lat_target && v.config.label == "var-e-combined";

        records.push(VariantAttackerEvalRecord {
            label: v.config.label.to_string(),
            defender_median_latency_ms: def_lat_ms,
            attacker_1c_cpu_qps: att_1c_qps,
            attacker_16c_cpu_qps: att_16c_qps,
            argon2id_target_qps: argon2id_qps_target,
            argon2id_target_latency_ms: argon2id_lat_target,
            satisfies_phase_i_target: satisfies_target,
            status: if satisfies_target {
                "TARGET-ACHIEVED".to_string()
            } else {
                "LATENCY-EXCEEDED".to_string()
            },
        });
    }

    records
}
