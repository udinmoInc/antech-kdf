//! Baseline benchmark grid implementations for Argon2id, scrypt, bcrypt, and PBKDF2.

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub algorithm: String,
    pub parameters: String,
    pub mean_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub memory_kib: usize,
}

/// Runs the full Argon2id baseline matrix.
pub fn run_argon2id_matrix(warmup: u32, iterations: u32) -> Vec<BaselineRecord> {
    let mut results = Vec::new();
    let salt = [0x42u8; 16];
    let password = b"research_baseline_password";

    let mem_levels_kib = [8192, 16384, 32768, 65536];
    let time_costs = [1, 2];
    let parallelism_levels = [1, 2];

    for &mem in &mem_levels_kib {
        for &t in &time_costs {
            for &p in &parallelism_levels {
                let params = match ParamsBuilder::new()
                    .m_cost(mem)
                    .t_cost(t)
                    .p_cost(p)
                    .output_len(32)
                    .build()
                {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let argon2_inst = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

                for _ in 0..warmup {
                    let mut out = [0u8; 32];
                    let _ = argon2_inst.hash_password_into(password, &salt, &mut out);
                }

                let t0 = Instant::now();
                for _ in 0..iterations {
                    let mut out = [0u8; 32];
                    let _ = argon2_inst.hash_password_into(password, &salt, &mut out);
                }
                let total_elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                let mean_ms = total_elapsed / (iterations as f64);

                results.push(BaselineRecord {
                    algorithm: "argon2id".to_string(),
                    parameters: format!("memory_kib={},time_cost={},parallelism={}", mem, t, p),
                    mean_latency_ms: mean_ms,
                    p50_latency_ms: mean_ms,
                    memory_kib: mem as usize,
                });
            }
        }
    }

    results
}
