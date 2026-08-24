//! Baseline benchmark grid implementations for Argon2id, scrypt, bcrypt, and PBKDF2.

use crate::metrics::{compute_stats, get_hardware_info, get_process_memory_bytes};
use crate::schema::{BenchmarkResult, RunInfo};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use pbkdf2::hmac::Hmac;
use scrypt::Params as ScryptParams;
use sha2::Sha256;
use std::time::Instant;

/// Runs the full Argon2id baseline matrix.
pub fn run_argon2id_matrix(warmup: u32, iterations: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    let hw = get_hardware_info();
    let salt = [0x42u8; 16];
    let password = b"research_baseline_password";

    let mem_levels_kib = [8192, 16384, 32768, 65536, 131072];
    let time_costs = [1, 2, 3, 4];
    let parallelism_levels = [1, 2, 4];

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

                // Warmup
                for _ in 0..warmup {
                    let mut out = [0u8; 32];
                    let _ = argon2_inst.hash_password_into(password, &salt, &mut out);
                }

                let start_mem = get_process_memory_bytes();
                let mut durations = Vec::with_capacity(iterations as usize);
                let mut peak_mem = start_mem;

                for _ in 0..iterations {
                    let mut out = [0u8; 32];
                    let t0 = Instant::now();
                    let _ = argon2_inst.hash_password_into(password, &salt, &mut out);
                    let elapsed = t0.elapsed();
                    durations.push(elapsed);
                    peak_mem = peak_mem.max(get_process_memory_bytes());
                }

                let bytes_read = (mem as u64) * 1024 * (t as u64);
                let bytes_written = (mem as u64) * 1024 * (t as u64);

                let stats = compute_stats(&durations, peak_mem, bytes_read, bytes_written);

                results.push(BenchmarkResult {
                    algorithm: "argon2id".to_string(),
                    version: "0.5.0".to_string(),
                    parameters: format!("memory_kib={},time_cost={},parallelism={}", mem, t, p),
                    hardware: hw.clone(),
                    run: RunInfo { warmup_iterations: warmup, iterations },
                    metrics: stats,
                });
            }
        }
    }

    results
}

/// Runs the full scrypt baseline matrix.
pub fn run_scrypt_matrix(warmup: u32, iterations: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    let hw = get_hardware_info();
    let salt = [0x42u8; 16];
    let password = b"research_baseline_password";

    let n_levels = [1024, 4096, 16384, 65536];
    let r_levels = [8, 16];
    let p_levels = [1, 2];

    for &n in &n_levels {
        for &r in &r_levels {
            for &p in &p_levels {
                let log_n = (n as f64).log2() as u8;
                let scrypt_params = match ScryptParams::new(log_n, r, p, 32) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Warmup
                for _ in 0..warmup {
                    let mut out = [0u8; 32];
                    let _ = scrypt::scrypt(password, &salt, &scrypt_params, &mut out);
                }

                let start_mem = get_process_memory_bytes();
                let mut durations = Vec::with_capacity(iterations as usize);
                let mut peak_mem = start_mem;

                for _ in 0..iterations {
                    let mut out = [0u8; 32];
                    let t0 = Instant::now();
                    let _ = scrypt::scrypt(password, &salt, &scrypt_params, &mut out);
                    let elapsed = t0.elapsed();
                    durations.push(elapsed);
                    peak_mem = peak_mem.max(get_process_memory_bytes());
                }

                let mem_bytes = 128 * (r as u64) * (n as u64);
                let stats = compute_stats(&durations, peak_mem, mem_bytes * 2, mem_bytes * 2);

                results.push(BenchmarkResult {
                    algorithm: "scrypt".to_string(),
                    version: "0.11.0".to_string(),
                    parameters: format!("N={},r={},p={}", n, r, p),
                    hardware: hw.clone(),
                    run: RunInfo { warmup_iterations: warmup, iterations },
                    metrics: stats,
                });
            }
        }
    }

    results
}

/// Runs the full bcrypt baseline matrix.
pub fn run_bcrypt_matrix(warmup: u32, iterations: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    let hw = get_hardware_info();
    let password = "research_baseline_password";

    let costs = [4, 6, 8, 10];

    for &cost in &costs {
        for _ in 0..warmup {
            let _ = bcrypt::hash(password, cost);
        }

        let start_mem = get_process_memory_bytes();
        let mut durations = Vec::with_capacity(iterations as usize);
        let mut peak_mem = start_mem;

        for _ in 0..iterations {
            let t0 = Instant::now();
            let _ = bcrypt::hash(password, cost);
            let elapsed = t0.elapsed();
            durations.push(elapsed);
            peak_mem = peak_mem.max(get_process_memory_bytes());
        }

        let stats = compute_stats(&durations, peak_mem, 4096 * (1 << cost), 4096 * (1 << cost));

        results.push(BenchmarkResult {
            algorithm: "bcrypt".to_string(),
            version: "0.15.0".to_string(),
            parameters: format!("cost={}", cost),
            hardware: hw.clone(),
            run: RunInfo { warmup_iterations: warmup, iterations },
            metrics: stats,
        });
    }

    results
}

/// Runs the full PBKDF2-HMAC-SHA256 baseline matrix.
pub fn run_pbkdf2_matrix(warmup: u32, iterations: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    let hw = get_hardware_info();
    let salt = [0x42u8; 16];
    let password = b"research_baseline_password";

    let iteration_counts = [1000, 10000, 50000, 100000];

    for &iters in &iteration_counts {
        for _ in 0..warmup {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, &salt, iters, &mut out).unwrap();
        }

        let start_mem = get_process_memory_bytes();
        let mut durations = Vec::with_capacity(iterations as usize);
        let mut peak_mem = start_mem;

        for _ in 0..iterations {
            let mut out = [0u8; 32];
            let t0 = Instant::now();
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, &salt, iters, &mut out).unwrap();
            let elapsed = t0.elapsed();
            durations.push(elapsed);
            peak_mem = peak_mem.max(get_process_memory_bytes());
        }

        let stats = compute_stats(&durations, peak_mem, 64 * (iters as u64), 64 * (iters as u64));

        results.push(BenchmarkResult {
            algorithm: "pbkdf2-sha256".to_string(),
            version: "0.12.0".to_string(),
            parameters: format!("iterations={}", iters),
            hardware: hw.clone(),
            run: RunInfo { warmup_iterations: warmup, iterations },
            metrics: stats,
        });
    }

    results
}
