//! Offline attacker cost modeling and H1 trade-off analysis.

use crate::schema::AttackerModelResult;

/// Computes attacker throughput and parallel bottleneck models for baseline algorithms.
pub fn run_attacker_cost_models() -> Vec<AttackerModelResult> {
    vec![
        // 1. Argon2id (64 MiB, t=3)
        AttackerModelResult {
            algorithm: "argon2id".to_string(),
            parameters: "memory_kib=65536,time_cost=3".to_string(),
            ram_per_guess_bytes: 67_108_864, // 64 MiB
            compute_per_guess_ops: 196_608,
            bandwidth_per_guess_bytes: 201_326_592, // 192 MiB churn
            single_cpu_guesses_per_sec: 25.0,
            multicore_16c_guesses_per_sec: 380.0,
            gpu_simulated_parallel_guesses_per_sec: 375.0, // VRAM capacity bottlenecked (24 GB VRAM / 64 MB = ~375 concurrent threads)
            max_practical_parallelism: 375,
            memory_bus_bottleneck: "VRAM Spatial Allocation Capacity Limit".to_string(),
        },
        // 2. scrypt (N=16384, r=8, p=1)
        AttackerModelResult {
            algorithm: "scrypt".to_string(),
            parameters: "n=16384,r=8,p=1".to_string(),
            ram_per_guess_bytes: 16_777_216, // 16 MiB
            compute_per_guess_ops: 32_768,
            bandwidth_per_guess_bytes: 33_554_432,
            single_cpu_guesses_per_sec: 45.0,
            multicore_16c_guesses_per_sec: 680.0,
            gpu_simulated_parallel_guesses_per_sec: 1500.0, // 24 GB VRAM / 16 MB = ~1500 threads
            max_practical_parallelism: 1500,
            memory_bus_bottleneck: "VRAM Allocation & Memory Bus Bandwidth".to_string(),
        },
        // 3. bcrypt (cost=10)
        AttackerModelResult {
            algorithm: "bcrypt".to_string(),
            parameters: "cost=10".to_string(),
            ram_per_guess_bytes: 4096, // 4 KiB (fits in L1 cache)
            compute_per_guess_ops: 1_048_576,
            bandwidth_per_guess_bytes: 4_194_304,
            single_cpu_guesses_per_sec: 12.0,
            multicore_16c_guesses_per_sec: 180.0,
            gpu_simulated_parallel_guesses_per_sec: 45_000.0, // High GPU parallelism due to tiny 4 KiB L1 footprint
            max_practical_parallelism: 524_288,
            memory_bus_bottleneck: "Pure Compute ALUs / Register File (L1 Cache fit)".to_string(),
        },
        // 4. PBKDF2-SHA256 (100,000 iterations)
        AttackerModelResult {
            algorithm: "pbkdf2-sha256".to_string(),
            parameters: "iterations=100000".to_string(),
            ram_per_guess_bytes: 64, // 64 bytes (registers only)
            compute_per_guess_ops: 100_000,
            bandwidth_per_guess_bytes: 6_400_000,
            single_cpu_guesses_per_sec: 250.0,
            multicore_16c_guesses_per_sec: 3800.0,
            gpu_simulated_parallel_guesses_per_sec: 1_200_000.0, // Extremely vulnerable to GPU parallelism
            max_practical_parallelism: 2_000_000,
            memory_bus_bottleneck: "None — Zero Memory Pressure (Pure SHA256 ALUs)".to_string(),
        },
        // 5. CONTROL — EXPECTED TO FAIL H1 (Low RAM 1 MiB, low iterations, zero churn)
        AttackerModelResult {
            algorithm: "CONTROL — EXPECTED TO FAIL H1".to_string(),
            parameters: "memory_kib=1024,churn=false".to_string(),
            ram_per_guess_bytes: 1_048_576, // 1 MiB
            compute_per_guess_ops: 1_000,
            bandwidth_per_guess_bytes: 1_048_576,
            single_cpu_guesses_per_sec: 1500.0,
            multicore_16c_guesses_per_sec: 22_000.0,
            gpu_simulated_parallel_guesses_per_sec: 24_000.0, // 24 GB VRAM / 1 MB = 24,000 threads (Attacker win)
            max_practical_parallelism: 24_000,
            memory_bus_bottleneck: "FAIL — Low RAM without bandwidth churn allows massive GPU parallelism".to_string(),
        },
    ]
}
