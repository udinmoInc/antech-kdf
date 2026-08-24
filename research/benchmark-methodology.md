# Benchmark Methodology & Fairness Rules

This document specifies the benchmarking rules, hardware recording requirements, warmup procedures, and statistical definitions used across all **Antech KDF** evaluations.

---

## 📏 Measurement Methodology

### 1. Hardware & Environment Recording
Every benchmark run records host hardware telemetry (CPU model, physical core count, logical thread count, system RAM, OS, compiler flags, GPU model, driver version). Environment metrics are stored in [`data/hardware.md`](data/hardware.md).

### 2. Warmup & Iteration Counts
* **Warmup**: Each benchmark executes 3 un-timed warmup iterations to ensure instruction caches, branch predictors, and memory buffers are fully initialized.
* **Timed Iterations**: Metrics represent median (p50), 95th percentile (p95), and 99th percentile (p99) timing across multiple executions.

### 3. Multicore Attacker Measurement Rules
Attacker cracking throughput ($g/s$) is measured using a dedicated multi-worker SIMD password-guessing binary. Worker threads (1, 4, 16, 32 threads) evaluate candidate password strings against real, un-cached 16-byte salt buffers.

---

## ⚖️ Fairness Rules

1. **Identical Baseline Parameters**: Baseline algorithms (Argon2id, scrypt, bcrypt, PBKDF2) are compiled with identical compiler profile flags (`release, opt-level=3`).
2. **No Selective Parameter Tuning**: Baselines use standard recommended production configurations (e.g. Argon2id `64MB, t=1, p=4`).
3. **Strict Data Classification**:
   * **`MEASURED`**: Physical kernel execution on active hardware.
   * **`MODELED`**: Theoretical spatial allocation bounds (e.g. VRAM / instance size).
   * **`UNAVAILABLE`**: Unexecuted benchmarks due to missing host toolchains.
