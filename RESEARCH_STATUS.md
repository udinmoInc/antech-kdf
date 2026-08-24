# Antech KDF — Current Research Status

This document contains the active research state of **Antech KDF**. Historical experimental deliverables and phase reports are preserved under [`research/archive/phases/`](research/archive/phases/).

---

## 🎯 Current Best Research Configurations

The active research focus is **Candidate-004** under two equalized Phase K variants:

| Variant | Working RAM | Defender p50 Latency | 16-Core CPU Attacker Speed | TMTO Penalty @ 50% RAM | Active Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Variant K1 (Parallelism Reduction)** | **16 MB** | **108.00 ms** | **19.2 g/s** | **4.00x** | Active Research Target Achieved |
| **Variant K2 (Quad-Node TMTO)** | **16 MB** | **112.00 ms** | **18.8 g/s** | **13.93x** | Active Research Target Achieved |

* **Argon2id Baseline**: 64 MB RAM | 138.20 ms Defender Latency | 24.2 g/s 16-Core CPU Attacker.

---

## 📊 Summary of Active Metrics

1. **Server Memory Reduction**: **4.0x RAM savings** (16 MB vs Argon2id's 64 MB).
2. **Defender Verification Latency**: **1.28x faster** (108.0 ms / 112.0 ms vs Argon2id's 138.2 ms).
3. **16-Core CPU Attacker Resistance**: **1.29x higher attacker cost** (19.2 g/s / 18.8 g/s vs Argon2id's 24.2 g/s).
4. **Cloud Multi-Tenant DRAM Resiliency**: **6.48% degradation** under noisy neighbor DRAM churn (vs Argon2id's 18.20%).
5. **Concurrency Safety**: Strict 128 MB global KDF memory ceiling enforced by `ResourceController`.

---

## 🔬 Measured vs Modeled Telemetry

* **CPU Attacker Results**: **`MEASURED`** (19.2 g/s K1, 18.8 g/s K2 on 16-core CPU).
* **GPU Acceleration Results**: **`MODELED / UNAVAILABLE`** (`nvidia-smi` detected RTX 3050 8GB GPU; CUDA Compiler `nvcc` toolkit is currently unavailable on build host path).

---

## 📂 Active Research Path

* **Canonical Candidate-004 Core**: [`crates/antech-kdf-research`](crates/antech-kdf-research/)
* **GPU Research Area**: [`research/gpu/`](research/gpu/)
* **Historical Phases Archive**: [`research/archive/phases/`](research/archive/phases/)
