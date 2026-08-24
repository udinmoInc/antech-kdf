# Antech KDF — Phase M Report: Real CUDA GPU Attack Benchmark

## 1. CUDA Hardware Telemetry & Discovery

- **GPU Model**: NVIDIA GeForce RTX 3050
- **VRAM Capacity**: 8.0 GB (8192 MB)
- **NVIDIA Driver Version**: 591.86
- **Supported CUDA Driver API**: 13.1
- **NVCC Toolkit Compiler Available**: false
- **Operating System**: windows
- **Rust Version**: 0.1.0
- **Compiler Profile**: release (opt-level=3, codegen-units=1)

## 2. Correctness Test Harness

| Algorithm Name | Test Vectors Count | Matches Count | Status |
| :--- | :--- | :--- | :--- |
| `Antech Variant K1 (16MB)` | 10 | 10 | **PASS** |
| `Antech Variant K2 (16MB)` | 10 | 10 | **PASS** |
| `Antech Variant K1 (16MB)` | 50 | 50 | **PASS** |
| `Antech Variant K2 (16MB)` | 50 | 50 | **PASS** |
| `Antech Variant K1 (16MB)` | 100 | 100 | **PASS** |
| `Antech Variant K2 (16MB)` | 100 | 100 | **PASS** |

## 3. CUDA Memory & Instance Bounds Analysis

| Algorithm Name | GPU Hardware | Per-Instance VRAM | Max Parallel CUDA Threads | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Argon2id Baseline** | NVIDIA RTX 3050 (8GB) | 64 MB | 125 threads | **UNAVAILABLE (NO NVCC TOOLKIT COMPILER)** |
| **Antech Variant K1** | NVIDIA RTX 3050 (8GB) | 16 MB | 500 threads | **UNAVAILABLE (NO NVCC TOOLKIT COMPILER)** |
| **Antech Variant K2** | NVIDIA RTX 3050 (8GB) | 16 MB | 500 threads | **UNAVAILABLE (NO NVCC TOOLKIT COMPILER)** |

## 4. Measured vs Modeled Audit

- **Measured CPU Results**: Argon2id = **24.2 g/s** | Antech K1 = **19.2 g/s** | Antech K2 = **18.8 g/s** (16-core CPU).

- **Measured CUDA GPU Results**: **UNAVAILABLE**. System PATH check confirmed `nvidia-smi` detected RTX 3050 (8GB, Driver 591.86, CUDA API 13.1), but the NVIDIA CUDA Compiler Toolkit (`nvcc.exe`) is not installed on this Windows build environment.

## 5. Final Verdict

### Final Verdict: **`CUDA UNAVAILABLE`**

In strict compliance with Directive 1 (*'If CUDA cannot actually execute, STOP and report CUDA UNAVAILABLE. Do not fall back to modeled values and call them measured'*), the final verdict for Phase M is **`CUDA UNAVAILABLE`**.

