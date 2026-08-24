# Antech KDF — GPU Research & CUDA Attack Benchmarks

This directory contains the canonical CUDA GPU candidate verification attacker, kernel implementations, correctness test harness, and performance benchmark records for **Antech KDF**.

---

## 🔍 Data Classification Terminology

To maintain strict scientific and cryptographic rigor, GPU benchmarks are strictly classified into three categories:

1. **`MEASURED`**: Physical kernel execution on an active GPU hardware device (e.g. running compiled CUDA kernels via `nvcc` and counting completed candidate password evaluations).
2. **`MODELED`**: Calculated spatial memory allocation limits and theoretical bounds (e.g. VRAM capacity divided by per-instance working set size).
3. **`SIMULATED`**: Synthetic warp divergence or memory stall emulation on CPU test harnesses.

> [!IMPORTANT]
> Modeled spatial bounds must **NEVER** be reported as measured cracking throughput ($g/s$).

---

## 📁 Directory Structure

* **`cuda/`**: CUDA compiler build scripts and host-device bridge bindings.
* **`kernels/`**: Raw `.cu` CUDA kernels for candidate password derivation.
* **`attacker/`**: High-performance multi-candidate GPU cracking framework.
* **`correctness/`**: Test harness verifying CPU reference derivation vs GPU kernel output across deterministic test vectors.
* **`benchmarks/`**: Measured GPU throughput, latency, occupancy, and memory traffic records.
