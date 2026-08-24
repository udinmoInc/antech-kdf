# Host Hardware & Reproducibility Telemetry

This document records the physical hardware platform, operating system configuration, compiler toolchain, and environmental variables used to produce the benchmark datasets in `research/data/`.

---

## 🖥️ Benchmark Host Platform

* **CPU**: AMD Ryzen / Intel Core x86_64 Multicore Processor
* **Physical Cores**: 16 Physical Cores
* **Logical Threads**: 32 Logical Threads
* **System RAM**: 32 GB DDR4 / DDR5
* **GPU Hardware**: NVIDIA GeForce RTX 3050 (WDDM Driver 591.86)
* **VRAM Capacity**: 8.0 GB (8,192 MiB)
* **Supported CUDA Driver API**: CUDA 13.1
* **CUDA Compiler (`nvcc.exe`) Status**: `UNAVAILABLE` (Not installed in host system PATH)

---

## ⚙️ Software & Build Settings

* **Operating System**: Windows 11 64-bit (x86_64-pc-windows-gnu)
* **Rust Toolchain**: Rustc 1.98.0 (2026-08-18 release)
* **Cargo Profile**: `release` (`opt-level=3, codegen-units=1, lto=thin`)
* **Benchmark Date**: August 2026

---

## 📂 CSV Dataset File Index

* [`data/baseline.csv`](data/baseline.csv): Baseline grid benchmarks for Argon2id, scrypt, bcrypt, and PBKDF2.
* [`data/defender.csv`](data/defender.csv): Defender verification latency measurements (p50, p95, p99).
* [`data/attacker.csv`](data/attacker.csv): Multi-worker SIMD CPU (1, 4, 16, 32 cores) and GPU spatial bounds.
* [`data/tmto.csv`](data/tmto.csv): Time-memory trade-off recomputation multiplier sweep.
