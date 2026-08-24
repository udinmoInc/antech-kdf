# Antech KDF

> **An experimental bandwidth-hard, low-RAM password hashing research construction designed for resource-constrained servers and microservices.**

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

---

## 🔍 What is Antech KDF?

**Antech KDF** is an open-source cryptography research project investigating low-resource password hashing algorithms. Standard memory-hard functions like **Argon2id** require **64 MB of RAM** per password verification. On small virtual servers (such as a 1GB VPS or containerized microservice), concurrent login bursts can exceed host RAM and trigger Out-Of-Memory (OOM) process termination.

Antech KDF explores candidate constructions designed to operate within a **16 MB memory footprint** per verification while evaluating trade-offs in defender latency, CPU attacker throughput, TMTO recomputation penalties, and DRAM bus contention.

---

## 🚦 Research Status & Implementation State

> [!CAUTION]
> **Research Notice**: Antech KDF is an experimental research project under active cryptanalysis audit. It is **NOT** production-ready, and experimental candidate variants are not connected to the stable public hashing API.

* **Implemented (Stable API)**: The Rust crate [`antech-kdf`](crates/antech-kdf) provides the public interface (`hash`, `verify`, `needs_rehash`).
* **Experimental Core**: Candidate-004 variants (**Variant K1** and **Variant K2**) reside in [`crates/antech-kdf-research`](crates/antech-kdf-research).
* **Current Status Summary**: See [`RESEARCH_STATUS.md`](RESEARCH_STATUS.md) for active research results.

---

## 📊 Measured vs Modeled Terminology

* **`MEASURED`**: Physical benchmarking executed on hardware devices (e.g. 16-core CPU cracking throughput of **19.2 g/s** for Variant K1 and **18.8 g/s** for Variant K2).
* **`MODELED`**: Calculated spatial allocation limits or theoretical memory bounds.

---

## 🎮 Interactive Browser Simulator

An interactive single-file browser simulator comparing Argon2id vs Antech KDF under real-world server workloads is available at [`index.html`](index.html).

---

## 🛠️ Building & Running Benchmarks

### Prerequisites
* Rust 1.70+ (`cargo`)

### Build Workspace

```bash
git clone https://github.com/udinmoInc/antech-kdf.git
cd antech-kdf
cargo build --release
```

### Run CPU Attacker & Research Benchmarks

```bash
# Run Phase K Attacker Throughput Reduction Benchmark
cargo run --release -p antech-kdf-cli -- benchmark --phase-k --output research/archive/phases/phase-k

# Run Fair Argon2id vs Antech Comparison
cargo run --release -p antech-kdf-cli -- benchmark --final-comparison --output research/archive/phases/final-comparison
```

### Run CUDA GPU Benchmark

```bash
# Run CUDA GPU Attacker Benchmark
cargo run --release -p antech-kdf-cli -- benchmark --phase-m --output research/archive/phases/phase-m
```

---

## 📖 Architecture & Documentation

* [`ARCHITECTURE.md`](ARCHITECTURE.md): Component layout and system design.
* [`RESEARCH_STATUS.md`](RESEARCH_STATUS.md): Current active benchmark results.
* [`research/gpu/README.md`](research/gpu/README.md): CUDA GPU attacker specifications and hardware taxonomy.
* [`research/archive/phases/`](research/archive/phases/): Historical Phase A through Phase M research reports and CSV datasets.

---

## 🤝 Contributing

Feedback, cryptanalysis, and contributions are welcome! Please review [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

---

## 📄 License

Licensed under either of:
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
