# Antech KDF

Antech KDF is an experimental key derivation function research project investigating whether password hashing can be made significantly more memory-efficient for small servers without sacrificing resistance to offline password-guessing attacks.

## Why

Standard memory-hard password functions like Argon2id generally require **64 MB of working memory** per verification attempt to provide robust security against GPU and ASIC cracking. On small virtual private servers (such as entry-level 1 GB VPS instances) or containerized microservices, concurrent authentication bursts can quickly saturate available host RAM. Under heavy load, memory exhaustion triggers Out-Of-Memory (OOM) kernel process termination, causing authentication outages.

Simply reducing memory allocations in conventional KDFs proportionally lowers the cost for offline password attackers. Antech investigates whether candidate constructions operating within a **16 MB memory footprint**—achieving a **4x server memory reduction**—can maintain offline attacker costs comparable to or higher than standard 64 MB Argon2id configurations.

## Current Research

The project currently evaluates two experimental variants of Candidate-004:

* **Variant K1 (Parallelism Reduction)**: Incorporates candidate-dependent dynamic state feedback into the ARX mixing step to induce SIMD vector divergence and warp execution stalls across parallel password guessing threads.
* **Variant K2 (Quad-Node TMTO Graph)**: Implements a 4-way directed acyclic memory graph reading 4 pseudo-random blocks per step, enforcing a steep $O((N/M)^4)$ recomputation penalty against low-memory attackers.

## Results

The table below summarizes measured defender verification latencies and 16-core CPU offline cracking throughput from reference benchmarks:

| Algorithm / Variant | Memory Footprint | Defender p50 Latency | 16-Core CPU Attacker Speed | Metric Classification |
| :--- | :---: | :---: | :---: | :--- |
| **Argon2id Baseline** | 64 MB | 138.2 ms | 24.2 guesses/sec | **MEASURED** |
| **Antech Variant K1** | 16 MB | 108.0 ms | 19.2 guesses/sec | **MEASURED** |
| **Antech Variant K2** | 16 MB | 112.0 ms | 18.8 guesses/sec | **MEASURED** |

*Note: Measured CPU throughput numbers reflect offline password-guessing performance on a reference 16-core x86 host; they do not by themselves establish overall security equivalence across all hardware architectures.*

## Security Status

This project is an **experimental research construction** under active evaluation.

* **Not for production use**: The experimental candidate variants are not connected to the stable public API and should not be used for production password storage.
* **Unmeasured GPU Execution**: GPU spatial memory bounds have been modeled, but physical CUDA execution throughput remains unmeasured due to host build environment limits.
* **Cryptographic Audit Required**: The construction has not undergone independent third-party peer review or formal security reductions.

## Research

Detailed technical design, adversarial cost analysis, time-memory trade-off bounds, and methodology documentation are available under [Research and Evaluation](./research/).

## Build

Building the project workspace requires Rust 1.70 or newer:

```bash
git clone https://github.com/udinmoInc/antech-kdf.git
cd antech-kdf
cargo build --release
```

## Benchmarks

To execute the research benchmark suite and export dataset CSV files to `research/data/`:

```bash
cargo run --release -p antech-kdf-cli -- benchmark --output research/data
```

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license ([LICENSE-MIT](LICENSE-MIT)).
