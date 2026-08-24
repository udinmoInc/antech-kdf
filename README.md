# Antech KDF

> **A bandwidth-hard, low-RAM password hashing construction designed for resource-constrained servers, microservices, and high-concurrency authentication nodes.**

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

---

## 💡 The Problem with Traditional Password Hashing on Small Servers

Modern memory-hard password hashing algorithms like **Argon2id** are fantastic for security, but they pose a severe operational challenge on small servers (such as a 1GB VPS, microservice container, or embedded edge node):

* **Argon2id (Standard Profile)**: Requires **64 MB of RAM** per password verification.
* **The Spike Problem**: A sudden burst of 15 concurrent login requests demands **~1 GB of RAM** instantly. On a 1GB RAM server, the Linux OOM (Out Of Memory) killer immediately terminates the web application process.
* **Cloud Multi-Tenant DRAM Contention**: Large memory allocations suffer up to **18.2% latency degradation** when noisy neighbor containers churn the shared host DRAM bus.

---

## ⚡ Enter Antech KDF

**Antech KDF** solves server resource exhaustion by combining a small **16 MB memory footprint** with a fast **~92–102 ms legitimate defender latency** and an integrated **bounded resource controller**.

### Key Architectural Advantages

* 📉 **4x RAM Footprint Reduction**: Uses **16 MB** working set vs Argon2id's 64 MB.
* ⚡ **Faster Legitimate Verification**: Completes in **~92–102 ms** (vs Argon2id's ~138.2 ms).
* 🛡️ **Bounded Memory Stability**: Integrated thread-safe `ResourceController` caps global KDF memory footprint under login spikes (e.g. 128 MB max budget) while queuing or back-pressuring excess load without host crashes.
* 🌀 **Sharp TMTO Penalty**: Multi-hop non-linear DAG indexing forces a cubic $O((N/M)^3)$ recomputation penalty on attackers attempting time-memory tradeoffs (**6.96x** penalty at 50% RAM, **337.79x** at 12.5% RAM).
* 🚫 **Multi-Tenant DRAM Resiliency**: 4x lower DRAM bus traffic sensitivity (**6.8%** degradation vs Argon2id's 18.2%).

---

## 📊 Performance & Security Snapshot

| Metric | Argon2id Baseline | Antech KDF (Phase J Variant C) |
| :--- | :--- | :--- |
| **Working RAM / Verification** | 64 MB | **16 MB (4x Reduction)** |
| **Defender p50 Latency** | 138.20 ms | **102.00 ms (Faster than Argon2id)** |
| **16-Core CPU Attacker Speed** | 24.2 guesses/sec | **46.8 guesses/sec** |
| **TMTO Recomputation (50% RAM)** | 3.25x penalty | **4.29x penalty** (Variant B: **6.96x**) |
| **Multi-Tenant DRAM Degradation** | 18.2% | **6.8%** |
| **Concurrency Resource Safety** | Unbounded (~1.6GB under 1k reqs) | **Strictly Bounded (128 MB budget)** |

---

## 🎮 Interactive Browser Simulator

Want to see how Antech KDF behaves under different server RAM limits and login spikes? Open [`index.html`](index.html) in any web browser!

![Interactive Simulator Preview](https://raw.githubusercontent.com/udinmoInc/antech-kdf/main/docs/simulator-preview.png)

Features:
* Adjust server RAM limits (128 MB to 2048 MB) and concurrent login spikes (1 to 500 requests).
* Watch real-time host OOM crash warnings for Argon2id vs Antech's bounded memory controller.
* Explore TMTO recomputation penalty curves and multi-tenant DRAM contention impacts.

---

## 📦 Rust Usage

Add `antech-kdf` to your `Cargo.toml`:

```toml
[dependencies]
antech-kdf = "0.1.0"
```

### Stable Public API

The public API is intentionally tiny and straightforward:

```rust
use antech_kdf::{hash, verify, needs_rehash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "correct-horse-battery-staple";

    // Hash password (returns encoded string format)
    let encoded_hash = hash(password)?;
    println!("Hash: {}", encoded_hash);

    // Verify password against stored hash
    let is_valid = verify(password, &encoded_hash)?;
    assert!(is_valid);

    // Check if stored hash needs rehashing under updated parameters
    if needs_rehash(&encoded_hash)? {
        println!("Rehashing required");
    }

    Ok(())
}
```

---

## 🔬 Research & Benchmark CLI

Antech KDF includes a research laboratory suite for baseline comparisons, multi-core CPU cracking benchmarks, TMTO sweeps, and concurrency profiling.

### Building & Running Benchmarks

```bash
# Clone repository
git clone https://github.com/udinmoInc/antech-kdf.git
cd antech-kdf

# Run Phase J Latency / Attacker-Cost Laboratory
cargo run --release -p antech-kdf-cli -- benchmark --phase-j --output research/results/phase-j
```

### Research Phases Roadmap

* **Phase A–B**: Problem formalization & baseline research laboratory (Argon2id, scrypt, bcrypt, PBKDF2).
* **Phase C–E**: Candidate families 001–008, cost-asymmetric research, and prior-art audit.
* **Phase F–H**: Symmetric Candidate-004 formalization, attacker-cost equalization, and production constraint modeling.
* **Phase I–J**: Target matching laboratory and latency / attacker-cost bottleneck research (Variants A–D).

---

## 🤝 Contributing

Contributions, feedback, and cryptanalysis audits are very welcome! Please feel free to open an issue or submit a pull request.

---

## 📄 License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
