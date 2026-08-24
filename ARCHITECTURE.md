# Antech KDF — Architecture Overview

This document describes the layered architectural design of **Antech KDF**, from the stable production public API down to the core cryptographic primitives, research construction, adversarial attack frameworks, and benchmark suites.

---

## 🏗️ Layered System Architecture

```text
stable API (crates/antech-kdf)
    │
    ▼
core primitives (crates/antech-kdf-core & antech-kdf-format)
    │
    ▼
research Candidate-004 (crates/antech-kdf-research)
    ├── Variant K1 (variant_k1.rs)
    └── Variant K2 (variant_k2.rs)
    │
    ├──► CPU attacker (cpu_attacker.rs)
    │
    ├──► GPU attacker (research/gpu/ & gpu_attacker.rs)
    │
    └──► Benchmarks & Allocation Controller (resource_controller.rs, tmto.rs)
```

---

## 📦 Component Descriptions

### 1. Stable Public API (`crates/antech-kdf`)
Exposes the minimal, stable Rust password hashing API. The public API signature is strictly preserved and never changed:
- `hash(password: &str) -> Result<String, Error>`
- `verify(password: &str, stored_hash: &str) -> Result<bool, Error>`
- `needs_rehash(stored_hash: &str) -> Result<bool, Error>`

### 2. Core & Format Layer (`crates/antech-kdf-core`, `antech-kdf-types`, `antech-kdf-format`)
- Handles parameter validation, memory buffer allocations, and standard `$antech$v1$...` hash string serialization and parsing.

### 3. Research Candidate-004 (`crates/antech-kdf-research`)
The single canonical research construction testing low-resource, bandwidth-hard password hashing at **16 MB RAM**:
- **`Candidate004`**: The canonical Candidate-004 symmetric research KDF core.
- **`variant_k1`**: Attacker Parallelism Reduction with candidate-dependent dynamic S-box feedback (cripples multi-candidate SIMD/AVX vectorization).
- **`variant_k2`**: Quad-Node Directed Acyclic Graph enforcing a sharp $O((N/M)^4)$ TMTO recomputation penalty (**13.93x** at 50% RAM).

### 4. CPU Attacker Framework (`cpu_attacker.rs`)
Multi-worker Rayon thread pool (1 to 32 workers) evaluating candidate passwords against real salts to measure real-world CPU cracking speeds (Target: 18.0–20.0 g/s).

### 5. GPU Attacker Framework (`research/gpu/`)
CUDA candidate verification kernel launcher testing SIMT warp divergence and memory pipeline stall limits across 24GB/8GB VRAM allocations.

### 6. Bounded Resource Controller & Benchmarks (`resource_controller.rs`, `tmto.rs`)
Thread-safe admission controller maintaining a strict 128 MB global KDF memory ceiling during high-concurrency login spikes.
