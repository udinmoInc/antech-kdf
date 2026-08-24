# Research and Evaluation

Antech KDF explores whether password derivation can be made more resource-efficient for small authentication servers without giving up meaningful resistance to offline password-guessing attacks.

The research examines working memory allocations, defender verification latency, concurrent authentication scalability, time-memory trade-offs (TMTO), and attacker performance across multicore CPU and parallel GPU execution environments.

Results are compared with established password KDFs, primarily **Argon2id**, using reproducible benchmark configurations. The research strictly separates measured physical execution results from modeled theoretical estimates and records known engineering limitations explicitly.

---

## 📖 Research Chapters

* [**Chapter 1: The Problem**](01-problem.md) — Server RAM cost, microservice memory bounds, 16 MB hypothesis.
* [**Chapter 2: Background**](02-background.md) — Memory-hard functions, Argon2id baseline, scrypt, bcrypt, PBKDF2.
* [**Chapter 3: Design**](03-design.md) — Candidate-004 core, Variant K1 (parallelism reduction), Variant K2 (Quad-DAG TMTO).
* [**Chapter 4: Evaluation**](04-evaluation.md) — Measured comparative metrics (16 MB vs 64 MB, 108 ms vs 138 ms, 19.2 g/s vs 24.2 g/s).
* [**Chapter 5: Security**](05-security.md) — Adversarial cost modeling, time-memory trade-offs, multi-target binding, cache behavior.
* [**Chapter 6: Limitations**](06-limitations.md) — Pending CUDA GPU measurements, ASIC bounds, third-party audit status.
* [**Chapter 7: Future Work**](07-future-work.md) — Physical CUDA execution roadmap, formal security reductions, hardware synthesis.

---

## 🛠️ Candidate Specifications & Methodology

* [**Candidate Variant K1 Specification**](candidates/k1.md) — Dynamic S-box state feedback.
* [**Candidate Variant K2 Specification**](candidates/k2.md) — Quad-node TMTO graph topology.
* [**Benchmark Methodology & Rules**](benchmark-methodology.md) — Measurement methodology, warmup, and fairness rules.

---

## 📊 Datasets & Telemetry

* [**Hardware & Reproducibility Telemetry**](data/hardware.md)
* [**Baseline Grid Dataset**](data/baseline.csv)
* [**Defender Latency Dataset**](data/defender.csv)
* [**Attacker Throughput Dataset**](data/attacker.csv)
* [**TMTO Recomputation Sweep Dataset**](data/tmto.csv)

---

## 🔬 Running Research Benchmarks

```bash
# Execute research benchmark suite and export dataset CSVs to research/data/
cargo run --release -p antech-kdf-cli -- benchmark --output research/data
```
