# Antech KDF — Cryptography Research Documentation

> **An experimental bandwidth-hard password hashing construction investigating low-RAM key derivation.**

---

## 📖 Research Paper Chapters

* [**Chapter 1: The Problem**](01-problem.md) — Server RAM cost, microservice memory bounds, 16 MB hypothesis.
* [**Chapter 2: Background**](02-background.md) — Memory-hard functions, Argon2id baseline, scrypt, bcrypt, PBKDF2.
* [**Chapter 3: Design**](03-design.md) — Candidate-004 core, Variant K1 (parallelism reduction), Variant K2 (Quad-DAG TMTO).
* [**Chapter 4: Evaluation**](04-evaluation.md) — Comparative measured metrics (16 MB vs 64 MB, 108 ms vs 138 ms, 19.2 g/s vs 24.2 g/s).
* [**Chapter 5: Security**](05-security.md) — Adversarial cost modeling, time-memory trade-offs, multi-target binding, cache behavior.
* [**Chapter 6: Limitations**](06-limitations.md) — Pending CUDA GPU measurements, ASIC/FPGA bounds, third-party audit status.
* [**Chapter 7: Future Work**](07-future-work.md) — Physical CUDA execution roadmap, formal security reductions, hardware synthesis.

---

## 📊 Benchmark Datasets & Reproducibility

* [**Hardware & Environment Telemetry**](data/hardware.md)
* [**Baseline Grid Dataset**](data/baseline.csv)
* [**Attacker Throughput Dataset**](data/attacker.csv)
* [**TMTO Recomputation Sweep Dataset**](data/tmto.csv)

---

## 🔬 How to Run Research Benchmarks

```bash
# Compile and run research benchmark suite, exporting dataset CSVs to research/data/
cargo run --release -p antech-kdf-cli -- benchmark --output research/data
```
