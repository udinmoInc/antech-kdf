# Antech KDF Research & Candidate Directory

This directory contains research candidate specifications, baseline comparisons, threat models, attacker efficiency models, and empirical benchmarking results for the Antech KDF project.

## Research Hypothesis

Investigate whether password verification can achieve strong resistance against offline password guessing using significantly reduced peak RAM, higher controlled latency, sustained memory bandwidth, and strict sequential dependency constraints.

## Directory Structure

- **`baselines/`**: Established password KDF implementations and benchmark baselines:
  - `argon2id/`
  - `scrypt/`
- **`candidates/`**: Antech KDF research candidates:
  - `candidate-001/`: Low-RAM bandwidth churn candidate (Draft/Experimental).
  - `candidate-002/`: Sequential dependency graph candidate (Draft).
  - `candidate-003/`: Dynamic memory access candidate (Draft).
- **`experiments/`**: Micro-benchmarks, cache access profiling, and churn scripts.
- **`attacker/`**: Attacker cost models (CPU, GPU, ASIC, FPGA throughput simulations).
- **`models/`**: Analytical mathematical memory-time-bandwidth tradeoff models.
- **`results/`**: Empirical measurement logs and memory profiling data.

## Candidate Lifecycle Statuses

- **`DRAFT`**: Conceptual design under drafting.
- **`EXPERIMENTAL`**: Initial implementation created; active analysis ongoing.
- **`FAILED`**: Failed initial safety, throughput, or memory ratio targets.
- **`SURVIVED_INITIAL_TESTS`**: Passed early sanity checks; undergoing deep analysis.
- **`UNDER_ANALYSIS`**: Cryptographic and side-channel review in progress.
- **`REJECTED`**: Proven insecure or vulnerable to shortcuts.
