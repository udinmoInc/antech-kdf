# Cryptographic Research Methodology

## Core Hypothesis
Password verification can achieve strong resistance against offline guessing using significantly reduced peak RAM, higher controlled latency, sustained memory bandwidth, and strict sequential dependencies.

## Methodology
1. **Candidate Scaffolding**: Modular research candidate algorithms under `research/candidates/`.
2. **Empirical Benchmarking**: Server latency and peak memory usage measured under concurrency (1 to 1000 threads).
3. **Attacker Modeling**: Estimating spatial memory vs. bandwidth constraints on ASIC/GPU cracking architectures.
