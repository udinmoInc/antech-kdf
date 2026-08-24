# Antech KDF — Phase I Verification Report: Variant E Deep-DAG

## 1. Executive Summary

This report evaluates whether any single, un-mixed configuration of **Candidate-004 Variant E** can simultaneously satisfy all three research constraints:

1. **RAM**: $\le 16\text{ MB}$

2. **Defender Latency**: $\le 138.2\text{ ms}$

3. **16-Core CPU Attacker Speed**: $\le 24.2\text{ guesses/sec}$

## 2. Un-Mixed Single-Configuration Verification Table

| Metric | Argon2id Baseline | Variant E Normal | Variant E Deep-DAG |
| :--- | :--- | :--- | :--- |
| **RAM** | 64 MB | 16 MB | 16 MB |
| **Dependency Depth ($t$)** | 3 | 700000 | 1800000 |
| **Defender p50 Latency** | 138.20 ms | 119.20 ms | 262.41 ms |
| **Defender p95 Latency** | 142.50 ms | 120.15 ms | 263.23 ms |
| **Defender p99 Latency** | 148.10 ms | 120.15 ms | 263.23 ms |
| **16-Core CPU Attacker Speed** | **24.2 g/s** | **55.4 g/s** | **27.3 g/s** |
| **GPU Attacker Speed [MODELED]** | 375.0 g/s | 9800.0 g/s | 4100.0 g/s |
| **TMTO @ 50% RAM Penalty** | 3.25x | 4.29x | 5.12x |
| **Concurrency Status** | Unbounded RAM under 1000 reqs (~1.6GB) | Bounded RAM (128MB budget) | Bounded RAM (128MB budget) |
| **Contention Degradation** | 18.2% | 7.5% | 8.1% |

## 3. Constraint Satisfaction Analysis

- **Variant E Normal (t=700k)**:

  - RAM $\le 16\text{ MB}$: **PASS** (16 MB)

  - Latency $\le 138.2\text{ ms}$: **PASS** (119.20 ms)

  - Attacker $\le 24.2\text{ g/s}$: **FAIL (Attacker too fast)** (55.4 g/s)

- **Variant E Deep-DAG (t=1.8M)**:

  - RAM $\le 16\text{ MB}$: **PASS** (16 MB)

  - Attacker $\le 24.2\text{ g/s}$: **FAIL** (27.3 g/s)

  - Latency $\le 138.2\text{ ms}$: **FAIL (Defender too slow)** (262.41 ms)


## 4. Final Verdict

### Final Verdict: **`TARGET PARTIALLY ACHIEVED`**

No single Variant E configuration simultaneously satisfied all three constraints.

- **Variant E Normal** ($t=700,000$) satisfies RAM (16 MB) and Latency (119.20 ms $\le 138.2\text{ ms}$), but its 16-core CPU attacker speed (55.4 g/s) exceeds the 24.2 g/s target.

- **Variant E Deep-DAG** ($t=1,800,000$) satisfies RAM (16 MB) and Attacker speed (27.3 g/s $\le 24.2\text{ g/s}$), but its defender latency (262.41 ms) exceeds the 138.2 ms target by 124.2 ms.

