# Candidate 004 — Opt-004: Bandwidth-Preserving Latency Tuning

**Status: EXPERIMENTAL / NOT PRODUCTION SAFE**

## Overview
Opt-004 combines vectorized ARX churn, zero-copy mutation, and tuned depth (120 steps) to achieve an optimal ~8–10 ms defender latency while preserving $>1.5\text{ GB/s}$ DRAM memory bus traffic.

- **Objective**: Asymmetric defender optimization (Defender CPU $\downarrow$, Attacker cost preserved).
- **Status**: **ACCEPTED**.
