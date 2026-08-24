# Candidate 004 — Opt-002: u64 Vectorized ARX Churn

**Status: EXPERIMENTAL / NOT PRODUCTION SAFE**

## Overview
Opt-002 replaces 64-byte block SHA-256 updates with u64x4 ARX (Addition-Rotation-XOR) churn updates.

- **Objective**: Reduce CPU cycle consumption while maintaining high-frequency memory bus traffic.
- **Expected Result**: Defender latency decreases significantly (~8–10 ms).
- **Attacker Impact**: Attacker speedup is bounded by DRAM memory bus bandwidth.
