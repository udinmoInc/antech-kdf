# Candidate 001 — Family A: Low-Capacity Memory Churn

**Status: EXPERIMENTAL / NOT PRODUCTION SAFE**

## Overview
Candidate 001 tests whether repeatedly churning a small memory working set (4–32 MiB) can produce sustained DRAM memory bus pressure without consuming large peak RAM allocations.

- **Hypothesis**: High-frequency memory churn over a compact buffer forces memory bus traffic while maintaining low peak RAM overhead.
- **Threat Model**: Attacker attempts parallel GPU/ASIC cracking by storing many candidate states in VRAM.
- **Defender RAM Target**: 4 MiB to 32 MiB.
- **Known Risks**: Working sets $\le 16$ MiB may fit entirely in CPU L3 cache and fail to generate DRAM bus traffic.
