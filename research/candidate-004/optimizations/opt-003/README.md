# Candidate 004 — Opt-003: Depth & Chain Tuning

**Status: EXPERIMENTAL / NOT PRODUCTION SAFE**

## Overview
Opt-003 tunes dependency chain depth ($D/2 = 100$ steps) to measure latency reduction vs TMTO recomputation penalty.

- **Objective**: Determine whether reducing dependency depth preserves TMTO recomputation penalty.
- **Expected Result**: Latency drops proportionally with depth.
- **Attacker Impact**: TMTO recomputation penalty factor decreases if depth is too low.
