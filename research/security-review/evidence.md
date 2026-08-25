# Existing Evidence — Antech KDF Cryptanalysis

Labels: **MEASURED** (instrumented run), **MODELED** (extrapolation / lower bound), **UNKNOWN** (not established).

Absence of a found attack is **not** a security proof.

Source campaigns (attacker-only; production KDF unchanged):

- `research/results/cryptanalysis/` (DAG / schedule / GPU)
- `research/results/cryptanalysis/tmto-advanced/` (reduced-memory TMTO)

---

## Canonical target (these experiments)

| Item | Value | Label |
|---|---|---|
| Engine | Production `AntechEngine` | MEASURED |
| Graph | CombinedFrontier (`g=3`) | MEASURED |
| Memory | 16 MiB default (also 1 MiB probes) | MEASURED |
| Nodes @ 16 MiB | 524288 | MEASURED |

---

## Full-evaluation cost (16 MiB)

| Metric | Value | Label |
|---|---|---|
| Mix pairs (approx.) | ~1.17e6 | MEASURED |
| Parent gathers | ~1.95e6 | MEASURED |
| Scatters | ~1.05e6 | MEASURED |
| Unique parents touched | ~all prior blocks | MEASURED |
| 1-thread reference-ish GPS | ~9.6 g/s (campaign machine) | MEASURED |

---

## DAG / algebraic shortcuts

| Claim | Result | Label |
|---|---|---|
| Skip nodes / DAG reduction with correct digest | **Not found**; skip prototypes **INCORRECT** | MEASURED |
| BFS gather+scatter reachability from last node | ~100% nodes on 1 MiB probe | MEASURED |
| Algebraic / linear shortcut in `MixPair` | **Not found** | MEASURED |
| Partial-state parent prediction | ~0.01% exact parent-set matches | MEASURED |
| Cross-guess DAG reuse | **None** (seed binds password+salt) | MEASURED |

---

## Strongest *correct cheaper* CPU attack (schedule only)

| Attack | Result | Label |
|---|---|---|
| `packed_prefetch` full DAG | Correct digests; wall-clock ≈ **0.51×** vs byte-buffer full walk @ 16 MiB / 1 thread | MEASURED |
| Cryptographic node / mix count | **Unchanged** (implementation win only) | MEASURED |
| 32-thread packed_prefetch | ~63 g/s on campaign host | MEASURED |

---

## GPU (RTX 3050-class)

| Mode | Result | Label |
|---|---|---|
| `packed_t32_b256` full-memory batch | ~**100.5 g/s**, digests verified vs CPU | MEASURED |
| Per-guess DAG work | Still full node walk | MEASURED |
| Reduced-VRAM TMTO kernel beating full VRAM | **Not demonstrated** | MEASURED / UNKNOWN |

---

## TMTO / reduced memory

| Claim | Result | Label |
|---|---|---|
| Naive reduced-memory / eviction TMTO | **INCORRECT** (dual scatter) | MEASURED |
| Early scatter-log prototypes | **INCORRECT** | MEASURED |
| Compact scatter index size @ 16 MiB | ~**4 MiB** (2×N×4 B) | MODELED |
| Full scatter-state log @ 16 MiB | ~**36 MiB** | MODELED |
| Sparse checkpoint ≤75% memory | Aborts at recompute budget (~1e6 node-steps); no correct cheap finish | MEASURED |
| Probe lower bound @ 16 MiB / 50% window | Order **10³–10⁴×** miss-based estimate | MODELED |
| Correct attack with both lower peak RAM and better cost than full_packed | **Not found** in campaign | MEASURED |

---

## Multi-target

| Claim | Result | Label |
|---|---|---|
| Shared cryptographic DAG across passwords | **No** | MEASURED |
| Buffer/layout reuse only | Yes (non-crypto) | MEASURED |

---

## Concurrency / FFI / parser

| Area | Result | Label |
|---|---|---|
| Cross-guess CPU scaling | Improves with threads until bandwidth/contention | MEASURED |
| Encoded hash parse / verify round-trip | Covered by production tests | MEASURED |
| Exhaustive FFI / language-binding audit | **Not** a substitute for cryptanalysis | UNKNOWN |

---

## What evidence does *not* show

- ASIC/FPGA dollar cost.
- That no TMTO exists outside tested strategies.
- That GPU kernels cannot improve further.
- Side-channel resistance of all deployments.
- Long-term confidence under future cryptanalysis.
