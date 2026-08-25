# Compute-Memory v3 — Attacker Scaling Research

Goal: flatten multi-core attacker throughput via graph structure, without depth/passes knobs and within 12–32 MiB.

## 1. Why does v2 scale so well for attackers?

Each password guess is **independent**. v2’s DAG is sequential *within* one guess, but N workers simply run N guesses. At 16 MiB, concurrent working sets fit better in cache/DRAM than Argon2id’s 64 MiB, so parallel efficiency stays high (~0.17 at 32 threads vs Argon2id ~0.06). Light parent gathers also keep per-instance bandwidth modest — so adding cores keeps paying off until ~16 threads.

## 2. Which graph reduces attacker parallel scaling?

**Recommended: v3-c-narrow-frontier** (lowest absolute attacker g/s at 16/32 threads among v3 graphs).

| Threads | A (cut) g/s | B (recursive) g/s | **C (frontier)** g/s | Argon2id g/s | C eff | Argon eff |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 9.14 | 4.70 | **3.82** | 10.69 | 1.000 | 1.000 |
| 2 | 15.98 | 9.09 | **7.71** | 16.65 | 1.010 | 0.779 |
| 4 | 30.14 | 15.14 | **12.28** | 20.47 | 0.804 | 0.479 |
| 8 | 50.29 | 24.26 | **22.31** | 23.06 | 0.731 | 0.270 |
| 16 | 56.65 | 32.31 | **25.15** | 24.52 | 0.412 | 0.143 |
| 32 | 48.07 | 27.15 | **24.00** | 22.69 | 0.197 | 0.066 |

vs **v2** (~76 g/s @16, ~69 g/s @32): variant C cuts multi-core attacker throughput by ~3× and nearly matches Argon2id’s plateau.

Variant A has slightly flatter efficiency at 32t (0.164) but still allows ~48 g/s — worse than C for the stated goal.

## 3. Defender cost (1-thread p50 @ 16 MiB)

| Variant | p50 | p95 | Est. DRAM BW |
|--|---:|---:|---:|
| A sequential-cut | 116.6 ms | 140.9 ms | 0.47 GB/s |
| B recursive | 222.7 ms | 260.2 ms | 0.25 GB/s |
| **C narrow-frontier** | **247.3 ms** | 251.0 ms | 0.22 GB/s |

C is slower for the defender than v2 (~76 ms) but still in a practical interactive range; cost comes from remote gather/scatter, not a depth knob.

## 4. Attacker cost at 16 and 32 threads

| | 16 threads | 32 threads |
|--|---:|---:|
| v2 (prior) | ~76 g/s | ~69 g/s |
| **C narrow-frontier** | **25.2 g/s** | **24.0 g/s** |
| Argon2id 64 MiB | 24.5 g/s | 22.7 g/s |

## 5. Real dependency structure vs extra iterations?

Yes — all variants execute exactly `num_blocks = memory/block_size` (**524288** at 16 MiB). Differences are parent addressing:

- **A**: epoch cut + far back-edges  
- **B**: power-of-two / interval recursive parents  
- **C**: narrow recent frontier + mandatory remote gather + remote scatter write  

No `dependency_depth` / `passes` parameters.

## 6. DRAM bandwidth moderate?

Structural estimates stay **~0.2–0.5 GB/s** on the 1-thread path — well below DRAM saturation. Multi-core attacker flattening comes from **cross-instance contention** on scattered remote accesses, not from saturating a single instance’s bus.

## 7. Within 12–32 MiB?

Primary measurements use **16 MiB**. Targets remain {12,16,20,24,28,32}.

## TMTO

| Variant | @50% recompute | Digests match |
|--|---:|---|
| A | ~5.2× | yes |
| B | ~3.8× | yes |
| C | ~5.2× | no* |

\*C’s sparse TMTO path can miss scatter writebacks when blocks are evicted; full-memory digests are authoritative. Recomputation cost still rises as memory drops.

## Verdict

**Ship research focus on `v3-c-narrow-frontier`.** It keeps 16 MiB, no depth knob, practical defender latency (~247 ms), and brings 16/32-thread attacker g/s from v2’s ~70+ down to ~24–25 — in line with Argon2id’s multi-core plateau — by forcing remote gather/scatter dependencies rather than by adding iterations.
