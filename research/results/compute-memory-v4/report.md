# Compute-Memory v4 — Latency-Optimized Narrow Frontier

Goal: bring existing v4 below **100 ms** defender p50 while preserving as much multi-thread attacker resistance as possible (prefer ~20–30 g/s at 16/32 threads). No depth/passes/delay knobs; work bound remains `num_blocks = memory/block_size`.

## What changed (in-place)

- **Removed per-node heap allocations**: `ParentSet` is a stack `[usize; 8]` (was `Vec` every DAG node — dominant cost behind ~288 ms v4-C).
- **Zero-copy parent gathers**: mix reads directly from frontier ring / buffer (no scratch memcpy).
- **Faster frontier + 32-byte block ops**: simplified ring hit test; specialized `state_to_block` / scatter XOR.
- **C locality + dual far-scatter**: far *reads* pulsed (every other / critical); dual far *writes* every node to keep concurrent guesses contending on DRAM without re-bloating sequential latency.
- Prefetch of parent lines on x86_64.

## Design

- **A reduced-critical-path**: light remote every node; heavy remote+scatter every `FRONTIER_WIDTH/16` nodes.
- **B cache-locality**: tile-biased reads; far scatter every node; far gather pulse every frontier width.
- **C combined**: tile-local reads + pulsed far gather + **dual** far scatter every node + critical far gathers + private frontier ring.
- Hot path is allocation-free (stack parents + frontier ring). Digests change only where C’s gather/scatter schedule changed.

## Results summary

### Defender (1-thread @ 16 MiB)

- **v4-a-reduced-critical-path**: p50=71.9 ms, p95=91.7 ms, p99=91.7 ms, DRAM BW≈0.706 GB/s, cycles≈276054214
- **v4-b-cache-locality**: p50=69.2 ms, p95=83.4 ms, p99=83.4 ms, DRAM BW≈0.904 GB/s, cycles≈259894775
- **v4-c-combined-frontier**: p50=96.3 ms, p95=111.5 ms, p99=111.5 ms, DRAM BW≈0.811 GB/s, cycles≈368928687

### Defender (1-thread @ 24 MiB)

- **v4-a-reduced-critical-path**: p50=109.8 ms, p95=121.5 ms, p99=121.5 ms, DRAM BW≈0.694 GB/s, cycles≈412460264
- **v4-b-cache-locality**: p50=98.2 ms, p95=102.8 ms, p99=102.8 ms, DRAM BW≈0.955 GB/s, cycles≈366696011
- **v4-c-combined-frontier**: p50=162.4 ms, p95=166.2 ms, p99=166.2 ms, DRAM BW≈0.722 GB/s, cycles≈596487690

### Defender (1-thread @ 32 MiB)

- **v4-a-reduced-critical-path**: p50=147.3 ms, p95=153.2 ms, p99=153.2 ms, DRAM BW≈0.690 GB/s, cycles≈545968818
- **v4-b-cache-locality**: p50=135.1 ms, p95=144.7 ms, p99=144.7 ms, DRAM BW≈0.925 GB/s, cycles≈505883381
- **v4-c-combined-frontier**: p50=224.8 ms, p95=249.9 ms, p99=249.9 ms, DRAM BW≈0.695 GB/s, cycles≈850905665

### Attacker scaling

#### 16 MiB

| Threads | A g/s | B g/s | C g/s | Argon2id g/s | A eff | B eff | C eff | Argon eff |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 15.02 | 14.69 | 10.16 | 10.35 | 1.000 | 1.000 | 1.000 | 1.000 |
| 2 | 26.91 | 27.00 | 17.16 | 16.13 | 0.896 | 0.919 | 0.845 | 0.779 |
| 4 | 47.70 | 47.72 | 26.76 | 21.00 | 0.794 | 0.812 | 0.659 | 0.507 |
| 8 | 66.13 | 68.13 | 36.08 | 22.69 | 0.551 | 0.580 | 0.444 | 0.274 |
| 16 | 79.32 | 78.34 | 40.56 | 22.94 | 0.330 | 0.333 | 0.250 | 0.139 |
| 32 | 64.41 | 71.67 | 38.27 | 23.66 | 0.134 | 0.152 | 0.118 | 0.071 |

#### 24 MiB

| Threads | A g/s | B g/s | C g/s | Argon2id g/s | A eff | B eff | C eff | Argon eff |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 9.10 | 8.36 | 5.65 | 10.35 | 1.000 | 1.000 | 1.000 | 1.000 |
| 2 | 17.04 | 18.16 | 11.07 | 16.13 | 0.937 | 1.086 | 0.980 | 0.779 |
| 4 | 28.97 | 29.70 | 17.38 | 21.00 | 0.796 | 0.888 | 0.769 | 0.507 |
| 8 | 42.08 | 42.18 | 23.06 | 22.69 | 0.578 | 0.631 | 0.511 | 0.274 |
| 16 | 45.92 | 47.32 | 25.17 | 22.94 | 0.316 | 0.354 | 0.279 | 0.139 |
| 32 | 44.36 | 42.91 | 27.66 | 23.66 | 0.152 | 0.160 | 0.153 | 0.071 |

#### 32 MiB

| Threads | A g/s | B g/s | C g/s | Argon2id g/s | A eff | B eff | C eff | Argon eff |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6.14 | 7.01 | 4.08 | 10.35 | 1.000 | 1.000 | 1.000 | 1.000 |
| 2 | 12.58 | 12.96 | 7.80 | 16.13 | 1.025 | 0.925 | 0.955 | 0.779 |
| 4 | 21.40 | 21.47 | 12.20 | 21.00 | 0.872 | 0.766 | 0.747 | 0.507 |
| 8 | 31.04 | 30.69 | 16.69 | 22.69 | 0.632 | 0.547 | 0.511 | 0.274 |
| 16 | 34.85 | 35.62 | 18.62 | 22.94 | 0.355 | 0.318 | 0.285 | 0.139 |
| 32 | 31.13 | 30.00 | 18.22 | 23.66 | 0.159 | 0.134 | 0.139 | 0.071 |

## Success criteria

| Variant | MiB | p50<100 | 16t≤25 | 32t≤25 | All |
|---|---:|---|---|---|---|
| v4-a-reduced-critical-path | 16 | yes (71.9 ms) | no (79.3) | no (64.4) | no |
| v4-b-cache-locality | 16 | yes (69.2 ms) | no (78.3) | no (71.7) | no |
| v4-c-combined-frontier | 16 | yes (96.3 ms) | no (40.6) | no (38.3) | no |
| v4-a-reduced-critical-path | 24 | no (109.8 ms) | no (45.9) | no (44.4) | no |
| v4-b-cache-locality | 24 | yes (98.2 ms) | no (47.3) | no (42.9) | no |
| v4-c-combined-frontier | 24 | no (162.4 ms) | no (25.2) | no (27.7) | no |
| v4-a-reduced-critical-path | 32 | no (147.3 ms) | no (34.9) | no (31.1) | no |
| v4-b-cache-locality | 32 | no (135.1 ms) | no (35.6) | no (30.0) | no |
| v4-c-combined-frontier | 32 | no (224.8 ms) | yes (18.6) | yes (18.2) | no |

## Bottleneck / verdict

**Primary latency target (<100 ms) is hit on some configs; ≤25 g/s at 16/32 remains hard on the same point.** Best scored tradeoff: **v4-c-combined-frontier @ 16 MiB**.

### Before → after

| Config | Defender p50 | 16t g/s | 32t g/s |
|---|---:|---:|---:|
| v4-C @ 24 MiB (before) | 287.8 ms | 21.2 | 20.3 |
| v4-C @ 24 MiB (after) | 162.4 ms | 25.2 | 27.7 |
| v4-C @ 16 MiB (after) | 96.3 ms | 40.6 | 38.3 |
| v4-A @ 16 MiB (before) | 140.7 ms | 42.5 | 36.1 |
| v4-A @ 16 MiB (after) | 71.9 ms | 79.3 | 64.4 |

**Why latency dropped:** per-node `Vec` parent lists + scratch parent copies dominated the ~288 ms path (~0.5M+ heap alloc/free cycles at 24 MiB). Stack parents + zero-copy gathers removed that. Pulsing far *reads* restored cache locality for the sequential verifier.

**Attacker cost:** implementation speedups raise 1-thread g/s nearly lockstep; dual far-scatter recovers some parallel write contention. Prefer **<100 ms / ~30–45 g/s** over **287 ms / ~20 g/s** per the stated objective. Best latency+resistance among <100 ms points: **v4-C @ 16 MiB (96.3 ms, 40.6 / 38.3 g/s)**. Closest to the 20–30 g/s band without throttling: **v4-C @ 24 MiB (162 ms, 25.2 / 27.7 g/s)** — over the latency budget.

## TMTO

Best-tradeoff variant TMTO @50% memory recomputation factor ≈ **16.45×**.

## GPU

CUDA toolkit detected (`nvcc`); no dedicated v4 GPU kernel shipped in this research pass — mark as available-but-not-run for Antech v4 graph.

## Reference

v3-C @ 16 MiB (prior): defender p50≈247 ms; attacker ≈3.8 / 25.2 / 24.0 g/s at 1/16/32 threads. Work nodes @16 MiB = 524288 (= memory/block_size).

