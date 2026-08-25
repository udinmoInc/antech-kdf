# Compute-memory v4 results

Goal of this pass: get defender p50 under ~100 ms while keeping multi-thread attacker rates from exploding. Work bound stays `memory / block_size`. Combined-frontier (C) is what production uses.

Implementation notes that mattered: stack `ParentSet`, zero-copy parent gathers, simpler frontier hits, pulsed far reads with dual far scatter on C.

## Defender (1-thread)

| Variant | 16 MiB p50 | 24 MiB p50 | 32 MiB p50 |
|---|---:|---:|---:|
| A reduced-critical-path | 71.9 ms | 109.8 ms | 147.3 ms |
| B cache-locality | 69.2 ms | 98.2 ms | 135.1 ms |
| C combined-frontier | 96.3 ms | 162.4 ms | 224.8 ms |

## Attacker @ 16 MiB (g/s)

| Threads | A | B | C | Argon2id |
|---:|---:|---:|---:|---:|
| 1 | 15.02 | 14.69 | 10.16 | 10.35 |
| 4 | 47.70 | 47.72 | 26.76 | 21.00 |
| 16 | 79.32 | 78.34 | 40.56 | 22.94 |
| 32 | 64.41 | 71.67 | 38.27 | 23.66 |

Full 24/32 MiB tables and efficiency columns are in the CSV exports beside this file. Before the allocation cleanup, v4-C @ 24 MiB was ~288 ms / ~21 g/s @16t; after, ~162 ms / ~25 g/s. Best <100 ms tradeoff here: **C @ 16 MiB** (96.3 ms, ~40.6 / 38.3 g/s at 16/32t). TMTO @ 50% for the preferred variant ≈ 16.45×.

GPU for this CPU campaign was not run here; later RTX 3050 numbers are in [gpu/report.md](gpu/report.md).
