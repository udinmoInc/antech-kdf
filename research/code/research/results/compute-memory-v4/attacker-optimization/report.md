# Antech v4-C attacker optimization

Attacker-only work. Production `hash()` / `verify()` / `needs_rehash()` and v4-C graph mix were not changed. Defender parameters stay 16 MiB CombinedFrontier.

## Summary table

| Attacker | Baseline g/s | Optimized g/s | Improvement |
|---|---:|---:|---:|
| CPU 16T | 39.593 | 43.587 | 1.101× |
| CPU 32T | 35.482 | 43.793 | 1.234× |
| RTX 3050 GPU | 16.678 | 85.980 | 5.155× |

Best CPU packed strategy at 16 threads: `packed_ring`.

## vs Argon2id (same machine, corpus, salt, 1.2 s window, warmup)

| | Antech opt | Argon2id |
|---|---:|---:|
| CPU 16T g/s | 43.587 | 22.669 |
| CPU 32T g/s | 43.793 | 23.244 |
| GPU g/s | 85.980 | 0.000 |

## What limits the attacker

Each guess is a 524288-node CombinedFrontier walk. Parent indices are **state-dependent**, so the DAG cannot be precomputed and independent nodes cannot be reordered inside a guess. Dual far-scatter XOR updates earlier blocks, so a full 16 MiB resident buffer is required for an exact digest (no lossless skip of nodes).

Local parents hit the last 64 blocks; far gathers and scatters are random in `[0, i-64)`. That random traffic dominates. Skipping the frontier ring is valid and often faster (one less 32-byte copy per node).

GPU: one thread owns one 16 MiB walk. Neighboring threads do not share block indices, so global loads do not coalesce. Occupancy is VRAM-bound (~16 MiB × batch). This is mostly **intrinsic to the graph**, not only a kernel bug — kernel packing (u64 words, skip memset) still helps the inner loop.

## Attacker-side reductions tried

| Idea | Result |
|---|---|
| Reuse scratch across guesses | Kept (allocation eliminated). |
| Compress blocks | 32-byte mixed state does not compress usefully. |
| Precompute graph metadata | Impossible: addresses depend on running state. |
| Reorder independent work | No independent nodes inside a guess. |
| Batch passwords | CPU dual lock-step; GPU batch. |
| Skip ring / skip memset | Valid; measured. |
| Avoid materializing nodes | Invalid for exact digest (scatters + far reads). |

## CPU scaling (all strategies)

| Impl | 1T | 8T | 16T | 32T | 16T eff |
|---|---:|---:|---:|---:|---:|
| production_engine | 8.06 | 31.59 | 39.59 | 35.48 | 0.307 |
| packed_ring | 9.11 | 35.24 | 43.59 | 43.79 | 0.299 |
| packed_noring | 9.37 | 35.31 | 42.30 | 45.42 | 0.282 |
| packed_prefetch | 9.50 | 35.60 | 41.58 | 41.86 | 0.273 |
| packed_dual_lockstep | 7.77 | 32.68 | 40.54 | 38.47 | 0.326 |
| argon2id | 9.81 | 23.81 | 22.67 | 23.24 | 0.144 |

## GPU notes

CUDA binary compiled; ptxas log in `ptxas.txt`.

L2 hit rate / SM util from Nsight are recorded as UNAVAILABLE unless nsys/ncu produced counters.

## Answers

1. CPU improvement vs this run's production 16T/32T: 1.101× / 1.234×.

2. GPU improvement vs this run's baseline kernel: 5.155×.

3. Limit: data-dependent far gathers/scatters over 16 MiB, 524288 serial mix steps.

4. ~33 g/s was partly kernel (byte loads, memset, occupancy) and partly intrinsic uncoalesced 16 MiB walks. See GPU table.

5. No digest-preserving shortcut: parent indices are not reusable across passwords; TMTO that drops blocks changes the digest or multiplies compute.

6. Packed attacker parallel efficiency: 16T 0.299, 32T 0.150 (vs 1T).

7. GPU still cannot merge walks across the warp; packing helps arithmetic, not coalescing.


Hardware counters (instructions/IPC/cache misses) require Linux `perf` or Nsight; on this Windows host they are marked UNAVAILABLE unless those tools ran. Cycles/guess use `RDTSC` around each guess.

