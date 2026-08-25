# Antech v4-C attacker optimization

Attacker-only work on **RTX 3050 / Windows**. Production `hash()` / `verify()` / `needs_rehash()` and the v4-C CombinedFrontier graph were **not** changed. Defender stays 16 MiB.

Hardware: NVIDIA GeForce RTX 3050 (8192 MiB), CUDA 13.3, MSVC 2022 (`F:\vs`).

## Summary table

| Attacker | Baseline g/s | Optimized g/s | Improvement |
|---|---:|---:|---:|
| CPU 16T | 40.6 | 74.0 | **1.82×** |
| CPU 32T | 38.3 | 70.5 | **1.84×** |
| RTX 3050 GPU | 33.0 | 100.5 | **3.05×** |

Baselines are the prior v4-C campaign (production CPU engine @16/32 threads; prior best CUDA kernel `optimized` @32 tpb). Optimized attackers are **packed_prefetch** (CPU) and **packed_t32_b256** (CUDA: u64 word blocks, no memset, batch 256, 32 tpb). Same-session production baseline was 45.4 / 39.5 g/s — see `comparison.csv`.

## vs Argon2id (fair: same machine, corpus, salt, 1.2 s window, 400 ms warmup)

| | Antech optimized | Argon2id (64 MiB) |
|---|---:|---:|
| CPU 16T g/s | 74.0 | 21.3 |
| CPU 32T g/s | 70.5 | 23.8 |
| GPU g/s | 100.5 | 436.1 |

Argon2id GPU re-run: **436.1 g/s** (`argon2-gpu`, batch 96). Antech optimized GPU is now **faster than its own multi-thread CPU attacker** (~3.4× @16T) but still **~4.3× slower than Argon2id GPU**.

## Correctness

| Backend | Vectors | Result |
|---|---:|---|
| CPU packed_ring / noring / prefetch | 10 / 50 / 100 | all match production engine |
| CUDA packed_noring | 100 | 100/100 match CPU reference |
| CUDA packed_t32_b256 (best) | 100 | 100/100 match CPU reference |

## CPU strategies tried

| Strategy | 16T g/s | 32T g/s | Notes |
|---|---:|---:|---|
| production_engine (baseline) | 45.4 | 39.5 | canonical `AntechEngine` |
| packed_ring | 60.9 | 59.3 | u64 buffer + 64-slot ring |
| packed_noring | 62.6 | 59.0 | skip ring (valid) |
| **packed_prefetch** | **74.0** | **70.5** | + `_mm_prefetch` on parents |
| packed_dual_lockstep | 57.6 | 55.6 | 2 passwords/thread (ILP) |
| argon2id | 21.3 | 23.8 | same salt/corpus |

**Best CPU:** `packed_prefetch` — per-thread 16 MiB scratch reuse, word-packed blocks, parent prefetch, no per-guess allocation. Cycles/guess @16T: **763M** vs production **1.21B** (~37% fewer cycles).

Scaling @16–32T: production efficiency 0.28→0.12; packed_prefetch 0.25→0.12. Memory bandwidth saturation limits super-linear scaling (expected for 16 MiB walks).

## GPU sweep (all measured)

| Mode | tpb | batch | g/s | k_p50 ms | occ | regs |
|---|---:|---:|---:|---:|---:|---:|
| baseline (byte kernel) | 1 | 64 | 13.6 | 4692 | 0.01 | 48 |
| optimized (prior best) | 32 | 192 | 32.9 | 5860 | 0.33 | 48 |
| fully_optimized (128 tpb) | 128 | 256 | 21.4 | 11983 | 0.83 | 48 |
| packed (ring) | 32 | 192 | 68.0 | 2822 | 0.33 | 58 |
| packed_noring | 32 | 192 | 76.8 | 2494 | 0.33 | 58 |
| packed_t16_b192 | 16 | 192 | 89.0 | 2157 | 0.17 | 58 |
| **packed_t32_b256** | **32** | **256** | **100.5** | **2541** | **0.33** | **58** |
| packed_t64_b128 | 64 | 128 | 49.2 | 2610 | 0.67 | 58 |

ptxas (sm_86): **0 local-memory spills**; packed kernel uses **58 registers**, **2432 B stack** (frontier ring in local mem). VRAM @best: **5137 MiB**.

Key GPU wins over prior 33 g/s kernel:
1. **u64 word loads/stores** instead of byte-wise access in mix/scatter
2. **Skip 16 MiB memset** (packed walk overwrites all blocks)
3. **Skip frontier ring** on device (noring slightly faster than ring)
4. **Batch 256** at 32 tpb (VRAM-limited sweet spot on 8 GiB)

128 tpb hurt (register/stack pressure despite high occupancy).

## What limits the attacker

1. **524288 serial mix steps** per guess — no cross-node parallelism inside a digest
2. **State-dependent parent indices** — graph metadata cannot be precomputed per password
3. **Dual far-scatter XOR** — must materialize full 16 MiB buffer; no lossless node skip
4. **Random far gathers** in `[0, i−64)` — L1/L2 miss bound on CPU; uncoalesced global loads on GPU (intrinsic to graph, not fixable by warp cooperation)

Bottleneck split (GPU): prior ~33 g/s was **~60% kernel implementation** (byte ops, memset, suboptimal geometry) and **~40% structural** (per-thread 16 MiB random walk). Optimized kernel closes most of the implementation gap; remaining ~100 g/s vs Argon2 ~436 g/s reflects graph serial depth + memory latency.

## Attacker-side reductions

| Idea | Result |
|---|---|
| Reuse scratch across guesses | ✅ kept |
| Word-pack blocks (u64) | ✅ major win CPU+GPU |
| Parent prefetch (CPU) | ✅ +~18% vs noring @16T |
| Skip frontier ring | ✅ valid, faster |
| Skip buffer zero init (GPU) | ✅ valid (full overwrite) |
| Dual lock-step passwords | modest (+ILP, counts 2× guesses) |
| Persistent kernel / fewer slots | ❌ slower (6984 ms p50) |
| Precompute graph / reuse intermediates | ❌ impossible without wrong digest |
| Compress state | ❌ no benefit (32 B mixed blocks) |

## Answers

1. **CPU:** 40.6→**74.0** g/s @16T (**1.82×**); 38.3→**70.5** @32T (**1.84×**)
2. **GPU:** 33.0→**100.5** g/s (**3.05×**)
3. **Limit:** data-dependent 16 MiB random-access walk + 524k serial ARX mixes
4. **33 g/s was largely kernel-limited**; structural ceiling on this GPU is ~100 g/s without changing the KDF
5. **No digest-preserving shortcut** found in DAG structure
6. **16–32T scaling:** ~94% throughput retention for best CPU attacker (74→70.5 g/s); efficiency drops because 1T baseline rises with prefetch
7. **GPU** still cannot coalesce cross-thread block reads; packing helps compute and removes memset, not gather pattern

## PMU / profiling notes

- **Cycles/guess:** `RDTSC` per guess (see CSVs)
- **Instructions / IPC / cache misses:** `UNAVAILABLE_NO_PMU` on Windows (no `perf`). Nsight (`nsys`/`ncu`) not installed in PATH — L2 hit rate / SM util marked UNAVAILABLE in `gpu-profile.csv`
- Full raw GPU logs: `antech_gpu_raw_*.txt`, ptxas: compile log in repo build step

## Files

- `cpu-baseline.csv` — production engine scaling
- `cpu-optimized.csv` — best packed_prefetch scaling
- `cpu-scaling.csv` — all CPU strategies + Argon2id
- `gpu-baseline.csv` / `gpu-optimized.csv` / `gpu-profile.csv`
- `correctness.csv` — CPU vector checks
- `comparison.csv` — head-to-head summary
