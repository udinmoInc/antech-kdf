# GPU Attack — Argon2id vs Antech v4-C @ 16 MiB

## Verdict

**REAL GPU BENCHMARK COMPLETED**

GPU head-to-head: **Argon2id 435.556 g/s > optimized Antech v4-C 32.9552 g/s** on RTX 3050.

Antech vs its own CPU attacker: **GPU ANTECH SLOWER TO ATTACK** (best GPU mode ~32.96 g/s vs CPU ~40.6 g/s @16t).

## Answers

1. Why was Antech initially only ~1% occupancy?
   The baseline kernel launched `1` thread per block and each thread carried a full 16 MiB walk. That produced just `1/96` of the SM thread budget per resident block, yielding measured occupancy `0.0104167`.

2. What optimization produced the largest improvement?
   Fixing launch geometry and moving to `32` threads per block. That raised occupancy from `0.0104` to `0.3333` and throughput from `13.7397` to `32.9552` g/s, a `2.40x` gain.

3. What is the final optimized Antech guesses/sec?
   `32.9552` g/s.

4. What is the final optimized Argon2id guesses/sec?
   `435.556` g/s.

5. What is the final GPU ratio between them?
   Argon2id is `13.22x` faster on GPU than optimized Antech (`435.556 / 32.9552`).

6. Does Antech remain slower to attack after serious GPU optimization?
   Yes. Even after the best Antech GPU tuning pass, it remains slower than its own CPU attacker and far slower than optimized Argon2id on this GPU.

7. Was the original 23.9 g/s result mostly a kernel-quality artifact?
   Largely yes. The worst issue was kernel launch quality. After correcting that, Antech improved materially beyond the earlier `23.9` g/s level, peaking at `32.96` g/s.

8. What GPU bottleneck remains?
   Memory footprint and bandwidth pressure from the per-guess 16 MiB working set. Pushing occupancy further with `128` threads per block increased VRAM pressure and total kernel time, dropping throughput to `21.152` g/s despite nominal occupancy `0.8333`.

## Progression

| Mode | Threads/block | Batch | Occupancy | Guesses/sec | Kernel p50 |
|---|---:|---:|---:|---:|---:|
| baseline | 1 | 64 | 0.0104 | 13.7397 | 4656.38 ms |
| optimized | 32 | 192 | 0.3333 | 32.9552 | 5820.12 ms |
| fully optimized | 128 | 256 | 0.8333 | 21.1520 | 12097.2 ms |

## Direct result

| Metric | Argon2id | Antech v4-C |
|---|---:|---:|
| Actual guesses/sec | 435.556 | 32.9552 |
| Kernel p50 | 220.376 ms | 5820.12 ms |
| VRAM used | 7425 MiB | 4109 MiB |
| Peak sampled GPU util | 100% | 100% |

Argon2 correctness: **10/10** vs `argon2` crate. Antech correctness: **10/50/100 all matched CPU** across baseline, optimized, and fully optimized modes.

