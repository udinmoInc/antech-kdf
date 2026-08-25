# CPU-Only Head-to-Head: Antech Compute-Memory v2 vs Argon2id

**Mode:** CPU only — no CUDA / GPU metrics.

## Configurations (unchanged)

- **Antech v2:** 16 MiB working set, block_size=32, fan_in=2 (no depth/passes)
- **Argon2id baseline:** m_cost=65536 KiB (64 MiB), t_cost=2, p_cost=1
- **Corpus:** 256 shared password candidates, shared salt `cpu_h2h_shared_salt`
- **Workers:** identical thread counts {1,2,4,8,16,32} and `std::thread` pool for both

## Comparison table

| Threads | Algorithm | RAM (MiB) | p50 (ms) | p95 (ms) | p99 (ms) | CPU cycles/op | Attacker g/s | Scaling |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | antech-compute-memory-v2 | 16 | 75.52 | 85.94 | 85.94 | 2.82e8 | 13.040 | 1.000 |
| 1 | argon2id | 64 | 97.71 | 123.40 | 123.40 | 3.69e8 | 10.698 | 1.000 |
| 2 | antech-compute-memory-v2 | 16 | 78.15 | 86.58 | 86.84 | 2.92e8 | 23.992 | 0.920 |
| 2 | argon2id | 64 | 120.31 | 135.91 | 137.46 | 4.51e8 | 15.577 | 0.728 |
| 4 | antech-compute-memory-v2 | 16 | 86.31 | 103.98 | 112.63 | 3.32e8 | 45.082 | 0.864 |
| 4 | argon2id | 64 | 184.98 | 219.44 | 228.50 | 6.85e8 | 20.743 | 0.485 |
| 8 | antech-compute-memory-v2 | 16 | 119.36 | 134.08 | 140.23 | 4.41e8 | 68.330 | 0.655 |
| 8 | argon2id | 64 | 350.77 | 380.41 | 388.65 | 1.28e9 | 22.793 | 0.266 |
| 16 | antech-compute-memory-v2 | 16 | 203.73 | 278.33 | 345.31 | 7.20e8 | 76.068 | 0.365 |
| 16 | argon2id | 64 | 710.24 | 816.64 | 829.20 | 2.51e9 | 20.416 | 0.119 |
| 32 | antech-compute-memory-v2 | 16 | 354.54 | 497.88 | 525.40 | 1.27e9 | 69.072 | 0.166 |
| 32 | argon2id | 64 | 1292.53 | 1530.08 | 1559.80 | 4.55e9 | 21.961 | 0.064 |

### Defender scaling

| Threads | Argon2id p50 | Antech v2 p50 | Argon2id RAM | Antech RAM |
|---:|---:|---:|---:|---:|
| 1 | 97.71 ms | 75.52 ms | 64 MiB | 16 MiB |
| 2 | 120.31 ms | 78.15 ms | 64 MiB | 16 MiB |
| 4 | 184.98 ms | 86.31 ms | 64 MiB | 16 MiB |
| 8 | 350.77 ms | 119.36 ms | 64 MiB | 16 MiB |
| 16 | 710.24 ms | 203.73 ms | 64 MiB | 16 MiB |
| 32 | 1292.53 ms | 354.54 ms | 64 MiB | 16 MiB |

### Attacker scaling

| Threads | Argon2id g/s | Antech v2 g/s | Antech/Argon ratio |
|---:|---:|---:|---:|
| 1 | 10.698 | 13.040 | 1.219 |
| 2 | 15.577 | 23.992 | 1.540 |
| 4 | 20.743 | 45.082 | 2.173 |
| 8 | 22.793 | 68.330 | 2.998 |
| 16 | 20.416 | 76.068 | 3.726 |
| 32 | 21.961 | 69.072 | 3.145 |

### Attacker speedup vs 1-thread baseline

| Threads | Argon2id speedup | Antech v2 speedup | Argon2id eff. | Antech eff. |
|---:|---:|---:|---:|---:|
| 1 | 1.00× | 1.00× | 1.000 | 1.000 |
| 2 | 1.46× | 1.84× | 0.728 | 0.920 |
| 4 | 1.94× | 3.46× | 0.485 | 0.864 |
| 8 | 2.13× | 5.24× | 0.266 | 0.655 |
| 16 | 1.91× | 5.83× | 0.119 | 0.365 |
| 32 | 2.05× | 5.30× | 0.064 | 0.166 |

## Answers

1. **Which uses less RAM?** Antech v2 (16 MiB working set) vs Argon2id (64 MiB).

2. **Which is faster for legitimate verification (1-thread p50)?** Antech v2 (75.52 ms vs 97.71 ms).

3. **Which scales better 1→32 (attacker efficiency)?** Antech v2 (eff 0.166 vs 0.064).

4. **Harder for optimized CPU attacker at 1 thread?** Argon2id (lower attacker g/s) (13.040 vs 10.698 g/s).

5. **Harder at 16 threads?** Argon2id (lower attacker g/s) (76.068 vs 20.416 g/s).

6. **Harder at 32 threads?** Argon2id (lower attacker g/s) (69.072 vs 21.961 g/s).

7. **Does Antech v2 maintain its CPU-cost advantage with all threads?** Antech is not harder at 1 or 32 threads under this baseline (1-thread harder for Antech: false; 32-thread harder for Antech: false).

8. **Does the graph-based design remain expensive without a huge depth loop?** Yes — work is `num_blocks = memory/block_size` (524288); 1-thread defender p50 ≈ 75.5 ms with no `dependency_depth` / `passes` knobs.

## Notes

- CPU cycles/op from `RDTSC` deltas (wall-clock turbo effects apply).
- Peak RSS is process peak working set sampled during the attacker window.
- Argon2id: `argon2` crate release build; Antech: optimized research engine release build.
- No GPU / CUDA results are included in this report.
