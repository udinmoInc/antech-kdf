# CPU head-to-head: compute-memory v2 vs Argon2id

CPU only. Antech v2 at 16 MiB / 32 B / fan-in 2; Argon2id at 64 MiB, t=2, p=1. Shared 256-candidate corpus and salt `cpu_h2h_shared_salt`; same thread grid `{1,2,4,8,16,32}`.

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

## Takeaway

Antech uses less RAM and is a bit faster for single-thread verify (~76 ms vs ~98 ms). Multi-core attackers scale better against Antech here (~76 g/s @16t vs Argon2id ~20 g/s), which is why later work changed the graph (v3/v4). Work is still `memory/block_size` nodes with no depth knob. Cycles from `RDTSC`; no GPU in this file.
