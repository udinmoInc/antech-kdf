# GPU: Argon2id vs Antech v4-C @ 16 MiB (RTX 3050)

Measured head-to-head. Best Antech mode: **~32.96 g/s**. Argon2id: **~435.56 g/s** (~13.2× faster on this GPU). Antech’s best GPU rate was still below its own multi-thread CPU attacker (~40.6 g/s @ 16 threads on the campaign host).

| Mode | Threads/block | Batch | Occupancy | g/s | Kernel p50 |
|---|---:|---:|---:|---:|---:|
| baseline | 1 | 64 | 0.0104 | 13.74 | 4656 ms |
| optimized | 32 | 192 | 0.3333 | 32.96 | 5820 ms |
| fully optimized | 128 | 256 | 0.8333 | 21.15 | 12097 ms |

| | Argon2id | Antech (optimized) |
|---|---:|---:|
| g/s | 435.56 | 32.96 |
| Kernel p50 | 220 ms | 5820 ms |
| VRAM | ~7425 MiB | ~4109 MiB |

Baseline launch used one thread per block (occupancy ~1%). Moving to 32 threads/block was the large win. Pushing to 128 threads raised occupancy but hurt throughput under the 16 MiB-per-guess footprint.

Argon2 digests matched the `argon2` crate (10/10). Antech digests matched CPU for 10/50/100 vectors across all three modes. CSVs and raw logs sit beside this file.
