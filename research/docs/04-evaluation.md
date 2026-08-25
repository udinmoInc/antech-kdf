# 04 — Evaluation

Early CPU comparison on the reference host (`MEASURED`):

| Profile | Memory | Defender p50 | 16-core attacker | TMTO @ 50% RAM |
|---|---:|---:|---:|---:|
| Argon2id | 64 MiB | 138.20 ms | 24.20 g/s | 3.25× |
| Antech K1 | 16 MiB | 108.00 ms | 19.20 g/s | 4.00× |
| Antech K2 | 16 MiB | 112.00 ms | 18.80 g/s | 13.93× |

Raw files: [data/defender.csv](data/defender.csv), [data/attacker.csv](data/attacker.csv), [data/tmto.csv](data/tmto.csv).

v3-C and v4 CPU/GPU campaigns live under `results/`. On an **RTX 3050** at 16 MiB (`MEASURED`):

| | Guesses/sec | Notes |
|---|---:|---|
| Antech v4-C (best GPU mode) | ~32.96 | 32 threads/block, batch 192, occupancy ~0.33 |
| Argon2id (same GPU) | ~435.56 | Correctness checked vs `argon2` crate |

Write-up: [results/compute-memory-v4/gpu/report.md](results/compute-memory-v4/gpu/report.md).

Host admission tests used a 128 MiB global ceiling (`BoundedResourceScheduler`) so large concurrent batches fail closed instead of OOMing the process.
