# Early CPU summary (K1 / K2)

| Metric | Argon2id | Antech K1 | Antech K2 | Class |
|---|---:|---:|---:|---|
| Memory | 64 MiB | 16 MiB | 16 MiB | MEASURED |
| Defender p50 | 138.20 ms | ~109–113 ms | ~109–112 ms | MEASURED |
| 16-core attacker | 24.20 g/s | 19.20 g/s | 18.80 g/s | MEASURED |
| TMTO @ 50% RAM | 3.25× | 4.00× | 13.93× | MEASURED |

GPU for that campaign was not run. Production is combined-frontier / v4-C; see [../results/compute-memory-v4/gpu/report.md](../results/compute-memory-v4/gpu/report.md) for RTX 3050 numbers (~33 g/s Antech vs ~436 g/s Argon2id).
