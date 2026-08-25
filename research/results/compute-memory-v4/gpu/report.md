# GPU Attack — Argon2id vs Antech v4-C @ 16 MiB

## Verdict

**REAL GPU BENCHMARK COMPLETED**

GPU head-to-head: **Argon2id 431.557 g/s > Antech v4-C 23.9139 g/s** on RTX 3050.

Antech vs its own CPU attacker: **GPU ANTECH SLOWER TO ATTACK** (GPU ~23.9139 g/s vs CPU ~40.6 g/s @16t).

## Direct result

| Metric | Argon2id | Antech v4-C |
|---|---:|---:|
| Actual guesses/sec | 431.557 | 23.9139 |
| Kernel p50 | 221.396 ms | 10714.2 ms |
| VRAM used | 7383 MiB | 5133 MiB |

Argon2 correctness: **10/10** vs argon2 crate. Antech correctness: **10/10** (prior).

