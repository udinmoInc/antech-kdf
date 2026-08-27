# 04 — Evaluation

Figures below are from the **current** construction (**v5** CombinedFrontier) unless a row is labeled as the prior v4-C campaign. Source reports and CSVs sit beside each table. Labels: **MEASURED** unless noted.

## CPU — combined-frontier @ 16 MiB

Source: [`../results/compute-memory-v4/v5-cost-tradeoff/report.md`](../results/compute-memory-v4/v5-cost-tradeoff/report.md) and `attacker-optimization/` (**MEASURED**).

| Variant | Defender p50 | Strongest attacker 16t | Strongest attacker 32t |
|---|---:|---:|---:|
| v5 CombinedFrontier (packed_prefetch) | 128.9 ms | 52.39 g/s | 49.93 g/s |
| Argon2id (64 MiB, same attacker-opt run) | — | 21.84 g/s | 21.43 g/s |
| v4-C CombinedFrontier (prior campaign, production engine table) | 96.3 ms | 40.56 g/s | 38.27 g/s |

v4-C’s *packed* attacker was higher (~74 / 70.5 g/s). Do not mix that row with the v5 packed numbers.

## GPU — RTX 3050 @ 16 MiB

Source: [`../results/compute-memory-v4/attacker-optimization/gpu-profile.csv`](../results/compute-memory-v4/attacker-optimization/gpu-profile.csv) (**MEASURED**, v5 kernel).

| | Guesses/sec | Kernel p50 | Notes |
|---|---:|---:|---|
| Antech v5 best (`packed_t32_b256`) | 97.69 | 2617 ms | Occupancy ~0.33, 5137 MiB |
| Argon2id (same GPU, same session) | 434.87 | 221 ms | |

Prior v4-C GPU report (`gpu/report.md`) used a different kernel generation; cite v5 `gpu-profile.csv` for the current construction.

## Engineering campaigns (production surfaces)

| Campaign | Verdict | Path |
|---|---|---|
| Correctness | PASS (421 cases; 2 bugs fixed) | [`../results/correctness/`](../results/correctness/) |
| Stress | PASS | [`../results/stress/`](../results/stress/) |
| Fuzz | PASS (632M execs on fallback harness; libFuzzer **BLOCKED** on Windows host, configured in CI) | [`../results/fuzz/`](../results/fuzz/) |

Host admission tests used the production `BoundedResourceScheduler` defaults (128 MiB global ceiling, queue limit 256) so oversized concurrent batches fail closed instead of OOMing the process.

## Cryptanalysis

Separate attacker-only campaigns against production digests: [`../results/cryptanalysis/`](../results/cryptanalysis/). Those reports include additional GPU schedule experiments; **do not** merge their rates with the head-to-head table above.
