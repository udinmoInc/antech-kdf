# 04 — Evaluation

Figures below are from the **current** v4 campaigns only. Source reports and CSVs sit beside each table. Labels: **MEASURED** unless noted.

## CPU — combined-frontier @ 16 MiB

Source: [`../results/compute-memory-v4/report.md`](../results/compute-memory-v4/report.md) (**MEASURED**).

| Variant | Defender p50 | Attacker 16t | Attacker 32t |
|---|---:|---:|---:|
| C combined-frontier | 96.3 ms | 40.56 g/s | 38.27 g/s |
| Argon2id (64 MiB, same campaign) | — | 22.94 g/s | 23.66 g/s |

TMTO at 50% retained memory for the preferred variant in that campaign was about **16.45×** recomputation (**MEASURED** sweep; see `tmto.csv` in the same folder).

## GPU — RTX 3050 @ 16 MiB

Source: [`../results/compute-memory-v4/gpu/report.md`](../results/compute-memory-v4/gpu/report.md) and `comparison.csv` (**MEASURED**).

| | Guesses/sec | Kernel p50 | Notes |
|---|---:|---:|---|
| Antech v4-C best mode (32 th/block, batch 192) | 32.96 | 5820 ms | Occupancy ~0.33 |
| Argon2id (same GPU) | 435.56 | 220 ms | Digests checked vs `argon2` crate |

On that host, Antech’s best GPU rate stayed below its own multi-thread CPU attacker (~40.6 g/s @ 16 threads). Treat this as an attacker-side measurement, not as a proof that Antech is “more secure than Argon2id.”

## Engineering campaigns (production surfaces)

| Campaign | Verdict | Path |
|---|---|---|
| Correctness | PASS (421 cases; 2 bugs fixed) | [`../results/correctness/`](../results/correctness/) |
| Stress | PASS | [`../results/stress/`](../results/stress/) |
| Fuzz | PASS (632M execs on fallback harness; libFuzzer **BLOCKED** on Windows host, configured in CI) | [`../results/fuzz/`](../results/fuzz/) |

Host admission tests used the production `BoundedResourceScheduler` defaults (128 MiB global ceiling, queue limit 256) so oversized concurrent batches fail closed instead of OOMing the process.

## Cryptanalysis

Separate attacker-only campaigns against production digests: [`../results/cryptanalysis/`](../results/cryptanalysis/). Those reports include additional GPU schedule experiments; **do not** merge their rates with the head-to-head table above.
