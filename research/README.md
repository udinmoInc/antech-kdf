# Research

Antech asks whether a password KDF can stay useful at about **16 MiB** of defender memory without collapsing offline attacker cost relative to a conventional Argon2id profile. What shipped in production is the compute-memory **combined-frontier** graph (`AntechEngine` in `antech-kdf-core`, construction version 5, hash format `$antech$v2$`).

**Dependency rule:** production (`crates/`) never imports research. Research may import production for correct digests.

| Area | Path |
|---|---|
| Review package (start here for auditors) | [`security-review/`](security-review/) |
| Narrative chapters | [`docs/`](docs/) |
| Research Rust + CUDA + runners | [`code/`](code/) |
| Current measured / modeled results | [`results/`](results/) |
| Historical early campaigns (not current claims) | [`archive/`](archive/) |

## Current results (use these numbers)

Every public table should cite one campaign and label each figure **MEASURED**, **MODELED**, **BLOCKED**, or **UNKNOWN**. Do not combine rates from different hosts or kernels into a single “best of” claim.

| Campaign | Path | Status |
|---|---|---|
| v5 cost tradeoff (current CombinedFrontier) | [`results/compute-memory-v4/v5-cost-tradeoff/`](results/compute-memory-v4/v5-cost-tradeoff/) | MEASURED |
| CPU/GPU attacker-opt suite (v5, RTX 3050) | [`results/compute-memory-v4/attacker-optimization/`](results/compute-memory-v4/attacker-optimization/) | MEASURED |
| CPU compute–memory v4-C (prior graph) | [`results/compute-memory-v4/`](results/compute-memory-v4/) | MEASURED (superseded graph) |
| Cryptanalysis + TMTO | [`results/cryptanalysis/`](results/cryptanalysis/) | MEASURED / MODELED |
| Correctness | [`results/correctness/`](results/correctness/) | PASS |
| Stress | [`results/stress/`](results/stress/) | PASS |
| Fuzz (fallback harness on Windows; libFuzzer in CI) | [`results/fuzz/`](results/fuzz/) | PASS |
| Reliability matrix | [`results/reliability/`](results/reliability/) | MEASURED |

Snapshot from the **v5** attacker-opt + defender microbench ([`results/compute-memory-v4/v5-cost-tradeoff/report.md`](results/compute-memory-v4/v5-cost-tradeoff/report.md)), **MEASURED**:

| Profile | Memory | Defender p50 | Strongest CPU 16t | Strongest CPU 32t |
|---|---:|---:|---:|---:|
| Antech CombinedFrontier (construction v5) | 16 MiB | 128.9 ms | 52.39 g/s packed_prefetch | 49.93 g/s packed_prefetch |
| Argon2id (same host, same runner) | 64 MiB | — | 21.84 g/s | 21.43 g/s |

GPU head-to-head on **RTX 3050** @ 16 MiB (same attacker-opt run), **MEASURED**:

| | Guesses/sec | Kernel p50 |
|---|---:|---:|
| Antech v5 (best: packed_t32_b256) | 97.69 | 2617 ms |
| Argon2id (same GPU, same session) | 434.87 | 221 ms |

## Build research

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

Historical v2/v3 runners still compile; their outputs belong under `archive/results/`, not under current claims.
