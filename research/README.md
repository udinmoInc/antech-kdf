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
| v5 asymmetry / cost tradeoff (current CombinedFrontier) | [`results/compute-memory-v4/v5-asymm/`](results/compute-memory-v4/v5-asymm/) · [`v5-cost-tradeoff/`](results/compute-memory-v4/v5-cost-tradeoff/) | MEASURED |
| CPU/GPU attacker-opt suite (construction v5, RTX 3050) | [`results/compute-memory-v4/attacker-optimization/`](results/compute-memory-v4/attacker-optimization/) | MEASURED |
| Cryptanalysis + TMTO | [`results/cryptanalysis/`](results/cryptanalysis/) | MEASURED / MODELED |
| Correctness | [`results/correctness/`](results/correctness/) | PASS |
| Stress | [`results/stress/`](results/stress/) | PASS |
| Fuzz (fallback harness on Windows; libFuzzer in CI) | [`results/fuzz/`](results/fuzz/) | PASS |
| Reliability matrix | [`results/reliability/`](results/reliability/) | MEASURED |

Snapshot from the **current v5** ship (dual-global + cold far; [`results/compute-memory-v4/v5-asymm/report.md`](results/compute-memory-v4/v5-asymm/report.md)), **MEASURED**:

| Profile | Memory | Defender p50 | Strongest CPU 16t | Strongest CPU 32t |
|---|---:|---:|---:|---:|
| Antech CombinedFrontier (construction v5) | 16 MiB | ~131 ms | ~43.1 g/s packed_prefetch | ~44.4 g/s packed_prefetch |
| Argon2id (same host, same runner) | 64 MiB | — | ~23.0 g/s | ~25.3 g/s |

GPU head-to-head on **RTX 3050** @ 16 MiB (same attacker-opt run), **MEASURED**:

| | Guesses/sec | Kernel p50 |
|---|---:|---:|
| Antech v5 (best: packed_t32_b256) | ~74.9 | ~3413 ms |
| Argon2id (same GPU, same session) | ~434.7 | ~221 ms |

The **20–30 g/s** CPU target under defender p50 ≤ 140 ms was **not reached** under honest work; see the tradeoff reports for the measured boundary.

## Build research

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

Historical v2/v3 engines and spent screens are under [`archive/code/`](archive/code/). Their outputs belong under `archive/results/`, not under current claims.
