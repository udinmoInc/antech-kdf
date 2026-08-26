# Research

Antech asks whether a password KDF can stay useful at about **16 MiB** of defender memory without collapsing offline attacker cost relative to a conventional Argon2id profile. What shipped in production is the compute-memory **combined-frontier** graph (`AntechEngine` in `antech-kdf-core`, construction version 4, hash format `$antech$v2$`).

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
| CPU compute–memory v4-C | [`results/compute-memory-v4/`](results/compute-memory-v4/) | MEASURED |
| GPU head-to-head (RTX 3050, 16 MiB) | [`results/compute-memory-v4/gpu/`](results/compute-memory-v4/gpu/) | MEASURED |
| Cryptanalysis + TMTO | [`results/cryptanalysis/`](results/cryptanalysis/) | MEASURED / MODELED |
| Correctness | [`results/correctness/`](results/correctness/) | PASS |
| Stress | [`results/stress/`](results/stress/) | PASS |
| Fuzz (fallback harness on Windows; libFuzzer in CI) | [`results/fuzz/`](results/fuzz/) | PASS |
| Reliability matrix | [`results/reliability/`](results/reliability/) | MEASURED |

Snapshot from the **v4-C** CPU campaign ([`results/compute-memory-v4/report.md`](results/compute-memory-v4/report.md)), **MEASURED**:

| Profile | Memory | Defender p50 | Attacker 16t | Attacker 32t |
|---|---:|---:|---:|---:|
| Antech combined-frontier (C) | 16 MiB | 96.3 ms | 40.56 g/s | 38.27 g/s |
| Argon2id (same host campaign) | 64 MiB | — | 22.94 g/s | 23.66 g/s |

GPU head-to-head on **RTX 3050** @ 16 MiB ([`results/compute-memory-v4/gpu/report.md`](results/compute-memory-v4/gpu/report.md)), **MEASURED**:

| | Guesses/sec | Kernel p50 |
|---|---:|---:|
| Antech v4-C (best mode: 32 threads/block, batch 192) | 32.96 | 5820 ms |
| Argon2id (same GPU) | 435.56 | 220 ms |

## Build research

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

Historical v2/v3 runners still compile; their outputs belong under `archive/results/`, not under current claims.
