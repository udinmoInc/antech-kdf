# Research

Antech explores whether a password KDF can run in roughly 16 MiB of defender memory without collapsing offline attacker cost relative to a conventional Argon2id profile. The construction that landed in production is the compute-memory **combined-frontier** graph, implemented as `AntechEngine` in `antech-kdf-core`.

**Production** (`crates/`) never depends on research. **Research** imports production/core only.

| Area | Path |
|---|---|
| Research Rust + CUDA | [`code/`](code/) |
| Independent review package | [`security-review/`](security-review/) |
| Narrative chapters | [`docs/`](docs/) |
| Datasets | [`data/`](data/) |
| Measured / modeled results | [`results/`](results/) |
| External baselines (e.g. argon2-gpu) | [`third_party/`](third_party/) |

## Build research (separate Cargo workspace)

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

Mark results as `MEASURED`, `MODELED`, or `UNAVAILABLE`. Do not mix them.

GPU head-to-head (RTX 3050, 16 MiB): [results/compute-memory-v4/gpu/report.md](results/compute-memory-v4/gpu/report.md).
