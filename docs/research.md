# Research notes (public docs index)

Notes, datasets, and runners live under [`research/`](../research/README.md). The production crates do not depend on research; research imports `antech-kdf-core`.

```bash
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example v4_gpu_runner
```
