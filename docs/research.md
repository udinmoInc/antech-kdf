# Research

Notes, datasets, and runners live under [`research/`](../research/README.md). The production crates do not depend on `antech-kdf-research`; that crate imports `antech-kdf-core`.

```bash
cargo run --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run --release -p antech-kdf-research --example v4_gpu_runner
```
