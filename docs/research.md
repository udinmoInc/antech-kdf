# Research documentation

Detailed research write-ups, datasets, and historical candidate notes live under [`research/`](../research/README.md).

Production libraries do **not** depend on research crates. Research tooling imports `antech-kdf-core` only.

```bash
cargo run --release -p antech-kdf-research --example compute_memory_v4_runner
```
