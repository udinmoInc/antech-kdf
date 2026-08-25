# Compute-memory v2 (research)

Work is `memory_bytes / block_size` nodes. No exposed dependency-depth or pass count.

Defaults: 16 MiB, 32 B blocks, fan-in 2 → 524 288 nodes. Frozen KAT (1 MiB, fan-in 2, password `antech-kat-password`, salt `antech-kat-salt!`):

`d2675d5422a98993886e9014728bcf4d72f8d587ffb57131321851c19d09ba63`

```bash
cargo test --manifest-path research/code/Cargo.toml -p antech-kdf-research compute_memory
cargo run  --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_runner
```
