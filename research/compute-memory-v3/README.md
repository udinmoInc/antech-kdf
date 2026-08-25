# Compute-Memory v3

Research variants that keep work = `memory/block_size` nodes but change **dependency shape** to reduce multi-core attacker scaling (the v2 failure mode).

## Variants

| ID | Graph | Idea |
|----|-------|------|
| A | Sequential-cut | Epoch checkpoints + far back-edges |
| B | Recursive | Power-of-two / interval parents |
| C | Narrow-frontier | Recent ring + remote gather + scatter write |

## Run

```bash
cargo test -p antech-kdf-research compute_memory_v3
cargo run --release -p antech-kdf-research --example compute_memory_v3_runner
```

Results → `research/results/compute-memory-v3/`.

## Measured highlight (16 MiB, CPU-only)

| | 1t g/s | 16t g/s | 32t g/s | 1t defender p50 |
|--|---:|---:|---:|---:|
| v2 (prior) | ~13 | ~76 | ~69 | ~76 ms |
| **v3-C** | **3.8** | **25.2** | **24.0** | ~247 ms |
| Argon2id 64MiB | 10.7 | 24.5 | 22.7 | ~98 ms |
