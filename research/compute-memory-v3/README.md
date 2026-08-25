# Compute-memory v3 (research)

Same work bound as v2 (`memory / block_size`), different dependency shapes aimed at multi-core attacker scaling.

| ID | Graph |
|---|---|
| A | Sequential-cut |
| B | Recursive |
| C | Narrow-frontier |

```bash
cargo test -p antech-kdf-research compute_memory_v3
cargo run --release -p antech-kdf-research --example compute_memory_v3_runner
```

Results under `research/results/compute-memory-v3/`. Highlight at 16 MiB (CPU): v3-C ~3.8 / 25.2 / 24.0 g/s at 1/16/32 threads; Argon2id 64 MiB ~10.7 / 24.5 / 22.7 g/s on the same campaign.
