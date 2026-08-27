# antech-kdf-research

Attackers, CUDA kernels, TMTO/concurrency experiments, cryptanalysis harnesses, and engineering runners. Depends on production `antech-kdf` / `antech-kdf-core`. Production crates do not depend on this package.

`compute_memory_v4::V4Engine` is a thin research alias that **delegates** to `AntechEngine`. Packed/CUDA attackers may re-layout the same graph for throughput measurement; they must match core digests.

Build from the repository root via the research workspace:

```bash
cargo check --manifest-path research/code/Cargo.toml -p antech-kdf-research
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

See [research/code/README.md](../README.md) and [research/README.md](../../README.md).
