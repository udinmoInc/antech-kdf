# antech-kdf-research

Attackers, CUDA kernels, TMTO/concurrency experiments, cryptanalysis harnesses, and historical compute-memory variants. Depends on production `antech-kdf` / `antech-kdf-core`. Production crates do not depend on this package.

Build from the repository root via the research workspace:

```bash
cargo check --manifest-path research/code/Cargo.toml -p antech-kdf-research
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

See [research/code/README.md](../README.md) and [research/README.md](../../README.md).
