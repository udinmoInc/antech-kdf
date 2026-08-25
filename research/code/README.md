# Research code

All research Rust lives here. Production crates under `crates/` never depend on this tree.

```text
research/code/
├── antech-kdf-research/   # attackers, CUDA, TMTO, cryptanalysis, benchmarks, stress, …
├── reference/             # independent readable reference (not production)
├── attackers/             # → antech-kdf-research/src/attackers (+ engineering CPU attackers)
├── cuda/                  # → antech-kdf-research/src/compute_memory*/cuda
├── tmto/                  # → antech-kdf-research/src/tmto + cryptanalysis/tmto_advanced
├── cryptanalysis/         # → antech-kdf-research/src/cryptanalysis
├── benchmarks/            # → antech-kdf-research/src/benchmarks + examples/*_runner.rs
├── stress/                # → engineering/stress + examples/reliability_runner.rs
├── side-channel/          # → engineering/side_channel
└── asic-fpga/             # → engineering/asic_fpga
```

## Build (separate workspace)

From the **repository root**:

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

Dependency direction: `antech-kdf-research` → `antech-kdf` / `antech-kdf-core` (never the reverse).
