# Research code

All research Rust lives here. Production crates under `crates/` never depend on this tree.

```text
research/code/
├── antech-kdf-research/   # attackers, CUDA, TMTO, cryptanalysis, engineering runners
│   └── src/
│       ├── compute_memory_v4/   # current construction wrappers + GPU/CPU attackers
│       ├── cryptanalysis/       # attack catalog vs production digests
│       ├── engineering/         # correctness / stress / side-channel / ASIC models
│       ├── compute_memory/      # historical v2 (archive outputs)
│       ├── compute_memory_v3/   # historical v3 (archive outputs)
│       └── candidates/          # research trait glue + early K1/K2
└── reference/             # independent readable reference (review package)
```

## Build (separate workspace)

From the repository root:

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
```

Dependency direction: `antech-kdf-research` → `antech-kdf` / `antech-kdf-core` (never the reverse).

Current results: `research/results/compute-memory-v4/`, `research/results/cryptanalysis/`. Historical runners write under `research/archive/results/`.
