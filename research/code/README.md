# Research code

All research Rust lives here. Production crates under `crates/` never depend on this tree.

```text
research/code/
├── antech-kdf-research/   # attackers, CUDA, TMTO, cryptanalysis, engineering runners
│   └── src/
│       ├── compute_memory_v4/   # thin aliases + CPU/GPU attackers around core
│       ├── compute_memory/      # shared bench helpers (Argon2 H2H, optional CUDA probe)
│       ├── cryptanalysis/       # attack catalog vs production digests
│       ├── engineering/         # correctness / stress / side-channel / ASIC models
│       └── candidates/          # research trait glue + early K1/K2 experiments
└── reference/             # independent readable reference (review package)
```

Canonical KDF: `crates/antech-kdf-core` (`AntechEngine`).  
`compute_memory_v4::V4Engine` delegates to core — it is not a second implementation.  
Historical v2/v3 engines: `research/archive/code/`.

## Build (separate workspace)

From the repository root:

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example compute_memory_v4_runner
```

Dependency direction: `antech-kdf-research` → `antech-kdf` / `antech-kdf-core` (never the reverse).

Current results: `research/results/compute-memory-v4/`, `research/results/cryptanalysis/`.
