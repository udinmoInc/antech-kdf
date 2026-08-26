# Contributing

Rust 1.70+.

```bash
git clone https://github.com/udinmoInc/antech-kdf.git
cd antech-kdf
cargo build --workspace
```

Layout:

```text
crates/                 # PRODUCTION only
├── antech-kdf/         # public API
├── antech-kdf-core/    # AntechEngine + resource scheduler
├── antech-kdf-format/  # v2 encode / parse
├── antech-kdf-types/   # config / errors
├── antech-kdf-cli/     # CLI
└── antech-kdf-ffi/     # C ABI

bindings/ + sdk/        # Language SDKs + conformance
fuzz/                   # Production-surface fuzz targets
docs/                   # End-user docs site
research/               # RESEARCH only (separate Cargo workspace)
├── code/               # attackers, CUDA, TMTO, cryptanalysis, reference
├── results/            # current MEASURED / MODELED campaigns
├── security-review/    # independent review package
├── docs/               # narrative chapters
└── archive/            # superseded campaigns (not current claims)
```

Stable logic goes in core/types/format. Experimental attackers and historical engines stay under `research/code/`. Keep `hash` / `verify` / `needs_rehash` behavior stable unless the change is intentional and documented.

Before a PR:

```bash
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Research changes also:

```bash
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
```

For benchmark PRs: record hardware, keep baselines untuned, and label numbers `MEASURED` / `MODELED` / `BLOCKED` / `UNKNOWN`. Cite one campaign per table; do not combine rates across hosts or kernels.
