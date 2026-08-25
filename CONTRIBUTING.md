# Contributing

Rust 1.70+.

```bash
git clone https://github.com/udinmoInc/antech-kdf.git
cd antech-kdf
cargo build --workspace
```

Layout:

```text
crates/
├── antech-kdf/           # public API
├── antech-kdf-core/      # AntechEngine + resource scheduler
├── antech-kdf-format/    # v2 encode / parse
├── antech-kdf-types/     # config / errors
├── antech-kdf-cli/       # CLI
├── antech-kdf-ffi/       # C ABI
└── antech-kdf-research/  # attackers, CUDA, old variants
```

Stable logic goes in core/types/format. Experimental attackers and historical engines stay in research. Keep `hash` / `verify` / `needs_rehash` behavior stable unless the change is intentional and documented.

Before a PR:

```bash
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test -p antech-kdf -p antech-kdf-core -p antech-kdf-format
```

For benchmark PRs: record hardware, keep baselines untuned, and label numbers `MEASURED` / `MODELED` / `UNAVAILABLE`.
