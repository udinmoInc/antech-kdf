# Build status (this engineering pass)

| Command | Result |
|---|---|
| `cargo fmt --all` | OK |
| `cargo check --workspace` | OK |
| `cargo check -p antech-kdf --no-default-features` | OK |
| `cargo test -p antech-kdf/core/format/reference` | OK |
| `cargo test --workspace --lib --release` | OK |
| `cargo clippy -p antech-kdf-research --lib` | OK (warnings elsewhere pre-existing) |
| `cargo clippy --workspace --all-targets --all-features` | Fixed research `min_max`; other crates warn-only |
| `cargo doc --workspace --no-deps` | BLOCKED — Windows lock on `target/doc/antech_kdf` |
| `engineering_complete_runner` | OK → `research/results/engineering-complete/` |
