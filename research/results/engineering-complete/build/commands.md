# Build / test commands

```bash
# Production (repo root)
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo check -p antech-kdf
cargo test -p antech-kdf
cargo test -p antech-kdf-core
cargo test -p antech-kdf-format

# Research (separate workspace)
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release
cargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example engineering_complete_runner
```
