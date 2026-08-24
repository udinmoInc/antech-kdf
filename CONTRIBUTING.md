# Contributing to Antech KDF

Thank you for your interest in contributing to Antech KDF!

## Guidelines

1. **Keep Public API Tiny**: The main `antech-kdf` crate must only expose `hash()`, `verify()`, and `needs_rehash()`. Do not expose internal parameter structs in the public API.
2. **Research Isolation**: Experimental algorithms must live under `research/candidates/` or feature flags. Never tag experimental code as production-ready.
3. **Coding Standards**:
   - Run `cargo fmt` and `cargo clippy --workspace` before submitting PRs.
   - All code must pass unit, integration, and fuzz tests (`cargo test --workspace`).
   - Sensitive memory buffers must be zeroized (`zeroize` crate).
4. **Pull Request Process**:
   - Ensure clear commit messages.
   - Update documentation under `docs/` or `research/` when introducing architecture or candidate changes.
