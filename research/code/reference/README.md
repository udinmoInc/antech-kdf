# Antech KDF — Reference Implementation (Review)

Readable CombinedFrontier implementation matching [`../../security-review/specification.md`](../../security-review/specification.md).

- **Not** production code — production digests come from `crates/antech-kdf-core`
- **Not** optimized
- Prefer this when comparing the specification to concrete computation
- Dev-tests cross-check digests against `AntechEngine`

```bash
cargo test --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release
cargo run  --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release -- derive \
  --password password --salt-hex 73616c745f31365f62797465735f2121 --memory-kib 1024
```
