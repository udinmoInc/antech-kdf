# Cross-language conformance

Canonical vectors: [`vectors.json`](vectors.json) (derived from `research/security-review/test-vectors.json`).

Every SDK must:

1. `hash_with_config_and_salt(password, salt, config)` → encoded `$antech$v2$…`
2. Extract the digest (last `$` field, hex) and match `digest_hex`
3. `verify(password, encoded)` → true
4. Reject malformed hashes with the shared error mapping

## Runners

```bash
# Rust (workspace)
cargo test -p antech-kdf conformance -- --nocapture

# FFI + Python (after build-native)
./sdk/scripts/build-native.sh   # or .ps1
python sdk/conformance/run_python.py
```

CI job `sdk` runs Rust + Python conformance on Linux/Windows/macOS where toolchains allow.
