# Changelog

## [0.1.0]

- Public API: `hash`, `hash_with_config`, `verify`, `needs_rehash`, `needs_rehash_with_policy`
- Canonical engine: combined-frontier compute-memory (`AntechEngine` in `antech-kdf-core`)
- Hash format `$antech$v2$...`; legacy `v1` rejected
- Crates: `antech-kdf`, `antech-kdf-core`, `antech-kdf-format`, `antech-kdf-types`, `antech-kdf-cli`, `antech-kdf-ffi`
- C ABI via `antech-kdf-ffi`
- Research attackers, CUDA, and historical variants under `research/code/` (separate Cargo workspace)
