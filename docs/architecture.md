# Antech KDF — Architecture

Production crates form a strict dependency stack. Research never feeds production.

```text
antech-kdf          public API (hash / verify / needs_rehash)
    ↓
antech-kdf-core     AntechEngine + resource scheduler
    ↓
antech-kdf-format   v2 encode / parse
antech-kdf-types    config, GraphKind, errors, rehash policy

antech-kdf-research → antech-kdf-core   (attackers, CUDA, benchmarks)
```

## Crates

| Crate | Role |
|---|---|
| `antech-kdf` | Stable developer API |
| `antech-kdf-core` | Canonical compute-memory engine |
| `antech-kdf-format` | `$antech$v2$...` encoding |
| `antech-kdf-types` | Configuration and error types |
| `antech-kdf-cli` | Production CLI |
| `antech-kdf-ffi` | C ABI |
| `antech-kdf-research` | Research-only tooling |

## Engine

One production engine: `AntechEngine` in `antech-kdf-core`.

Work is derived from `memory / block_size`. Supported structural parameters:

- memory, block size, fan-in, graph kind, salt length, output length

There are no dependency-depth or pass-count knobs.

Default graph kind is **combined-frontier**.
