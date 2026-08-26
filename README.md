# Antech KDF

Password hashing library built around a compute-memory construction. The default profile uses 16 MiB of working memory and a combined-frontier dependency graph. Work is derived from `memory / block_size`; there is no separate iteration-count knob.

**Status: Experimental.** Prefer Argon2id for production password storage until Antech has undergone independent cryptographic review and any resulting conclusions are published.

Documentation: [developers.udinmo.com](https://developers.udinmo.com)

## Install

```toml
[dependencies]
antech-kdf = "0.1"
```

Rust 1.70+. Python, Node, and .NET packages are published at version **0.1.0** — see [SDK overview](https://developers.udinmo.com/antech-kdf/sdk/overview) for install commands.

## Usage

```rust
use antech_kdf::{hash, verify, needs_rehash};

let stored = hash("correct_horse_battery_staple")?;
assert!(verify("correct_horse_battery_staple", &stored)?);
assert!(!needs_rehash(&stored)?);
```

Custom parameters:

```rust
use antech_kdf::{hash_with_config, AntechConfig, GraphKind};

let config = AntechConfig::builder()
    .memory_mib(16)
    .fan_in(2)
    .graph(GraphKind::CombinedFrontier)
    .build()?;

let stored = hash_with_config("password", &config)?;
```

| Parameter | Default | Notes |
|---|---|---|
| Memory | 16 MiB | Working set |
| Block size | 32 B | DAG node size |
| Fan-in | 2 | Parents mixed per node |
| Graph | combined-frontier | Tag `g=3` in the encoded hash |
| Salt length | 16 B | 8–256 |
| Output length | 32 B | Digest size |

## Hash format

```text
$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>
```

`verify` rebuilds the config from the string. Legacy `v1` encodings are rejected.

## Security & review

Antech is submitted for independent cryptanalysis. The repository includes the formal construction, production source, test vectors, conformance suite, benchmark evidence, and known limitations.

Start at [`research/security-review/`](./research/security-review/) or the [Security & review](https://developers.udinmo.com/antech-kdf/security-review/overview) documentation page.

## SDKs

Thin wrappers over [`antech-kdf-ffi`](crates/antech-kdf-ffi) — same API everywhere: `hash`, `verify`, `needs_rehash`, `hash_with_config`, rehash policy, and config fields.

| Language | Path |
|---|---|
| C / C++ | [`bindings/c`](bindings/c), [`bindings/cpp`](bindings/cpp) |
| Go | [`bindings/go`](bindings/go) |
| Python | [`bindings/python`](bindings/python) |
| Node / TypeScript | [`bindings/node`](bindings/node) |
| Java / Kotlin | [`bindings/java`](bindings/java), [`bindings/kotlin`](bindings/kotlin) |
| Swift | [`bindings/swift`](bindings/swift) |
| .NET / C# | [`bindings/dotnet`](bindings/dotnet) |

Conformance: [`sdk/conformance/`](sdk/conformance/).

## Crates

| Crate | Role |
|---|---|
| `antech-kdf` | Public API |
| `antech-kdf-core` | Engine and resource scheduler |
| `antech-kdf-format` | Encode / parse |
| `antech-kdf-types` | Config and errors |
| `antech-kdf-cli` | `hash` / `verify` CLI |
| `antech-kdf-ffi` | C ABI |

Research (attackers, CUDA, TMTO, cryptanalysis) lives under [`research/code/`](research/code/) in a **separate** Cargo workspace. Production never imports research.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md). Current release: **0.1.0**.

## Build (from source)

```bash
cargo test --workspace
```

License: MIT OR Apache-2.0.
