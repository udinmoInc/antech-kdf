# Antech KDF

Password hashing library built around a compute-memory construction. The default profile uses 16 MiB of working memory and a combined-frontier dependency graph. Work is derived from `memory / block_size`; there is no separate iteration-count knob.

This is experimental software. Benchmarks are useful for comparing attacker cost under fixed conditions. They are not a substitute for cryptographic review. Prefer Argon2id for production password storage until Antech has undergone independent cryptographic review and any resulting conclusions are published.

## Security Review

Antech is an experimental password KDF currently **submitted for independent cryptanalysis**. The repository includes the formal construction, test vectors, threat model, and prior attack results for review.

See [`research/security-review/`](./research/security-review/).

## Install

```toml
[dependencies]
antech-kdf = "0.1"
```

Rust 1.70+.

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

Stored hashes are self-describing:

```text
$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>
```

`verify` rebuilds the config from the string. Legacy `v1` encodings are rejected.

Rehash policy:

```rust
use antech_kdf::{needs_rehash_with_policy, RehashPolicy};

let policy = RehashPolicy::builder().preferred_memory_mib(32).build();
if needs_rehash_with_policy(&stored, &policy)? {
    // upgrade on login
}
```

Per-hash memory comes from `AntechConfig`. Server-wide admission control is separate (`BoundedResourceScheduler` in `antech-kdf-core`, default 128 MiB global ceiling).

## Crates

| Crate | Role |
|---|---|
| `antech-kdf` | Public API |
| `antech-kdf-core` | Engine and resource scheduler |
| `antech-kdf-format` | Encode / parse |
| `antech-kdf-types` | Config and errors |
| `antech-kdf-cli` | `hash` / `verify` CLI |
| `antech-kdf-ffi` | C ABI |

Research (attackers, CUDA, TMTO, cryptanalysis) lives under [`research/code/`](research/code/) in a **separate** Cargo workspace. Dependency rule: research imports core; production never imports research.

## SDKs (cross-language)

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

Authoritative version: [`VERSION`](VERSION). Native build: `sdk/scripts/build-native.(sh|ps1)`. Conformance: [`sdk/conformance/`](sdk/conformance/). See [`sdk/README.md`](sdk/README.md).

## Research highlights

Attacker-oriented measurements (CPU/GPU/TMTO) are summarized under [`research/security-review/evidence.md`](research/security-review/evidence.md). Runners:

```bash
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
```

## Documentation

Full developer documentation: [developers.udinmo.com](https://developers.udinmo.com)

Source MDX for that site lives in [`docs/`](docs/) (`docs/sidebar.json`).

## Build

```bash
# Production (default workspace)
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy -p antech-kdf --all-targets

# Research (separate workspace)
cargo check --manifest-path research/code/Cargo.toml --workspace
cargo test  --manifest-path research/code/Cargo.toml --workspace
```

More detail: [developers.udinmo.com](https://developers.udinmo.com). License: MIT OR Apache-2.0.
