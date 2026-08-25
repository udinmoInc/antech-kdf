# Antech KDF

Password hashing library built around a compute-memory construction. The default profile uses 16 MiB of working memory and a combined-frontier dependency graph. Work is derived from `memory / block_size`; there is no separate iteration-count knob.

This is experimental software. Benchmarks are useful for comparing attacker cost under fixed conditions. They are not a substitute for cryptographic review. Prefer Argon2id for production password storage until Antech has been independently audited.

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
| `antech-kdf-research` | Attackers, CUDA, historical variants |

Dependency rule: research imports core; production never imports research.

## Research highlights

At 16 MiB on an RTX 3050 (measured), optimized Antech GPU attacker throughput was about **33 g/s** versus Argon2id at about **436 g/s**. Details and methodology live under [`research/`](research/README.md).

```bash
cargo run --release -p antech-kdf-research --example compute_memory_v4_runner
```

## Build

```bash
cargo fmt --all
cargo check -p antech-kdf -p antech-kdf-core
cargo test -p antech-kdf -p antech-kdf-core -p antech-kdf-format
cargo clippy -p antech-kdf -p antech-kdf-core --all-targets
```

More detail: [`docs/`](docs/api.md). License: MIT OR Apache-2.0.
