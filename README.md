# Antech KDF

Antech KDF is a password hashing project built around a compute-memory construction tuned for small-server memory budgets while preserving resistance to offline guessing attacks.

## Overview

The **production implementation** lives in `antech-kdf-core` and is exposed through the stable `antech-kdf` crate:

- `hash` / `hash_with_config`
- `verify`
- `needs_rehash` / `needs_rehash_with_policy`

Work is structure-derived: one traversal of a `memory / block_size` dependency graph. There are no user-facing iteration-count or dependency-depth knobs.

The default graph family is **combined-frontier**.

## Installation

```toml
[dependencies]
antech-kdf = "0.1"
```

Requires Rust 1.70+.

## Usage

```rust
use antech_kdf::{hash, verify};

let stored = hash("correct_horse_battery_staple")?;
assert!(verify("correct_horse_battery_staple", &stored)?);
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

## Configuration

Supported structural parameters:

| Parameter | Role |
|---|---|
| Memory | Working set size (default 16 MiB) |
| Block size | DAG node size (default 32 B) |
| Fan-in | Parents mixed per node (default 2) |
| Graph | Dependency shape (default combined-frontier) |
| Salt length | 8–256 bytes |
| Output length | Digest size |

## Verification

Stored hashes use format version **`v2`**:

```text
$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>
```

`verify()` reconstructs configuration from the stored string. Legacy **`v1`** research hashes are rejected — they are not silently reinterpreted.

## Rehashing

Compare stored parameters against application policy:

```rust
use antech_kdf::{needs_rehash_with_policy, RehashPolicy};

let policy = RehashPolicy::builder().preferred_memory_mib(32).build();
if needs_rehash_with_policy(&stored, &policy)? {
    // upgrade hash
}
```

## Resource policy

KDF memory (`AntechConfig`) is separate from server admission control (`BoundedResourceScheduler` in core). Example: 16 MiB per operation can coexist with a 128 MiB global budget.

## Security status

**Experimental — not production-proven.**

The current implementation reflects validated benchmark work on the combined-frontier construction. Passing benchmarks does **not** substitute for independent cryptographic review. Do not claim security equivalence with Argon2id without evidence.

## Research

Attacker tooling, CUDA kernels, TMTO, multi-target experiments, and historical variants remain in `antech-kdf-research`. Research imports core; production never imports research.

```bash
cargo run --release -p antech-kdf-research --example compute_memory_v4_runner
```

See [research/README.md](research/README.md).

## Build & test

```bash
cargo fmt --all
cargo check -p antech-kdf
cargo check -p antech-kdf-core
cargo test -p antech-kdf -p antech-kdf-core -p antech-kdf-format
cargo clippy -p antech-kdf -p antech-kdf-core --all-targets
```

## Crate layout

```text
crates/
├── antech-kdf/          # Public API
├── antech-kdf-core/     # Canonical engine
├── antech-kdf-format/   # Hash encoding
├── antech-kdf-types/    # Config & errors
├── antech-kdf-cli/      # Production CLI
├── antech-kdf-ffi/      # C ABI
└── antech-kdf-research/ # Benchmarks & attackers
```

## License

MIT OR Apache-2.0
