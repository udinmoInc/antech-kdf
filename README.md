# Antech KDF

Antech is an experimental password-hashing library. The default profile uses **16 MiB** of working memory and a **combined-frontier** dependency graph. Work scales with `memory / block_size`; there is no separate iteration-count knob.

**Status: Experimental.** Prefer Argon2id for production password storage until Antech has independent cryptographic review and published conclusions.

Docs site: [developers.udinmo.com](https://developers.udinmo.com)

## Repository layout

```text
crates/                 # Production library (start here)
bindings/ + sdk/        # Language SDKs and conformance vectors
docs/                   # End-user documentation (Mintlify)
examples/               # Usage samples
fuzz/                   # Production-surface fuzz targets
research/               # Construction narrative, attackers, measured results, review package
```

Production crates never import research. Research may import production for correct digests.

## Install

```toml
[dependencies]
antech-kdf = "0.1"
```

Rust 1.70+. Other language packages pin **0.1.0** — see the [SDK overview](https://developers.udinmo.com/antech-kdf/sdk/overview).

## Usage

```rust
use antech_kdf::{hash, verify, needs_rehash};

let stored = hash("correct_horse_battery_staple")?;
assert!(verify("correct_horse_battery_staple", &stored)?);
assert!(!needs_rehash(&stored)?);
```

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
| Block size | 32 B | DAG node size (16–64) |
| Fan-in | 2 | Parents mixed per node |
| Graph | combined-frontier | Encoded as `g=3` |
| Salt length | 16 B | 8–256 |
| Output length | 32 B | Digest size |

## Hash format

```text
$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>
```

`verify` rebuilds the config from the string. Legacy `v1` encodings are rejected.

## Production crates

| Crate | Role |
|---|---|
| `antech-kdf` | Public API (`hash` / `verify` / rehash) |
| `antech-kdf-core` | `AntechEngine` + resource scheduler |
| `antech-kdf-format` | Encode / parse |
| `antech-kdf-types` | Config and errors |
| `antech-kdf-ffi` | C ABI for SDKs |
| `antech-kdf-cli` | CLI |

```bash
cargo test --workspace
```

## Security & review

Independent review materials live in [`research/security-review/`](./research/security-review/). Start with [`REQUEST_FOR_REVIEW.md`](./research/security-review/REQUEST_FOR_REVIEW.md).

Canonical construction: **construction version 4**, CombinedFrontier, `$antech$v2$`. Evidence is labeled **MEASURED** / **MODELED** / **BLOCKED** / **UNKNOWN** — do not mix campaigns.

## Research (second)

Narrative, attackers, CUDA, TMTO, and campaign outputs: [`research/`](./research/). Current measured datasets:

| Dataset | Path |
|---|---|
| CPU / GPU compute–memory (v4-C) | [`research/results/compute-memory-v4/`](./research/results/compute-memory-v4/) |
| Cryptanalysis + TMTO | [`research/results/cryptanalysis/`](./research/results/cryptanalysis/) |
| Correctness | [`research/results/correctness/`](./research/results/correctness/) |
| Stress | [`research/results/stress/`](./research/results/stress/) |
| Fuzz | [`research/results/fuzz/`](./research/results/fuzz/) |

## SDKs

Thin wrappers over `antech-kdf-ffi`: C/C++, Go, Python, Node, Java/Kotlin, Swift, .NET. Conformance vectors: [`sdk/conformance/`](./sdk/conformance/).

## Changelog

[CHANGELOG.md](./CHANGELOG.md) — current release **0.1.0**.

License: MIT OR Apache-2.0.
