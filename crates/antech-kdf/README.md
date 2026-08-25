# antech-kdf

Stable Rust API for Antech password hashing and verification.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
antech-kdf = "0.1"
```

## Usage

```rust
use antech_kdf::{hash, verify, needs_rehash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stored = hash("my_secret_password")?;
    assert!(verify("my_secret_password", &stored)?);
    if needs_rehash(&stored)? {
        // Re-hash with current policy parameters
    }
    Ok(())
}
```

## Configuration

Advanced callers can supply structural parameters (memory, block size, fan-in, graph family) via [`AntechConfig`](https://docs.rs/antech-kdf/latest/antech_kdf/struct.AntechConfig.html) and `hash_with_config`.

Work is derived from `memory / block_size`. There are no iteration-count or dependency-depth knobs.

## Verification

Stored hashes are self-describing (`$antech$v2$...`). `verify()` parses version, algorithm, structural parameters, salt, and digest — applications do not pass salt or config separately.

Legacy `v1` research encodings are rejected explicitly and are not silently reinterpreted.

## Rehashing

Use `needs_rehash()` with the default policy, or `needs_rehash_with_policy()` to compare stored parameters against your application's targets (minimum memory, preferred fan-in, output length).

## Resource policy

Per-operation memory is configured on [`AntechConfig`]. Server-wide admission control lives in `antech-kdf-core`'s resource scheduler and is separate from the KDF algorithm.

## Security status

This crate implements the project's current validated compute-memory construction. **Passing benchmarks does not establish cryptographic security.** Independent review is required before relying on this construction for production password storage.

Do not interpret benchmark comparisons as proof of superiority over Argon2id or any other KDF.

## Research

Attacker tooling, CUDA kernels, TMTO experiments, and historical variants live in the separate `antech-kdf-research` crate. Production builds do not depend on research code.

## Limitations

- Experimental construction; no third-party cryptographic audit
- GPU attacker results are research-only and not linked into this crate
- Hash format version `v2` is required for new passwords
