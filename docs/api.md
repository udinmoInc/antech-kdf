# Antech KDF — Developer API

The `antech-kdf` crate exposes password hashing and verification with a self-describing v2 hash format.

## Public API

| Function | Purpose |
|---|---|
| `hash(password)` | Hash with default config (16 MiB, combined-frontier) |
| `hash_with_config(password, &config)` | Hash with explicit structural parameters |
| `verify(password, stored_hash)` | Constant-time verification |
| `needs_rehash(stored_hash)` | Check against default rehash policy |
| `needs_rehash_with_policy(stored_hash, &policy)` | Check against custom policy |

## Default usage

```rust
use antech_kdf::{hash, verify, needs_rehash, Error};

fn main() -> Result<(), Error> {
    let password = "correct_horse_battery_staple";
    let stored = hash(password)?;
    assert!(verify(password, &stored)?);
    assert!(!needs_rehash(&stored)?);
    Ok(())
}
```

## Custom configuration

Work is structure-derived from `memory / block_size`. There are no dependency-depth or pass-count knobs.

```rust
use antech_kdf::{hash_with_config, verify, AntechConfig, GraphKind, Error};

fn main() -> Result<(), Error> {
    let config = AntechConfig::builder()
        .memory_mib(16)
        .salt_length(32)
        .block_size(32)
        .fan_in(2)
        .graph(GraphKind::CombinedFrontier)
        .output_length(32)
        .build()?;

    let stored = hash_with_config("password", &config)?;
    assert!(verify("password", &stored)?);
    Ok(())
}
```

## Rehash policy

```rust
use antech_kdf::{hash, needs_rehash_with_policy, RehashPolicy};

let stored = hash("user_password")?;
let policy = RehashPolicy::builder()
    .minimum_memory_mib(16)
    .preferred_memory_mib(32)
    .preferred_fan_in(2)
    .build();

if needs_rehash_with_policy(&stored, &policy)? {
    // re-hash on login
}
```

## Security notice

This construction is experimental. Passing benchmarks does not establish cryptographic security. Independent review is required before production password storage.
