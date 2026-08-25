# API

The `antech-kdf` crate is the stable entry point.

| Function | Purpose |
|---|---|
| `hash(password)` | Hash with defaults (16 MiB, combined-frontier) |
| `hash_with_config(password, &config)` | Hash with an explicit `AntechConfig` |
| `verify(password, stored)` | Constant-time verify against a v2 string |
| `needs_rehash(stored)` | Compare against the default rehash policy |
| `needs_rehash_with_policy(stored, &policy)` | Compare against a custom policy |

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

Work is `memory / block_size` nodes. There is no dependency-depth or pass-count setting.

```rust
use antech_kdf::{hash_with_config, AntechConfig, GraphKind, Error};

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
    Ok(())
}
```

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

Errors are `antech_kdf::Error` (`KdfError` from `antech-kdf-types`). Graph tags in the encoded string: `1` reduced-critical-path, `2` cache-locality, `3` combined-frontier.
