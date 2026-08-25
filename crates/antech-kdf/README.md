# antech-kdf

Rust API for Antech password hashing.

```toml
[dependencies]
antech-kdf = "0.1"
```

```rust
use antech_kdf::{hash, verify, needs_rehash};

let stored = hash("my_secret_password")?;
assert!(verify("my_secret_password", &stored)?);
if needs_rehash(&stored)? {
    // upgrade parameters
}
```

`hash_with_config` takes an `AntechConfig` (memory, block size, fan-in, graph, salt/output lengths). Work is `memory / block_size`. Hashes are `$antech$v2$...`; `v1` is rejected. Rehash checks use `needs_rehash` / `needs_rehash_with_policy`.

Experimental — not audited. Attackers and CUDA live in `antech-kdf-research`.
