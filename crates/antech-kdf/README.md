# antech-kdf

Public developer API for Antech KDF.

## Usage

```rust
use antech_kdf::{hash, verify, needs_rehash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stored = hash("my_secret_password")?;
    let valid = verify("my_secret_password", &stored)?;
    assert!(valid);
    Ok(())
}
```
