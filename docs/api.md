# Antech KDF API Specification

## Public API (`antech-kdf`)

### `hash`
```rust
pub fn hash(password: impl AsRef<[u8]>) -> Result<String, Error>;
```
Generates a self-describing password hash string using recommended default parameters and secure random salt.

### `verify`
```rust
pub fn verify(
    password: impl AsRef<[u8]>,
    encoded_hash: impl AsRef<str>,
) -> Result<bool, Error>;
```
Verifies a password against a stored self-describing hash string in constant time. Returns `Ok(true)` on match, `Ok(false)` on mismatch.

### `needs_rehash`
```rust
pub fn needs_rehash(
    encoded_hash: impl AsRef<str>,
) -> Result<bool, Error>;
```
Determines if a stored hash string is obsolete due to version or parameter changes.
