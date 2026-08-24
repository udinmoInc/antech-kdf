// Backend Integration Example: Rust + Axum
// Demonstrates strictly where hash() and verify() are invoked.

use antech_kdf::{hash, verify};

pub fn register_user(password: &str) -> Result<String, String> {
    hash(password).map_err(|e| e.to_string())
}

pub fn authenticate_user(password: &str, stored_hash: &str) -> Result<bool, String> {
    verify(password, stored_hash).map_err(|e| e.to_string())
}
