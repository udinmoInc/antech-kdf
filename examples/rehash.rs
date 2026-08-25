//! Password rehash policy evaluation example.

use antech_kdf::{hash, needs_rehash, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "user_password_string";
    let stored_hash = hash(password)?;

    if verify(password, &stored_hash)? {
        if needs_rehash(&stored_hash)? {
            println!("Hash is outdated. Upgrading stored hash...");
            let _upgraded = hash(password)?;
        } else {
            println!("Hash is up to date.");
        }
    }

    Ok(())
}
