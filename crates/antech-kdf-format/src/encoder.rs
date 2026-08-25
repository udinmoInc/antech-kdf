//! Encoder for self-describing password hash strings.

use antech_kdf_types::{AntechConfig, ConfigError};
use std::fmt::Write;

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Encodes salt and digest into self-describing format string:
/// `$antech$v1$m=16384,s=32,t=650000,p=1,b=32,l=32$<salt_hex>$<digest_hex>`
pub fn encode_hash(
    config: &AntechConfig,
    salt: &[u8],
    digest: &[u8],
) -> Result<String, ConfigError> {
    config.validate()?;
    Ok(format!(
        "${}$v1$m={},s={},t={},p={},b={},l={}${}${}",
        config.algorithm.as_str(),
        config.memory.as_kib(),
        salt.len(),
        config.dependency_depth.get(),
        config.passes.get(),
        config.block_size.as_bytes(),
        digest.len(),
        hex_encode(salt),
        hex_encode(digest)
    ))
}
