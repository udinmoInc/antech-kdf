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

/// Encodes salt and digest:
/// `$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>$<salt_hex>$<digest_hex>`
pub fn encode_hash(
    config: &AntechConfig,
    salt: &[u8],
    digest: &[u8],
) -> Result<String, ConfigError> {
    config.validate()?;
    Ok(format!(
        "${}$v2$m={},s={},b={},f={},g={},l={}${}${}",
        config.algorithm.as_str(),
        config.memory.as_kib(),
        salt.len(),
        config.block_size.as_bytes(),
        config.fan_in.get(),
        config.graph.tag(),
        digest.len(),
        hex_encode(salt),
        hex_encode(digest)
    ))
}
