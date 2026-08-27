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
/// `$antech$v2$m=<kib>,s=<salt_len>,b=<block>,f=<fan>,g=<graph>,l=<out>[,sk=1][,adl=<n>]$<salt_hex>$<digest_hex>`
///
/// Optional `sk=1` / `adl=<n>` are omitted when unused so legacy hashes stay byte-compatible
/// when re-encoded without secret/AD requirements. Secret bytes are never written.
pub fn encode_hash(
    config: &AntechConfig,
    salt: &[u8],
    digest: &[u8],
) -> Result<String, ConfigError> {
    config.validate()?;
    let mut params = format!(
        "m={},s={},b={},f={},g={},l={}",
        config.memory.as_kib(),
        salt.len(),
        config.block_size.as_bytes(),
        config.fan_in.get(),
        config.graph.tag(),
        digest.len(),
    );
    if config.secret_required {
        params.push_str(",sk=1");
    }
    if let Some(adl) = config.associated_data_length {
        let _ = write!(params, ",adl={adl}");
    }
    Ok(format!(
        "${}$v2${}${}${}",
        config.algorithm.as_str(),
        params,
        hex_encode(salt),
        hex_encode(digest)
    ))
}
