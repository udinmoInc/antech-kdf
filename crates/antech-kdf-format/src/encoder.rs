//! Hash string serialization engine.

use crate::error::FormatError;
use antech_kdf_types::RawHashComponents;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;

/// Encodes raw hash components into self-describing hash string.
///
/// Format: `$antech$v1$m=65536,t=3,p=1,bw=100$<salt_b64>$<digest_b64>`
pub fn encode_hash(components: &RawHashComponents) -> Result<String, FormatError> {
    let salt_b64 = STANDARD_NO_PAD.encode(&components.salt);
    let digest_b64 = STANDARD_NO_PAD.encode(&components.digest);

    Ok(format!(
        "$antech${}$m={},t={},p={},bw={}${}${}",
        components.version.as_str(),
        components.memory_kib,
        components.time_cost,
        components.parallelism,
        components.bandwidth_target,
        salt_b64,
        digest_b64
    ))
}
