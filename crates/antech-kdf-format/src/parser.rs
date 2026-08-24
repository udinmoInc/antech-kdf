//! Self-describing hash string parser.

use crate::error::FormatError;
use antech_kdf_types::{AlgorithmVersion, RawHashComponents};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;

/// Parses a formatted password hash string into raw components.
///
/// Format: `$antech$<version>$m=<mem>,t=<time>,p=<par>,bw=<bw>$<salt_b64>$<digest_b64>`
pub fn parse_hash(encoded: &str) -> Result<RawHashComponents, FormatError> {
    if !encoded.starts_with("$antech$") {
        return Err(FormatError::InvalidPrefix);
    }

    let parts: Vec<&str> = encoded.split('$').collect();
    // Expect: ["", "antech", version, params, salt, digest]
    if parts.len() != 6 || parts[1] != "antech" {
        return Err(FormatError::InvalidEncoding);
    }

    let version_str = parts[2];
    let version = AlgorithmVersion::parse(version_str)
        .ok_or_else(|| FormatError::UnsupportedVersion(version_str.to_string()))?;

    let params_str = parts[3];
    let mut memory_kib = 0;
    let mut time_cost = 0;
    let mut parallelism = 0;
    let mut bandwidth_target = 0;

    for kv in params_str.split(',') {
        let mut sub_parts = kv.split('=');
        let key = sub_parts.next().ok_or(FormatError::InvalidEncoding)?;
        let val_str = sub_parts.next().ok_or(FormatError::InvalidEncoding)?;

        match key {
            "m" => memory_kib = val_str.parse().map_err(|_| FormatError::InvalidParameter("m".to_string()))?,
            "t" => time_cost = val_str.parse().map_err(|_| FormatError::InvalidParameter("t".to_string()))?,
            "p" => parallelism = val_str.parse().map_err(|_| FormatError::InvalidParameter("p".to_string()))?,
            "bw" => bandwidth_target = val_str.parse().map_err(|_| FormatError::InvalidParameter("bw".to_string()))?,
            _ => return Err(FormatError::InvalidParameter(key.to_string())),
        }
    }

    let salt = STANDARD_NO_PAD
        .decode(parts[4])
        .map_err(|_| FormatError::InvalidBase64)?;
    let digest = STANDARD_NO_PAD
        .decode(parts[5])
        .map_err(|_| FormatError::InvalidBase64)?;

    Ok(RawHashComponents {
        version,
        memory_kib,
        time_cost,
        parallelism,
        bandwidth_target,
        salt,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_parse_encode() {
        let raw = RawHashComponents {
            version: AlgorithmVersion::V1,
            memory_kib: 65536,
            time_cost: 3,
            parallelism: 1,
            bandwidth_target: 100,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            digest: vec![42; 32],
        };

        let encoded = crate::encoder::encode_hash(&raw).unwrap();
        assert!(encoded.starts_with("$antech$v1$m=65536,t=3,p=1,bw=100$"));

        let parsed = parse_hash(&encoded).unwrap();
        assert_eq!(parsed, raw);
    }
}
