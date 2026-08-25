//! Parser for self-describing password hash strings.

use antech_kdf_types::{Algorithm, AlgorithmVersion, KdfError, RawHashComponents};

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Odd length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex byte at {}: {}", i, e))
        })
        .collect()
}

/// Parse self-describing hash string into `RawHashComponents`.
pub fn parse_hash(encoded: &str) -> Result<RawHashComponents, KdfError> {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 {
        return Err(KdfError::Encoding("Invalid hash field count".to_string()));
    }

    let algo = Algorithm::parse(parts[1])
        .ok_or_else(|| KdfError::Encoding(format!("Unknown algorithm identifier: {}", parts[1])))?;

    let version = AlgorithmVersion::parse(parts[2])
        .ok_or_else(|| KdfError::Encoding(format!("Unknown version identifier: {}", parts[2])))?;

    let mut memory_kib = 16384;
    let mut salt_len = 16;
    let mut dependency_depth = 650000;
    let mut passes = 1;
    let mut block_size = 32;
    let mut output_len = 32;

    for param_kv in parts[3].split(',') {
        let kv: Vec<&str> = param_kv.split('=').collect();
        if kv.len() == 2 {
            match kv[0] {
                "m" => memory_kib = kv[1].parse().unwrap_or(16384),
                "s" => salt_len = kv[1].parse().unwrap_or(16),
                "t" => dependency_depth = kv[1].parse().unwrap_or(650000),
                "p" => passes = kv[1].parse().unwrap_or(1),
                "b" => block_size = kv[1].parse().unwrap_or(32),
                "l" => output_len = kv[1].parse().unwrap_or(32),
                _ => {}
            }
        }
    }

    let salt =
        hex_decode(parts[4]).map_err(|e| KdfError::Encoding(format!("Invalid salt hex: {}", e)))?;
    let digest = hex_decode(parts[5])
        .map_err(|e| KdfError::Encoding(format!("Invalid digest hex: {}", e)))?;

    Ok(RawHashComponents {
        version,
        algorithm: algo,
        memory_kib,
        salt_len,
        dependency_depth,
        passes,
        block_size,
        output_len,
        salt,
        digest,
    })
}
