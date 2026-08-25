//! Parser for self-describing password hash strings.

use antech_kdf_types::{Algorithm, AlgorithmVersion, GraphKind, KdfError, RawHashComponents};

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte at {i}: {e}"))
        })
        .collect()
}

fn parse_u32(field: &str, value: &str) -> Result<u32, KdfError> {
    value
        .parse()
        .map_err(|_| KdfError::Encoding(format!("invalid {field} value: {value}")))
}

fn parse_usize(field: &str, value: &str) -> Result<usize, KdfError> {
    value
        .parse()
        .map_err(|_| KdfError::Encoding(format!("invalid {field} value: {value}")))
}

/// Parse a stored hash. Legacy `v1` strings are rejected, not reinterpreted.
pub fn parse_hash(encoded: &str) -> Result<RawHashComponents, KdfError> {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 || !parts[0].is_empty() {
        return Err(KdfError::Encoding("invalid hash field count".to_string()));
    }

    let algo = Algorithm::parse(parts[1])
        .ok_or_else(|| KdfError::Encoding(format!("unknown algorithm identifier: {}", parts[1])))?;

    if parts[2] == "v1" || parts[2] == "1" {
        return Err(KdfError::Encoding(
            "unsupported hash version v1 (legacy research encoding is not verified)".to_string(),
        ));
    }

    let version = AlgorithmVersion::parse(parts[2])
        .ok_or_else(|| KdfError::Encoding(format!("unknown version identifier: {}", parts[2])))?;

    let mut memory_kib = None;
    let mut salt_len = None;
    let mut block_size = None;
    let mut fan_in = None;
    let mut graph_tag = None;
    let mut output_len = None;

    for param_kv in parts[3].split(',') {
        let Some((k, v)) = param_kv.split_once('=') else {
            return Err(KdfError::Encoding(format!(
                "invalid parameter field: {param_kv}"
            )));
        };
        match k {
            "m" => memory_kib = Some(parse_u32("m", v)?),
            "s" => salt_len = Some(parse_usize("s", v)?),
            "b" => block_size = Some(parse_usize("b", v)?),
            "f" => fan_in = Some(parse_u32("f", v)?),
            "g" => graph_tag = Some(parse_u32("g", v)?),
            "l" => output_len = Some(parse_usize("l", v)?),
            other => {
                return Err(KdfError::Encoding(format!(
                    "unknown parameter field: {other}"
                )));
            }
        }
    }

    let memory_kib =
        memory_kib.ok_or_else(|| KdfError::Encoding("missing m= memory parameter".into()))?;
    let salt_len =
        salt_len.ok_or_else(|| KdfError::Encoding("missing s= salt length parameter".into()))?;
    let block_size =
        block_size.ok_or_else(|| KdfError::Encoding("missing b= block size parameter".into()))?;
    let fan_in = fan_in.ok_or_else(|| KdfError::Encoding("missing f= fan-in parameter".into()))?;
    let graph_tag =
        graph_tag.ok_or_else(|| KdfError::Encoding("missing g= graph parameter".into()))?;
    let output_len = output_len
        .ok_or_else(|| KdfError::Encoding("missing l= output length parameter".into()))?;

    let graph = GraphKind::from_tag(graph_tag)
        .ok_or_else(|| KdfError::Encoding(format!("unknown graph tag: {graph_tag}")))?;

    let salt =
        hex_decode(parts[4]).map_err(|e| KdfError::Encoding(format!("invalid salt hex: {e}")))?;
    let digest =
        hex_decode(parts[5]).map_err(|e| KdfError::Encoding(format!("invalid digest hex: {e}")))?;

    if salt.len() != salt_len {
        return Err(KdfError::Encoding(format!(
            "salt length mismatch: declared {salt_len}, actual {}",
            salt.len()
        )));
    }
    if digest.len() != output_len {
        return Err(KdfError::Encoding(format!(
            "digest length mismatch: declared {output_len}, actual {}",
            digest.len()
        )));
    }

    Ok(RawHashComponents {
        version,
        algorithm: algo,
        memory_kib,
        salt_len,
        block_size,
        fan_in,
        graph,
        output_len,
        salt,
        digest,
    })
}
