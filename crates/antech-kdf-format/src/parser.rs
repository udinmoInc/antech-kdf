//! Parser for self-describing password hash strings.

use antech_kdf_types::{
    Algorithm, AlgorithmVersion, BlockSize, FanIn, GraphKind, KdfError, MemorySize, OutputLength,
    RawHashComponents, SaltLength,
};

/// Reject pathological inputs before allocating.
const MAX_ENCODED_HASH_LEN: usize = 8192;
const MAX_PARAM_SECTION_LEN: usize = 256;

fn hex_decode(s: &str, expected_len: usize, field: &str) -> Result<Vec<u8>, KdfError> {
    let expected_hex = expected_len
        .checked_mul(2)
        .ok_or_else(|| KdfError::Encoding(format!("{field} length overflow")))?;
    if s.len() != expected_hex {
        return Err(KdfError::Encoding(format!(
            "{field} hex length mismatch: expected {expected_hex} chars, got {}",
            s.len()
        )));
    }
    if !s.len().is_multiple_of(2) {
        return Err(KdfError::Encoding(format!("odd-length {field} hex string")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| KdfError::Encoding(format!("invalid {field} hex byte at {i}: {e}")))
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
    if encoded.len() > MAX_ENCODED_HASH_LEN {
        return Err(KdfError::Encoding(format!(
            "encoded hash exceeds maximum length ({MAX_ENCODED_HASH_LEN} bytes)"
        )));
    }

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

    if parts[3].len() > MAX_PARAM_SECTION_LEN {
        return Err(KdfError::Encoding("parameter section too long".into()));
    }

    let mut seen_m = false;
    let mut seen_s = false;
    let mut seen_b = false;
    let mut seen_f = false;
    let mut seen_g = false;
    let mut seen_l = false;

    for param_kv in parts[3].split(',') {
        let Some((k, v)) = param_kv.split_once('=') else {
            return Err(KdfError::Encoding(format!(
                "invalid parameter field: {param_kv}"
            )));
        };
        match k {
            "m" => {
                if seen_m {
                    return Err(KdfError::Encoding("duplicate m= parameter".into()));
                }
                seen_m = true;
                memory_kib = Some(parse_u32("m", v)?);
            }
            "s" => {
                if seen_s {
                    return Err(KdfError::Encoding("duplicate s= parameter".into()));
                }
                seen_s = true;
                salt_len = Some(parse_usize("s", v)?);
            }
            "b" => {
                if seen_b {
                    return Err(KdfError::Encoding("duplicate b= parameter".into()));
                }
                seen_b = true;
                block_size = Some(parse_usize("b", v)?);
            }
            "f" => {
                if seen_f {
                    return Err(KdfError::Encoding("duplicate f= parameter".into()));
                }
                seen_f = true;
                fan_in = Some(parse_u32("f", v)?);
            }
            "g" => {
                if seen_g {
                    return Err(KdfError::Encoding("duplicate g= parameter".into()));
                }
                seen_g = true;
                graph_tag = Some(parse_u32("g", v)?);
            }
            "l" => {
                if seen_l {
                    return Err(KdfError::Encoding("duplicate l= parameter".into()));
                }
                seen_l = true;
                output_len = Some(parse_usize("l", v)?);
            }
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

    MemorySize::kib(memory_kib as usize)
        .validate()
        .map_err(KdfError::Config)?;
    BlockSize::bytes(block_size)
        .validate()
        .map_err(KdfError::Config)?;
    FanIn::new(fan_in).validate().map_err(KdfError::Config)?;
    SaltLength::bytes(salt_len)
        .validate()
        .map_err(KdfError::Config)?;
    OutputLength::bytes(output_len)
        .validate()
        .map_err(KdfError::Config)?;

    let salt = hex_decode(parts[4], salt_len, "salt")?;
    let digest = hex_decode(parts[5], output_len, "digest")?;

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
