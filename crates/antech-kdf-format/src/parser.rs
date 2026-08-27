//! Parser for self-describing password hash strings.

use antech_kdf_types::{
    Algorithm, AlgorithmVersion, BlockSize, FanIn, GraphKind, KdfError, MemorySize, OutputLength,
    RawHashComponents, SaltLength,
};

/// Reject pathological inputs before allocating.
const MAX_ENCODED_HASH_LEN: usize = 8192;
const MAX_PARAM_SECTION_LEN: usize = 256;

fn encoding(msg: impl Into<String>) -> KdfError {
    KdfError::Encoding(msg.into())
}

fn hex_decode(s: &str, expected_len: usize, field: &str) -> Result<Vec<u8>, KdfError> {
    let expected_hex = expected_len
        .checked_mul(2)
        .ok_or_else(|| encoding(format!("{field} length overflow")))?;
    // Hex must be ASCII; reject multi-byte UTF-8 before byte-indexing (avoids panics on
    // non-char-boundary slices such as s[i..i+2]).
    if !s.is_ascii() {
        return Err(encoding(format!("{field} hex must be ASCII [0-9a-fA-F]")));
    }
    if s.len() != expected_hex {
        return Err(encoding(format!(
            "{field} hex length mismatch: expected {expected_hex} chars, got {}",
            s.len()
        )));
    }
    if !s.len().is_multiple_of(2) {
        return Err(encoding(format!("odd-length {field} hex string")));
    }
    let bytes = s.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            // ASCII-only: these two bytes are always valid UTF-8 char boundaries.
            let pair = std::str::from_utf8(&bytes[i..i + 2])
                .map_err(|_| encoding(format!("invalid {field} hex byte at {i}")))?;
            u8::from_str_radix(pair, 16)
                .map_err(|e| encoding(format!("invalid {field} hex byte at {i}: {e}")))
        })
        .collect()
}

fn parse_u32(field: &str, value: &str) -> Result<u32, KdfError> {
    value
        .parse()
        .map_err(|_| encoding(format!("invalid {field} value: {value}")))
}

fn parse_usize(field: &str, value: &str) -> Result<usize, KdfError> {
    value
        .parse()
        .map_err(|_| encoding(format!("invalid {field} value: {value}")))
}

fn set_once<T>(
    slot: &mut Option<T>,
    seen: &mut bool,
    name: &str,
    value: T,
) -> Result<(), KdfError> {
    if *seen {
        return Err(encoding(format!("duplicate {name}= parameter")));
    }
    *seen = true;
    *slot = Some(value);
    Ok(())
}

fn require_param<T>(slot: Option<T>, name: &str, desc: &str) -> Result<T, KdfError> {
    slot.ok_or_else(|| encoding(format!("missing {name}= {desc} parameter")))
}

/// Parse a stored hash. Legacy `v1` strings are rejected, not reinterpreted.
pub fn parse_hash(encoded: &str) -> Result<RawHashComponents, KdfError> {
    if encoded.len() > MAX_ENCODED_HASH_LEN {
        return Err(encoding(format!(
            "encoded hash exceeds maximum length ({MAX_ENCODED_HASH_LEN} bytes)"
        )));
    }

    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 || !parts[0].is_empty() {
        return Err(encoding("invalid hash field count"));
    }

    let algo = Algorithm::parse(parts[1])
        .ok_or_else(|| encoding(format!("unknown algorithm identifier: {}", parts[1])))?;

    if parts[2] == "v1" || parts[2] == "1" {
        return Err(encoding(
            "unsupported hash version v1 (legacy research encoding is not verified)",
        ));
    }

    let version = AlgorithmVersion::parse(parts[2])
        .ok_or_else(|| encoding(format!("unknown version identifier: {}", parts[2])))?;

    let mut memory_kib = None;
    let mut salt_len = None;
    let mut block_size = None;
    let mut fan_in = None;
    let mut graph_tag = None;
    let mut output_len = None;
    let mut secret_required = false;
    let mut associated_data_length: Option<u32> = None;

    if parts[3].len() > MAX_PARAM_SECTION_LEN {
        return Err(encoding("parameter section too long"));
    }

    let mut seen_m = false;
    let mut seen_s = false;
    let mut seen_b = false;
    let mut seen_f = false;
    let mut seen_g = false;
    let mut seen_l = false;
    let mut seen_sk = false;
    let mut seen_adl = false;

    for param_kv in parts[3].split(',') {
        let Some((k, v)) = param_kv.split_once('=') else {
            return Err(encoding(format!("invalid parameter field: {param_kv}")));
        };
        match k {
            "m" => set_once(&mut memory_kib, &mut seen_m, "m", parse_u32("m", v)?)?,
            "s" => set_once(&mut salt_len, &mut seen_s, "s", parse_usize("s", v)?)?,
            "b" => set_once(&mut block_size, &mut seen_b, "b", parse_usize("b", v)?)?,
            "f" => set_once(&mut fan_in, &mut seen_f, "f", parse_u32("f", v)?)?,
            "g" => set_once(&mut graph_tag, &mut seen_g, "g", parse_u32("g", v)?)?,
            "l" => set_once(&mut output_len, &mut seen_l, "l", parse_usize("l", v)?)?,
            "sk" => {
                if seen_sk {
                    return Err(encoding("duplicate sk= parameter"));
                }
                seen_sk = true;
                let flag = parse_u32("sk", v)?;
                if flag > 1 {
                    return Err(encoding("sk= must be 0 (unused) or 1 (secret required)"));
                }
                secret_required = flag == 1;
            }
            "adl" => {
                if seen_adl {
                    return Err(encoding("duplicate adl= parameter"));
                }
                seen_adl = true;
                let n = parse_u32("adl", v)?;
                antech_kdf_types::validate_associated_data_len(n as usize)
                    .map_err(KdfError::Config)?;
                associated_data_length = Some(n);
            }
            other => {
                return Err(encoding(format!("unknown parameter field: {other}")));
            }
        }
    }

    let memory_kib = require_param(memory_kib, "m", "memory")?;
    let salt_len = require_param(salt_len, "s", "salt length")?;
    let block_size = require_param(block_size, "b", "block size")?;
    let fan_in = require_param(fan_in, "f", "fan-in")?;
    let graph_tag = require_param(graph_tag, "g", "graph")?;
    let output_len = require_param(output_len, "l", "output length")?;

    let graph = GraphKind::from_tag(graph_tag)
        .ok_or_else(|| encoding(format!("unknown graph tag: {graph_tag}")))?;

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
        return Err(encoding(format!(
            "salt length mismatch: declared {salt_len}, actual {}",
            salt.len()
        )));
    }
    if digest.len() != output_len {
        return Err(encoding(format!(
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
        secret_required,
        associated_data_length,
        salt,
        digest,
    })
}
