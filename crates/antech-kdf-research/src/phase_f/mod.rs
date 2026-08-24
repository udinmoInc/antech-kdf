//! Phase F formal Candidate-004 research KDF engine and parameter definitions.

pub mod cand_004_core;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Parameters for Candidate-004 symmetric research KDF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResearchParams {
    pub memory_kib: u32,
    pub passes: u32,
    pub dependency_depth: u32,
    pub block_size: u32,
}

impl Default for ResearchParams {
    fn default() -> Self {
        Self {
            memory_kib: 16384, // 16 MiB
            passes: 1,
            dependency_depth: 120,
            block_size: 32,
        }
    }
}

/// Errors returned during research KDF operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResearchError {
    InvalidParameters(String),
    EncodingError(String),
    DerivationError(String),
}

impl fmt::Display for ResearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResearchError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            ResearchError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            ResearchError::DerivationError(msg) => write!(f, "Derivation error: {}", msg),
        }
    }
}

impl std::error::Error for ResearchError {}

/// Internal research KDF trait.
pub(crate) trait ResearchKdf: Sync + Send {
    fn name(&self) -> &'static str;
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError>;
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
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

/// Formats encoded hash string: `$antech$v1$m=16384,t=120,p=1$<salt_hex>$<digest_hex>`
pub fn encode_research_hash(
    params: &ResearchParams,
    salt: &[u8],
    digest: &[u8],
) -> String {
    format!(
        "$antech$v1$m={},t={},p={}${}${}",
        params.memory_kib,
        params.dependency_depth,
        params.passes,
        hex_encode(salt),
        hex_encode(digest)
    )
}

/// Parses an encoded research hash string into (params, salt, digest).
pub fn parse_research_hash(
    encoded: &str,
) -> Result<(ResearchParams, Vec<u8>, Vec<u8>), ResearchError> {
    let parts: Vec<&str> = encoded.split('$').collect();
    if parts.len() != 6 || parts[1] != "antech" || parts[2] != "v1" {
        return Err(ResearchError::EncodingError(
            "Invalid Antech research hash header".to_string(),
        ));
    }

    let mut memory_kib = 16384;
    let mut dependency_depth = 120;
    let mut passes = 1;

    for param_kv in parts[3].split(',') {
        let kv: Vec<&str> = param_kv.split('=').collect();
        if kv.len() == 2 {
            match kv[0] {
                "m" => memory_kib = kv[1].parse().unwrap_or(16384),
                "t" => dependency_depth = kv[1].parse().unwrap_or(120),
                "p" => passes = kv[1].parse().unwrap_or(1),
                _ => {}
            }
        }
    }

    let salt = hex_decode(parts[4])
        .map_err(|e| ResearchError::EncodingError(format!("Invalid salt hex: {}", e)))?;
    let digest = hex_decode(parts[5])
        .map_err(|e| ResearchError::EncodingError(format!("Invalid digest hex: {}", e)))?;

    let params = ResearchParams {
        memory_kib,
        passes,
        dependency_depth,
        block_size: 32,
    };

    Ok((params, salt, digest))
}
