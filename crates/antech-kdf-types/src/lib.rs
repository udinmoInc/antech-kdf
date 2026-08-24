//! Shared data types, configuration types, and error definitions for Antech KDF.

pub mod algorithm;
pub mod config;
pub mod errors;
pub mod rehash;

pub use algorithm::Algorithm;
pub use config::{
    AntechConfig, AntechConfigBuilder, BlockSize, DependencyDepth, MemorySize, OutputLength,
    Parallelism, PassCount, SaltLength,
};
pub use errors::{ConfigError, KdfError};
pub use rehash::{RehashPolicy, RehashPolicyBuilder};

use std::fmt;

/// Algorithm version enum for self-describing hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum AlgorithmVersion {
    /// Initial version V1.
    #[default]
    V1 = 1,
}

impl AlgorithmVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlgorithmVersion::V1 => "v1",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "v1" | "1" => Some(AlgorithmVersion::V1),
            _ => None,
        }
    }
}

impl fmt::Display for AlgorithmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Extracted components from a self-describing password hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHashComponents {
    pub version: AlgorithmVersion,
    pub algorithm: Algorithm,
    pub memory_kib: u32,
    pub salt_len: usize,
    pub dependency_depth: u32,
    pub passes: u32,
    pub block_size: usize,
    pub output_len: usize,
    pub salt: Vec<u8>,
    pub digest: Vec<u8>,
}
