//! Shared data types for Antech KDF.
//!
//! Internal types shared between format, core, and engine crates.

use std::fmt;

/// Algorithm version enum for self-describing hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum AlgorithmVersion {
    /// Initial experimental version V1.
    #[default]
    V1 = 1,
}

impl AlgorithmVersion {
    /// Return standard identifier string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AlgorithmVersion::V1 => "v1",
        }
    }

    /// Parse version from string identifier.
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

/// Extracted components from a serialized password hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHashComponents {
    /// Algorithm version.
    pub version: AlgorithmVersion,
    /// Memory allocation parameter in KiB.
    pub memory_kib: u32,
    /// Time cost parameter (iterations/rounds).
    pub time_cost: u32,
    /// Parallelism factor (lanes).
    pub parallelism: u32,
    /// Target bandwidth in MB/s.
    pub bandwidth_target: u64,
    /// Salt raw bytes.
    pub salt: Vec<u8>,
    /// Derived key digest raw bytes.
    pub digest: Vec<u8>,
}
