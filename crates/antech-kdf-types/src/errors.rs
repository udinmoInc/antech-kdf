//! Error types for configuration, encoding, and derivation.

use std::fmt;

/// Errors returned during parameter validation or configuration building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidSaltLength {
        len: usize,
        min: usize,
        max: usize,
    },
    InvalidMemorySize {
        kib: usize,
        min_kib: usize,
        max_kib: usize,
    },
    InvalidBlockSize {
        size: usize,
    },
    InvalidFanIn {
        fan_in: u32,
    },
    InvalidOutputLength {
        len: usize,
        min: usize,
        max: usize,
    },
    InvalidParameterValue(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidSaltLength { len, min, max } => {
                write!(
                    f,
                    "salt length {len} bytes out of allowed bounds [{min}..{max}]"
                )
            }
            ConfigError::InvalidMemorySize {
                kib,
                min_kib,
                max_kib,
            } => {
                write!(
                    f,
                    "memory size {kib} KiB out of allowed bounds [{min_kib}..{max_kib} KiB]"
                )
            }
            ConfigError::InvalidBlockSize { size } => {
                write!(
                    f,
                    "block size {size} must be a power of two in {}..={} bytes",
                    crate::config::BlockSize::MIN_BYTES,
                    crate::config::BlockSize::MAX_BYTES
                )
            }
            ConfigError::InvalidFanIn { fan_in } => {
                write!(f, "fan-in {fan_in} must be in 2..=8")
            }
            ConfigError::InvalidOutputLength { len, min, max } => {
                write!(
                    f,
                    "output length {len} bytes out of allowed bounds [{min}..{max}]"
                )
            }
            ConfigError::InvalidParameterValue(msg) => {
                write!(f, "invalid parameter value: {msg}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// General KDF execution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    Config(ConfigError),
    Encoding(String),
    Derivation(String),
    ResourceExhausted(String),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::Config(err) => write!(f, "configuration error: {err}"),
            KdfError::Encoding(msg) => write!(f, "encoding error: {msg}"),
            KdfError::Derivation(msg) => write!(f, "derivation error: {msg}"),
            KdfError::ResourceExhausted(msg) => write!(f, "resource exhausted: {msg}"),
        }
    }
}

impl std::error::Error for KdfError {}

impl From<ConfigError> for KdfError {
    fn from(err: ConfigError) -> Self {
        KdfError::Config(err)
    }
}
