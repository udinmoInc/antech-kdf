//! Error types for configuration, encoding, and derivation.

use std::fmt;

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
    InvalidSecretLength {
        len: usize,
        max: usize,
    },
    InvalidAssociatedDataLength {
        len: usize,
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
            ConfigError::InvalidSecretLength { len, max } => {
                write!(
                    f,
                    "secret length {len} bytes exceeds maximum of {max} bytes"
                )
            }
            ConfigError::InvalidAssociatedDataLength { len, max } => {
                write!(
                    f,
                    "associated data length {len} bytes exceeds maximum of {max} bytes"
                )
            }
            ConfigError::InvalidParameterValue(msg) => {
                write!(f, "invalid parameter value: {msg}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    Config(ConfigError),
    Encoding(String),
    Derivation(String),
    ResourceExhausted(String),
    /// Stored hash requires a secret; caller did not provide one.
    MissingSecret,
    /// Stored hash requires associated data; caller did not provide it.
    MissingAssociatedData,
    AssociatedDataLengthMismatch {
        expected: usize,
        got: usize,
    },
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::Config(err) => write!(f, "configuration error: {err}"),
            KdfError::Encoding(msg) => write!(f, "encoding error: {msg}"),
            KdfError::Derivation(msg) => write!(f, "derivation error: {msg}"),
            KdfError::ResourceExhausted(msg) => write!(f, "resource exhausted: {msg}"),
            KdfError::MissingSecret => write!(
                f,
                "verification requires an application secret; none was provided"
            ),
            KdfError::MissingAssociatedData => write!(
                f,
                "verification requires associated data; none was provided"
            ),
            KdfError::AssociatedDataLengthMismatch { expected, got } => write!(
                f,
                "associated data length mismatch: expected {expected} bytes, got {got}"
            ),
        }
    }
}

impl std::error::Error for KdfError {}

impl From<ConfigError> for KdfError {
    fn from(err: ConfigError) -> Self {
        KdfError::Config(err)
    }
}
