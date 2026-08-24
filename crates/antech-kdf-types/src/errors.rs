//! Error types for Antech KDF configuration, validation, and execution.

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
    InvalidPassCount {
        passes: u32,
    },
    InvalidDependencyDepth {
        depth: u32,
    },
    InvalidBlockSize {
        size: usize,
    },
    InvalidParallelism {
        lanes: u32,
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
                    "Salt length {} bytes out of allowed bounds [{}..{}]",
                    len, min, max
                )
            }
            ConfigError::InvalidMemorySize {
                kib,
                min_kib,
                max_kib,
            } => {
                write!(
                    f,
                    "Memory size {} KiB out of allowed bounds [{}..{} KiB]",
                    kib, min_kib, max_kib
                )
            }
            ConfigError::InvalidPassCount { passes } => {
                write!(f, "Pass count {} must be >= 1", passes)
            }
            ConfigError::InvalidDependencyDepth { depth } => {
                write!(f, "Dependency depth {} must be >= 10", depth)
            }
            ConfigError::InvalidBlockSize { size } => {
                write!(f, "Block size {} must be power of 2 and >= 16 bytes", size)
            }
            ConfigError::InvalidParallelism { lanes } => {
                write!(f, "Parallelism {} must be >= 1", lanes)
            }
            ConfigError::InvalidOutputLength { len, min, max } => {
                write!(
                    f,
                    "Output length {} bytes out of allowed bounds [{}..{}]",
                    len, min, max
                )
            }
            ConfigError::InvalidParameterValue(msg) => {
                write!(f, "Invalid parameter value: {}", msg)
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
            KdfError::Config(err) => write!(f, "Configuration error: {}", err),
            KdfError::Encoding(msg) => write!(f, "Encoding error: {}", msg),
            KdfError::Derivation(msg) => write!(f, "Derivation error: {}", msg),
            KdfError::ResourceExhausted(msg) => write!(f, "Resource exhausted: {}", msg),
        }
    }
}

impl std::error::Error for KdfError {}

impl From<ConfigError> for KdfError {
    fn from(err: ConfigError) -> Self {
        KdfError::Config(err)
    }
}
