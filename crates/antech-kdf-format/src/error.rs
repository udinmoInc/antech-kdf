//! Error types for hash string parsing and encoding.

use thiserror::Error;

/// Format errors returned during hash parsing or encoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    /// Provided string does not start with expected prefix `$antech$`
    #[error("Invalid hash prefix")]
    InvalidPrefix,

    /// Encoding format is malformed or missing sections
    #[error("Invalid hash encoding format")]
    InvalidEncoding,

    /// Algorithm version in hash string is unsupported
    #[error("Unsupported algorithm version: {0}")]
    UnsupportedVersion(String),

    /// Base64 decoding failed for salt or digest
    #[error("Base64 decoding failed")]
    InvalidBase64,

    /// Parameter field failed to parse
    #[error("Invalid parameter field: {0}")]
    InvalidParameter(String),
}
