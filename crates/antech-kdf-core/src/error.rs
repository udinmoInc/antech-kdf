//! Core error types for Antech KDF internal operations.

use thiserror::Error;

/// Error type returned by Antech KDF core functions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    /// Formatted hash string is invalid or malformed
    #[error("Invalid hash format")]
    InvalidHash,

    /// Algorithm version is unsupported by this build
    #[error("Unsupported algorithm version")]
    UnsupportedVersion,

    /// Encoding or decoding failed
    #[error("Invalid hash encoding")]
    InvalidEncoding,

    /// Hash parameters are invalid or out of acceptable bounds
    #[error("Invalid algorithm parameters")]
    InvalidParameters,

    /// Cryptographic salt generation failed
    #[error("Salt generation failed")]
    SaltGenerationFailed,

    /// Internal engine error or cryptographic computation failure
    #[error("Internal algorithm failure")]
    InternalFailure,
}

impl From<antech_kdf_format::FormatError> for CoreError {
    fn from(err: antech_kdf_format::FormatError) -> Self {
        match err {
            antech_kdf_format::FormatError::InvalidPrefix => CoreError::InvalidHash,
            antech_kdf_format::FormatError::InvalidEncoding => CoreError::InvalidEncoding,
            antech_kdf_format::FormatError::UnsupportedVersion(_) => CoreError::UnsupportedVersion,
            antech_kdf_format::FormatError::InvalidBase64 => CoreError::InvalidEncoding,
            antech_kdf_format::FormatError::InvalidParameter(_) => CoreError::InvalidParameters,
        }
    }
}
