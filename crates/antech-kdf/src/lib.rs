//! # Antech KDF
//!
//! Antech KDF is an experimental, bandwidth-hard password Key Derivation Function (KDF) research project.
//!
//! ## Minimal Developer API
//!
//! Antech KDF provides an extremely simple public API. Salt generation, memory parameters,
//! version dispatch, encoding, and constant-time verification are managed automatically.
//!
//! ```rust
//! use antech_kdf::{hash, verify, needs_rehash};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let stored = hash("my super secret password")?;
//!
//! let is_valid = verify("my super secret password", &stored)?;
//! assert!(is_valid);
//!
//! let rehash_needed = needs_rehash(&stored)?;
//! assert!(!rehash_needed);
//! # Ok(())
//! # }
//! ```

use antech_kdf_core::CoreError;
use thiserror::Error;

/// Public error type returned by Antech KDF operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Stored password hash string is invalid or malformed
    #[error("Invalid password hash format")]
    InvalidHash,

    /// Stored password hash uses an unsupported algorithm version
    #[error("Unsupported hash version")]
    UnsupportedVersion,

    /// Stored password hash encoding is corrupted or invalid
    #[error("Invalid hash encoding")]
    InvalidEncoding,

    /// Stored hash parameters are out of allowed bounds
    #[error("Invalid hash parameters")]
    InvalidParameters,

    /// Internal engine error or cryptographic computation failure
    #[error("Internal algorithm failure")]
    InternalFailure,
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::InvalidHash => Error::InvalidHash,
            CoreError::UnsupportedVersion => Error::UnsupportedVersion,
            CoreError::InvalidEncoding => Error::InvalidEncoding,
            CoreError::InvalidParameters => Error::InvalidParameters,
            CoreError::SaltGenerationFailed => Error::InternalFailure,
            CoreError::InternalFailure => Error::InternalFailure,
        }
    }
}

/// Hashes a password using recommended default parameters and a secure random salt.
///
/// Returns a self-describing encoded hash string.
///
/// # Example
/// ```
/// use antech_kdf::hash;
/// let encoded = hash("my password").unwrap();
/// assert!(encoded.starts_with("$antech$v1$"));
/// ```
pub fn hash(password: impl AsRef<[u8]>) -> Result<String, Error> {
    antech_kdf_core::core_hash(password.as_ref()).map_err(Into::into)
}

/// Verifies a password against a stored self-describing encoded hash.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if password does not match, or `Err(Error)` if the hash is malformed.
///
/// # Example
/// ```
/// use antech_kdf::{hash, verify};
/// let encoded = hash("my password").unwrap();
/// assert_eq!(verify("my password", &encoded).unwrap(), true);
/// assert_eq!(verify("wrong password", &encoded).unwrap(), false);
/// ```
pub fn verify(
    password: impl AsRef<[u8]>,
    encoded_hash: impl AsRef<str>,
) -> Result<bool, Error> {
    antech_kdf_core::core_verify(password.as_ref(), encoded_hash.as_ref()).map_err(Into::into)
}

/// Determines whether a stored hash should be upgraded/re-hashed due to version or parameter changes.
///
/// # Example
/// ```
/// use antech_kdf::{hash, needs_rehash};
/// let encoded = hash("my password").unwrap();
/// assert_eq!(needs_rehash(&encoded).unwrap(), false);
/// ```
pub fn needs_rehash(
    encoded_hash: impl AsRef<str>,
) -> Result<bool, Error> {
    antech_kdf_core::core_needs_rehash(encoded_hash.as_ref()).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify_flow() {
        let password = "correct_horse_battery_staple";
        let encoded = hash(password).unwrap();
        assert!(encoded.starts_with("$antech$v1$"));

        let valid = verify(password, &encoded).unwrap();
        assert!(valid);

        let invalid = verify("wrong_password", &encoded).unwrap();
        assert!(!invalid);

        let rehash = needs_rehash(&encoded).unwrap();
        assert!(!rehash);
    }

    #[test]
    fn test_malformed_hash_returns_error() {
        let malformed = "$antech$v1$invalid_params$salt$digest";
        let res = verify("password", malformed);
        assert!(res.is_err());
    }
}
