//! Cryptographically secure salt generation routines.

use crate::error::CoreError;
use zeroize::Zeroizing;

/// Standard salt length in bytes (128 bits).
pub const RECOMMENDED_SALT_LEN: usize = 16;

/// Generates a cryptographically secure random salt of default length.
pub fn generate_salt() -> Result<Vec<u8>, CoreError> {
    generate_salt_with_len(RECOMMENDED_SALT_LEN)
}

/// Generates a cryptographically secure random salt of specific byte length.
pub fn generate_salt_with_len(len: usize) -> Result<Vec<u8>, CoreError> {
    if len < 8 {
        return Err(CoreError::InvalidParameters);
    }
    let mut salt = Zeroizing::new(vec![0u8; len]);
    getrandom::getrandom(&mut salt).map_err(|_| CoreError::SaltGenerationFailed)?;
    Ok(salt.to_vec())
}
