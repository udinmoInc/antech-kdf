//! Optional application-held secret for derivation (never stored in the hash).

use crate::errors::ConfigError;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum secret length in bytes (typical API/HMAC keys; bounds seed-input DoS).
pub const SECRET_MAX_BYTES: usize = 1024;

/// Maximum associated-data length in bytes (public context, not secret).
pub const ASSOCIATED_DATA_MAX_BYTES: usize = 65_536;

/// Application-held confidential bytes bound into the KDF seed.
///
/// Never serialized into `$antech$v2$…` strings. `Debug` / `Display` redact contents.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Empty is allowed and is distinct from “no secret”.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, ConfigError> {
        let b = bytes.as_ref();
        validate_secret_len(b.len())?;
        Ok(Self { bytes: b.to_vec() })
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([redacted]; len={})", self.bytes.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted secret; len={}]", self.bytes.len())
    }
}

pub fn validate_secret_len(len: usize) -> Result<(), ConfigError> {
    if len > SECRET_MAX_BYTES {
        Err(ConfigError::InvalidSecretLength {
            len,
            max: SECRET_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

pub fn validate_associated_data_len(len: usize) -> Result<(), ConfigError> {
    if len > ASSOCIATED_DATA_MAX_BYTES {
        Err(ConfigError::InvalidAssociatedDataLength {
            len,
            max: ASSOCIATED_DATA_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Optional advanced inputs for a single derive / verify call.
///
/// - [`None`] = absent (legacy seed path when both are [`None`])
/// - [`Some`] with empty bytes = present but empty (bound differently)
#[derive(Clone, Default)]
pub struct DeriveInputs {
    pub secret: Option<SecretBytes>,
    pub associated_data: Option<Vec<u8>>,
}

impl DeriveInputs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_secret(mut self, secret: SecretBytes) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn with_associated_data(mut self, ad: impl AsRef<[u8]>) -> Result<Self, ConfigError> {
        let ad = ad.as_ref();
        validate_associated_data_len(ad.len())?;
        self.associated_data = Some(ad.to_vec());
        Ok(self)
    }

    pub fn has_extras(&self) -> bool {
        self.secret.is_some() || self.associated_data.is_some()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(s) = &self.secret {
            validate_secret_len(s.len())?;
        }
        if let Some(ad) = &self.associated_data {
            validate_associated_data_len(ad.len())?;
        }
        Ok(())
    }
}

impl fmt::Debug for DeriveInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeriveInputs")
            .field("secret", &self.secret.as_ref().map(|s| s.len()))
            .field(
                "associated_data_len",
                &self.associated_data.as_ref().map(|a| a.len()),
            )
            .finish()
    }
}
