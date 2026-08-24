//! Public developer API crate for Antech KDF.
//!
//! Exposes clean, simple functions for default hashing and verification, as well
//! as advanced APIs for custom parameter configurations and rehash policies.

pub use antech_kdf_types::{
    Algorithm, AntechConfig, AntechConfigBuilder, BlockSize, ConfigError, DependencyDepth,
    KdfError as Error, MemorySize, OutputLength, Parallelism, PassCount, RehashPolicy,
    RehashPolicyBuilder, SaltLength,
};

use antech_kdf_core::{core_hash_with_config, core_needs_rehash_with_policy, core_verify};

/// Hash a password using recommended default configuration parameters.
pub fn hash(password: impl AsRef<[u8]>) -> Result<String, Error> {
    let config = AntechConfig::default();
    hash_with_config(password, &config)
}

/// Hash a password using an explicit custom `AntechConfig`.
pub fn hash_with_config(
    password: impl AsRef<[u8]>,
    config: &AntechConfig,
) -> Result<String, Error> {
    core_hash_with_config(password.as_ref(), config)
}

/// Verify a password against a stored self-describing hash string in constant time.
pub fn verify(password: impl AsRef<[u8]>, encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    core_verify(password.as_ref(), encoded_hash.as_ref())
}

/// Check if a stored hash string is obsolete against default application rehash policy.
pub fn needs_rehash(encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    let policy = RehashPolicy::default();
    needs_rehash_with_policy(encoded_hash, &policy)
}

/// Check if a stored hash string is obsolete against a custom `RehashPolicy`.
pub fn needs_rehash_with_policy(
    encoded_hash: impl AsRef<str>,
    policy: &RehashPolicy,
) -> Result<bool, Error> {
    core_needs_rehash_with_policy(encoded_hash.as_ref(), policy)
}
