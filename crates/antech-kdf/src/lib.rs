//! Antech KDF developer API.
//!
//! Provides password hashing and verification functions with support for custom
//! configurations and rehash policies.

pub use antech_kdf_types::{
    Algorithm, AntechConfig, AntechConfigBuilder, BlockSize, ConfigError, DependencyDepth,
    KdfError as Error, MemorySize, OutputLength, Parallelism, PassCount, RehashPolicy,
    RehashPolicyBuilder, SaltLength,
};

use antech_kdf_core::{core_hash_with_config, core_needs_rehash_with_policy, core_verify};

/// Hashes a password using default parameters.
///
/// # Examples
///
/// ```
/// let hash_string = antech_kdf::hash("correct_horse_battery_staple")?;
/// # Ok::<(), antech_kdf::Error>(())
/// ```
pub fn hash(password: impl AsRef<[u8]>) -> Result<String, Error> {
    let config = AntechConfig::default();
    hash_with_config(password, &config)
}

/// Hashes a password using an explicit configuration profile.
///
/// # Examples
///
/// ```
/// use antech_kdf::AntechConfig;
///
/// let config = AntechConfig::builder()
///     .salt_length(32)
///     .memory_mib(24)
///     .build()?;
///
/// let hash_string = antech_kdf::hash_with_config("password", &config)?;
/// # Ok::<(), antech_kdf::Error>(())
/// ```
pub fn hash_with_config(
    password: impl AsRef<[u8]>,
    config: &AntechConfig,
) -> Result<String, Error> {
    core_hash_with_config(password.as_ref(), config)
}

/// Verifies a password against a stored self-describing hash string in constant time.
///
/// # Examples
///
/// ```
/// let stored = antech_kdf::hash("my_password")?;
/// let valid = antech_kdf::verify("my_password", &stored)?;
/// assert!(valid);
/// # Ok::<(), antech_kdf::Error>(())
/// ```
pub fn verify(password: impl AsRef<[u8]>, encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    core_verify(password.as_ref(), encoded_hash.as_ref())
}

/// Evaluates whether a stored hash string satisfies default rehash policies.
pub fn needs_rehash(encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    let policy = RehashPolicy::default();
    needs_rehash_with_policy(encoded_hash, &policy)
}

/// Evaluates whether a stored hash string satisfies a target rehash policy.
pub fn needs_rehash_with_policy(
    encoded_hash: impl AsRef<str>,
    policy: &RehashPolicy,
) -> Result<bool, Error> {
    core_needs_rehash_with_policy(encoded_hash.as_ref(), policy)
}
