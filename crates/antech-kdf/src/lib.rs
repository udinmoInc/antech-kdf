//! Antech KDF — password hashing and verification.
//!
//! # Overview
//!
//! This crate exposes a stable API for hashing and verifying passwords using the
//! current Antech compute-memory construction.
//!
//! # Security status
//!
//! The implementation reflects the project's latest validated construction and
//! benchmark results. **It has not undergone independent cryptographic review**
//! and must not be treated as production-proven merely because benchmarks pass.
//!
//! # Examples
//!
//! ```
//! let stored = antech_kdf::hash("correct_horse_battery_staple")?;
//! assert!(antech_kdf::verify("correct_horse_battery_staple", &stored)?);
//! # Ok::<(), antech_kdf::Error>(())
//! ```

pub use antech_kdf_types::{
    AntechConfig, AntechConfigBuilder, BlockSize, ConfigError, FanIn, GraphKind, KdfError as Error,
    MemorySize, OutputLength, RehashPolicy, RehashPolicyBuilder, SaltLength,
};

use antech_kdf_core::{
    core_hash_with_config, core_hash_with_config_and_salt, core_needs_rehash_with_policy,
    core_verify,
};

/// Hashes a password using default parameters (16 MiB, combined-frontier graph).
pub fn hash(password: impl AsRef<[u8]>) -> Result<String, Error> {
    hash_with_config(password, &AntechConfig::default())
}

/// Hashes a password using an explicit configuration profile.
pub fn hash_with_config(
    password: impl AsRef<[u8]>,
    config: &AntechConfig,
) -> Result<String, Error> {
    core_hash_with_config(password.as_ref(), config)
}

/// Hashes a password with an explicit salt (must match `config.salt_length`).
///
/// Prefer [`hash_with_config`] for production use (random salt). This helper is for
/// deterministic test vectors and interoperability checks.
pub fn hash_with_config_and_salt(
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    config: &AntechConfig,
) -> Result<String, Error> {
    core_hash_with_config_and_salt(password.as_ref(), salt.as_ref(), config)
}

/// Verifies a password against a stored self-describing hash string in constant time.
pub fn verify(password: impl AsRef<[u8]>, encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    core_verify(password.as_ref(), encoded_hash.as_ref())
}

/// Evaluates whether a stored hash satisfies the default rehash policy.
pub fn needs_rehash(encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    needs_rehash_with_policy(encoded_hash, &RehashPolicy::default())
}

/// Evaluates whether a stored hash satisfies a caller-defined rehash policy.
pub fn needs_rehash_with_policy(
    encoded_hash: impl AsRef<str>,
    policy: &RehashPolicy,
) -> Result<bool, Error> {
    core_needs_rehash_with_policy(encoded_hash.as_ref(), policy)
}
