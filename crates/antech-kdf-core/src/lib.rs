//! Internal core engine implementation for Antech KDF.
//!
//! Handles salt generation, internal parameter selection, KDF engine dispatch,
//! self-describing formatting, constant-time verification, and rehash checks.

pub mod bandwidth;
pub mod compare;
pub mod dependency;
pub mod engine;
pub mod error;
pub mod memory;
pub mod params;
pub mod salt;
pub mod version;

use crate::compare::constant_time_compare;
use crate::engine::{KdfEngine, PlaceholderKdfEngine};
pub use crate::error::CoreError;
use crate::params::InternalParams;
use crate::salt::generate_salt;
use crate::version::check_needs_rehash;

use antech_kdf_format::{encode_hash, parse_hash};
use antech_kdf_types::{AlgorithmVersion, RawHashComponents};

/// Hashes a password using default recommended parameters and secure salt.
pub fn core_hash(password: &[u8]) -> Result<String, CoreError> {
    let salt = generate_salt()?;
    let params = InternalParams::current_parameters();
    let version = AlgorithmVersion::V1;

    let digest = PlaceholderKdfEngine::derive(password, &salt, &params)?;

    let components = RawHashComponents {
        version,
        memory_kib: params.memory_kib,
        time_cost: params.time_cost,
        parallelism: params.parallelism,
        bandwidth_target: params.bandwidth_target,
        salt,
        digest,
    };

    encode_hash(&components).map_err(Into::into)
}

/// Verifies a password against an encoded hash string.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, or `Err(CoreError)` on malformed input.
pub fn core_verify(password: &[u8], encoded_hash: &str) -> Result<bool, CoreError> {
    let components = parse_hash(encoded_hash)?;

    let params = InternalParams {
        memory_kib: components.memory_kib,
        time_cost: components.time_cost,
        parallelism: components.parallelism,
        bandwidth_target: components.bandwidth_target,
    };

    let expected_digest = match components.version {
        AlgorithmVersion::V1 => PlaceholderKdfEngine::derive(password, &components.salt, &params)?,
    };

    Ok(constant_time_compare(&expected_digest, &components.digest))
}

/// Checks whether a stored hash requires rehashing due to version or parameter changes.
pub fn core_needs_rehash(encoded_hash: &str) -> Result<bool, CoreError> {
    let components = parse_hash(encoded_hash)?;
    Ok(check_needs_rehash(&components))
}
