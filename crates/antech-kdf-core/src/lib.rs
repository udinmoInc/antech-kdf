//! Core execution engines, resource scheduler, and traits for Antech KDF.

pub mod engine;
pub mod resource;
pub mod traits;

pub use engine::{Candidate004Engine, KdfProvider};
pub use resource::{BoundedResourceScheduler, ResourcePolicy};
pub use traits::{KdfEngine, ResourcePermit, ResourceScheduler};

use antech_kdf_format::{encode_hash, parse_hash};
use antech_kdf_types::{AntechConfig, KdfError, RehashPolicy};
use rand::RngCore;

/// Execute password hashing with an explicit `AntechConfig`.
pub fn core_hash_with_config(password: &[u8], config: &AntechConfig) -> Result<String, KdfError> {
    config.validate()?;

    // 1. Generate cryptographically secure random salt of configured length
    let mut salt = vec![0u8; config.salt_length.as_bytes()];
    rand::thread_rng().fill_bytes(&mut salt);

    // 2. Select algorithm provider engine
    let engine = KdfProvider::get_engine(config.algorithm)?;

    // 3. Acquire resource permit from default scheduler
    let scheduler = BoundedResourceScheduler::default_scheduler();
    let permit = scheduler.acquire(config.memory.as_kib())?;

    // 4. Execute derivation
    let digest = engine.derive(password, &salt, config)?;

    // 5. Release permit
    scheduler.release(permit);

    // 6. Encode into self-describing hash string
    encode_hash(config, &salt, &digest).map_err(KdfError::Config)
}

/// Verify a password against a stored self-describing hash string in constant time.
pub fn core_verify(password: &[u8], encoded_hash: &str) -> Result<bool, KdfError> {
    // 1. Parse stored hash string into components
    let components = parse_hash(encoded_hash)?;

    // 2. Reconstruct configuration from parsed hash string
    let config = AntechConfig::builder()
        .algorithm(components.algorithm)
        .memory_kib(components.memory_kib as usize)
        .salt_length(components.salt_len)
        .dependency_depth(components.dependency_depth)
        .passes(components.passes)
        .block_size(components.block_size)
        .output_length(components.output_len)
        .build()?;

    // 3. Select algorithm provider engine
    let engine = KdfProvider::get_engine(config.algorithm)?;

    // 4. Derive candidate digest
    let candidate_digest = engine.derive(password, &components.salt, &config)?;

    // 5. Constant-time digest comparison
    if candidate_digest.len() != components.digest.len() {
        return Ok(false);
    }

    let is_valid = subtle::ConstantTimeEq::ct_eq(&candidate_digest[..], &components.digest[..]);
    Ok(is_valid.into())
}

/// Check if a stored hash needs re-hashing against a target `RehashPolicy`.
pub fn core_needs_rehash_with_policy(
    encoded_hash: &str,
    policy: &RehashPolicy,
) -> Result<bool, KdfError> {
    let components = parse_hash(encoded_hash)?;
    let config = AntechConfig::builder()
        .algorithm(components.algorithm)
        .memory_kib(components.memory_kib as usize)
        .salt_length(components.salt_len)
        .dependency_depth(components.dependency_depth)
        .passes(components.passes)
        .block_size(components.block_size)
        .output_length(components.output_len)
        .build()?;

    Ok(policy.needs_rehash(&config))
}
