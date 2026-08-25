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

pub fn core_hash_with_config(password: &[u8], config: &AntechConfig) -> Result<String, KdfError> {
    config.validate()?;

    let mut salt = vec![0u8; config.salt_length.as_bytes()];
    rand::thread_rng().fill_bytes(&mut salt);

    let engine = KdfProvider::get_engine(config.algorithm)?;

    let scheduler = BoundedResourceScheduler::default_scheduler();
    let permit = scheduler.acquire(config.memory.as_kib())?;

    let digest = engine.derive(password, &salt, config)?;
    scheduler.release(permit);

    encode_hash(config, &salt, &digest).map_err(KdfError::Config)
}

pub fn core_verify(password: &[u8], encoded_hash: &str) -> Result<bool, KdfError> {
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

    let engine = KdfProvider::get_engine(config.algorithm)?;
    let candidate_digest = engine.derive(password, &components.salt, &config)?;

    if candidate_digest.len() != components.digest.len() {
        return Ok(false);
    }

    let is_valid = subtle::ConstantTimeEq::ct_eq(&candidate_digest[..], &components.digest[..]);
    Ok(is_valid.into())
}

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
