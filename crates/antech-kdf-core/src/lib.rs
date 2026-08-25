//! Core execution engine, resource scheduler, and hash helpers.
//!
//! # Security notice
//!
//! Passing benchmarks does **not** establish cryptographic security. Independent
//! review is required before relying on this construction for password storage.

pub mod config;
pub mod engine;
pub mod graph;
pub mod memory;
pub mod mixing;
pub mod resource;
pub mod state;
pub mod traits;

pub use config::{
    CONSTRUCTION_VERSION, DEFAULT_BLOCK_SIZE, DEFAULT_FAN_IN, DEFAULT_MEMORY_KIB, FRONTIER_WIDTH,
    MIX_ROUNDS, TILE_BLOCKS,
};
pub use engine::AntechEngine;
pub use resource::{BoundedResourceScheduler, ResourcePolicy};
pub use traits::{KdfEngine, ResourcePermit, ResourceScheduler};

use antech_kdf_format::{encode_hash, parse_hash};
use antech_kdf_types::{AntechConfig, KdfError, RehashPolicy};
use rand::RngCore;

pub fn core_hash_with_config(password: &[u8], config: &AntechConfig) -> Result<String, KdfError> {
    config.validate()?;

    let mut salt = vec![0u8; config.salt_length.as_bytes()];
    rand::thread_rng().fill_bytes(&mut salt);

    let scheduler = BoundedResourceScheduler::default_scheduler();
    let permit = scheduler.acquire(config.memory.as_kib())?;
    let digest = AntechEngine::new().derive(password, &salt, config)?;
    scheduler.release(permit);

    encode_hash(config, &salt, &digest).map_err(KdfError::Config)
}

pub fn core_verify(password: &[u8], encoded_hash: &str) -> Result<bool, KdfError> {
    let components = parse_hash(encoded_hash)?;
    let config = components_to_config(&components)?;
    let candidate_digest = AntechEngine::new().derive(password, &components.salt, &config)?;

    if candidate_digest.len() != components.digest.len() {
        return Ok(false);
    }

    Ok(subtle::ConstantTimeEq::ct_eq(&candidate_digest[..], &components.digest[..]).into())
}

pub fn core_needs_rehash_with_policy(
    encoded_hash: &str,
    policy: &RehashPolicy,
) -> Result<bool, KdfError> {
    let components = parse_hash(encoded_hash)?;
    let config = components_to_config(&components)?;
    Ok(policy.needs_rehash(&config))
}

fn components_to_config(
    components: &antech_kdf_types::RawHashComponents,
) -> Result<AntechConfig, KdfError> {
    AntechConfig::builder()
        .algorithm(components.algorithm)
        .memory_kib(components.memory_kib as usize)
        .salt_length(components.salt_len)
        .block_size(components.block_size)
        .fan_in(components.fan_in)
        .graph(components.graph)
        .output_length(components.output_len)
        .build()
        .map_err(KdfError::Config)
}
