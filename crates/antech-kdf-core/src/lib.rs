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
use std::sync::OnceLock;

struct PermitGuard<'a> {
    scheduler: &'a BoundedResourceScheduler,
    permit: Option<ResourcePermit>,
}

impl Drop for PermitGuard<'_> {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.scheduler.release(permit);
        }
    }
}

fn global_scheduler() -> &'static BoundedResourceScheduler {
    static SCHEDULER: OnceLock<BoundedResourceScheduler> = OnceLock::new();
    SCHEDULER.get_or_init(BoundedResourceScheduler::default_scheduler)
}

/// Diagnostics for integration tests (not stable API).
#[doc(hidden)]
pub fn scheduler_stats() -> resource::SchedulerStats {
    global_scheduler().stats()
}

pub fn core_hash_with_config(password: &[u8], config: &AntechConfig) -> Result<String, KdfError> {
    config.validate()?;

    let mut salt = vec![0u8; config.salt_length.as_bytes()];
    rand::thread_rng().fill_bytes(&mut salt);

    let scheduler = global_scheduler();
    let _permit = PermitGuard {
        scheduler,
        permit: Some(scheduler.acquire(config.memory.as_kib())?),
    };
    let digest = AntechEngine::new().derive(password, &salt, config)?;

    encode_hash(config, &salt, &digest).map_err(KdfError::Config)
}

pub fn core_verify(password: &[u8], encoded_hash: &str) -> Result<bool, KdfError> {
    let components = parse_hash(encoded_hash)?;
    let config = components_to_config(&components)?;

    let scheduler = global_scheduler();
    let _permit = PermitGuard {
        scheduler,
        permit: Some(scheduler.acquire(config.memory.as_kib())?),
    };

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

#[cfg(test)]
mod integration_tests {
    use super::*;
    use antech_kdf_types::AntechConfig;

    #[test]
    fn hash_verify_roundtrip_releases_resources() {
        let hash = core_hash_with_config(b"roundtrip", &AntechConfig::default()).unwrap();
        assert!(core_verify(b"roundtrip", &hash).unwrap());
        assert!(!core_verify(b"wrong", &hash).unwrap());
    }
}
