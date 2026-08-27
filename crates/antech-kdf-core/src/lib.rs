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
use antech_kdf_types::{AntechConfig, DeriveInputs, KdfError};
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

fn with_permit<T>(
    memory_kib: usize,
    f: impl FnOnce() -> Result<T, KdfError>,
) -> Result<T, KdfError> {
    let scheduler = global_scheduler();
    let _permit = PermitGuard {
        scheduler,
        permit: Some(scheduler.acquire(memory_kib)?),
    };
    f()
}

/// Markers always match what was cryptographically bound; secret/AD bytes are never stored.
fn config_with_input_markers(config: &AntechConfig, inputs: &DeriveInputs) -> AntechConfig {
    let mut cfg = *config;
    cfg.secret_required = inputs.secret.is_some();
    cfg.associated_data_length = inputs.associated_data.as_ref().map(|a| a.len() as u32);
    cfg
}

fn check_verify_inputs(config: &AntechConfig, inputs: &DeriveInputs) -> Result<(), KdfError> {
    if config.secret_required && inputs.secret.is_none() {
        return Err(KdfError::MissingSecret);
    }
    if let Some(expected) = config.associated_data_length {
        match &inputs.associated_data {
            None => return Err(KdfError::MissingAssociatedData),
            Some(ad) if ad.len() != expected as usize => {
                return Err(KdfError::AssociatedDataLengthMismatch {
                    expected: expected as usize,
                    got: ad.len(),
                });
            }
            Some(_) => {}
        }
    }
    Ok(())
}

pub fn core_hash_with_config(password: &[u8], config: &AntechConfig) -> Result<String, KdfError> {
    core_hash_with_config_and_inputs(password, config, &DeriveInputs::default())
}

pub fn core_hash_with_config_and_inputs(
    password: &[u8],
    config: &AntechConfig,
    inputs: &DeriveInputs,
) -> Result<String, KdfError> {
    config.validate()?;
    inputs.validate()?;

    let mut salt = vec![0u8; config.salt_length.as_bytes()];
    rand::thread_rng().fill_bytes(&mut salt);

    core_hash_with_config_salt_and_inputs(password, &salt, config, inputs)
}

/// Deterministic hashing for KATs; production callers should prefer random-salt helpers.
pub fn core_hash_with_config_and_salt(
    password: &[u8],
    salt: &[u8],
    config: &AntechConfig,
) -> Result<String, KdfError> {
    core_hash_with_config_salt_and_inputs(password, salt, config, &DeriveInputs::default())
}

pub fn core_hash_with_config_salt_and_inputs(
    password: &[u8],
    salt: &[u8],
    config: &AntechConfig,
    inputs: &DeriveInputs,
) -> Result<String, KdfError> {
    config.validate()?;
    inputs.validate()?;
    if salt.len() != config.salt_length.as_bytes() {
        return Err(KdfError::Config(
            antech_kdf_types::ConfigError::InvalidSaltLength {
                len: salt.len(),
                min: config.salt_length.as_bytes(),
                max: config.salt_length.as_bytes(),
            },
        ));
    }

    let encode_cfg = config_with_input_markers(config, inputs);
    encode_cfg.validate()?;

    with_permit(encode_cfg.memory.as_kib(), || {
        let digest = AntechEngine::new().derive_with_inputs(password, salt, &encode_cfg, inputs)?;
        encode_hash(&encode_cfg, salt, &digest).map_err(KdfError::Config)
    })
}

pub fn core_verify(password: &[u8], encoded_hash: &str) -> Result<bool, KdfError> {
    core_verify_with_inputs(password, encoded_hash, &DeriveInputs::default())
}

pub fn core_verify_with_inputs(
    password: &[u8],
    encoded_hash: &str,
    inputs: &DeriveInputs,
) -> Result<bool, KdfError> {
    inputs.validate()?;
    let components = parse_hash(encoded_hash)?;
    let config = components_to_config(&components)?;
    check_verify_inputs(&config, inputs)?;

    with_permit(config.memory.as_kib(), || {
        let candidate_digest =
            AntechEngine::new().derive_with_inputs(password, &components.salt, &config, inputs)?;

        if candidate_digest.len() != components.digest.len() {
            return Ok(false);
        }

        Ok(subtle::ConstantTimeEq::ct_eq(&candidate_digest[..], &components.digest[..]).into())
    })
}

pub fn core_needs_rehash_with_policy(
    encoded_hash: &str,
    policy: &antech_kdf_types::RehashPolicy,
) -> Result<bool, KdfError> {
    let components = parse_hash(encoded_hash)?;
    let config = components_to_config(&components)?;
    Ok(policy.needs_rehash(&config))
}

fn components_to_config(
    components: &antech_kdf_types::RawHashComponents,
) -> Result<AntechConfig, KdfError> {
    let mut builder = AntechConfig::builder()
        .algorithm(components.algorithm)
        .memory_kib(components.memory_kib as usize)
        .salt_length(components.salt_len)
        .block_size(components.block_size)
        .fan_in(components.fan_in)
        .graph(components.graph)
        .output_length(components.output_len)
        .secret_required(components.secret_required);
    if let Some(adl) = components.associated_data_length {
        builder = builder.associated_data_length(adl);
    }
    builder.build().map_err(KdfError::Config)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use antech_kdf_types::{AntechConfig, SecretBytes};

    #[test]
    fn hash_verify_roundtrip_releases_resources() {
        let hash = core_hash_with_config(b"roundtrip", &AntechConfig::default()).unwrap();
        assert!(core_verify(b"roundtrip", &hash).unwrap());
        assert!(!core_verify(b"wrong", &hash).unwrap());
    }

    #[test]
    fn secret_bound_hash_requires_secret_on_plain_verify() {
        let inputs = DeriveInputs::default().with_secret(SecretBytes::new(b"app-secret").unwrap());
        let hash =
            core_hash_with_config_and_inputs(b"pw", &AntechConfig::default(), &inputs).unwrap();
        assert!(hash.contains(",sk=1"));
        assert!(!hash.contains("app-secret"));
        assert!(matches!(
            core_verify(b"pw", &hash),
            Err(KdfError::MissingSecret)
        ));
        assert!(core_verify_with_inputs(b"pw", &hash, &inputs).unwrap());
    }

    #[test]
    fn associated_data_marker_and_roundtrip() {
        let inputs = DeriveInputs::default()
            .with_associated_data(b"tenant:42")
            .unwrap();
        let hash =
            core_hash_with_config_and_inputs(b"pw", &AntechConfig::default(), &inputs).unwrap();
        assert!(hash.contains(",adl=9"));
        assert!(matches!(
            core_verify(b"pw", &hash),
            Err(KdfError::MissingAssociatedData)
        ));
        assert!(core_verify_with_inputs(b"pw", &hash, &inputs).unwrap());
    }
}
