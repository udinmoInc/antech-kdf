//! Antech KDF — password hashing and verification.
//!
//! Advanced optional inputs (application secret and associated data) are available
//! via [`hash_with_inputs`] / [`verify_with_inputs`]. They do not change the simple
//! [`hash`] / [`verify`] / [`needs_rehash`] path when unused.
//!
//! # Security status
//!
//! The implementation reflects the project's latest validated construction.
//! **It has not undergone independent cryptographic review** and must not be treated
//! as production-proven merely because benchmarks pass.
//!
//! # Examples
//!
//! ```
//! let stored = antech_kdf::hash("correct_horse_battery_staple")?;
//! assert!(antech_kdf::verify("correct_horse_battery_staple", &stored)?);
//! # Ok::<(), antech_kdf::Error>(())
//! ```

pub use antech_kdf_types::{
    validate_associated_data_len, validate_secret_len, AntechConfig, AntechConfigBuilder,
    BlockSize, ConfigError, DeriveInputs, FanIn, GraphKind, KdfError as Error, MemorySize,
    OutputLength, RehashPolicy, RehashPolicyBuilder, SaltLength, SecretBytes,
    ASSOCIATED_DATA_MAX_BYTES, SECRET_MAX_BYTES,
};

use antech_kdf_core::{
    core_hash_with_config, core_hash_with_config_and_inputs, core_hash_with_config_and_salt,
    core_hash_with_config_salt_and_inputs, core_needs_rehash_with_policy, core_verify,
    core_verify_with_inputs,
};

/// Hashes a password using default parameters (16 MiB, combined-frontier graph).
pub fn hash(password: impl AsRef<[u8]>) -> Result<String, Error> {
    hash_with_config(password, &AntechConfig::default())
}

pub fn hash_with_config(
    password: impl AsRef<[u8]>,
    config: &AntechConfig,
) -> Result<String, Error> {
    core_hash_with_config(password.as_ref(), config)
}

/// When both inputs are [`None`], behavior matches [`hash_with_config`].
/// Present inputs set public markers (`sk=1`, `adl=n`); bytes themselves are never stored.
pub fn hash_with_inputs(
    password: impl AsRef<[u8]>,
    config: &AntechConfig,
    inputs: &DeriveInputs,
) -> Result<String, Error> {
    core_hash_with_config_and_inputs(password.as_ref(), config, inputs)
}

/// Prefer [`hash_with_config`] for production (random salt). This helper is for KATs.
pub fn hash_with_config_and_salt(
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    config: &AntechConfig,
) -> Result<String, Error> {
    core_hash_with_config_and_salt(password.as_ref(), salt.as_ref(), config)
}

pub fn hash_with_inputs_and_salt(
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    config: &AntechConfig,
    inputs: &DeriveInputs,
) -> Result<String, Error> {
    core_hash_with_config_salt_and_inputs(password.as_ref(), salt.as_ref(), config, inputs)
}

/// Hashes created with secret/AD requirements return
/// [`Error::MissingSecret`] / [`Error::MissingAssociatedData`] — use
/// [`verify_with_inputs`] instead.
pub fn verify(password: impl AsRef<[u8]>, encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    core_verify(password.as_ref(), encoded_hash.as_ref())
}

pub fn verify_with_inputs(
    password: impl AsRef<[u8]>,
    encoded_hash: impl AsRef<str>,
    inputs: &DeriveInputs,
) -> Result<bool, Error> {
    core_verify_with_inputs(password.as_ref(), encoded_hash.as_ref(), inputs)
}

pub fn needs_rehash(encoded_hash: impl AsRef<str>) -> Result<bool, Error> {
    needs_rehash_with_policy(encoded_hash, &RehashPolicy::default())
}

/// Policy may require `sk=1` / `adl=` markers; it never compares secret bytes.
pub fn needs_rehash_with_policy(
    encoded_hash: impl AsRef<str>,
    policy: &RehashPolicy,
) -> Result<bool, Error> {
    core_needs_rehash_with_policy(encoded_hash.as_ref(), policy)
}

#[cfg(test)]
mod api_tests {
    use super::*;

    fn small_cfg() -> AntechConfig {
        AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(16)
            .block_size(32)
            .fan_in(2)
            .output_length(32)
            .build()
            .unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore = "1MiB derive; covered by normal cargo test")]
    fn legacy_path_unchanged_shape() {
        let salt = b"salt_16_bytes!!!";
        let h = hash_with_config_and_salt(b"pw", salt, &small_cfg()).unwrap();
        assert!(h.starts_with("$antech$v2$"));
        assert!(!h.contains(",sk="));
        assert!(!h.contains(",adl="));
        assert!(verify(b"pw", &h).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "multi 1MiB derives; covered by normal cargo test")]
    fn secret_and_ad_vectors() {
        let cfg = small_cfg();
        let salt = b"salt_16_bytes!!!";
        let pw = b"password";
        let engine = antech_kdf_core::AntechEngine::new();

        let none = DeriveInputs::default();
        let secret_only =
            DeriveInputs::default().with_secret(SecretBytes::new(b"secret-key").unwrap());
        let ad_only = DeriveInputs::default()
            .with_associated_data(b"context")
            .unwrap();
        let both = DeriveInputs::default()
            .with_secret(SecretBytes::new(b"secret-key").unwrap())
            .with_associated_data(b"context")
            .unwrap();

        let d_none = engine.derive_with_inputs(pw, salt, &cfg, &none).unwrap();
        let d_secret = engine
            .derive_with_inputs(pw, salt, &cfg, &secret_only)
            .unwrap();
        let d_ad = engine.derive_with_inputs(pw, salt, &cfg, &ad_only).unwrap();
        let d_both = engine.derive_with_inputs(pw, salt, &cfg, &both).unwrap();

        assert_ne!(d_none, d_secret);
        assert_ne!(d_none, d_ad);
        assert_ne!(d_secret, d_ad);
        assert_ne!(d_both, d_secret);
        assert_ne!(d_both, d_ad);

        let h_both = hash_with_inputs_and_salt(pw, salt, &cfg, &both).unwrap();
        assert!(!h_both.contains("secret-key"));
        assert!(verify_with_inputs(pw, &h_both, &both).unwrap());
        assert!(matches!(
            verify_with_inputs(pw, &h_both, &secret_only),
            Err(Error::MissingAssociatedData)
        ));
        let wrong_secret = DeriveInputs::default()
            .with_secret(SecretBytes::new(b"other-secret").unwrap())
            .with_associated_data(b"context")
            .unwrap();
        assert!(!verify_with_inputs(pw, &h_both, &wrong_secret).unwrap());
        let wrong_ad = DeriveInputs::default()
            .with_secret(SecretBytes::new(b"secret-key").unwrap())
            .with_associated_data(b"contExt")
            .unwrap();
        assert!(!verify_with_inputs(pw, &h_both, &wrong_ad).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "1MiB derive; covered by normal cargo test")]
    fn empty_secret_differs_from_absent() {
        let cfg = small_cfg();
        let salt = b"salt_16_bytes!!!";
        let engine = antech_kdf_core::AntechEngine::new();
        let absent = DeriveInputs::default();
        let empty = DeriveInputs::default().with_secret(SecretBytes::new(b"").unwrap());
        let a = engine
            .derive_with_inputs(b"pw", salt, &cfg, &absent)
            .unwrap();
        let b = engine
            .derive_with_inputs(b"pw", salt, &cfg, &empty)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    #[cfg_attr(miri, ignore = "1MiB derive; covered by normal cargo test")]
    fn empty_ad_differs_from_absent() {
        let cfg = small_cfg();
        let salt = b"salt_16_bytes!!!";
        let engine = antech_kdf_core::AntechEngine::new();
        let absent = DeriveInputs::default();
        let empty = DeriveInputs::default().with_associated_data(b"").unwrap();
        let a = engine
            .derive_with_inputs(b"pw", salt, &cfg, &absent)
            .unwrap();
        let b = engine
            .derive_with_inputs(b"pw", salt, &cfg, &empty)
            .unwrap();
        assert_ne!(a, b);
        let h = hash_with_inputs_and_salt(b"pw", salt, &cfg, &empty).unwrap();
        assert!(h.contains(",adl=0"));
    }

    #[test]
    fn secret_redacted_in_debug() {
        let s = SecretBytes::new(b"super-secret-value").unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "1MiB hash/verify loops; deterministic_small_config covers engine under Miri"
    )]
    fn repeated_hash_verify_deterministic_salt() {
        let cfg = small_cfg();
        let salt = b"salt_16_bytes!!!";
        let a = hash_with_config_and_salt(b"pw", salt, &cfg).unwrap();
        let b = hash_with_config_and_salt(b"pw", salt, &cfg).unwrap();
        assert_eq!(a, b);
        for _ in 0..4 {
            assert!(verify(b"pw", &a).unwrap());
            assert!(!verify(b"wrong", &a).unwrap());
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "1MiB hash; malformed parse paths still covered without derive below"
    )]
    fn malformed_verify_and_needs_rehash_paths() {
        assert!(verify(b"pw", "").is_err());
        assert!(verify(b"pw", "$antech$v1$x").is_err());
        assert!(needs_rehash("$antech$v2$not-valid").is_err());
        let h = hash_with_config_and_salt(b"pw", b"salt_16_bytes!!!", &small_cfg()).unwrap();
        // Default policy prefers 16 MiB — a 1 MiB hash must need rehash.
        assert!(needs_rehash(&h).unwrap());
        let match_small = RehashPolicy::builder()
            .minimum_memory_mib(1)
            .preferred_memory_mib(1)
            .preferred_fan_in(2)
            .preferred_output_length(32)
            .build();
        assert!(!needs_rehash_with_policy(&h, &match_small).unwrap());
        let policy = RehashPolicy::builder()
            .minimum_memory_mib(1)
            .preferred_memory_mib(1)
            .preferred_secret_required(true)
            .build();
        assert!(needs_rehash_with_policy(&h, &policy).unwrap());
    }

    #[test]
    fn malformed_inputs_without_derive() {
        assert!(verify(b"pw", "").is_err());
        assert!(verify(b"pw", "$antech$v1$x").is_err());
        assert!(needs_rehash("$antech$v2$not-valid").is_err());
        assert!(SecretBytes::new(vec![0u8; SECRET_MAX_BYTES + 1]).is_err());
        assert!(DeriveInputs::default()
            .with_associated_data(vec![0u8; ASSOCIATED_DATA_MAX_BYTES + 1])
            .is_err());
    }

    #[test]
    fn oversized_secret_rejected_before_derive() {
        let cfg = small_cfg();
        let big = vec![0u8; SECRET_MAX_BYTES + 1];
        let err = SecretBytes::new(&big);
        assert!(err.is_err());
        let inputs =
            DeriveInputs::default().with_associated_data(vec![0u8; ASSOCIATED_DATA_MAX_BYTES + 1]);
        assert!(inputs.is_err());
        let _ = cfg; // config unused; rejection is at input construction
    }
}
