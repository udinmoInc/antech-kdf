//! Focused boundary / ownership tests intended for `cargo miri test`.
//!
//! These do not invoke the KDF engine — only config, secret, AD, and rehash logic.

use super::*;

#[test]
fn memory_size_boundaries() {
    assert!(MemorySize::kib(MemorySize::MIN_KIB).validate().is_ok());
    assert!(MemorySize::kib(MemorySize::MAX_KIB).validate().is_ok());
    assert!(MemorySize::kib(MemorySize::MIN_KIB - 1).validate().is_err());
    assert!(MemorySize::kib(MemorySize::MAX_KIB + 1).validate().is_err());
}

#[test]
fn salt_length_boundaries() {
    assert!(SaltLength::bytes(SaltLength::MIN_BYTES).validate().is_ok());
    assert!(SaltLength::bytes(SaltLength::MAX_BYTES).validate().is_ok());
    assert!(SaltLength::bytes(SaltLength::MIN_BYTES - 1)
        .validate()
        .is_err());
    assert!(SaltLength::bytes(SaltLength::MAX_BYTES + 1)
        .validate()
        .is_err());
}

#[test]
fn block_size_boundaries() {
    for ok in [16usize, 32, 64] {
        assert!(BlockSize::bytes(ok).validate().is_ok(), "ok={ok}");
    }
    for bad in [0usize, 8, 15, 24, 48, 65, 128] {
        assert!(BlockSize::bytes(bad).validate().is_err(), "bad={bad}");
    }
}

#[test]
fn fan_in_boundaries() {
    assert!(FanIn::new(FanIn::MIN).validate().is_ok());
    assert!(FanIn::new(FanIn::MAX).validate().is_ok());
    assert!(FanIn::new(FanIn::MIN - 1).validate().is_err());
    assert!(FanIn::new(FanIn::MAX + 1).validate().is_err());
}

#[test]
fn output_length_boundaries() {
    assert!(OutputLength::bytes(OutputLength::MIN_BYTES)
        .validate()
        .is_ok());
    assert!(OutputLength::bytes(OutputLength::MAX_BYTES)
        .validate()
        .is_ok());
    assert!(OutputLength::bytes(OutputLength::MIN_BYTES - 1)
        .validate()
        .is_err());
    assert!(OutputLength::bytes(OutputLength::MAX_BYTES + 1)
        .validate()
        .is_err());
}

#[test]
fn builder_rejects_too_few_blocks() {
    // At MIN memory + max block, block count is still >> 64. Drop memory below MIN
    // via struct update so validate() fails (memory bound and/or block count).
    let cfg = AntechConfig {
        memory: MemorySize::kib(1024),
        block_size: BlockSize::bytes(64),
        ..AntechConfig::default()
    };
    assert!(cfg.validate().is_ok());
    let bad = AntechConfig {
        memory: MemorySize::kib(1),
        block_size: BlockSize::bytes(64),
        ..AntechConfig::default()
    };
    assert!(bad.validate().is_err());
}

#[test]
fn builder_accepts_canonical_small_config() {
    let cfg = AntechConfig::builder()
        .memory_kib(1024)
        .salt_length(16)
        .block_size(32)
        .fan_in(2)
        .output_length(32)
        .build()
        .unwrap();
    assert_eq!(cfg.num_blocks(), 1024 * 1024 / 32);
}

#[test]
fn secret_len_boundaries() {
    assert!(validate_secret_len(0).is_ok());
    assert!(validate_secret_len(SECRET_MAX_BYTES).is_ok());
    assert!(validate_secret_len(SECRET_MAX_BYTES + 1).is_err());
    assert!(SecretBytes::new(vec![0u8; SECRET_MAX_BYTES]).is_ok());
    assert!(SecretBytes::new(vec![0u8; SECRET_MAX_BYTES + 1]).is_err());
}

#[test]
fn associated_data_len_boundaries() {
    assert!(validate_associated_data_len(0).is_ok());
    assert!(validate_associated_data_len(ASSOCIATED_DATA_MAX_BYTES).is_ok());
    assert!(validate_associated_data_len(ASSOCIATED_DATA_MAX_BYTES + 1).is_err());
    assert!(DeriveInputs::default()
        .with_associated_data(vec![0u8; ASSOCIATED_DATA_MAX_BYTES])
        .is_ok());
    assert!(DeriveInputs::default()
        .with_associated_data(vec![0u8; ASSOCIATED_DATA_MAX_BYTES + 1])
        .is_err());
}

#[test]
fn secret_bytes_redacts_and_exposes() {
    let s = SecretBytes::new(b"hunter2").unwrap();
    assert_eq!(s.expose(), b"hunter2");
    assert_eq!(s.len(), 7);
    assert!(!s.is_empty());
    let dbg = format!("{s:?}");
    let disp = format!("{s}");
    assert!(!dbg.contains("hunter2"));
    assert!(!disp.contains("hunter2"));
    assert!(dbg.contains("redacted"));
}

#[test]
fn derive_inputs_empty_vs_absent() {
    let absent = DeriveInputs::default();
    assert!(!absent.has_extras());
    let empty_secret = DeriveInputs::default().with_secret(SecretBytes::new(b"").unwrap());
    assert!(empty_secret.has_extras());
    assert!(empty_secret.secret.as_ref().unwrap().is_empty());
    let empty_ad = DeriveInputs::default().with_associated_data(b"").unwrap();
    assert!(empty_ad.has_extras());
    assert_eq!(empty_ad.associated_data.as_ref().unwrap().len(), 0);
}

#[test]
fn associated_data_length_on_config_validated() {
    let ok = AntechConfig::builder()
        .memory_kib(1024)
        .associated_data_length(ASSOCIATED_DATA_MAX_BYTES as u32)
        .build();
    assert!(ok.is_ok());
    let bad = AntechConfig {
        associated_data_length: Some((ASSOCIATED_DATA_MAX_BYTES as u32).saturating_add(1)),
        ..AntechConfig::default()
    };
    assert!(bad.validate().is_err());
}

#[test]
fn rehash_policy_flags() {
    let cfg = AntechConfig::builder()
        .memory_mib(16)
        .fan_in(2)
        .output_length(32)
        .build()
        .unwrap();
    assert!(!RehashPolicy::default().needs_rehash(&cfg));

    let want_secret = RehashPolicy::builder()
        .preferred_secret_required(true)
        .build();
    assert!(want_secret.needs_rehash(&cfg));

    let with_sk = AntechConfig::builder()
        .memory_mib(16)
        .secret_required(true)
        .build()
        .unwrap();
    assert!(!want_secret.needs_rehash(&with_sk));

    let want_ad = RehashPolicy::builder()
        .preferred_associated_data(true)
        .build();
    assert!(want_ad.needs_rehash(&cfg));
    let with_ad = AntechConfig::builder()
        .memory_mib(16)
        .associated_data_length(0)
        .build()
        .unwrap();
    assert!(!want_ad.needs_rehash(&with_ad));
}

#[test]
fn graph_kind_tags_roundtrip() {
    for g in [
        GraphKind::ReducedCriticalPath,
        GraphKind::CacheLocality,
        GraphKind::CombinedFrontier,
    ] {
        assert_eq!(GraphKind::from_tag(g.tag()), Some(g));
    }
    assert_eq!(GraphKind::from_tag(0), None);
    assert_eq!(GraphKind::from_tag(99), None);
}

#[test]
fn algorithm_version_parse() {
    assert_eq!(AlgorithmVersion::parse("v2"), Some(AlgorithmVersion::V2));
    assert_eq!(AlgorithmVersion::parse("v1"), None);
    assert_eq!(Algorithm::parse("antech"), Some(Algorithm::Antech));
    assert_eq!(Algorithm::parse("argon2id"), None);
}
