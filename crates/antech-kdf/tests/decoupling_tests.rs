//! Integration tests for custom configuration and rehash policies.

use antech_kdf::{
    hash, hash_with_config, needs_rehash, needs_rehash_with_policy, verify, AntechConfig,
    ConfigError, GraphKind, RehashPolicy,
};

#[test]
fn config_builder_validates_salt_length_bounds() {
    for &len in &[8usize, 16, 32, 64, 128, 256] {
        let config = AntechConfig::builder()
            .salt_length(len)
            .memory_mib(16)
            .build();
        assert!(config.is_ok(), "salt length {len} should be valid");
    }
}

#[test]
fn config_builder_rejects_invalid_salt_lengths() {
    for &len in &[0usize, 1, 7, 257, 512] {
        let config = AntechConfig::builder().salt_length(len).build();
        assert!(config.is_err(), "salt length {len} should be invalid");
        match config.unwrap_err() {
            ConfigError::InvalidSaltLength { len: l, .. } => assert_eq!(l, len),
            err => panic!("unexpected error: {err:?}"),
        }
    }
}

#[test]
fn config_builder_validates_memory_size_bounds() {
    for &mib in &[16usize, 24, 32, 64, 128, 256] {
        let config = AntechConfig::builder().memory_mib(mib).build();
        assert!(config.is_ok(), "memory {mib} MiB should be valid");
    }
}

#[test]
fn custom_hash_with_config_roundtrip_verifies() {
    let password = "custom_test_password_123";
    let config = AntechConfig::builder()
        .salt_length(32)
        .memory_mib(24)
        .fan_in(2)
        .graph(GraphKind::CombinedFrontier)
        .output_length(32)
        .build()
        .expect("build config");

    let encoded_hash = hash_with_config(password, &config).expect("hash");
    assert!(
        encoded_hash.starts_with("$antech$v2$m=24576,s=32,"),
        "unexpected format: {encoded_hash}"
    );

    assert!(verify(password, &encoded_hash).unwrap());
    assert!(!verify("wrong_password", &encoded_hash).unwrap());
}

#[test]
fn rehash_policy_evaluates_memory_upgrades() {
    let password = "rehash_test_password";
    let config_16mb = AntechConfig::builder().memory_mib(16).build().unwrap();
    let hash_16mb = hash_with_config(password, &config_16mb).unwrap();
    assert!(!needs_rehash(&hash_16mb).unwrap());

    let strict_policy = RehashPolicy::builder()
        .preferred_memory_mib(32)
        .preferred_fan_in(4)
        .build();
    assert!(needs_rehash_with_policy(&hash_16mb, &strict_policy).unwrap());
}

#[test]
fn standard_hash_verifies_with_default_config() {
    let password = "standard_password";
    let stored = hash(password).expect("hash");
    assert!(verify(password, &stored).unwrap());
}

#[test]
fn graph_variants_produce_distinct_digests() {
    let password = "graph_test";
    let salt_cfg = |graph: GraphKind| {
        AntechConfig::builder()
            .memory_mib(16)
            .graph(graph)
            .build()
            .unwrap()
    };
    let h_a = hash_with_config(password, &salt_cfg(GraphKind::ReducedCriticalPath)).unwrap();
    let h_b = hash_with_config(password, &salt_cfg(GraphKind::CacheLocality)).unwrap();
    let h_c = hash_with_config(password, &salt_cfg(GraphKind::CombinedFrontier)).unwrap();
    assert_ne!(h_a, h_b);
    assert_ne!(h_b, h_c);
}
