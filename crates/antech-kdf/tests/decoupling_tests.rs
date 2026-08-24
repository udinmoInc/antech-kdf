use antech_kdf::{
    hash, hash_with_config, needs_rehash, needs_rehash_with_policy, verify, Algorithm,
    AntechConfig, ConfigError, MemorySize, PassCount, RehashPolicy, SaltLength,
};

#[test]
fn test_config_builder_valid_salt_lengths() {
    let valid_lengths = [8, 16, 32, 64, 128, 256];
    for &len in &valid_lengths {
        let config = AntechConfig::builder()
            .salt_length(len)
            .memory_mib(16)
            .build();
        assert!(config.is_ok(), "Salt length {} bytes should be valid", len);
        assert_eq!(config.unwrap().salt_length.as_bytes(), len);
    }
}

#[test]
fn test_config_builder_invalid_salt_lengths() {
    let invalid_lengths = [0, 1, 7, 257, 512];
    for &len in &invalid_lengths {
        let config = AntechConfig::builder().salt_length(len).build();
        assert!(
            config.is_err(),
            "Salt length {} bytes should be invalid",
            len
        );
        match config.unwrap_err() {
            ConfigError::InvalidSaltLength {
                len: l,
                min: 8,
                max: 256,
            } => {
                assert_eq!(l, len);
            }
            err => panic!("Unexpected error type: {:?}", err),
        }
    }
}

#[test]
fn test_config_builder_valid_memory_sizes() {
    let valid_memory = [16, 24, 32, 64, 128, 256];
    for &mib in &valid_memory {
        let config = AntechConfig::builder().memory_mib(mib).build();
        assert!(config.is_ok(), "Memory size {} MiB should be valid", mib);
        assert_eq!(config.unwrap().memory.as_mib(), mib);
    }
}

#[test]
fn test_custom_hash_with_config_roundtrip() {
    let password = "custom_test_password_123";

    // Profile B: 32 bytes salt, 24 MiB memory, 3 passes
    let config = AntechConfig::builder()
        .algorithm(Algorithm::Antech)
        .salt_length(32)
        .memory_mib(24)
        .passes(3)
        .dependency_depth(100)
        .output_length(32)
        .build()
        .expect("Failed to build custom config");

    // Hash password with custom config
    let encoded_hash = hash_with_config(password, &config).expect("Failed to hash with config");
    assert!(
        encoded_hash.starts_with("$antech$v1$m=24576,s=32,"),
        "Encoded hash format mismatch: {}",
        encoded_hash
    );

    // Verify password using standard verify API (recovers parameters automatically from stored hash)
    let is_valid = verify(password, &encoded_hash).expect("Verification failed");
    assert!(is_valid, "Password should verify cleanly");

    let is_invalid = verify("wrong_password", &encoded_hash).expect("Verification failed");
    assert!(!is_invalid, "Wrong password should be rejected");
}

#[test]
fn test_rehash_policy_evaluation() {
    let password = "rehash_test_password";

    // Hash with 16 MiB config
    let config_16mb = AntechConfig::builder().memory_mib(16).build().unwrap();
    let hash_16mb = hash_with_config(password, &config_16mb).unwrap();

    // Default policy expects 16 MiB
    assert!(!needs_rehash(&hash_16mb).unwrap());

    // Strict policy requiring 32 MiB preferred memory
    let strict_policy = RehashPolicy::builder()
        .preferred_memory_mib(32)
        .preferred_passes(3)
        .build();

    assert!(needs_rehash_with_policy(&hash_16mb, &strict_policy).unwrap());
}

#[test]
fn test_standard_hash_backward_compatibility() {
    let password = "standard_password";
    let stored = hash(password).expect("Default hash failed");
    let ok = verify(password, &stored).expect("Default verify failed");
    assert!(ok);
}
