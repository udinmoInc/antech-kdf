//! Integration tests for Antech KDF public API.

use antech_kdf::{hash, needs_rehash, verify};

#[test]
fn test_correct_password() {
    let password = "SuperSecretPassword123!";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
}

#[test]
fn test_wrong_password() {
    let password = "SuperSecretPassword123!";
    let encoded = hash(password).unwrap();
    assert!(!verify("WrongPassword123!", &encoded).unwrap());
}

#[test]
fn test_empty_password() {
    let password = "";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
    assert!(!verify("non_empty", &encoded).unwrap());
}

#[test]
fn test_unicode_password() {
    let password = "🔒🔑 Password_über_123_日本語 🔑🔒";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
    assert!(!verify("🔒🔑 Password_über_123_日本語 🔑🔓", &encoded).unwrap());
}

#[test]
fn test_binary_password() {
    let password = [0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF];
    let encoded = hash(&password).unwrap();
    assert!(verify(&password, &encoded).unwrap());

    let wrong_binary = [0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xF0];
    assert!(!verify(&wrong_binary, &encoded).unwrap());
}

#[test]
fn test_large_password() {
    let password = vec![b'A'; 65536];
    let encoded = hash(&password).unwrap();
    assert!(verify(&password, &encoded).unwrap());
}

#[test]
fn test_malformed_hash() {
    assert!(verify("pass", "invalid_string").is_err());
    assert!(verify("pass", "$antech$v1$m=invalid$salt$digest").is_err());
}

#[test]
fn test_wrong_version() {
    let wrong_version_hash = "$antech$v999$m=65536,t=3,p=1,bw=100$AQIDBAUGBwgJCgsMDQ4PEA==$AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    assert!(verify("pass", wrong_version_hash).is_err());
}

#[test]
fn test_rehash_detection() {
    let current_hash = hash("my_pass").unwrap();
    assert!(!needs_rehash(&current_hash).unwrap());

    let outdated_params_hash = "$antech$v1$m=1024,t=1,p=1,bw=50$AQIDBAUGBwgJCgsMDQ4PEA==$AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    assert!(needs_rehash(outdated_params_hash).unwrap());
}
