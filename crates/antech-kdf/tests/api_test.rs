//! Integration tests for Antech KDF public API entry points.

use antech_kdf::{hash, needs_rehash, verify};

#[test]
fn correct_password_verifies_successfully() {
    let password = "SuperSecretPassword123!";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
}

#[test]
fn wrong_password_fails_verification() {
    let password = "SuperSecretPassword123!";
    let encoded = hash(password).unwrap();
    assert!(!verify("WrongPassword123!", &encoded).unwrap());
}

#[test]
fn empty_password_verifies_successfully() {
    let password = "";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
    assert!(!verify("non_empty", &encoded).unwrap());
}

#[test]
fn unicode_password_verifies_successfully() {
    let password = "🔒🔑 Password_über_123_日本語 🔑🔒";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
    assert!(!verify("🔒🔑 Password_über_123_日本語 🔑🔓", &encoded).unwrap());
}

#[test]
fn binary_password_verifies_successfully() {
    let password = [0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF];
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());

    let wrong_binary = [0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xF0];
    assert!(!verify(wrong_binary, &encoded).unwrap());
}

#[test]
fn large_password_verifies_successfully() {
    let password = vec![b'A'; 65536];
    let encoded = hash(&password).unwrap();
    assert!(verify(&password, &encoded).unwrap());
}

#[test]
fn malformed_hash_returns_error() {
    assert!(verify("pass", "invalid_string").is_err());
    assert!(verify("pass", "$antech$v2$m=invalid$salt$digest").is_err());
}

#[test]
fn legacy_v1_hash_rejected() {
    let legacy = "$antech$v1$m=16384,s=16,t=650000,p=1,b=32,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff";
    assert!(verify("pass", legacy).is_err());
}

#[test]
fn rehash_policy_detects_outdated_hashes() {
    let current_hash = hash("my_pass").unwrap();
    assert!(!needs_rehash(&current_hash).unwrap());

    let outdated_params_hash = "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee";
    assert!(needs_rehash(outdated_params_hash).unwrap());
}
