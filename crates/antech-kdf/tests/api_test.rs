//! Integration tests for public API entry points (named scenarios).
//! Boundary tables live in `reliability_matrix.rs`.

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
fn unicode_password_verifies_successfully() {
    let password = "🔒🔑 Password_über_123_日本語 🔑🔒";
    let encoded = hash(password).unwrap();
    assert!(verify(password, &encoded).unwrap());
    assert!(!verify("🔒🔑 Password_über_123_日本語 🔑🔓", &encoded).unwrap());
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
