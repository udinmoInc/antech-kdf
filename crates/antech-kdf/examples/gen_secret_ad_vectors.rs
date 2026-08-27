//! Print hex digests for secret/AD conformance vectors (dev helper).

use antech_kdf::{AntechConfig, DeriveInputs, SecretBytes};
use antech_kdf_core::AntechEngine;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let cfg = AntechConfig::builder()
        .memory_kib(1024)
        .salt_length(16)
        .block_size(32)
        .fan_in(2)
        .output_length(32)
        .build()
        .unwrap();
    let pw = b"password";
    let salt = b"salt_16_bytes!!!";
    let engine = AntechEngine::new();

    let cases: &[(&str, DeriveInputs)] = &[
        ("none", DeriveInputs::default()),
        (
            "secret_only",
            DeriveInputs::default().with_secret(SecretBytes::new(b"app-secret").unwrap()),
        ),
        (
            "ad_only",
            DeriveInputs::default()
                .with_associated_data(b"tenant:42")
                .unwrap(),
        ),
        (
            "secret_and_ad",
            DeriveInputs::default()
                .with_secret(SecretBytes::new(b"app-secret").unwrap())
                .with_associated_data(b"tenant:42")
                .unwrap(),
        ),
        (
            "empty_secret",
            DeriveInputs::default().with_secret(SecretBytes::new(b"").unwrap()),
        ),
        (
            "empty_ad",
            DeriveInputs::default().with_associated_data(b"").unwrap(),
        ),
        (
            "binary_secret_ad",
            DeriveInputs::default()
                .with_secret(SecretBytes::new([0x00u8, 0xff, 0x7f, 0x80]).unwrap())
                .with_associated_data([0x01u8, 0x02, 0x00, 0xfe])
                .unwrap(),
        ),
        (
            "long_secret",
            DeriveInputs::default().with_secret(SecretBytes::new(vec![0x41u8; 1024]).unwrap()),
        ),
        (
            "long_ad",
            DeriveInputs::default()
                .with_associated_data(vec![0x42u8; 4096])
                .unwrap(),
        ),
    ];

    for (id, inputs) in cases {
        let d = engine.derive_with_inputs(pw, salt, &cfg, inputs).unwrap();
        println!("{id} {}", hex(&d));
    }
}
