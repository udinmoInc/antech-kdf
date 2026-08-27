//! Cross-SDK conformance against `sdk/conformance/vectors.json`.

use antech_kdf::{
    hash_with_config_and_salt, hash_with_inputs_and_salt, needs_rehash, verify, verify_with_inputs,
    AntechConfig, DeriveInputs, GraphKind, SecretBytes,
};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct VectorsFile {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    password_hex: String,
    salt_hex: String,
    digest_hex: String,
    config: CaseConfig,
    /// Present key (even `""`) means secret was used; omit key for absent.
    #[serde(default)]
    secret_hex: Option<String>,
    #[serde(default)]
    associated_data_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CaseConfig {
    memory_kib: usize,
    salt_length: usize,
    block_size: usize,
    fan_in: u32,
    graph: u32,
    output_length: usize,
}

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/conformance/vectors.json")
}

fn graph(tag: u32) -> GraphKind {
    GraphKind::from_tag(tag).expect("graph tag")
}

fn inputs_for(case: &Case) -> DeriveInputs {
    let mut inputs = DeriveInputs::default();
    if let Some(hex) = &case.secret_hex {
        inputs.secret = Some(SecretBytes::new(hex_decode(hex)).expect("secret"));
    }
    if let Some(hex) = &case.associated_data_hex {
        inputs = inputs
            .with_associated_data(hex_decode(hex))
            .expect("associated data");
    }
    inputs
}

#[test]
fn conformance_vectors_match_digest_and_verify() {
    let raw = std::fs::read_to_string(vectors_path()).expect("vectors.json");
    let doc: VectorsFile = serde_json::from_str(&raw).expect("parse vectors");
    assert!(!doc.cases.is_empty());

    for case in &doc.cases {
        let cfg = AntechConfig::builder()
            .memory_kib(case.config.memory_kib)
            .salt_length(case.config.salt_length)
            .block_size(case.config.block_size)
            .fan_in(case.config.fan_in)
            .graph(graph(case.config.graph))
            .output_length(case.config.output_length)
            .build()
            .unwrap_or_else(|e| panic!("{}: config {e}", case.id));

        let password = hex_decode(&case.password_hex);
        let salt = hex_decode(&case.salt_hex);
        let inputs = inputs_for(case);
        let encoded = if inputs.has_extras() {
            hash_with_inputs_and_salt(&password, &salt, &cfg, &inputs)
        } else {
            hash_with_config_and_salt(&password, &salt, &cfg)
        }
        .unwrap_or_else(|e| panic!("{}: hash {e}", case.id));

        let digest = encoded.rsplit('$').next().expect("digest field");
        assert_eq!(digest, case.digest_hex, "{} digest mismatch", case.id);

        if inputs.has_extras() {
            assert!(
                verify_with_inputs(&password, &encoded, &inputs).unwrap(),
                "{} verify_with_inputs failed",
                case.id
            );
            assert!(
                verify(&password, &encoded).is_err(),
                "{} plain verify must fail closed when extras required",
                case.id
            );
        } else {
            assert!(
                verify(&password, &encoded).unwrap(),
                "{} verify failed",
                case.id
            );
        }
        let _ = needs_rehash(&encoded).unwrap();
    }
}
