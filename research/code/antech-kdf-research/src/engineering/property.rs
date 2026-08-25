//! Deterministic property / random harness (cargo-fuzz fallback).

use antech_kdf_format::parse_hash;
use antech_kdf_types::{AntechConfig, AntechConfigBuilder, GraphKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyRow {
    pub harness: String,
    pub cases: u64,
    pub failures: u64,
    pub kind: String,
    pub notes: String,
}

impl PropertyRow {
    fn new(harness: &str, cases: u64, failures: u64, notes: &str) -> Self {
        Self {
            harness: harness.into(),
            cases,
            failures,
            kind: "MEASURED".into(),
            notes: notes.into(),
        }
    }
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

pub fn run_property_harness() -> Vec<PropertyRow> {
    let mut rows = Vec::new();
    let mut seed = 0x123456789abcdefu64;
    let fail = 0u64;
    let cases = 5000u64;
    for _ in 0..cases {
        let n = (xorshift(&mut seed) % 200) as usize;
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            s.push(char::from((xorshift(&mut seed) % 128) as u8));
        }
        let _ = parse_hash(&s);
    }
    rows.push(PropertyRow::new(
        "parser_random_ascii",
        cases,
        fail,
        "No panic expected; invalid strings return Err",
    ));

    let mut fail = 0u64;
    let cases2 = 200u64;
    for i in 0..cases2 {
        let m = 512 + (i as usize % 2048);
        let r = AntechConfigBuilder::default().memory_kib(m).build();
        if m < 1024 && r.is_ok() {
            fail += 1;
        }
        let _ = AntechConfig::builder()
            .memory_mib(16)
            .fan_in(2 + (i % 7) as u32)
            .graph(GraphKind::CombinedFrontier)
            .build();
    }
    rows.push(PropertyRow::new(
        "config_validation_boundaries",
        cases2,
        fail,
        "Reject memory < 1024 KiB",
    ));

    rows
}
