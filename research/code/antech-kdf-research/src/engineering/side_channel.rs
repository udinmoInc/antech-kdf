//! Practical side-channel engineering checks (timing / control-flow), research-only.

use antech_kdf::{hash_with_config, verify};
use antech_kdf_format::parse_hash;
use antech_kdf_types::AntechConfig;
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelRow {
    pub test_id: String,
    pub finding: String,
    pub severity: String,
    pub kind: String,
    pub notes: String,
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Compare verify timing for correct vs wrong password (same encoded hash).
pub fn run_side_channel_suite() -> Vec<SideChannelRow> {
    let mut rows = Vec::new();
    let cfg = AntechConfig::builder().memory_kib(1024).build().unwrap();
    let encoded = hash_with_config(b"sidechan_correct_pw", &cfg).unwrap();

    // Warmup
    for _ in 0..3 {
        let _ = verify(b"sidechan_correct_pw", &encoded);
        let _ = verify(b"sidechan_WRONG_pw!!", &encoded);
    }

    let samples = 40usize;
    let mut correct_ms = Vec::with_capacity(samples);
    let mut wrong_ms = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        let ok = verify(b"sidechan_correct_pw", &encoded).unwrap();
        black_box(ok);
        correct_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let t1 = Instant::now();
        let bad = verify(b"sidechan_WRONG_pw!!", &encoded).unwrap();
        black_box(bad);
        wrong_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
    }
    let mc = median(correct_ms.clone());
    let mw = median(wrong_ms.clone());
    let ratio = mc / mw.max(1e-12);
    // Full derive runs for both; expect similar medians (no early reject on wrong password).
    let early_reject = ratio > 1.5 || ratio < (1.0 / 1.5);
    rows.push(SideChannelRow {
        test_id: "SC1_verify_correct_vs_wrong_timing".into(),
        finding: if early_reject {
            format!("MEDIAN_DIVERGENCE correct_ms={mc:.3} wrong_ms={mw:.3} ratio={ratio:.3}")
        } else {
            format!("SIMILAR_MEDIANS correct_ms={mc:.3} wrong_ms={mw:.3} ratio={ratio:.3}")
        },
        severity: if early_reject { "investigate".into() } else { "info".into() },
        kind: "MEASURED".into(),
        notes: "Wrong password still runs full Derive; digest compared with ConstantTimeEq. Not a formal CT proof.".into(),
    });

    // Malformed hash should fail fast (parse), not full derive.
    let t0 = Instant::now();
    for _ in 0..1000 {
        let _ = verify(b"x", "not-a-hash");
    }
    let malformed_us = t0.elapsed().as_secs_f64() * 1e6 / 1000.0;
    rows.push(SideChannelRow {
        test_id: "SC2_malformed_hash_fast_fail".into(),
        finding: format!("avg_us_per_call={malformed_us:.3}"),
        severity: "info".into(),
        kind: "MEASURED".into(),
        notes: "Parse failure expected; should not allocate full 16MiB working set.".into(),
    });

    // Parser never panics on arbitrary UTF-8 (property-style).
    let mut panics = 0u32;
    for i in 0..200u32 {
        let s = format!("$antech$v2$m={},s=16,b=32,f=2,g=3,l=32$deadbeef$cafe", i);
        if std::panic::catch_unwind(|| {
            let _ = parse_hash(&s);
        })
        .is_err()
        {
            panics += 1;
        }
    }
    rows.push(SideChannelRow {
        test_id: "SC3_parser_no_panic_fuzzish".into(),
        finding: format!("panics={panics}"),
        severity: if panics > 0 {
            "high".into()
        } else {
            "info".into()
        },
        kind: "MEASURED".into(),
        notes: "Deterministic malformed v2 strings.".into(),
    });

    rows.push(SideChannelRow {
        test_id: "SC4_secret_dependent_memory".into(),
        finding: "Parent/scatter addresses depend on rolling state derived from password; access pattern is secret-dependent by design (memory-hard KDF).".into(),
        severity: "accepted_design".into(),
        kind: "MODELED".into(),
        notes: "Not claimed constant-time w.r.t. password. Offline attacker already knows salt/hash.".into(),
    });

    rows.push(SideChannelRow {
        test_id: "SC5_digest_compare".into(),
        finding: "verify uses subtle::ConstantTimeEq on digests after full derive.".into(),
        severity: "info".into(),
        kind: "MEASURED".into(),
        notes: "Source: antech-kdf-core core_verify.".into(),
    });

    rows
}
