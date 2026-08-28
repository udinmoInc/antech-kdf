//! Linux PMU probe scenarios for side-channel cache analysis (research-only).
//!
//! Invoked as: `side_channel_pmu_runner <scenario>` with optional `PMU_ITERS` (default 12).

use antech_kdf::{
    hash_with_config, hash_with_config_and_salt, hash_with_inputs, verify, verify_with_inputs,
    AntechConfig, DeriveInputs, SecretBytes,
};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const PW_CORRECT: &[u8] = b"sc_correct_password_2026";
const PW_WRONG: &[u8] = b"sc_WRONG_password_xxxxx"; // equal length to PW_CORRECT

fn cfg_1mib() -> AntechConfig {
    AntechConfig::builder()
        .memory_kib(1024)
        .salt_length(16)
        .block_size(32)
        .fan_in(2)
        .output_length(32)
        .build()
        .unwrap()
}

fn cfg_16mib() -> AntechConfig {
    AntechConfig::builder().memory_kib(16384).build().unwrap()
}

fn cfg_secret_ad() -> AntechConfig {
    AntechConfig::builder()
        .memory_kib(1024)
        .secret_required(true)
        .associated_data_length(12)
        .build()
        .unwrap()
}

fn inputs_secret_ad() -> DeriveInputs {
    DeriveInputs::default()
        .with_secret(SecretBytes::new(b"app-secret-key!!").unwrap())
        .with_associated_data(b"tenant:alpha")
        .unwrap()
}

fn iters() -> usize {
    std::env::var("PMU_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
}

fn main() {
    let scenario = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "verify_correct_1mib".to_string());
    let n = iters();
    match scenario.as_str() {
        "verify_correct_1mib" => verify_1mib(PW_CORRECT, n),
        "verify_wrong_1mib" => verify_1mib(PW_WRONG, n),
        "verify_correct_16mib" => verify_16mib(PW_CORRECT, n),
        "verify_wrong_16mib" => verify_16mib(b"sc16_WRONG_pw_pad_xx", n),
        "hash_password_len4" => hash_len(b"pw12", n),
        "hash_password_len256" => hash_len(&[b'x'; 256], n),
        "verify_secret_correct" => verify_secret(true, n),
        "verify_secret_wrong" => verify_secret(false, n),
        "verify_ad_correct" => verify_ad(true, n),
        "verify_ad_wrong" => verify_ad(false, n),
        "verify_correct_under_load" => verify_under_load(n),
        other => panic!("unknown scenario: {other}"),
    }
}

fn verify_1mib(password: &[u8], n: usize) {
    let cfg = cfg_1mib();
    let encoded = hash_with_config(PW_CORRECT, &cfg).unwrap();
    for _ in 0..n {
        black_box(verify(password, &encoded).unwrap());
    }
}

fn verify_16mib(password: &[u8], n: usize) {
    let cfg = cfg_16mib();
    let salt = [0x42u8; 16];
    let encoded = hash_with_config_and_salt(b"sc16_pw", &salt, &cfg).unwrap();
    for _ in 0..n {
        black_box(verify(password, &encoded).unwrap());
    }
}

fn hash_len(password: &[u8], n: usize) {
    let cfg = cfg_1mib();
    let salt = [0x42u8; 16];
    for _ in 0..n {
        black_box(hash_with_config_and_salt(password, &salt, &cfg).unwrap());
    }
}

fn verify_secret(correct: bool, n: usize) {
    let cfg = cfg_secret_ad();
    let inputs = inputs_secret_ad();
    let encoded = hash_with_inputs(b"bound_pw", &cfg, &inputs).unwrap();
    let bad = DeriveInputs::default()
        .with_secret(SecretBytes::new(b"wrong-secret!!!!").unwrap())
        .with_associated_data(b"tenant:alpha")
        .unwrap();
    for _ in 0..n {
        if correct {
            black_box(verify_with_inputs(b"bound_pw", &encoded, &inputs).unwrap());
        } else {
            black_box(verify_with_inputs(b"bound_pw", &encoded, &bad).unwrap());
        }
    }
}

fn verify_ad(correct: bool, n: usize) {
    let cfg = cfg_secret_ad();
    let inputs = inputs_secret_ad();
    let encoded = hash_with_inputs(b"bound_pw", &cfg, &inputs).unwrap();
    let bad = DeriveInputs::default()
        .with_secret(SecretBytes::new(b"app-secret-key!!").unwrap())
        .with_associated_data(b"tenant:bravo")
        .unwrap();
    for _ in 0..n {
        if correct {
            black_box(verify_with_inputs(b"bound_pw", &encoded, &inputs).unwrap());
        } else {
            black_box(verify_with_inputs(b"bound_pw", &encoded, &bad).unwrap());
        }
    }
}

fn verify_under_load(n: usize) {
    let cfg = cfg_1mib();
    let encoded = hash_with_config(PW_CORRECT, &cfg).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let bg = thread::spawn(move || {
        let heavy = cfg_1mib();
        let salt = [7u8; 16];
        while !stop_bg.load(Ordering::Relaxed) {
            let _ = hash_with_config_and_salt(b"background_load", &salt, &heavy);
        }
    });
    thread::sleep(Duration::from_millis(30));
    for _ in 0..n {
        black_box(verify(PW_CORRECT, &encoded).unwrap());
    }
    stop.store(true, Ordering::Relaxed);
    let _ = bg.join();
}
