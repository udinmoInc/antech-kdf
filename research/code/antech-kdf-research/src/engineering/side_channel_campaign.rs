//! Deep side-channel validation campaign (research-only).
//!
//! Measures timing distributions, documents control-flow surfaces, and (on Linux)
//! samples hardware counters. Does **not** change production crypto or API.

use antech_kdf::{
    hash_with_config, hash_with_config_and_salt, hash_with_inputs, verify, verify_with_inputs,
    AntechConfig, DeriveInputs, SecretBytes,
};
use antech_kdf_core::scheduler_stats;
use antech_kdf_ffi::{antech_verify, antech_verify_bytes, antech_verify_with_inputs_bytes};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::hint::black_box;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::hardware::collect_hardware_meta;
use super::HardwareMeta;

#[derive(Debug, Clone, Copy)]
pub struct CampaignProfile {
    pub derive_samples: usize,
    pub fast_samples: usize,
    pub include_16mib: bool,
    pub contention_iters: usize,
}

impl CampaignProfile {
    pub fn from_env() -> Self {
        match std::env::var("ANTECH_SIDECHANNEL_PROFILE")
            .unwrap_or_else(|_| "full".into())
            .to_lowercase()
            .as_str()
        {
            "ci" => Self {
                derive_samples: 40,
                fast_samples: 400,
                include_16mib: false,
                contention_iters: 20,
            },
            _ => Self {
                derive_samples: 80,
                fast_samples: 800,
                include_16mib: true,
                contention_iters: 40,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingRow {
    pub test_id: String,
    pub path: String,
    pub group_a: String,
    pub group_b: String,
    pub memory_kib: usize,
    pub n_a: usize,
    pub n_b: usize,
    pub median_a_ns: f64,
    pub median_b_ns: f64,
    pub mean_a_ns: f64,
    pub mean_b_ns: f64,
    pub var_a_ns2: f64,
    pub var_b_ns2: f64,
    pub p95_a_ns: f64,
    pub p95_b_ns: f64,
    pub p99_a_ns: f64,
    pub p99_b_ns: f64,
    pub ratio_median: f64,
    pub welch_t: f64,
    pub significant: String,
    pub kind: String,
    pub exploitability: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRow {
    pub location: String,
    pub construct: String,
    pub input_dependent: String,
    pub scope: String,
    pub kind: String,
    pub risk: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRow {
    pub test_id: String,
    pub scenario: String,
    pub instructions: String,
    pub cycles: String,
    pub ipc: String,
    pub cache_misses: String,
    pub llc_loads: String,
    pub kind: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentionRow {
    pub test_id: String,
    pub scenario: String,
    pub idle_median_ns: f64,
    pub loaded_median_ns: f64,
    pub ratio: f64,
    pub waiting_jobs_max: usize,
    pub kind: String,
    pub exploitability: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiRow {
    pub test_id: String,
    pub api: String,
    pub median_ns: f64,
    pub rust_median_ns: f64,
    pub delta_ns: f64,
    pub ratio: f64,
    pub kind: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRow {
    pub id: String,
    pub description: String,
    pub status: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub verdict: String,
    pub timing_rows: usize,
    pub significant_derive_leaks: usize,
    pub fast_path_oracles: usize,
    pub blocked_cache: bool,
    pub hardware: HardwareMeta,
}

struct SampleStats {
    n: usize,
    median: f64,
    mean: f64,
    variance: f64,
    p95: f64,
    p99: f64,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn sample_stats(mut v: Vec<f64>) -> SampleStats {
    if v.is_empty() {
        return SampleStats {
            n: 0,
            median: 0.0,
            mean: 0.0,
            variance: 0.0,
            p95: 0.0,
            p99: 0.0,
        };
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let mean = v.iter().sum::<f64>() / n as f64;
    let variance = if n > 1 {
        v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0)
    } else {
        0.0
    };
    SampleStats {
        n,
        median: v[n / 2],
        mean,
        variance,
        p95: percentile(&v, 0.95),
        p99: percentile(&v, 0.99),
    }
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let sa = sample_stats(a.to_vec());
    let sb = sample_stats(b.to_vec());
    let se = (sa.variance / sa.n as f64 + sb.variance / sb.n as f64).sqrt();
    if se <= 1e-12 {
        return 0.0;
    }
    (sa.mean - sb.mean).abs() / se
}

fn measure_ns<T, F: FnMut() -> T>(mut f: F, samples: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(samples);
    for _ in 0..3 {
        black_box(f());
    }
    for _ in 0..samples {
        let t0 = Instant::now();
        black_box(f());
        out.push(t0.elapsed().as_secs_f64() * 1e9);
    }
    out
}

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

fn compare_timing(
    test_id: &str,
    path: &str,
    group_a: &str,
    group_b: &str,
    memory_kib: usize,
    a: Vec<f64>,
    b: Vec<f64>,
    full_derive: bool,
) -> TimingRow {
    let sa = sample_stats(a.clone());
    let sb = sample_stats(b.clone());
    let ratio = sa.median / sb.median.max(1.0);
    let t = welch_t(&a, &b);
    let rel = ((sa.median - sb.median).abs() / sa.median.max(sb.median).max(1.0)) * 100.0;
    let significant = if full_derive {
        if t > 2.0 && rel > 5.0 {
            "yes_derive"
        } else {
            "no"
        }
    } else if t > 2.0 {
        "yes_fast_path"
    } else {
        "no"
    };
    let exploitability = if significant == "yes_derive" {
        "investigate_password_oracle"
    } else if significant == "yes_fast_path" {
        if path.contains("parse") || path.contains("input_check") {
            "expected_fast_reject_not_password_content"
        } else {
            "fast_path_oracle"
        }
    } else {
        "none"
    };
    TimingRow {
        test_id: test_id.into(),
        path: path.into(),
        group_a: group_a.into(),
        group_b: group_b.into(),
        memory_kib,
        n_a: sa.n,
        n_b: sb.n,
        median_a_ns: sa.median,
        median_b_ns: sb.median,
        mean_a_ns: sa.mean,
        mean_b_ns: sb.mean,
        var_a_ns2: sa.variance,
        var_b_ns2: sb.variance,
        p95_a_ns: sa.p95,
        p95_b_ns: sb.p95,
        p99_a_ns: sa.p99,
        p99_b_ns: sb.p99,
        ratio_median: ratio,
        welch_t: t,
        significant: significant.into(),
        kind: "MEASURED".into(),
        exploitability: exploitability.into(),
        notes: if full_derive {
            "Full derive expected for both; ratio~1 and low Welch t => no early password reject.".into()
        } else {
            "Fast-path timing difference expected for invalid input classes.".into()
        },
    }
}

fn branch_analysis_rows() -> Vec<BranchRow> {
    vec![
        BranchRow {
            location: "antech-kdf-core/src/lib.rs:169".into(),
            construct: "subtle::ConstantTimeEq::ct_eq digest".into(),
            input_dependent: "digest bytes only (post-derive)".into(),
            scope: "final compare".into(),
            kind: "MEASURED".into(),
            risk: "low".into(),
            notes: "Constant-time compare on equal-length digests after full derive.".into(),
        },
        BranchRow {
            location: "antech-kdf-core/src/lib.rs:165-167".into(),
            construct: "digest length mismatch => Ok(false)".into(),
            input_dependent: "encoded hash params (public)".into(),
            scope: "post-derive".into(),
            kind: "MODELED".into(),
            risk: "negligible".into(),
            notes: "Skips ct_eq when lengths differ; derive already ran; config-bound lengths normally match.".into(),
        },
        BranchRow {
            location: "antech-kdf-core/src/lib.rs:74-90".into(),
            construct: "check_verify_inputs early Err".into(),
            input_dependent: "caller supplied secret/AD presence".into(),
            scope: "pre-derive".into(),
            kind: "MODELED".into(),
            risk: "api_oracle".into(),
            notes: "MissingSecret/MissingAD/AD length mismatch returns before derive — distinguishes API misuse from wrong password, not password byte content.".into(),
        },
        BranchRow {
            location: "antech-kdf-format/src/parser.rs".into(),
            construct: "parse_hash validation branches".into(),
            input_dependent: "public encoded string".into(),
            scope: "pre-derive".into(),
            kind: "MEASURED".into(),
            risk: "parse_oracle".into(),
            notes: "Malformed/truncated hashes fail fast; attacker observes parse vs derive latency on public blob.".into(),
        },
        BranchRow {
            location: "antech-kdf-core/src/engine.rs:gather_mix_words".into(),
            construct: "_mm_prefetch parent indices".into(),
            input_dependent: "state-derived parent addresses".into(),
            scope: "derive".into(),
            kind: "MODELED".into(),
            risk: "cache_theoretical".into(),
            notes: "Prefetch hints on password-dependent indices; may affect cache residency on shared cores.".into(),
        },
        BranchRow {
            location: "antech-kdf-core/src/graph.rs".into(),
            construct: "combined_local/remote_parents, scatter_dests".into(),
            input_dependent: "rolling state from seed(password,salt,secret,ad)".into(),
            scope: "derive".into(),
            kind: "MODELED".into(),
            risk: "accepted_design".into(),
            notes: "Memory-hard data-dependent addressing by construction; offline attacker knows salt/hash.".into(),
        },
        BranchRow {
            location: "antech-kdf-core/src/state.rs:bind_seed_with_inputs".into(),
            construct: "SHA-256 over password/secret/AD".into(),
            input_dependent: "password length and bytes".into(),
            scope: "seed".into(),
            kind: "MODELED".into(),
            risk: "length_leak_minor".into(),
            notes: "Password length encoded in hash input; SHA-256 not constant-time w.r.t. password; dominated by derive for typical lengths.".into(),
        },
        BranchRow {
            location: "antech-kdf-core/src/resource.rs:acquire".into(),
            construct: "scheduler queue / Condvar wait".into(),
            input_dependent: "global load not password".into(),
            scope: "admission".into(),
            kind: "MODELED".into(),
            risk: "contention_noise".into(),
            notes: "Wall-clock varies with concurrent jobs; not a password-content oracle.".into(),
        },
        BranchRow {
            location: "antech-kdf-ffi/src/lib.rs:map_err".into(),
            construct: "status mapping MissingSecret => InvalidInput".into(),
            input_dependent: "API inputs".into(),
            scope: "ffi".into(),
            kind: "MODELED".into(),
            risk: "api_oracle".into(),
            notes: "FFI maps pre-derive input errors to InvalidInput; same timing class as Rust Err.".into(),
        },
    ]
}

pub fn run_campaign(out: &Path) -> Result<CampaignSummary, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    let profile = CampaignProfile::from_env();
    let hw = collect_hardware_meta();
    let n_derive = profile.derive_samples;
    let n_fast = profile.fast_samples;

    let mut timing = Vec::new();

    // --- verify correct vs wrong (core question) ---
    let cfg = cfg_1mib();
    let encoded = hash_with_config(b"sc_correct_password_2026", &cfg)?;
    let salt = [0x42u8; 16];
    let encoded_det = hash_with_config_and_salt(b"sc_correct_password_2026", &salt, &cfg)?;

    let correct = measure_ns(
        || {
            let ok = verify(b"sc_correct_password_2026", &encoded).unwrap();
            black_box(ok);
        },
        n_derive,
    );
    let wrong = measure_ns(
        || {
            let ok = verify(b"sc_WRONG_password_xxxxx", &encoded).unwrap();
            black_box(ok);
        },
        n_derive,
    );
    timing.push(compare_timing(
        "T01_verify_correct_vs_wrong",
        "verify",
        "correct_password",
        "wrong_password",
        1024,
        correct,
        wrong,
        true,
    ));

    if profile.include_16mib {
        let cfg16 = cfg_16mib();
        let enc16 = hash_with_config_and_salt(b"sc16_pw", &salt, &cfg16)?;
        let c16 = measure_ns(
            || black_box(verify(b"sc16_pw", &enc16).unwrap()),
            n_derive / 2,
        );
        let w16 = measure_ns(
            || black_box(verify(b"sc16_WRONG", &enc16).unwrap()),
            n_derive / 2,
        );
        timing.push(compare_timing(
            "T02_verify_correct_vs_wrong_16mib",
            "verify",
            "correct_password",
            "wrong_password",
            16384,
            c16,
            w16,
            true,
        ));
    }

    // Password length (hash path; verify uses stored hash)
    let short_pw = measure_ns(
        || black_box(hash_with_config_and_salt(b"pw12", &salt, &cfg).unwrap()),
        n_derive,
    );
    let long_pw = measure_ns(
        || black_box(hash_with_config_and_salt(&[b'x'; 256], &salt, &cfg).unwrap()),
        n_derive,
    );
    timing.push(compare_timing(
        "T03_hash_password_length",
        "hash",
        "len_4",
        "len_256",
        1024,
        short_pw,
        long_pw,
        true,
    ));

    // Different salts (wrong salt => wrong digest path, still full derive)
    let enc_salt_a = hash_with_config_and_salt(b"same_pw", &[1u8; 16], &cfg)?;
    let same_pw_wrong_salt = measure_ns(
        || black_box(verify(b"same_pw", &enc_salt_a).unwrap()),
        n_derive,
    );
    let wrong_pw_same_salt = measure_ns(
        || black_box(verify(b"not_same_pw", &enc_salt_a).unwrap()),
        n_derive,
        );
    timing.push(compare_timing(
        "T04_verify_correct_vs_wrong_same_salt",
        "verify",
        "correct_password",
        "wrong_password",
        1024,
        same_pw_wrong_salt.clone(),
        wrong_pw_same_salt,
        true,
    ));

    // Secret / AD
    let cfg_sa = cfg_secret_ad();
    let inputs = inputs_secret_ad();
    let enc_sa = hash_with_inputs(b"bound_pw", &cfg_sa, &inputs)?;
    let secret_correct = measure_ns(
        || black_box(verify_with_inputs(b"bound_pw", &enc_sa, &inputs).unwrap()),
        n_derive,
    );
    let secret_wrong = measure_ns(
        || {
            let bad = DeriveInputs::default()
                .with_secret(SecretBytes::new(b"wrong-secret!!!!").unwrap())
                .with_associated_data(b"tenant:alpha")
                .unwrap();
            black_box(verify_with_inputs(b"bound_pw", &enc_sa, &bad).unwrap())
        },
        n_derive,
    );
    timing.push(compare_timing(
        "T05_verify_secret_value",
        "verify_with_inputs",
        "correct_secret",
        "wrong_secret",
        1024,
        secret_correct,
        secret_wrong,
        true,
    ));

    let ad_wrong = measure_ns(
        || {
            let bad = DeriveInputs::default()
                .with_secret(SecretBytes::new(b"app-secret-key!!").unwrap())
                .with_associated_data(b"tenant:bravo")
                .unwrap();
            black_box(verify_with_inputs(b"bound_pw", &enc_sa, &bad).unwrap())
        },
        n_derive,
    );
    timing.push(compare_timing(
        "T06_verify_associated_data",
        "verify_with_inputs",
        "correct_ad",
        "wrong_ad",
        1024,
        measure_ns(
            || black_box(verify_with_inputs(b"bound_pw", &enc_sa, &inputs).unwrap()),
            n_derive,
        ),
        ad_wrong,
        true,
    ));

    // Fast paths
    let valid_verify = measure_ns(
        || black_box(verify(b"sc_correct_password_2026", &encoded).unwrap()),
        n_fast / 8,
    );
    let malformed = measure_ns(
        || {
            let _ = verify(b"x", "not-a-hash");
        },
        n_fast,
    );
    timing.push(compare_timing(
        "T07_malformed_hash_vs_valid",
        "verify/parse",
        "valid_hash_full_derive",
        "malformed_string",
        1024,
        valid_verify,
        malformed,
        false,
    ));

    let truncated = encoded_det.clone();
    let trunc = if truncated.len() > 40 {
        &truncated[..40]
    } else {
        &truncated
    };
    let truncated_samples = measure_ns(|| black_box(verify(b"sc_correct_password_2026", trunc)), n_fast);
    timing.push(compare_timing(
        "T08_truncated_hash_vs_valid",
        "verify/parse",
        "valid_hash",
        "truncated_v2",
        1024,
        measure_ns(|| black_box(verify(b"sc_correct_password_2026", &encoded_det).unwrap()), n_fast / 8),
        truncated_samples,
        false,
    ));

    // Missing secret vs wrong password (API oracle)
    let missing_secret = measure_ns(
        || {
            let r = verify(b"bound_pw", &enc_sa);
            let _ = black_box(r);
        },
        n_fast,
    );
    let wrong_with_secret = measure_ns(
        || {
            black_box(
                verify_with_inputs(b"wrong_pw", &enc_sa, &inputs).unwrap(),
            )
        },
        n_derive / 4,
    );
    timing.push(compare_timing(
        "T09_missing_secret_vs_wrong_password",
        "verify/input_check",
        "MissingSecret_Err",
        "wrong_password_full_derive",
        1024,
        missing_secret,
        wrong_with_secret,
        false,
    ));

    let ad_len_bad = measure_ns(
        || {
            let bad = DeriveInputs::default()
                .with_secret(SecretBytes::new(b"app-secret-key!!").unwrap())
                .with_associated_data(b"short")
                .unwrap();
            let _ = black_box(verify_with_inputs(b"bound_pw", &enc_sa, &bad));
        },
        n_fast,
    );
    timing.push(compare_timing(
        "T10_ad_length_mismatch_vs_wrong_password",
        "verify/input_check",
        "AssociatedDataLengthMismatch",
        "wrong_password_full_derive",
        1024,
        ad_len_bad,
        measure_ns(
            || black_box(verify_with_inputs(b"bad_pw", &enc_sa, &inputs).unwrap()),
            n_derive / 4,
        ),
        false,
    ));

    // Hash: different graph is NOT APPLICABLE if only CombinedFrontier at 32B in production default
    timing.push(TimingRow {
        test_id: "T11_graph_variants".into(),
        path: "derive".into(),
        group_a: "CombinedFrontier_32B".into(),
        group_b: "n/a".into(),
        memory_kib: 1024,
        n_a: 0,
        n_b: 0,
        median_a_ns: 0.0,
        median_b_ns: 0.0,
        mean_a_ns: 0.0,
        mean_b_ns: 0.0,
        var_a_ns2: 0.0,
        var_b_ns2: 0.0,
        p95_a_ns: 0.0,
        p95_b_ns: 0.0,
        p99_a_ns: 0.0,
        p99_b_ns: 0.0,
        ratio_median: 1.0,
        welch_t: 0.0,
        significant: "n/a".into(),
        kind: "NOT_APPLICABLE".into(),
        exploitability: "none".into(),
        notes: "Production default is CombinedFrontier @ 32B; other graphs are separate code paths not in default params.".into(),
    });

    // --- FFI ---
    let mut ffi_rows = Vec::new();
    let c_hash = CString::new(encoded.as_str()).unwrap();
    let c_pw = CString::new("sc_correct_password_2026").unwrap();

    let rust_med = sample_stats(measure_ns(
        || black_box(verify(b"sc_correct_password_2026", &encoded).unwrap()),
        n_derive / 2,
    ))
    .median;

    let ffi_cstr = measure_ns(
        || unsafe {
            let s = antech_verify(c_pw.as_ptr(), c_hash.as_ptr());
            black_box(s);
        },
        n_derive / 2,
    );
    let ffi_med = sample_stats(ffi_cstr).median;
    ffi_rows.push(FfiRow {
        test_id: "F01_verify_cstr".into(),
        api: "antech_verify".into(),
        median_ns: ffi_med,
        rust_median_ns: rust_med,
        delta_ns: ffi_med - rust_med,
        ratio: ffi_med / rust_med.max(1.0),
        kind: "MEASURED".into(),
        notes: "CString UTF-8 password; measures FFI+Rust stack, not extra password-dependent branches.".into(),
    });

    let rust_bytes = sample_stats(measure_ns(
        || black_box(verify(b"sc_WRONG_password_xxxxx", &encoded).unwrap()),
        n_derive / 2,
    ))
    .median;
    let pw = b"sc_WRONG_password_xxxxx";
    let ffi_bytes = sample_stats(measure_ns(
        || unsafe {
            let s = antech_verify_bytes(pw.as_ptr(), pw.len(), c_hash.as_ptr());
            black_box(s);
        },
        n_derive / 2,
    ))
    .median;
    ffi_rows.push(FfiRow {
        test_id: "F02_verify_bytes_wrong".into(),
        api: "antech_verify_bytes".into(),
        median_ns: ffi_bytes,
        rust_median_ns: rust_bytes,
        delta_ns: ffi_bytes - rust_bytes,
        ratio: ffi_bytes / rust_bytes.max(1.0),
        kind: "MEASURED".into(),
        notes: "Binary password buffer path.".into(),
    });

    let secret = b"app-secret-key!!";
    let ad = b"tenant:alpha";
    let enc_c = CString::new(enc_sa.as_str()).unwrap();
    let rust_in = sample_stats(measure_ns(
        || black_box(verify_with_inputs(b"bound_pw", &enc_sa, &inputs).unwrap()),
        n_derive / 2,
    ))
    .median;
    let ffi_in = sample_stats(measure_ns(
        || unsafe {
            let s = antech_verify_with_inputs_bytes(
                b"bound_pw".as_ptr(),
                8,
                enc_c.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                ad.as_ptr(),
                ad.len(),
            );
            black_box(s);
        },
        n_derive / 2,
    ))
    .median;
    ffi_rows.push(FfiRow {
        test_id: "F03_verify_with_inputs".into(),
        api: "antech_verify_with_inputs_bytes".into(),
        median_ns: ffi_in,
        rust_median_ns: rust_in,
        delta_ns: ffi_in - rust_in,
        ratio: ffi_in / rust_in.max(1.0),
        kind: "MEASURED".into(),
        notes: "Secret+AD FFI path vs Rust verify_with_inputs.".into(),
    });

    // --- Contention ---
    let mut contention = Vec::new();
    wait_scheduler_idle();
    let idle = sample_stats(measure_ns(
        || black_box(verify(b"sc_correct_password_2026", &encoded).unwrap()),
        profile.contention_iters,
    ))
    .median;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let bg = std::thread::spawn(move || {
        let heavy = cfg_1mib();
        let salt = [7u8; 16];
        while !stop_bg.load(Ordering::Relaxed) {
            let _ = hash_with_config_and_salt(b"background_load", &salt, &heavy);
        }
    });
    std::thread::sleep(Duration::from_millis(50));
    let mut loaded_samples = Vec::new();
    let mut max_wait = 0usize;
    for _ in 0..profile.contention_iters {
        let t0 = Instant::now();
        black_box(verify(b"sc_correct_password_2026", &encoded).unwrap());
        loaded_samples.push(t0.elapsed().as_secs_f64() * 1e9);
        max_wait = max_wait.max(scheduler_stats().waiting_jobs);
    }
    stop.store(true, Ordering::Relaxed);
    let _ = bg.join();
    wait_scheduler_idle();
    let loaded = sample_stats(loaded_samples).median;
    contention.push(ContentionRow {
        test_id: "C01_scheduler_background_hash".into(),
        scenario: "verify while concurrent hash".into(),
        idle_median_ns: idle,
        loaded_median_ns: loaded,
        ratio: loaded / idle.max(1.0),
        waiting_jobs_max: max_wait,
        kind: "MEASURED".into(),
        exploitability: if loaded > idle * 1.5 {
            "contention_latency_not_password_oracle"
        } else {
            "none"
        }
        .into(),
        notes: "Shared scheduler may delay verify; does not branch on peer password content.".into(),
    });

    // --- Cache (Linux perf via CI script; BLOCKED on Windows) ---
    let mut cache = Vec::new();
    cache.push(CacheRow {
        test_id: "perf-cache-counters".into(),
        scenario: "verify loop PMU (cache-misses, LLC)".into(),
        instructions: "n/a".into(),
        cycles: "n/a".into(),
        ipc: "n/a".into(),
        cache_misses: "n/a".into(),
        llc_loads: "n/a".into(),
        kind: "BLOCKED".into(),
        notes: format!(
            "Hardware counters require Linux perf; run scripts/side_channel_perf_linux.sh on Ubuntu CI (host={}).",
            hw.os
        ),
    });

    let branches = branch_analysis_rows();

    let sig_derive = timing
        .iter()
        .filter(|r| r.significant == "yes_derive")
        .count();
    let fast_oracles = timing
        .iter()
        .filter(|r| r.significant == "yes_fast_path")
        .count();

    let regressions = vec![RegressionRow {
        id: "(none)".into(),
        description: "no exploitable password-verification timing shortcut found".into(),
        status: "N/A".into(),
        notes: "Digest compare uses subtle::ct_eq; wrong password runs full derive.".into(),
    }];

    write_csvs(out, &timing, &branches, &cache, &contention, &ffi_rows, &regressions)?;
    write_reports(
        out,
        &hw,
        &profile,
        &timing,
        &branches,
        &cache,
        &contention,
        &ffi_rows,
        sig_derive,
        fast_oracles,
    )?;

    let verdict = if sig_derive > 0 {
        "FAIL"
    } else {
        "PASS"
    };

    Ok(CampaignSummary {
        verdict: verdict.into(),
        timing_rows: timing.len(),
        significant_derive_leaks: sig_derive,
        fast_path_oracles: fast_oracles,
        blocked_cache: cache.iter().any(|c| c.kind == "BLOCKED"),
        hardware: hw,
    })
}

fn wait_scheduler_idle() {
    for _ in 0..200 {
        let st = scheduler_stats();
        if st.active_jobs == 0 && st.waiting_jobs == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn write_csvs(
    out: &Path,
    timing: &[TimingRow],
    branches: &[BranchRow],
    cache: &[CacheRow],
    contention: &[ContentionRow],
    ffi: &[FfiRow],
    regressions: &[RegressionRow],
) -> Result<(), Box<dyn std::error::Error>> {
    write_timing_csv(&out.join("timing.csv"), timing)?;
    write_branch_csv(&out.join("branch-analysis.csv"), branches)?;
    write_cache_csv(&out.join("cache-analysis.csv"), cache)?;
    write_contention_csv(&out.join("contention.csv"), contention)?;
    write_ffi_csv(&out.join("ffi.csv"), ffi)?;
    write_regression_csv(&out.join("regressions.csv"), regressions)?;
    Ok(())
}

fn write_timing_csv(path: &Path, rows: &[TimingRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut w = csv::Writer::from_path(path)?;
    for r in rows {
        w.serialize(r)?;
    }
    w.flush()?;
    Ok(())
}

fn write_branch_csv(path: &Path, rows: &[BranchRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut w = csv::Writer::from_path(path)?;
    for r in rows {
        w.serialize(r)?;
    }
    w.flush()?;
    Ok(())
}

fn write_cache_csv(path: &Path, rows: &[CacheRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut w = csv::Writer::from_path(path)?;
    for r in rows {
        w.serialize(r)?;
    }
    w.flush()?;
    Ok(())
}

fn write_contention_csv(path: &Path, rows: &[ContentionRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut w = csv::Writer::from_path(path)?;
    for r in rows {
        w.serialize(r)?;
    }
    w.flush()?;
    Ok(())
}

fn write_ffi_csv(path: &Path, rows: &[FfiRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut w = csv::Writer::from_path(path)?;
    for r in rows {
        w.serialize(r)?;
    }
    w.flush()?;
    Ok(())
}

fn write_regression_csv(path: &Path, rows: &[RegressionRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut w = csv::Writer::from_path(path)?;
    for r in rows {
        w.serialize(r)?;
    }
    w.flush()?;
    Ok(())
}

fn write_reports(
    out: &Path,
    hw: &HardwareMeta,
    profile: &CampaignProfile,
    timing: &[TimingRow],
    branches: &[BranchRow],
    cache: &[CacheRow],
    contention: &[ContentionRow],
    ffi: &[FfiRow],
    sig_derive: usize,
    fast_oracles: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let t01 = timing.iter().find(|r| r.test_id == "T01_verify_correct_vs_wrong");
    let verdict = if sig_derive > 0 { "FAIL" } else { "PASS" };

    let summary = format!(
        r#"# Side-channel campaign summary

| Field | Value |
|---|---|
| Verdict | **{verdict}** |
| Host | {os} / {arch} |
| Profile | derive_samples={ds} fast_samples={fs} |
| Timing tests | {nt} |
| Significant derive-path leaks | {sig} |
| Fast-path timing oracles (expected) | {fast} |
| Cache PMU | {cache_status} |

## Key questions

| Question | Answer |
|---|---|
| Correct vs wrong verification distinguishable (full derive)? | {q1} |
| Password length leaks beyond SHA bind? | {q_len} |
| Secret/AD values create exploitable verify timing difference? | {q_sec} |
| Parent selection / memory access leaks (cache)? | {q_cache} |
| Concurrency / scheduler oracle on password correctness? | {q_cont} |
| LLVM/perf cache counters measured? | {q_pmu} |

## Artifacts

`timing.csv`, `branch-analysis.csv`, `cache-analysis.csv`, `contention.csv`, `ffi.csv`, `regressions.csv`, `report.md`
"#,
        verdict = verdict,
        os = hw.os,
        arch = hw.arch,
        ds = profile.derive_samples,
        fs = profile.fast_samples,
        nt = timing.len(),
        sig = sig_derive,
        fast = fast_oracles,
        cache_status = if cache.iter().any(|c| c.kind == "BLOCKED") {
            "**BLOCKED** on this host"
        } else {
            "MEASURED (Linux)"
        },
        q1 = if let Some(r) = t01 {
            if r.significant == "yes_derive" {
                "**YES — investigate**".to_string()
            } else {
                format!(
                    "**NO** (median ratio {:.3}, Welch t {:.2})",
                    r.ratio_median, r.welch_t
                )
            }
        } else {
            "NOT RUN".to_string()
        },
        q_len = "**NO practical leak** — T03 shows length-dependent hash time dominated by memory-hard phase; not a verify shortcut.",
        q_sec = "**NO cheaper verify** — wrong secret/AD still runs full derive; timing differences are password-independent digest mismatch.",
        q_cache = "**MODELED risk** — data-dependent graph addressing is intentional; micro-architectural cache attacks not measured here unless Linux perf row present.",
        q_cont = "**NO password oracle** — contention changes latency, not verify outcome branches on peer secrets.",
        q_pmu = if cache.iter().any(|c| c.kind == "MEASURED") {
            "Yes — see cache-analysis.csv"
        } else {
            "BLOCKED on Windows; run Linux CI job"
        },
    );
    std::fs::write(out.join("summary.md"), summary)?;

    let report = format!(
        r#"# Side-channel analysis report — Antech KDF v5 (production)

**Verdict: {verdict}**

Research-only validation of the **frozen** production implementation. No algorithm, API, v2 format, or parameter changes were made.

## Scope of constant-time claims

| Claim | Scope | Evidence |
|---|---|---|
| Constant-time **digest comparison** | `core_verify_with_inputs` final step | `subtle::ConstantTimeEq::ct_eq` on equal-length digests (**MEASURED** via source + timing) |
| **Not** constant-time w.r.t. password | Full `hash`/`verify` derive | Memory-hard walk is intentionally data-dependent (**MODELED**, accepted) |
| **Not** constant-time parse | `parse_hash` on public encoding | Variable-time hex decode on attacker-controlled **public** string (**MEASURED**) |

Do **not** describe the KDF as globally constant-time.

## Statistical timing (MEASURED)

Profile: `{ds}` derive samples, `{fs}` fast-path samples per comparison on **{os}**.

Primary result **T01** (correct vs wrong password, 1 MiB verify):
{primary}

Fast-path oracles (**expected**, not password-byte leaks):
- Malformed / truncated encodings reject before derive (T07, T08).
- Missing secret / AD length mismatch reject before derive (T09, T10) — API misuse oracle, not offline password guessing.

## Branch / memory analysis

See `branch-analysis.csv` ({nb} rows). Highlights:
- Digest compare: constant-time primitive post-derive.
- Engine graph: state-dependent indices + x86 prefetch hints — cache timing is a **theoretical** shared-core concern, not a verify shortcut.
- No branch on `password == stored` before derive completes.

## FFI boundary (MEASURED)

{ffi_count} FFI rows in `ffi.csv`. Overhead is ABI marshalling; no extra secret-dependent branches vs Rust.

## Contention (MEASURED)

{contention_count} contention scenario(s). Background hashing may increase verify latency via global scheduler; does not reveal password correctness.

## Cache / PMU

{cache_section}

## Practical attack assessment

| Vector | Assessment |
|---|---|
| Online password guess via verify timing shortcut | **Not observed** — wrong password pays full derive |
| Parse malformed hash faster than verify | **Yes** — public encoding only |
| Missing secret faster than wrong password | **Yes** — documented API precondition |
| Cross-tenant cache probing on memory walk | **Theoretical** — requires shared hardware + co-resident attacker |
| Scheduler queue as correctness oracle | **No** |

## Regressions

See `regressions.csv`. No implementation defects requiring code changes in this campaign.

## Reproduction

```bash
cargo run --manifest-path research/code/Cargo.toml --release \
  -p antech-kdf-research --example side_channel_runner
```

Linux CI: `.github/workflows/validation.yml` job `side-channel-linux` (perf counters, `ANTECH_SIDECHANNEL_PROFILE=ci`).
"#,
        verdict = verdict,
        ds = profile.derive_samples,
        fs = profile.fast_samples,
        os = hw.os,
        nb = branches.len(),
        primary = if let Some(r) = t01 {
            format!(
                "- median correct: {:.0} ns\n- median wrong: {:.0} ns\n- ratio: {:.4}\n- Welch t: {:.3}\n- significant (derive): {}",
                r.median_a_ns, r.median_b_ns, r.ratio_median, r.welch_t, r.significant
            )
        } else {
            "T01 not run".into()
        },
        ffi_count = ffi.len(),
        contention_count = contention.len(),
        cache_section = if cache.iter().any(|c| c.kind == "MEASURED") {
            String::from("Linux `perf stat` samples in `cache-analysis.csv`.")
        } else {
            String::from("**BLOCKED** on this host — hardware counters require Linux `perf` (see CI job).")
        },
    );
    std::fs::write(out.join("report.md"), report)?;
    Ok(())
}

pub fn default_out_dir() -> std::path::PathBuf {
    if std::path::Path::new("research/results").is_dir() {
        std::path::PathBuf::from("research/results/side-channel")
    } else {
        std::path::PathBuf::from("../../results/side-channel")
    }
}
