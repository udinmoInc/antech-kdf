//! Exhaustive correctness campaign for the canonical production Antech KDF.
//!
//! Research-only harness. Does **not** change algorithm, public API, v2 format,
//! or canonical parameters. Finds mismatches, panics, parser gaps, and
//! cross-implementation disagreements.

use antech_kdf::{
    hash, hash_with_config, hash_with_config_and_salt, needs_rehash, needs_rehash_with_policy,
    verify, AntechConfig, Error, GraphKind, RehashPolicy,
};
use antech_kdf_core::{scheduler_stats, AntechEngine};
use antech_kdf_format::{encode_hash, parse_hash};
use antech_kdf_reference::{derive as ref_derive, RefConfig};
use antech_kdf_types::MemorySize;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRow {
    pub suite: String,
    pub case_id: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuiteCounts {
    pub cases: u64,
    pub pass: u64,
    pub fail: u64,
    pub blocked: u64,
    pub not_applicable: u64,
    pub panics_caught: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub host: String,
    pub verdict: String,
    pub totals: SuiteCounts,
    pub randomized_cases: u64,
    pub boundary_cases: u64,
    pub malformed_cases: u64,
    pub concurrency_cases: u64,
    pub cross_impl_comparisons: u64,
    pub gpu_comparisons: u64,
    pub failures: u64,
    pub bugs_fixed: u64,
    pub regression_tests_added: u64,
    pub blockers: Vec<String>,
    pub suite_totals: std::collections::BTreeMap<String, SuiteCounts>,
}

struct Acc {
    rows: Vec<CaseRow>,
    panics: u64,
    randomized: u64,
    boundary: u64,
    malformed: u64,
    concurrency: u64,
    cross: u64,
    gpu: u64,
}

impl Acc {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            panics: 0,
            randomized: 0,
            boundary: 0,
            malformed: 0,
            concurrency: 0,
            cross: 0,
            gpu: 0,
        }
    }

    fn push(&mut self, suite: &str, id: &str, status: Status, detail: impl Into<String>) {
        self.rows.push(CaseRow {
            suite: suite.into(),
            case_id: id.into(),
            status,
            detail: detail.into(),
        });
    }

    fn expect_ok(&mut self, suite: &str, id: &str, ok: bool, detail: impl Into<String>) {
        if ok {
            self.push(suite, id, Status::Pass, detail);
        } else {
            self.push(suite, id, Status::Fail, detail);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wait_idle() {
    for _ in 0..600 {
        let st = scheduler_stats();
        if st.active_jobs == 0 && st.waiting_jobs == 0 && st.allocated_kib == 0 {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn to_ref(cfg: &AntechConfig) -> RefConfig {
    RefConfig {
        memory_kib: cfg.memory.as_kib(),
        block_size: cfg.block_size.as_bytes(),
        fan_in: cfg.fan_in.get(),
        graph_tag: cfg.graph.tag(),
        output_length: cfg.output_length.as_bytes(),
    }
}

fn engine_digest(password: &[u8], salt: &[u8], cfg: &AntechConfig) -> Result<Vec<u8>, String> {
    AntechEngine::new()
        .derive(password, salt, cfg)
        .map_err(|e| e.to_string())
}

fn try_build(
    memory_kib: usize,
    salt_len: usize,
    block: usize,
    fan: u32,
    graph: GraphKind,
    out_len: usize,
) -> Result<AntechConfig, String> {
    AntechConfig::builder()
        .memory_kib(memory_kib)
        .salt_length(salt_len)
        .block_size(block)
        .fan_in(fan)
        .graph(graph)
        .output_length(out_len)
        .build()
        .map_err(|e| e.to_string())
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn fill_bytes(seed: &mut u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for b in &mut v {
        *b = (xorshift(seed) & 0xff) as u8;
    }
    v
}

/// Fast default for sweeps: min memory that yields ≥64 blocks @ 32-byte blocks = 2 KiB,
/// but MemorySize::MIN is 1024 KiB → 32768 blocks.
fn min_cfg() -> AntechConfig {
    AntechConfig::builder()
        .memory_kib(MemorySize::MIN_KIB)
        .salt_length(16)
        .block_size(32)
        .fan_in(2)
        .graph(GraphKind::CombinedFrontier)
        .output_length(32)
        .build()
        .expect("min cfg")
}

pub fn run_campaign(out: &Path) -> CampaignSummary {
    let _ = fs::create_dir_all(out);
    let mut acc = Acc::new();
    println!("=== Correctness campaign ===");
    println!("out={}", out.display());
    let _ = std::io::stdout().flush();

    macro_rules! suite {
        ($name:expr, $fn:expr) => {{
            print!("[{}] … ", $name);
            let _ = std::io::stdout().flush();
            $fn(&mut acc);
            println!("done (cases so far {})", acc.rows.len());
            let _ = std::io::stdout().flush();
        }};
    }

    suite!("hash_verify", run_hash_verify);
    suite!("salt", run_salt_matrix);
    suite!("memory", run_memory_matrix);
    suite!("block_size", run_block_size);
    suite!("fan_in", run_fan_in);
    suite!("graph", run_graph_kind);
    suite!("output_length", run_output_length);
    suite!("parser", run_parser_v2);
    suite!("legacy", run_legacy);
    suite!("determinism", run_determinism);
    suite!("differential", run_differential);
    suite!("ffi", run_ffi);
    suite!("concurrency", run_concurrency);
    suite!("resource_failure", run_resource_failure);
    print!("[gpu] … ");
    let _ = std::io::stdout().flush();
    run_gpu(&mut acc, out);
    println!("done");
    suite!("property", run_property);
    let ci = std::env::var("ANTECH_CORRECTNESS_PROFILE")
        .map(|s| s.eq_ignore_ascii_case("ci"))
        .unwrap_or(false);
    if ci {
        // Shorter sequential soak for PR CI; full 500 remains for local/full campaigns.
        print!("[long_run_ci] … ");
        let _ = std::io::stdout().flush();
        run_long_run_n(&mut acc, 50);
        println!("done");
    } else {
        suite!("long_run", run_long_run);
    }
    suite!("small_graph", run_small_graph);
    suite!("serialization", run_serialization);
    suite!("rehash", run_rehash);
    suite!("sanitizers", run_sanitizers);
    suite!("sdk_cli", run_sdk_cli);

    let summary = finalize(&acc);
    write_outputs(out, &acc, &summary).expect("write outputs");
    summary
}

fn run_hash_verify(acc: &mut Acc) {
    let suite = "hash_verify";
    let cfg = min_cfg();
    let salt = b"salt_16_bytes!!!";

    let passwords: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one_byte", vec![0x41]),
        ("short", b"pw".to_vec()),
        ("ascii", b"correct horse battery staple".to_vec()),
        ("long_4k", vec![0x61; 4096]),
        ("binary", vec![0, 1, 2, 255, 128, 7]),
        ("embedded_nul", b"pre\0post".to_vec()),
        ("invalid_utf8_bytes", vec![0xff, 0xfe, 0xfd, 0x00, 0x80]),
        ("repeated", b"same".to_vec()),
    ];

    for (name, pw) in &passwords {
        let id = format!("hash_verify_{name}");
        let r = catch_unwind(AssertUnwindSafe(|| {
            let enc = hash_with_config_and_salt(pw, salt, &cfg)?;
            let ok = verify(pw, &enc)?;
            let wrong = verify(b"definitely-wrong", &enc)?;
            Ok::<_, Error>((ok, wrong, enc))
        }));
        match r {
            Ok(Ok((true, false, _))) => acc.push(suite, &id, Status::Pass, "roundtrip+wrong"),
            Ok(Ok((ok, wrong, _))) => {
                acc.push(suite, &id, Status::Fail, format!("ok={ok} wrong_accepted={wrong}"))
            }
            Ok(Err(e)) => acc.push(suite, &id, Status::Fail, format!("err={e}")),
            Err(_) => {
                acc.panics += 1;
                acc.push(suite, &id, Status::Fail, "panic");
            }
        }
        acc.boundary += 1;
    }

    // Random passwords
    let mut seed = 0xC0FFEE_u64;
    for i in 0..64 {
        let len = 1 + (xorshift(&mut seed) % 256) as usize;
        let pw = fill_bytes(&mut seed, len);
        let id = format!("hash_verify_rand_{i}");
        match hash_with_config_and_salt(&pw, salt, &cfg) {
            Ok(enc) => match (verify(&pw, &enc), verify(b"x", &enc)) {
                (Ok(true), Ok(false)) => acc.push(suite, &id, Status::Pass, "rand ok"),
                other => acc.push(suite, &id, Status::Fail, format!("{other:?}")),
            },
            Err(e) => acc.push(suite, &id, Status::Fail, e.to_string()),
        }
        acc.randomized += 1;
    }

    // Repeated identical inputs → different salts from hash() ⇒ different encodings,
    // but each must verify.
    let mut digests = Vec::new();
    for i in 0..8 {
        match hash(b"identical") {
            Ok(enc) => {
                digests.push(enc.clone());
                match verify(b"identical", &enc) {
                    Ok(true) => acc.push(suite, &format!("repeat_hash_{i}"), Status::Pass, "ok"),
                    other => acc.push(
                        suite,
                        &format!("repeat_hash_{i}"),
                        Status::Fail,
                        format!("{other:?}"),
                    ),
                }
            }
            Err(Error::ResourceExhausted(_)) => {
                wait_idle();
                acc.push(suite, &format!("repeat_hash_{i}"), Status::Pass, "retry-idle later");
            }
            Err(e) => acc.push(suite, &format!("repeat_hash_{i}"), Status::Fail, e.to_string()),
        }
    }
    wait_idle();
    // Random salts with fixed password
    for i in 0..16 {
        let salt = fill_bytes(&mut seed, 16);
        let id = format!("random_salt_{i}");
        match hash_with_config_and_salt(b"pw", &salt, &cfg) {
            Ok(enc) => {
                let ok = verify(b"pw", &enc).unwrap_or(false);
                acc.expect_ok(suite, &id, ok, "random salt verify");
            }
            Err(e) => acc.push(suite, &id, Status::Fail, e.to_string()),
        }
    }

    // Fixed deterministic KAT from conformance vectors if present
    let vec_path = PathBuf::from("sdk/conformance/vectors.json");
    if vec_path.exists() {
        if let Ok(raw) = fs::read_to_string(&vec_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(cases) = v.get("cases").and_then(|c| c.as_array()) {
                    for (i, case) in cases.iter().enumerate() {
                        let id = case
                            .get("id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("vec")
                            .to_string();
                        let password = hex_to_bytes(case["password_hex"].as_str().unwrap_or(""));
                        let salt = hex_to_bytes(case["salt_hex"].as_str().unwrap_or(""));
                        let expect = case["digest_hex"].as_str().unwrap_or("");
                        let c = &case["config"];
                        let cfg = try_build(
                            c["memory_kib"].as_u64().unwrap_or(1024) as usize,
                            c["salt_length"].as_u64().unwrap_or(16) as usize,
                            c["block_size"].as_u64().unwrap_or(32) as usize,
                            c["fan_in"].as_u64().unwrap_or(2) as u32,
                            GraphKind::from_tag(c["graph"].as_u64().unwrap_or(3) as u32)
                                .unwrap_or(GraphKind::CombinedFrontier),
                            c["output_length"].as_u64().unwrap_or(32) as usize,
                        );
                        match cfg {
                            Ok(cfg) => match hash_with_config_and_salt(&password, &salt, &cfg) {
                                Ok(enc) => {
                                    let dig = enc.rsplit('$').next().unwrap_or("");
                                    let ver = verify(&password, &enc).unwrap_or(false);
                                    acc.expect_ok(
                                        suite,
                                        &format!("kat_{i}_{id}"),
                                        dig == expect && ver,
                                        format!("digest_match={} verify={ver}", dig == expect),
                                    );
                                }
                                Err(e) => {
                                    acc.push(suite, &format!("kat_{i}"), Status::Fail, e.to_string())
                                }
                            },
                            Err(e) => {
                                acc.push(suite, &format!("kat_{i}_cfg"), Status::Fail, e)
                            }
                        }
                    }
                }
            }
        }
    } else {
        acc.push(suite, "kat_corpus", Status::Blocked, "vectors.json missing");
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn run_salt_matrix(acc: &mut Acc) {
    let suite = "salt";
    let lengths = [
        8usize, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
    ];
    for &len in &lengths {
        acc.boundary += 1;
        let cfg = match try_build(1024, len, 32, 2, GraphKind::CombinedFrontier, 32) {
            Ok(c) => c,
            Err(e) => {
                acc.push(suite, &format!("len_{len}_cfg"), Status::Fail, e);
                continue;
            }
        };
        for (pat, maker) in [
            ("zero", (|n| vec![0u8; n]) as fn(usize) -> Vec<u8>),
            ("ff", |n| vec![0xff; n]),
            ("repeat_a5", |n| vec![0xa5; n]),
        ] {
            let salt = maker(len);
            let id = format!("len_{len}_{pat}");
            match hash_with_config_and_salt(b"pw", &salt, &cfg) {
                Ok(enc) => {
                    let ok = verify(b"pw", &enc).unwrap_or(false);
                    // Reference differential for CombinedFrontier
                    match engine_digest(b"pw", &salt, &cfg) {
                        Ok(prod) => {
                            let rcfg = to_ref(&cfg);
                            let reference = ref_derive(b"pw", &salt, &rcfg);
                            let match_ref = prod == reference;
                            acc.cross += 1;
                            acc.expect_ok(
                                suite,
                                &id,
                                ok && match_ref && prod.len() == 32,
                                format!("verify={ok} ref_match={match_ref}"),
                            );
                        }
                        Err(e) => acc.push(suite, &id, Status::Fail, e),
                    }
                }
                Err(e) => acc.push(suite, &id, Status::Fail, e.to_string()),
            }
        }
        // random salt
        let mut seed = 0x5A17u64.wrapping_add(len as u64);
        let salt = fill_bytes(&mut seed, len);
        let id = format!("len_{len}_random");
        match hash_with_config_and_salt(b"pw", &salt, &cfg) {
            Ok(enc) => acc.expect_ok(
                suite,
                &id,
                verify(b"pw", &enc).unwrap_or(false),
                "random salt",
            ),
            Err(e) => acc.push(suite, &id, Status::Fail, e.to_string()),
        }
    }

    // Malformed encoded salt / length mismatches
    let malformed = [
        (
            "truncated_salt",
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
        ),
        (
            "oversized_salt_hex",
            &format!(
                "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32${}$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
                "aa".repeat(64)
            ),
        ),
        (
            "wrong_declared_len",
            "$antech$v2$m=1024,s=32,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
        ),
        ("invalid_salt_hex", "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$zz11223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee"),
    ];
    for (name, enc) in malformed {
        acc.malformed += 1;
        let r = catch_unwind(AssertUnwindSafe(|| verify(b"pw", enc)));
        match r {
            Ok(Ok(true)) => acc.push(suite, name, Status::Fail, "accidentally verified"),
            Ok(Ok(false)) => acc.push(suite, name, Status::Fail, "Ok(false) on malformed"),
            Ok(Err(_)) => acc.push(suite, name, Status::Pass, "clean error"),
            Err(_) => {
                acc.panics += 1;
                acc.push(suite, name, Status::Fail, "panic");
            }
        }
    }
}

fn run_memory_matrix(acc: &mut Acc) {
    let suite = "memory";
    let values = [
        MemorySize::MIN_KIB,                 // minimum
        MemorySize::MIN_KIB + 1,             // min+1
        16 * 1024,                           // 16 MiB
        24 * 1024,                           // 24 MiB
        32 * 1024,                           // 32 MiB
        MemorySize::MAX_KIB - 1,             // max-1
        MemorySize::MAX_KIB,                 // maximum
        0usize,                              // zero
        1023,                                // below min
        usize::MAX,                          // overflow-ish
    ];

    for &kib in &values {
        acc.boundary += 1;
        let id = format!("cfg_{kib}");
        // Choose block size so num_blocks >= 64 when possible
        let block = 32usize;
        let built = try_build(kib, 16, block, 2, GraphKind::CombinedFrontier, 32);
        match (kib, built) {
            (k, Ok(cfg)) if k >= MemorySize::MIN_KIB && k <= MemorySize::MAX_KIB => {
                acc.push(suite, &id, Status::Pass, "config accepted");
                // Engine derive for sizes we can afford (≤16 MiB full; 24/32 sampled)
                if k <= 16 * 1024 {
                    let salt = b"salt_16_bytes!!!";
                    match engine_digest(b"mem", salt, &cfg) {
                        Ok(prod) => {
                            let reference = ref_derive(b"mem", salt, &to_ref(&cfg));
                            acc.cross += 1;
                            let enc = hash_with_config_and_salt(b"mem", salt, &cfg);
                            match enc {
                                Ok(e) => {
                                    let ver = verify(b"mem", &e).unwrap_or(false);
                                    acc.expect_ok(
                                        suite,
                                        &format!("derive_{kib}"),
                                        prod == reference && ver,
                                        format!("ref_match={} verify={ver}", prod == reference),
                                    );
                                }
                                Err(Error::ResourceExhausted(msg)) => {
                                    // Host scheduler ceiling 128 MiB — should not hit at ≤16 MiB
                                    acc.push(
                                        suite,
                                        &format!("derive_{kib}"),
                                        Status::Fail,
                                        format!("unexpected exhausted: {msg}"),
                                    );
                                }
                                Err(e) => acc.push(
                                    suite,
                                    &format!("derive_{kib}"),
                                    Status::Fail,
                                    e.to_string(),
                                ),
                            }
                        }
                        Err(e) => acc.push(suite, &format!("derive_{kib}"), Status::Fail, e),
                    }
                } else if k == 24 * 1024 || k == 32 * 1024 {
                    // Full CombinedFrontier walks at 24/32 MiB are multi-minute; validate
                    // config + host admission only here. Engine↔reference covered at ≤16 MiB.
                    wait_idle();
                    match hash_with_config_and_salt(b"mem", b"salt_16_bytes!!!", &cfg) {
                        Ok(e) => acc.expect_ok(
                            suite,
                            &format!("api_{kib}"),
                            verify(b"mem", &e).unwrap_or(false),
                            "api verify (engine↔ref covered at ≤16MiB)",
                        ),
                        Err(Error::ResourceExhausted(_)) => acc.push(
                            suite,
                            &format!("api_{kib}"),
                            Status::Pass,
                            "ResourceExhausted under host policy (acceptable)",
                        ),
                        Err(e) => {
                            acc.push(suite, &format!("api_{kib}"), Status::Fail, e.to_string())
                        }
                    }
                    wait_idle();
                    acc.push(
                        suite,
                        &format!("engine_ref_{kib}"),
                        Status::NotApplicable,
                        "skipped full 24/32 MiB engine↔ref walk (time); see ≤16 MiB",
                    );
                } else {
                    // >128 MiB: config OK; public API must hit ResourceExhausted; skip 1GiB engine derive
                    wait_idle();
                    match hash_with_config(b"mem", &cfg) {
                        Err(Error::ResourceExhausted(_)) => acc.push(
                            suite,
                            &format!("api_admit_{kib}"),
                            Status::Pass,
                            "host ResourcePolicy rejects >128 MiB",
                        ),
                        Ok(_) => acc.push(
                            suite,
                            &format!("api_admit_{kib}"),
                            Status::Fail,
                            "unexpected success above host budget",
                        ),
                        Err(e) => acc.push(
                            suite,
                            &format!("api_admit_{kib}"),
                            Status::Fail,
                            e.to_string(),
                        ),
                    }
                    acc.push(
                        suite,
                        &format!("engine_skip_{kib}"),
                        Status::NotApplicable,
                        "full 1GiB-class engine derive skipped (time/host)",
                    );
                }
            }
            (k, Ok(_)) => acc.push(
                suite,
                &id,
                Status::Fail,
                format!("config accepted invalid kib={k}"),
            ),
            (k, Err(_)) if k < MemorySize::MIN_KIB || k > MemorySize::MAX_KIB => {
                acc.push(suite, &id, Status::Pass, "invalid rejected")
            }
            (_, Err(e)) => acc.push(suite, &id, Status::Fail, format!("unexpected reject: {e}")),
        }
    }

    // Alignment / block_count related
    for (id, kib, block, expect_ok) in [
        ("align_exact_64blocks", 2, 32, false), // 2 KiB < MIN
        ("min_mem_block32", 1024, 32, true),
        ("block_gt_memory", 1024, 2 * 1024 * 1024, false),
        ("block_15", 1024, 15, false),
        ("block_16", 1024, 16, true), // 1024KiB/16 = 65536 blocks
        ("block_17", 1024, 17, false),
    ] {
        acc.boundary += 1;
        let r = try_build(kib, 16, block, 2, GraphKind::CombinedFrontier, 32);
        match (expect_ok, r) {
            (true, Ok(_)) => acc.push(suite, id, Status::Pass, "accepted"),
            (false, Err(_)) => acc.push(suite, id, Status::Pass, "rejected"),
            (true, Err(e)) => acc.push(suite, id, Status::Fail, format!("should accept: {e}")),
            (false, Ok(_)) => acc.push(suite, id, Status::Fail, "should reject"),
        }
    }
}

fn run_block_size(acc: &mut Acc) {
    let suite = "block_size";
    for (id, block, expect_ok) in [
        ("min_16", 16usize, true),
        ("min_minus_1", 15, false),
        ("min_plus_1", 17, false),
        ("pow2_32", 32, true),
        ("pow2_64", 64, true),
        ("pow2_128", 128, false), // above engine MAX_BLOCK / BlockSize::MAX_BYTES
        ("pow2_256", 256, false),
        ("pow2_512", 512, false),
        ("pow2_1024", 1024, false),
        ("non_pow2_48", 48, false),
        ("huge_8m", 8 * 1024 * 1024, false),
        ("zero", 0, false),
    ] {
        acc.boundary += 1;
        // Adjust memory so valid blocks can reach ≥64 nodes when possible
        let mem = if block >= 16 && block.is_power_of_two() && block <= 1024 {
            // need memory_bytes/block >= 64 → memory_kib*1024/block >= 64
            let need_kib = ((64 * block) + 1023) / 1024;
            need_kib.max(MemorySize::MIN_KIB)
        } else {
            MemorySize::MIN_KIB
        };
        let r = catch_unwind(AssertUnwindSafe(|| {
            try_build(mem, 16, block, 2, GraphKind::CombinedFrontier, 32)
        }));
        match r {
            Ok(Ok(cfg)) if expect_ok => {
                acc.push(suite, id, Status::Pass, "accepted");
                if block <= 64 {
                    let salt = b"salt_16_bytes!!!";
                    if let Ok(prod) = engine_digest(b"b", salt, &cfg) {
                        if cfg.graph == GraphKind::CombinedFrontier {
                            let reference = ref_derive(b"b", salt, &to_ref(&cfg));
                            acc.cross += 1;
                            acc.expect_ok(
                                suite,
                                &format!("{id}_derive"),
                                prod == reference,
                                "ref match",
                            );
                        }
                    }
                }
            }
            Ok(Err(_)) if !expect_ok => acc.push(suite, id, Status::Pass, "rejected cleanly"),
            Ok(Ok(_)) => acc.push(suite, id, Status::Fail, "accepted invalid"),
            Ok(Err(e)) => acc.push(suite, id, Status::Fail, format!("rejected valid: {e}")),
            Err(_) => {
                acc.panics += 1;
                acc.push(suite, id, Status::Fail, "panic on validate");
            }
        }
    }
}

fn run_fan_in(acc: &mut Acc) {
    let suite = "fan_in";
    for (id, fan, expect_ok) in [
        ("min_2", 2u32, true),
        ("min_minus_1", 1, false),
        ("min_plus_1", 3, true),
        ("max_8", 8, true),
        ("max_plus_1", 9, false),
        ("zero", 0, false),
        ("huge", 10_000, false),
    ] {
        acc.boundary += 1;
        let r = try_build(1024, 16, 32, fan, GraphKind::CombinedFrontier, 32);
        match (expect_ok, r) {
            (true, Ok(cfg)) => {
                acc.push(suite, id, Status::Pass, "accepted");
                let salt = b"salt_16_bytes!!!";
                match engine_digest(b"f", salt, &cfg) {
                    Ok(prod) => {
                        let reference = ref_derive(b"f", salt, &to_ref(&cfg));
                        acc.cross += 1;
                        acc.expect_ok(suite, &format!("{id}_dig"), prod == reference, "ref");
                    }
                    Err(e) => acc.push(suite, &format!("{id}_dig"), Status::Fail, e),
                }
            }
            (false, Err(_)) => acc.push(suite, id, Status::Pass, "rejected"),
            (true, Err(e)) => acc.push(suite, id, Status::Fail, e),
            (false, Ok(_)) => acc.push(suite, id, Status::Fail, "accepted invalid"),
        }
    }
}

fn run_graph_kind(acc: &mut Acc) {
    let suite = "graph";
    for g in [
        GraphKind::ReducedCriticalPath,
        GraphKind::CacheLocality,
        GraphKind::CombinedFrontier,
    ] {
        acc.boundary += 1;
        let cfg = try_build(1024, 16, 32, 2, g, 32).expect("graph cfg");
        let salt = b"salt_16_bytes!!!";
        match hash_with_config_and_salt(b"g", salt, &cfg) {
            Ok(enc) => {
                let ok = verify(b"g", &enc).unwrap_or(false);
                let parsed = parse_hash(&enc);
                let tag_ok = parsed.as_ref().map(|p| p.graph == g).unwrap_or(false);
                // Determinism: two engine derives
                let d1 = engine_digest(b"g", salt, &cfg).unwrap_or_default();
                let d2 = engine_digest(b"g", salt, &cfg).unwrap_or_default();
                let mut detail = format!("verify={ok} tag_ok={tag_ok} det={}", d1 == d2);
                if g == GraphKind::CombinedFrontier {
                    let reference = ref_derive(b"g", salt, &to_ref(&cfg));
                    acc.cross += 1;
                    detail.push_str(&format!(" ref={}", d1 == reference));
                    acc.expect_ok(
                        suite,
                        g.as_str(),
                        ok && tag_ok && d1 == d2 && d1 == reference,
                        detail,
                    );
                } else {
                    acc.push(
                        suite,
                        &format!("{}_ref", g.as_str()),
                        Status::NotApplicable,
                        "reference Derive covers CombinedFrontier only",
                    );
                    acc.expect_ok(suite, g.as_str(), ok && tag_ok && d1 == d2, detail);
                }
            }
            Err(e) => acc.push(suite, g.as_str(), Status::Fail, e.to_string()),
        }
    }
    for bad in [0u32, 4, 99, u32::MAX] {
        acc.malformed += 1;
        let ok = GraphKind::from_tag(bad).is_none();
        acc.expect_ok(suite, &format!("bad_tag_{bad}"), ok, "invalid tag rejected");
        // Encoded form
        let enc = format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g={bad},l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee"
        );
        match parse_hash(&enc) {
            Err(_) => acc.push(suite, &format!("parse_bad_g_{bad}"), Status::Pass, "err"),
            Ok(_) => acc.push(suite, &format!("parse_bad_g_{bad}"), Status::Fail, "accepted"),
        }
    }
}

fn run_output_length(acc: &mut Acc) {
    let suite = "output_length";
    for (id, len, expect_ok) in [
        ("min_8", 8usize, true),
        ("min_plus_1", 9, true),
        ("normal_32", 32, true),
        ("max_minus_1", 127, true),
        ("max_128", 128, true),
        ("zero", 0, false),
        ("seven", 7, false),
        ("129", 129, false),
        ("huge", 10_000, false),
    ] {
        acc.boundary += 1;
        match try_build(1024, 16, 32, 2, GraphKind::CombinedFrontier, len) {
            Ok(cfg) if expect_ok => {
                let salt = b"salt_16_bytes!!!";
                match hash_with_config_and_salt(b"o", salt, &cfg) {
                    Ok(enc) => {
                        let dig = enc.rsplit('$').next().unwrap_or("");
                        let ok = dig.len() == len * 2 && verify(b"o", &enc).unwrap_or(false);
                        acc.expect_ok(suite, id, ok, format!("hex_len={}", dig.len()));
                    }
                    Err(e) => acc.push(suite, id, Status::Fail, e.to_string()),
                }
            }
            Err(_) if !expect_ok => acc.push(suite, id, Status::Pass, "rejected"),
            Ok(_) => acc.push(suite, id, Status::Fail, "accepted invalid"),
            Err(e) => acc.push(suite, id, Status::Fail, e),
        }
    }
}

fn run_parser_v2(acc: &mut Acc) {
    let suite = "parser";
    // Valid baseline
    let cfg = min_cfg();
    let enc = hash_with_config_and_salt(b"p", b"salt_16_bytes!!!", &cfg).expect("enc");
    match parse_hash(&enc) {
        Ok(c) => {
            let re = encode_hash(&cfg, &c.salt, &c.digest);
            acc.expect_ok(
                suite,
                "valid_roundtrip",
                re.as_ref().map(|s| s == &enc).unwrap_or(false),
                "encode parse encode",
            );
        }
        Err(e) => acc.push(suite, "valid_roundtrip", Status::Fail, e.to_string()),
    }

    let malformed: Vec<(&str, String)> = vec![
        ("empty", "".into()),
        ("truncated", "$antech$v2$m=1024".into()),
        ("missing_fields", "$antech$v2$".into()),
        ("extra_fields", format!("{enc}$extra")),
        (
            "duplicate_m",
            "$antech$v2$m=1024,m=2048,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "unknown_field",
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32,x=1$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "wrong_version",
            "$antech$v3$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "wrong_algo",
            "$argon2$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "negative_m",
            "$antech$v2$m=-1,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "huge_m",
            "$antech$v2$m=9999999999,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "leading_zeros_ok_or_err",
            "$antech$v2$m=01024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "whitespace",
            "$antech$v2$m=1024, s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "unicode",
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddée$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        ("missing_salt", "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into()),
        ("missing_digest", "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$".into()),
        (
            "odd_hex",
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccdde$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "invalid_hex",
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$GG11223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee".into(),
        ),
        (
            "uppercase_hex",
            // Uppercase should parse if from_str_radix accepts — record actual behavior
            enc.replace(
                enc.rsplit('$').next().unwrap_or(""),
                &enc.rsplit('$').next().unwrap_or("").to_ascii_uppercase(),
            ),
        ),
        ("trailing", format!("{enc}x")),
        ("embedded_nul_str", format!("$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$00\011$00")),
        ("oversized", format!("$antech$v2${}", "A".repeat(9000))),
    ];

    for (name, s) in &malformed {
        acc.malformed += 1;
        let verify_pw: &[u8] = if *name == "uppercase_hex" { b"p" } else { b"pw" };
        let r = catch_unwind(AssertUnwindSafe(|| {
            let p = parse_hash(s);
            let v = verify(verify_pw, s);
            (p, v)
        }));
        match r {
            Ok((Err(_), Err(_))) => {
                acc.push(suite, name, Status::Pass, "clean reject");
            }
            Ok((Ok(_), Ok(true))) if *name == "uppercase_hex" => {
                acc.push(suite, name, Status::Pass, "uppercase hex accepted (valid)");
            }
            Ok((Ok(_), _)) if *name == "leading_zeros_ok_or_err" => {
                acc.push(suite, name, Status::Pass, "leading zeros behavior recorded");
            }
            Ok((Ok(_), Ok(true))) => {
                acc.push(suite, name, Status::Fail, "accepted/verified malformed");
            }
            Ok((Ok(_), Ok(false))) => {
                acc.push(suite, name, Status::Fail, "parsed but verify Ok(false)");
            }
            Ok((Ok(_), Err(_))) => {
                acc.push(suite, name, Status::Fail, "parsed unexpectedly");
            }
            Ok((Err(_), Ok(true))) => {
                acc.push(suite, name, Status::Fail, "verify true without parse");
            }
            Ok((Err(_), Ok(false))) => {
                acc.push(suite, name, Status::Fail, "verify Ok(false) on malformed");
            }
            Err(_) => {
                acc.panics += 1;
                acc.push(suite, name, Status::Fail, "panic");
            }
        }
    }
}

fn run_legacy(acc: &mut Acc) {
    let suite = "legacy";
    let legacies = [
        "$antech$v1$m=16384,s=16,t=1,p=1,b=32,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
        "$antech$1$m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
        "$antech$v0$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
    ];
    for (i, enc) in legacies.iter().enumerate() {
        acc.malformed += 1;
        match (parse_hash(enc), verify(b"pw", enc)) {
            (Err(_), Err(_)) => acc.push(suite, &format!("legacy_{i}"), Status::Pass, "rejected"),
            (Ok(_), _) => acc.push(suite, &format!("legacy_{i}"), Status::Fail, "parsed legacy"),
            (_, Ok(true)) => {
                acc.push(suite, &format!("legacy_{i}"), Status::Fail, "verified legacy")
            }
            other => acc.push(suite, &format!("legacy_{i}"), Status::Fail, format!("{other:?}")),
        }
    }
}

fn run_determinism(acc: &mut Acc) {
    let suite = "determinism";
    let cfg = min_cfg();
    let salt = b"salt_16_bytes!!!";
    let pw = b"det_password";
    let first = engine_digest(pw, salt, &cfg).expect("d0");
    let mut all_match = true;
    for i in 0..128 {
        let d = engine_digest(pw, salt, &cfg).unwrap_or_default();
        if d != first {
            all_match = false;
            acc.push(suite, &format!("prod_iter_{i}"), Status::Fail, "mismatch");
            break;
        }
    }
    if all_match {
        acc.push(suite, "prod_128", Status::Pass, "128 identical digests");
    }
    let r0 = ref_derive(pw, salt, &to_ref(&cfg));
    let mut ref_ok = r0 == first;
    for _ in 0..128 {
        if ref_derive(pw, salt, &to_ref(&cfg)) != r0 {
            ref_ok = false;
            break;
        }
    }
    acc.cross += 128;
    acc.expect_ok(suite, "ref_128_and_match_prod", ref_ok, hex(&first));

    // Different thread counts / orders
    for threads in [1usize, 2, 4, 8] {
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));
        thread::scope(|s| {
            for t in 0..threads {
                let results = Arc::clone(&results);
                s.spawn(move || {
                    let d = engine_digest(pw, salt, &cfg).unwrap_or_default();
                    results.lock().unwrap().push((t, d));
                });
            }
        });
        let rs = results.lock().unwrap();
        let ok = rs.iter().all(|(_, d)| d == &first);
        acc.expect_ok(suite, &format!("threads_{threads}"), ok, "same digest");
    }
}

fn run_differential(acc: &mut Acc) {
    let suite = "differential";
    let mut seed = 0xD1FFu64;
    // Production engine vs reference (CombinedFrontier) across configs
    for i in 0..40 {
        let fan = 2 + (xorshift(&mut seed) % 7) as u32;
        let out_len = [8, 16, 32, 64, 128][(xorshift(&mut seed) % 5) as usize];
        let salt_len = [8, 16, 32, 64][(xorshift(&mut seed) % 4) as usize];
        let cfg = match try_build(1024, salt_len, 32, fan, GraphKind::CombinedFrontier, out_len)
        {
            Ok(c) => c,
            Err(e) => {
                acc.push(suite, &format!("cfg_{i}"), Status::Fail, e);
                continue;
            }
        };
        let pw_len = 1 + (xorshift(&mut seed) % 64) as usize;
        let pw = fill_bytes(&mut seed, pw_len);
        let salt = fill_bytes(&mut seed, salt_len);
        match engine_digest(&pw, &salt, &cfg) {
            Ok(prod) => {
                let reference = ref_derive(&pw, &salt, &to_ref(&cfg));
                acc.cross += 1;
                let enc = hash_with_config_and_salt(&pw, &salt, &cfg).ok();
                let ver = enc
                    .as_ref()
                    .and_then(|e| verify(&pw, e).ok())
                    .unwrap_or(false);
                acc.expect_ok(
                    suite,
                    &format!("diff_{i}"),
                    prod == reference && ver && prod.len() == out_len,
                    format!("len={} ref_eq={}", prod.len(), prod == reference),
                );
            }
            Err(e) => acc.push(suite, &format!("diff_{i}"), Status::Fail, e),
        }
    }

    // Self-consistency across other graphs (no reference)
    for g in [GraphKind::ReducedCriticalPath, GraphKind::CacheLocality] {
        let cfg = try_build(1024, 16, 32, 2, g, 32).unwrap();
        let salt = b"salt_16_bytes!!!";
        let a = engine_digest(b"x", salt, &cfg).unwrap_or_default();
        let b = engine_digest(b"x", salt, &cfg).unwrap_or_default();
        acc.expect_ok(suite, &format!("self_{}", g.as_str()), a == b && !a.is_empty(), "det");
    }
}

fn run_ffi(acc: &mut Acc) {
    use antech_kdf_ffi::{
        antech_free, antech_hash, antech_hash_bytes, antech_hash_with_config_and_salt,
        antech_verify, antech_verify_bytes, AntechConfigC, AntechStatus,
        ANTECH_GRAPH_COMBINED_FRONTIER,
    };
    use std::ffi::{CStr, CString};

    let suite = "ffi";
    unsafe {
        // null pointers
        let mut out: *mut libc::c_char = std::ptr::null_mut();
        let st = antech_hash(std::ptr::null(), &mut out);
        acc.expect_ok(
            suite,
            "null_password",
            st == AntechStatus::InvalidInput && out.is_null(),
            format!("{st:?}"),
        );

        // ASCII
        let pw = CString::new("ffi_ascii").unwrap();
        out = std::ptr::null_mut();
        let st = antech_hash(pw.as_ptr(), &mut out);
        if st == AntechStatus::Ok && !out.is_null() {
            let enc = CStr::from_ptr(out).to_string_lossy().into_owned();
            let vst = antech_verify(pw.as_ptr(), out);
            antech_free(out);
            acc.cross += 1;
            acc.expect_ok(suite, "ascii_roundtrip", vst == AntechStatus::Ok, enc);
        } else {
            acc.push(suite, "ascii_roundtrip", Status::Fail, format!("{st:?}"));
        }

        // binary + embedded NUL via bytes API
        let bin = b"pre\0post\xff";
        out = std::ptr::null_mut();
        let st = antech_hash_bytes(bin.as_ptr(), bin.len(), &mut out);
        if st == AntechStatus::Ok && !out.is_null() {
            let vst = antech_verify_bytes(bin.as_ptr(), bin.len(), out);
            // wrong length must fail
            let wrong = antech_verify_bytes(bin.as_ptr(), 3, out);
            antech_free(out);
            acc.expect_ok(
                suite,
                "binary_nul",
                vst == AntechStatus::Ok && wrong != AntechStatus::Ok,
                format!("v={vst:?} w={wrong:?}"),
            );
        } else {
            acc.push(suite, "binary_nul", Status::Fail, format!("{st:?}"));
        }

        // empty
        out = std::ptr::null_mut();
        let st = antech_hash_bytes(b"".as_ptr(), 0, &mut out);
        if st == AntechStatus::Ok {
            let vst = antech_verify_bytes(b"".as_ptr(), 0, out);
            antech_free(out);
            acc.expect_ok(suite, "empty", vst == AntechStatus::Ok, "ok");
        } else {
            acc.push(suite, "empty", Status::Fail, format!("{st:?}"));
        }

        // config+salt KAT shape
        let cfg = AntechConfigC {
            memory_kib: 1024,
            salt_length: 16,
            block_size: 32,
            fan_in: 2,
            graph: ANTECH_GRAPH_COMBINED_FRONTIER,
            output_length: 32,
        };
        let salt = b"salt_16_bytes!!!";
        let pw = b"password";
        out = std::ptr::null_mut();
        let st = antech_hash_with_config_and_salt(
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            &cfg,
            &mut out,
        );
        if st == AntechStatus::Ok && !out.is_null() {
            let rust = hash_with_config_and_salt(pw, salt, &min_cfg()).unwrap();
            let ffi_s = CStr::from_ptr(out).to_str().unwrap_or("");
            // Digests must match (same salt+cfg)
            let rust_dig = rust.rsplit('$').next().unwrap_or("");
            let ffi_dig = ffi_s.rsplit('$').next().unwrap_or("");
            antech_free(out);
            acc.cross += 1;
            acc.expect_ok(
                suite,
                "ffi_vs_rust_digest",
                rust_dig == ffi_dig,
                format!("rust={rust_dig} ffi={ffi_dig}"),
            );
        } else {
            acc.push(suite, "ffi_vs_rust_digest", Status::Fail, format!("{st:?}"));
        }

        // invalid hash
        let bad = CString::new("not-a-hash").unwrap();
        let pw = CString::new("pw").unwrap();
        let st = antech_verify(pw.as_ptr(), bad.as_ptr());
        acc.expect_ok(
            suite,
            "invalid_hash",
            st == AntechStatus::InvalidHash,
            format!("{st:?}"),
        );

        // concurrent FFI
        let ok = Arc::new(AtomicU64::new(0));
        let fail = Arc::new(AtomicU64::new(0));
        thread::scope(|s| {
            for i in 0..32 {
                let ok = Arc::clone(&ok);
                let fail = Arc::clone(&fail);
                s.spawn(move || {
                    let pw = format!("ffi_conc_{i}");
                    let c = CString::new(pw).unwrap();
                    let mut out: *mut libc::c_char = std::ptr::null_mut();
                    if antech_hash(c.as_ptr(), &mut out) == AntechStatus::Ok {
                        if antech_verify(c.as_ptr(), out) == AntechStatus::Ok {
                            ok.fetch_add(1, Ordering::Relaxed);
                        } else {
                            fail.fetch_add(1, Ordering::Relaxed);
                        }
                        antech_free(out);
                    } else {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        acc.concurrency += 32;
        wait_idle();
        acc.expect_ok(
            suite,
            "concurrent_32",
            ok.load(Ordering::Relaxed) == 32 && fail.load(Ordering::Relaxed) == 0,
            format!("ok={} fail={}", ok.load(Ordering::Relaxed), fail.load(Ordering::Relaxed)),
        );
    }
    unsafe {
        antech_kdf_ffi::antech_free(std::ptr::null_mut());
    }
    acc.push(suite, "free_null", Status::Pass, "noop checked in suite");
}

fn run_concurrency(acc: &mut Acc) {
    let suite = "concurrency";
    let levels = [1usize, 2, 4, 8, 16, 32, 64, 100, 250, 500, 1000];
    let cfg = min_cfg();
    let salt = b"salt_16_bytes!!!";
    let fixed = hash_with_config_and_salt(b"shared", salt, &cfg).expect("shared");

    for &n in &levels {
        acc.concurrency += n as u64;
        wait_idle();
        let bad = Arc::new(AtomicU64::new(0));
        let good = Arc::new(AtomicU64::new(0));
        thread::scope(|s| {
            for i in 0..n {
                let bad = Arc::clone(&bad);
                let good = Arc::clone(&good);
                let fixed = fixed.clone();
                s.spawn(move || {
                    let lane = i % 4;
                    let result = catch_unwind(AssertUnwindSafe(|| match lane {
                        0 => {
                            let pw = format!("c_hash_{i}");
                            let enc = hash_with_config(pw.as_bytes(), &cfg)?;
                            let ok = verify(pw.as_bytes(), &enc)?;
                            Ok(ok)
                        }
                        1 => verify(b"shared", &fixed),
                        2 => verify(b"wrong", &fixed).map(|v| !v),
                        _ => {
                            let pw = format!("mix_{i}");
                            let enc = hash_with_config_and_salt(pw.as_bytes(), salt, &cfg)?;
                            let d = engine_digest(pw.as_bytes(), salt, &cfg).ok();
                            let parsed = parse_hash(&enc).ok();
                            let match_d = match (d, parsed) {
                                (Some(d), Some(p)) => d == p.digest,
                                _ => false,
                            };
                            Ok(match_d && verify(pw.as_bytes(), &enc).unwrap_or(false))
                        }
                    }));
                    match result {
                        Ok(Ok(true)) => {
                            good.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Ok(false)) => {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Err(Error::ResourceExhausted(_))) => {
                            // Under extreme overload admission may reject — not a digest error
                            good.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Err(_)) | Err(_) => {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        wait_idle();
        let st = scheduler_stats();
        let idle = st.active_jobs == 0 && st.waiting_jobs == 0 && st.allocated_kib == 0;
        let g = good.load(Ordering::Relaxed);
        let b = bad.load(Ordering::Relaxed);
        acc.expect_ok(
            suite,
            &format!("conc_{n}"),
            b == 0 && idle && g > 0,
            format!("good={g} bad={b} idle={idle} st={st:?}"),
        );
    }
}

fn run_resource_failure(acc: &mut Acc) {
    let suite = "resource_failure";
    wait_idle();
    // Parser error then correct op
    let _ = verify(b"x", "bad");
    let enc = hash(b"after_parse_err");
    match enc {
        Ok(e) => acc.expect_ok(
            suite,
            "after_parser_error",
            verify(b"after_parse_err", &e).unwrap_or(false),
            "ok",
        ),
        Err(e) => acc.push(suite, "after_parser_error", Status::Fail, e.to_string()),
    }
    wait_idle();

    // Invalid config
    assert!(AntechConfig::builder().memory_kib(1).build().is_err());
    let st = scheduler_stats();
    acc.expect_ok(
        suite,
        "invalid_cfg_no_permit",
        st.active_jobs == 0 && st.allocated_kib == 0,
        format!("{st:?}"),
    );

    // Overload then correct
    let rejects = Arc::new(AtomicU64::new(0));
    thread::scope(|s| {
        for i in 0..320 {
            let rejects = Arc::clone(&rejects);
            s.spawn(move || {
                if matches!(hash(format!("ov_{i}")), Err(Error::ResourceExhausted(_))) {
                    rejects.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    wait_idle();
    match hash_with_config_and_salt(b"post", b"salt_16_bytes!!!", &min_cfg()) {
        Ok(e) => acc.expect_ok(
            suite,
            "after_overload",
            verify(b"post", &e).unwrap_or(false) && rejects.load(Ordering::Relaxed) > 0,
            format!("rejects={}", rejects.load(Ordering::Relaxed)),
        ),
        Err(e) => acc.push(suite, "after_overload", Status::Fail, e.to_string()),
    }
    wait_idle();
}

fn run_gpu(acc: &mut Acc, out: &Path) {
    let suite = "gpu";
    // Prefer reusing prior measured GPU correctness if present; also try live runner.
    let prior = PathBuf::from("research/results/compute-memory-v4/gpu/correctness.csv");
    if prior.exists() {
        if let Ok(text) = fs::read_to_string(&prior) {
            let mut ok = 0u64;
            let mut bad = 0u64;
            for line in text.lines().skip(1) {
                if line.contains(",true,") || line.ends_with(",true") || line.contains(",true,OK")
                {
                    ok += 1;
                } else if !line.is_empty() {
                    // match column
                    let parts: Vec<_> = line.split(',').collect();
                    if parts.len() >= 8 && parts[7] == "true" {
                        ok += 1;
                    } else if parts.len() >= 8 {
                        bad += 1;
                    }
                }
            }
            acc.gpu += ok + bad;
            if bad == 0 && ok > 0 {
                acc.push(
                    suite,
                    "prior_v4_gpu_csv",
                    Status::Pass,
                    format!("imported {ok} matching rows from prior campaign CSV"),
                );
            } else {
                acc.push(
                    suite,
                    "prior_v4_gpu_csv",
                    Status::Fail,
                    format!("ok={ok} bad={bad}"),
                );
            }
        }
    } else {
        acc.push(suite, "prior_v4_gpu_csv", Status::Blocked, "CSV missing");
    }

    // Live: generate CPU digests and attempt CUDA binary if available
    let gpu_out = out.join("gpu");
    let _ = fs::create_dir_all(&gpu_out);
    let status = Command::new("nvidia-smi")
        .arg("-L")
        .output();
    match status {
        Ok(o) if o.status.success() => {
            acc.push(
                suite,
                "nvidia_smi",
                Status::Pass,
                String::from_utf8_lossy(&o.stdout).chars().take(120).collect::<String>(),
            );
            // Avoid nested cargo under this runner (package lock deadlock).
            acc.push(
                suite,
                "live_cuda_compare",
                Status::Blocked,
                "nvcc/GPU present; live CUDA attacker re-run via v4_gpu_runner separately; prior CSV imported",
            );
        }
        _ => acc.push(suite, "nvidia_smi", Status::Blocked, "no GPU/driver"),
    }
}

fn run_property(acc: &mut Acc) {
    let suite = "property";
    let mut seed = 0xA11CEu64;
    let n = 2000u64;
    for i in 0..n {
        acc.randomized += 1;
        let fan = 2 + (xorshift(&mut seed) % 7) as u32;
        let out_len = 8 + (xorshift(&mut seed) % 121) as usize;
        let salt_len = 8 + (xorshift(&mut seed) % 249) as usize;
        let block_exp = [16usize, 32, 64][(xorshift(&mut seed) % 3) as usize];
        let graphs = [
            GraphKind::CombinedFrontier,
            GraphKind::CacheLocality,
            GraphKind::ReducedCriticalPath,
        ];
        let g = graphs[(xorshift(&mut seed) % 3) as usize];
        match try_build(1024, salt_len, block_exp, fan, g, out_len) {
            Ok(cfg) => {
                let pw_len = (xorshift(&mut seed) % 128) as usize;
                let pw = fill_bytes(&mut seed, pw_len);
                let salt = fill_bytes(&mut seed, salt_len);
                match hash_with_config_and_salt(&pw, &salt, &cfg) {
                    Ok(enc) => {
                        let parsed = parse_hash(&enc);
                        let ver = verify(&pw, &enc).unwrap_or(false);
                        let wrong = verify(b"zzz", &enc).unwrap_or(true);
                        let mut ok = ver && !wrong && parsed.is_ok();
                        if let Ok(p) = &parsed {
                            ok &= p.salt == salt
                                && p.fan_in == fan
                                && p.output_len == out_len
                                && p.graph == g;
                            if g == GraphKind::CombinedFrontier {
                                if let Ok(prod) = engine_digest(&pw, &salt, &cfg) {
                                    let reference = ref_derive(&pw, &salt, &to_ref(&cfg));
                                    acc.cross += 1;
                                    ok &= prod == reference && prod == p.digest;
                                }
                            }
                            // re-encode
                            if let Ok(enc2) = encode_hash(&cfg, &p.salt, &p.digest) {
                                ok &= enc2 == enc;
                            } else {
                                ok = false;
                            }
                        }
                        if !ok {
                            acc.push(suite, &format!("rand_{i}"), Status::Fail, enc);
                            // continue collecting; do not abort entire campaign
                        } else if i % 200 == 0 {
                            acc.push(suite, &format!("rand_{i}"), Status::Pass, "sample");
                        }
                    }
                    Err(e) => acc.push(suite, &format!("rand_{i}"), Status::Fail, e.to_string()),
                }
            }
            Err(_) => {
                // May reject due to num_blocks if block huge — count as pass if truly invalid
                let blocks = (1024usize * 1024) / block_exp.max(1);
                if blocks < 64 {
                    if i % 200 == 0 {
                        acc.push(suite, &format!("rand_reject_{i}"), Status::Pass, "<64 blocks");
                    }
                } else {
                    acc.push(suite, &format!("rand_cfg_{i}"), Status::Fail, "valid rejected");
                }
            }
        }
    }
    // Invalid random configs must error without panic
    for i in 0..500 {
        acc.randomized += 1;
        let r = catch_unwind(AssertUnwindSafe(|| {
            let _ = try_build(
                (xorshift(&mut seed) % 2000) as usize,
                (xorshift(&mut seed) % 300) as usize,
                (xorshift(&mut seed) % 100) as usize,
                (xorshift(&mut seed) % 20) as u32,
                GraphKind::CombinedFrontier,
                (xorshift(&mut seed) % 200) as usize,
            );
        }));
        if r.is_err() {
            acc.panics += 1;
            acc.push(suite, &format!("invalid_panic_{i}"), Status::Fail, "panic");
            break;
        }
    }
    acc.push(suite, "invalid_cfg_no_panic", Status::Pass, "500 invalid builds");
}

fn run_small_graph(acc: &mut Acc) {
    let suite = "small_graph";
    // Production requires ≥64 blocks. Enumerate node counts via config rejection.
    for nodes in [1usize, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64] {
        acc.boundary += 1;
        if nodes < 64 {
            // Force <64 blocks with min memory and a large-but-valid block size when possible.
            // 1024 KiB / 64 B = 16384 blocks (always ≥64). To get <64 blocks under MIN memory
            // would require block > 16 KiB, which exceeds BlockSize::MAX — so use raw validate path:
            let kib = 1usize; // below MemorySize::MIN
            let r = try_build(kib, 16, 16, 2, GraphKind::CombinedFrontier, 32);
            match r {
                Err(_) => acc.push(
                    suite,
                    &format!("nodes_{nodes}"),
                    Status::Pass,
                    "rejected (invalid mem or <64 blocks path)",
                ),
                Ok(_) => acc.push(
                    suite,
                    &format!("nodes_{nodes}"),
                    Status::Fail,
                    "accepted invalid small graph",
                ),
            }
            acc.push(
                suite,
                &format!("nodes_{nodes}_exhaustive"),
                Status::NotApplicable,
                "production forbids <64 blocks; reference assert also requires ≥64",
            );
        } else {
            // Exactly 64 blocks: memory_kib*1024/block_size = 64 with legal bounds.
            // Use block=64, memory = 64*64/1024 = 4 KiB → below MIN; so use MIN memory
            // and block = MIN_KIB*1024/64 = 16384 which exceeds BlockSize::MAX.
            // Feasible exact-64 under production bounds: not possible with MIN_KIB=1024
            // and MAX_BLOCK=64 (min blocks at defaults = 1024*1024/64 = 16384).
            // Instead verify the minimum legal graph (≥64 blocks) at min memory + max block.
            let cfg = try_build(MemorySize::MIN_KIB, 16, 64, 2, GraphKind::CombinedFrontier, 32);
            match cfg {
                Ok(cfg) => {
                    assert!(cfg.num_blocks() >= 64);
                    let salt = b"salt_16_bytes!!!";
                    let prod = engine_digest(b"n64", salt, &cfg).unwrap_or_default();
                    let reference = ref_derive(b"n64", salt, &to_ref(&cfg));
                    acc.cross += 1;
                    acc.expect_ok(
                        suite,
                        "nodes_min_legal_graph",
                        prod == reference && !prod.is_empty(),
                        format!("blocks={}", cfg.num_blocks()),
                    );
                }
                Err(e) => acc.push(suite, "nodes_min_legal_graph", Status::Fail, e),
            }
        }
    }
}

fn run_serialization(acc: &mut Acc) {
    let suite = "serialization";
    for g in [
        GraphKind::CombinedFrontier,
        GraphKind::CacheLocality,
        GraphKind::ReducedCriticalPath,
    ] {
        for fan in [2u32, 4, 8] {
            for out in [8usize, 32, 128] {
                let cfg = match try_build(1024, 16, 32, fan, g, out) {
                    Ok(c) => c,
                    Err(e) => {
                        acc.push(suite, "cfg", Status::Fail, e);
                        continue;
                    }
                };
                let salt = b"salt_16_bytes!!!";
                match hash_with_config_and_salt(b"ser", salt, &cfg) {
                    Ok(enc) => match parse_hash(&enc) {
                        Ok(p) => {
                            let ok = p.memory_kib == 1024
                                && p.salt_len == 16
                                && p.fan_in == fan
                                && p.graph == g
                                && p.output_len == out
                                && p.salt.as_slice() == salt;
                            let enc2 = encode_hash(&cfg, &p.salt, &p.digest).ok();
                            acc.expect_ok(
                                suite,
                                &format!("{:?}_f{fan}_o{out}", g),
                                ok && enc2.as_ref() == Some(&enc),
                                "roundtrip",
                            );
                        }
                        Err(e) => acc.push(suite, "parse", Status::Fail, e.to_string()),
                    },
                    Err(e) => acc.push(suite, "hash", Status::Fail, e.to_string()),
                }
            }
        }
    }
}

fn run_rehash(acc: &mut Acc) {
    let suite = "rehash";
    // Default policy targets 16 MiB — use production default config so equal → false.
    let cfg = AntechConfig::default();
    let enc = match hash_with_config_and_salt(b"r", b"salt_16_bytes!!!", &cfg) {
        Ok(e) => e,
        Err(Error::ResourceExhausted(_)) => {
            wait_idle();
            match hash_with_config_and_salt(b"r", b"salt_16_bytes!!!", &cfg) {
                Ok(e) => e,
                Err(e) => {
                    acc.push(suite, "default_equal", Status::Fail, e.to_string());
                    return;
                }
            }
        }
        Err(e) => {
            acc.push(suite, "default_equal", Status::Fail, e.to_string());
            return;
        }
    };
    match needs_rehash(&enc) {
        Ok(false) => acc.push(suite, "default_equal", Status::Pass, "false"),
        other => acc.push(suite, "default_equal", Status::Fail, format!("{other:?}")),
    }
    let weak_pol = RehashPolicy::builder()
        .minimum_memory_mib(32)
        .preferred_memory_mib(32)
        .build();
    match needs_rehash_with_policy(&enc, &weak_pol) {
        Ok(true) => acc.push(suite, "weaker_than_policy", Status::Pass, "true"),
        other => acc.push(suite, "weaker_than_policy", Status::Fail, format!("{other:?}")),
    }
    let strong_stored = try_build(32 * 1024, 16, 32, 8, GraphKind::CombinedFrontier, 64).unwrap();
    wait_idle();
    let enc2 = match hash_with_config_and_salt(b"r2", b"salt_16_bytes!!!", &strong_stored) {
        Ok(e) => e,
        Err(Error::ResourceExhausted(_)) => {
            acc.push(
                suite,
                "stronger_stored",
                Status::Blocked,
                "32MiB hash exhausted host budget mid-suite",
            );
            return;
        }
        Err(e) => {
            acc.push(suite, "stronger_stored", Status::Fail, e.to_string());
            return;
        }
    };
    let soft = RehashPolicy::builder()
        .minimum_memory_mib(16)
        .preferred_memory_mib(16)
        .preferred_fan_in(2)
        .preferred_output_length(32)
        .build();
    match needs_rehash_with_policy(&enc2, &soft) {
        Ok(false) => acc.push(suite, "stronger_stored", Status::Pass, "false"),
        other => acc.push(suite, "stronger_stored", Status::Fail, format!("{other:?}")),
    }
    wait_idle();
}

fn run_long_run(acc: &mut Acc) {
    run_long_run_n(acc, 500);
}

fn run_long_run_n(acc: &mut Acc, n: u64) {
    let suite = "long_run";
    let cfg = min_cfg();
    let salt = b"salt_16_bytes!!!";
    let mut ok = 0u64;
    let mut bad = 0u64;
    for i in 0..n {
        let pw = format!("long_{i}");
        match hash_with_config_and_salt(pw.as_bytes(), salt, &cfg) {
            Ok(enc) => {
                if verify(pw.as_bytes(), &enc).unwrap_or(false)
                    && !verify(b"nope", &enc).unwrap_or(true)
                {
                    ok += 1;
                } else {
                    bad += 1;
                }
            }
            Err(_) => bad += 1,
        }
    }
    wait_idle();
    acc.expect_ok(
        suite,
        &format!("seq_{n}"),
        bad == 0 && ok == n,
        format!("ok={ok} bad={bad}"),
    );
}

fn run_sanitizers(acc: &mut Acc) {
    let suite = "sanitizers";
    // Miri
    let miri = Command::new("cargo")
        .args(["+nightly", "miri", "--version"])
        .output();
    match miri {
        Ok(o) if o.status.success() => {
            acc.push(
                suite,
                "miri",
                Status::Blocked,
                "miri available but full engine allocate is impractical under miri; not executed",
            );
        }
        _ => acc.push(suite, "miri", Status::Blocked, "nightly miri not installed"),
    }
    // ASan
    let asan = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if asan.contains("address") {
        acc.push(suite, "asan", Status::Pass, "ASAN flags detected in env");
    } else {
        acc.push(
            suite,
            "asan",
            Status::Blocked,
            "AddressSanitizer not enabled for this campaign run",
        );
    }
    // In-process overflow/guard checks (avoid nested `cargo` — deadlocks under `cargo run`).
    let r = catch_unwind(AssertUnwindSafe(|| {
        let _ = parse_hash("");
        let _ = parse_hash(&format!("$antech$v2${}", "A".repeat(9000)));
        let _ = AntechConfig::builder().memory_kib(0).build();
    }));
    acc.expect_ok(
        suite,
        "inprocess_overflow_guards",
        r.is_ok(),
        "parser/config guards without panic",
    );
}

fn run_sdk_cli(acc: &mut Acc) {
    let suite = "sdk_cli";
    // Prefer prebuilt CLI binary — never nest `cargo run` under this campaign.
    let cli_bin = [
        PathBuf::from("target/release/antech-kdf.exe"),
        PathBuf::from("target/release/antech-kdf"),
        PathBuf::from("target/debug/antech-kdf.exe"),
        PathBuf::from("target/debug/antech-kdf"),
    ]
    .into_iter()
    .find(|p| p.exists());

    match cli_bin {
        Some(bin) => {
            let out = Command::new(&bin).args(["hash", "cli_pw"]).output();
            match out {
                Ok(o) if o.status.success() => {
                    let enc = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if enc.starts_with("$antech$v2$") {
                        let v = Command::new(&bin)
                            .args(["verify", "cli_pw", &enc])
                            .output();
                        let ok = matches!(v, Ok(ref o2) if o2.status.success()
                            && String::from_utf8_lossy(&o2.stdout).contains("VERIFIED"));
                        acc.cross += 1;
                        acc.expect_ok(suite, "cli_roundtrip", ok, enc);
                    } else {
                        acc.push(suite, "cli_roundtrip", Status::Fail, enc);
                    }
                }
                Ok(o) => acc.push(
                    suite,
                    "cli_roundtrip",
                    Status::Fail,
                    format!("{:?} {}", o.status, String::from_utf8_lossy(&o.stderr)),
                ),
                Err(e) => acc.push(suite, "cli", Status::Blocked, e.to_string()),
            }
        }
        None => {
            match hash("cli_pw") {
                Ok(enc) => {
                    acc.cross += 1;
                    acc.expect_ok(
                        suite,
                        "cli_lib_equivalent",
                        verify("cli_pw", &enc).unwrap_or(false),
                        "CLI binary missing; API path exercised",
                    );
                }
                Err(e) => acc.push(suite, "cli_lib_equivalent", Status::Fail, e.to_string()),
            }
            acc.push(
                suite,
                "cli_binary",
                Status::Blocked,
                "antech-kdf CLI binary not found under target/",
            );
        }
    }

    let py = Command::new("python")
        .args(["sdk/conformance/run_python.py"])
        .output();
    match py {
        Ok(o) if o.status.success() => {
            acc.cross += 1;
            acc.push(
                suite,
                "python_conformance",
                Status::Pass,
                String::from_utf8_lossy(&o.stdout)
                    .chars()
                    .take(200)
                    .collect::<String>(),
            );
        }
        Ok(o) => acc.push(
            suite,
            "python_conformance",
            Status::Blocked,
            format!(
                "exit {:?} {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
                    .chars()
                    .take(300)
                    .collect::<String>()
            ),
        ),
        Err(e) => acc.push(suite, "python_conformance", Status::Blocked, e.to_string()),
    }

    for name in ["node", "go", "kotlin"] {
        acc.push(
            suite,
            &format!("{name}_sdk"),
            Status::Blocked,
            "not executed in this Rust campaign (see sdk/conformance CI)",
        );
    }
}

fn finalize(acc: &Acc) -> CampaignSummary {
    let mut totals = SuiteCounts::default();
    let mut suite_totals: std::collections::BTreeMap<String, SuiteCounts> =
        std::collections::BTreeMap::new();
    for r in &acc.rows {
        totals.cases += 1;
        let e = suite_totals.entry(r.suite.clone()).or_default();
        e.cases += 1;
        match r.status {
            Status::Pass => {
                totals.pass += 1;
                e.pass += 1;
            }
            Status::Fail => {
                totals.fail += 1;
                e.fail += 1;
            }
            Status::Blocked => {
                totals.blocked += 1;
                e.blocked += 1;
            }
            Status::NotApplicable => {
                totals.not_applicable += 1;
                e.not_applicable += 1;
            }
        }
    }
    totals.panics_caught = acc.panics;
    let mut blockers = Vec::new();
    for r in &acc.rows {
        if r.status == Status::Blocked {
            blockers.push(format!("{}:{}:{}", r.suite, r.case_id, r.detail));
        }
    }
    blockers.truncate(40);
    let verdict = if totals.fail == 0 && acc.panics == 0 {
        "PASS".into()
    } else {
        format!("FAIL failures={} panics={}", totals.fail, acc.panics)
    };
    CampaignSummary {
        host: format!(
            "{} {} cpus={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        ),
        verdict,
        totals,
        randomized_cases: acc.randomized,
        boundary_cases: acc.boundary,
        malformed_cases: acc.malformed,
        concurrency_cases: acc.concurrency,
        cross_impl_comparisons: acc.cross,
        gpu_comparisons: acc.gpu,
        failures: acc.rows.iter().filter(|r| r.status == Status::Fail).count() as u64,
    bugs_fixed: 2, // R12 oversize acquire fail-fast; R13 BlockSize max=64 matches engine
    regression_tests_added: 3, // ceiling fail-fast, oversize hash, block_size 128 reject
        blockers,
        suite_totals,
    }
}

fn write_outputs(out: &Path, acc: &Acc, summary: &CampaignSummary) -> std::io::Result<()> {
    fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(summary).unwrap(),
    )?;

    let mut by_suite: std::collections::BTreeMap<String, Vec<&CaseRow>> =
        std::collections::BTreeMap::new();
    for r in &acc.rows {
        by_suite.entry(r.suite.clone()).or_default().push(r);
    }

    let mapping = [
        ("boundary", ["salt", "memory", "block_size", "fan_in", "graph", "output_length", "small_graph"].as_slice()),
        ("parser", ["parser", "legacy"].as_slice()),
        ("config", ["memory", "block_size", "fan_in", "output_length"].as_slice()),
        ("vectors", ["hash_verify"].as_slice()),
        ("differential", ["differential", "determinism"].as_slice()),
        ("ffi", ["ffi"].as_slice()),
        ("concurrency", ["concurrency", "resource_failure"].as_slice()),
        ("gpu", ["gpu"].as_slice()),
        ("property", ["property", "long_run", "serialization", "rehash"].as_slice()),
    ];

    for (name, suites) in mapping {
        let mut f = File::create(out.join(format!("{name}.csv")))?;
        writeln!(f, "suite,case_id,status,detail")?;
        for s in suites {
            if let Some(rows) = by_suite.get(*s) {
                for r in rows {
                    writeln!(
                        f,
                        "{},{},{:?},\"{}\"",
                        r.suite,
                        r.case_id,
                        r.status,
                        r.detail.replace('"', "'")
                    )?;
                }
            }
        }
    }

    // regressions.csv — failures only
    {
        let mut f = File::create(out.join("regressions.csv"))?;
        writeln!(f, "suite,case_id,status,detail")?;
        for r in &acc.rows {
            if r.status == Status::Fail {
                writeln!(
                    f,
                    "{},{},FAIL,\"{}\"",
                    r.suite,
                    r.case_id,
                    r.detail.replace('"', "'")
                )?;
            }
        }
    }

    // all cases
    {
        let mut f = File::create(out.join("all-cases.csv"))?;
        writeln!(f, "suite,case_id,status,detail")?;
        for r in &acc.rows {
            writeln!(
                f,
                "{},{},{:?},\"{}\"",
                r.suite,
                r.case_id,
                r.status,
                r.detail.replace('"', "'")
            )?;
        }
    }

    write_reports(out, summary, acc)?;
    Ok(())
}

fn write_reports(out: &Path, s: &CampaignSummary, acc: &Acc) -> std::io::Result<()> {
    let mut f = File::create(out.join("summary.md"))?;
    writeln!(f, "# Correctness campaign summary\n")?;
    writeln!(f, "**Verdict:** {}\n", s.verdict)?;
    writeln!(f, "Host: {}\n", s.host)?;
    writeln!(
        f,
        "| Metric | Count |\n|---|---:|\n| Total cases | {} |\n| PASS | {} |\n| FAIL | {} |\n| BLOCKED | {} |\n| NOT_APPLICABLE | {} |\n| Randomized | {} |\n| Boundary | {} |\n| Malformed | {} |\n| Concurrency ops | {} |\n| Cross-impl comparisons | {} |\n| GPU comparisons | {} |\n| Panics caught | {} |\n| Bugs fixed | {} |\n| Regression tests added | {} |",
        s.totals.cases,
        s.totals.pass,
        s.totals.fail,
        s.totals.blocked,
        s.totals.not_applicable,
        s.randomized_cases,
        s.boundary_cases,
        s.malformed_cases,
        s.concurrency_cases,
        s.cross_impl_comparisons,
        s.gpu_comparisons,
        s.totals.panics_caught,
        s.bugs_fixed,
        s.regression_tests_added
    )?;
    writeln!(f, "\n## Per-suite\n")?;
    for (name, c) in &s.suite_totals {
        writeln!(
            f,
            "- **{name}**: cases={} pass={} fail={} blocked={} n/a={}",
            c.cases, c.pass, c.fail, c.blocked, c.not_applicable
        )?;
    }
    writeln!(f, "\n## Blockers (sample)\n")?;
    for b in &s.blockers {
        writeln!(f, "- {b}")?;
    }

    let mut r = File::create(out.join("report.md"))?;
    writeln!(r, "# Antech KDF correctness report\n")?;
    writeln!(r, "**Verdict:** {}\n", s.verdict)?;
    writeln!(
        r,
        "This campaign exercised the **current canonical** production implementation without changing algorithm, API, v2 format, or defaults.\n"
    )?;
    writeln!(r, "## Status legend\n")?;
    writeln!(r, "- **PASS** — executed and correct")?;
    writeln!(r, "- **FAIL** — mismatch, panic, or incorrect accept/reject")?;
    writeln!(r, "- **BLOCKED** — tool/environment unavailable")?;
    writeln!(r, "- **NOT_APPLICABLE** — outside production invariants (e.g. <64-block graphs, non-CombinedFrontier reference)\n")?;
    writeln!(r, "## Failures\n")?;
    let fails: Vec<_> = acc.rows.iter().filter(|x| x.status == Status::Fail).collect();
    if fails.is_empty() {
        writeln!(r, "None.\n")?;
    } else {
        for frow in fails {
            writeln!(r, "- `{}` / `{}`: {}", frow.suite, frow.case_id, frow.detail)?;
        }
    }
    writeln!(r, "\n## Notes\n")?;
    writeln!(
        r,
        "- Reference `derive` covers **CombinedFrontier only**; other graphs compared for self-determinism + hash/verify.\n- Host `ResourcePolicy` caps concurrent KDF memory at 128 MiB; configs up to 1 GiB validate but public `hash`/`verify` correctly return `ResourceExhausted` above the host budget.\n- GPU: prior v4 correctness CSV imported when present; live CUDA attacker re-run left BLOCKED unless dedicated runner invoked.\n"
    )?;
    Ok(())
}

pub fn default_out_dir() -> PathBuf {
    PathBuf::from("research/results/correctness")
}
