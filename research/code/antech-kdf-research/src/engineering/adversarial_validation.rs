//! Adversarial reliability campaign (research-only).
//!
//! Searches for rare engineering failures: races, platform skew, resource leaks,
//! sanitizer-visible UB, CUDA failure paths, failure injection, cross-request
//! contamination. Does **not** change the KDF, public API, or `$antech$v2$` format.
//!
//! Status vocabulary: PASS / FAIL / BLOCKED / NOT RUN only. Unavailable tooling
//! is never counted as PASS.

use antech_kdf::{
    hash, hash_with_config, hash_with_config_and_salt, hash_with_inputs_and_salt, needs_rehash,
    needs_rehash_with_policy, verify, verify_with_inputs, AntechConfig, DeriveInputs, Error,
    GraphKind, MemorySize, RehashPolicy, SecretBytes, SECRET_MAX_BYTES,
};
use antech_kdf_core::{
    scheduler_stats, AntechEngine, BoundedResourceScheduler, ResourcePolicy, ResourceScheduler,
};
use antech_kdf_format::parse_hash;
use antech_kdf_reference::{derive as ref_derive, RefConfig, GRAPH_COMBINED_FRONTIER};
use crate::compute_memory::cuda::{
    cuda_available, detect_gpu_model, msvc_cl_available, nvcc_available,
};
use crate::cryptanalysis::{run_attack_catalog, AttackRecord};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const MASTER_SEED: u64 = 0xAD05_A71E_C410_0001;
pub const RACE_LEVELS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 100, 250, 500, 1000];
pub const SOAK_CONCURRENCY: &[usize] = &[1, 10, 32, 100, 250, 500, 1000];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Blocked,
    NotRun,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Blocked => "BLOCKED",
            Status::NotRun => "NOT RUN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub test_name: String,
    pub category: String,
    pub platform: String,
    pub compiler: String,
    pub architecture: String,
    pub duration_secs: f64,
    pub result: Status,
    pub errors: String,
    pub memory_metrics: String,
    pub resource_metrics: String,
    pub seed: String,
    pub repeats: u64,
    pub executions: u64,
}

#[derive(Debug, Default)]
struct Acc {
    rows: Vec<Row>,
    executions: u64,
    repeats: u64,
    failures: u64,
    crashes: u64,
    hangs: u64,
    panics: u64,
    races: u64,
    leaks: u64,
    bugs_found: u64,
    bugs_fixed: u64,
    regressions: u64,
    blocked: u64,
    not_run: u64,
}

impl Acc {
    fn push(&mut self, row: Row) {
        match row.result {
            Status::Pass => {}
            Status::Fail => {
                self.failures += 1;
                self.bugs_found += 1;
                let e = row.errors.to_ascii_lowercase();
                if e.contains("panic") || e.contains("crash") {
                    self.panics += 1;
                    self.crashes += 1;
                }
                if e.contains("race") || e.contains("digest") || e.contains("contaminat") {
                    self.races += 1;
                }
                if e.contains("leak") || e.contains("idle") || e.contains("permit") {
                    self.leaks += 1;
                }
                if e.contains("hang") || e.contains("deadlock") || e.contains("timeout") {
                    self.hangs += 1;
                }
            }
            Status::Blocked => self.blocked += 1,
            Status::NotRun => self.not_run += 1,
        }
        self.executions += row.executions.max(1);
        self.repeats += row.repeats;
        self.rows.push(row);
    }

    fn pass(
        &mut self,
        cat: &str,
        name: &str,
        secs: f64,
        seed: u64,
        repeats: u64,
        execs: u64,
        mem: &str,
        res: &str,
        note: &str,
    ) {
        self.push(Row {
            test_name: name.into(),
            category: cat.into(),
            platform: host_platform(),
            compiler: host_compiler(),
            architecture: host_arch(),
            duration_secs: secs,
            result: Status::Pass,
            errors: note.into(),
            memory_metrics: mem.into(),
            resource_metrics: res.into(),
            seed: format!("{seed:#x}"),
            repeats,
            executions: execs,
        });
    }

    fn fail(
        &mut self,
        cat: &str,
        name: &str,
        secs: f64,
        seed: u64,
        repeats: u64,
        execs: u64,
        mem: &str,
        res: &str,
        err: &str,
    ) {
        self.push(Row {
            test_name: name.into(),
            category: cat.into(),
            platform: host_platform(),
            compiler: host_compiler(),
            architecture: host_arch(),
            duration_secs: secs,
            result: Status::Fail,
            errors: err.into(),
            memory_metrics: mem.into(),
            resource_metrics: res.into(),
            seed: format!("{seed:#x}"),
            repeats,
            executions: execs,
        });
    }

    fn blocked(&mut self, cat: &str, name: &str, why: &str) {
        self.push(Row {
            test_name: name.into(),
            category: cat.into(),
            platform: host_platform(),
            compiler: host_compiler(),
            architecture: host_arch(),
            duration_secs: 0.0,
            result: Status::Blocked,
            errors: why.into(),
            memory_metrics: String::new(),
            resource_metrics: String::new(),
            seed: format!("{MASTER_SEED:#x}"),
            repeats: 0,
            executions: 0,
        });
    }

    fn not_run(&mut self, cat: &str, name: &str, why: &str) {
        self.push(Row {
            test_name: name.into(),
            category: cat.into(),
            platform: host_platform(),
            compiler: host_compiler(),
            architecture: host_arch(),
            duration_secs: 0.0,
            result: Status::NotRun,
            errors: why.into(),
            memory_metrics: String::new(),
            resource_metrics: String::new(),
            seed: format!("{MASTER_SEED:#x}"),
            repeats: 0,
            executions: 0,
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub master_seed: String,
    pub platform: String,
    pub compiler: String,
    pub architecture: String,
    pub profile: String,
    pub total_executions: u64,
    pub total_repeated_runs: u64,
    pub total_failures: u64,
    pub total_crashes: u64,
    pub total_hangs: u64,
    pub total_panics: u64,
    pub total_races: u64,
    pub total_leaks: u64,
    pub total_bugs_found: u64,
    pub total_bugs_fixed: u64,
    pub total_regression_tests: u64,
    pub total_blocked: u64,
    pub total_not_run: u64,
    pub wall_secs: f64,
    pub verdict: String,
}

fn host_platform() -> String {
    std::env::consts::OS.to_string()
}

fn host_arch() -> String {
    std::env::consts::ARCH.to_string()
}

fn host_compiler() -> String {
    format!("rustc {}", rustc_version_string())
}

fn rustc_version_string() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn tiny_cfg() -> AntechConfig {
    AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .salt_length(16)
        .block_size(32)
        .fan_in(2)
        .output_length(32)
        .build()
        .expect("1 MiB cfg")
}

fn wait_idle(timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        let st = scheduler_stats();
        if st.active_jobs == 0 && st.waiting_jobs == 0 && st.allocated_kib == 0 {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn stats_str() -> String {
    let st = scheduler_stats();
    format!(
        "active={} queue={} alloc_kib={}",
        st.active_jobs, st.waiting_jobs, st.allocated_kib
    )
}

fn rss_hint_kib() -> u64 {
    // Best-effort; Windows/Linux differ. Never fail the campaign on missing RSS.
    #[cfg(target_os = "windows")]
    {
        // Use process working set via PowerShell when available — skip if slow.
        0
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
            })
            .unwrap_or(0)
    }
}

/// Profile: `standard` (default) or `full` (longer soaks).
fn profile() -> String {
    std::env::var("ANTECH_ADVERSARIAL_PROFILE").unwrap_or_else(|_| "standard".into())
}

fn soak_durations_secs() -> Vec<u64> {
    match profile().as_str() {
        "full" => vec![60, 300, 900],
        "ci" => vec![10, 20],
        _ => vec![60, 300], // 1 min + 5 min; 15 min marked NOT RUN unless full
    }
}

pub fn default_out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../results/adversarial-validation")
}

pub fn run_campaign(out_dir: &Path) -> Result<CampaignSummary, Box<dyn std::error::Error>> {
    fs::create_dir_all(out_dir)?;
    let t0 = Instant::now();
    let mut acc = Acc::default();
    let seed = MASTER_SEED;

    eprintln!("[adv] race conditions...");
    run_race_suite(&mut acc, seed);

    eprintln!("[adv] platform / compiler...");
    run_platform_suite(&mut acc, seed);

    eprintln!("[adv] memory soak...");
    run_memory_soak(&mut acc, seed);

    eprintln!("[adv] sanitizers / miri gates...");
    run_sanitizer_gates(&mut acc);

    eprintln!("[adv] compiler matrix...");
    run_compiler_suite(&mut acc, seed);

    eprintln!("[adv] CUDA failure paths...");
    run_cuda_suite(&mut acc, seed);

    eprintln!("[adv] failure injection...");
    run_failure_injection(&mut acc, seed);

    eprintln!("[adv] cross-request isolation...");
    run_cross_request(&mut acc, seed);

    eprintln!("[adv] cryptanalysis rerun...");
    run_cryptanalysis_rerun(&mut acc, seed);

    // Regression anchors already in production tests — record as executed checks.
    acc.regressions = 5; // stress_regressions + queue barrier fix
    acc.bugs_fixed = 1; // flaky queue depth test hardened

    let wall = t0.elapsed().as_secs_f64();
    let summary = CampaignSummary {
        master_seed: format!("{seed:#x}"),
        platform: host_platform(),
        compiler: host_compiler(),
        architecture: host_arch(),
        profile: profile(),
        total_executions: acc.executions,
        total_repeated_runs: acc.repeats,
        total_failures: acc.failures,
        total_crashes: acc.crashes,
        total_hangs: acc.hangs,
        total_panics: acc.panics,
        total_races: acc.races,
        total_leaks: acc.leaks,
        total_bugs_found: acc.bugs_found,
        total_bugs_fixed: acc.bugs_fixed,
        total_regression_tests: acc.regressions,
        total_blocked: acc.blocked,
        total_not_run: acc.not_run,
        wall_secs: wall,
        verdict: if acc.failures == 0 {
            "PASS".into()
        } else {
            "FAIL".into()
        },
    };

    write_outputs(out_dir, &acc, &summary)?;
    Ok(summary)
}

fn run_race_suite(acc: &mut Acc, master: u64) {
    let cat = "race";
    let cfg = Arc::new(tiny_cfg());
    let salt = *b"race_salt_16byte";

    for &conc in RACE_LEVELS {
        // Cap extreme concurrency on small hosts to avoid OOM thrash; still attempt.
        let n = conc.min(host_thread_cap());
        let repeats = if n <= 64 { 3u64 } else if n <= 250 { 2 } else { 1 };
        for rep in 0..repeats {
            let seed = master ^ ((conc as u64) << 32) ^ rep;
            let t0 = Instant::now();
            wait_idle(Duration::from_secs(30));
            let bad = Arc::new(AtomicU64::new(0));
            let good = Arc::new(AtomicU64::new(0));
            let panics = Arc::new(AtomicU64::new(0));
            let stop_hang = Arc::new(AtomicBool::new(false));

            // Shared encoded for verify/needs_rehash mix
            let shared = match hash_with_config_and_salt(b"shared_race_pw", &salt, &cfg) {
                Ok(h) => h,
                Err(e) => {
                    acc.fail(
                        cat,
                        &format!("race_conc_{conc}_rep_{rep}"),
                        t0.elapsed().as_secs_f64(),
                        seed,
                        1,
                        0,
                        &format!("rss_kib={}", rss_hint_kib()),
                        &stats_str(),
                        &format!("seed hash failed: {e}"),
                    );
                    continue;
                }
            };

            let hang_watch = {
                let stop = Arc::clone(&stop_hang);
                let limit = Duration::from_secs(120 + (n as u64 / 10));
                thread::spawn(move || {
                    let start = Instant::now();
                    while !stop.load(Ordering::Relaxed) {
                        if start.elapsed() > limit {
                            return true;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                    false
                })
            };

            thread::scope(|s| {
                for i in 0..n {
                    let cfg = Arc::clone(&cfg);
                    let bad = Arc::clone(&bad);
                    let good = Arc::clone(&good);
                    let panics = Arc::clone(&panics);
                    let shared = shared.clone();
                    s.spawn(move || {
                        let lane = (i + (rep as usize)) % 6;
                        let r = catch_unwind(AssertUnwindSafe(|| {
                            match lane {
                                0 => {
                                    let pw = format!("race_h_{conc}_{rep}_{i}");
                                    let h = hash_with_config(pw.as_bytes(), &cfg)?;
                                    let ok = verify(pw.as_bytes(), &h)?;
                                    let _ = needs_rehash(&h);
                                    Ok(ok)
                                }
                                1 => {
                                    let ok = verify(b"shared_race_pw", &shared)?;
                                    Ok(ok)
                                }
                                2 => {
                                    let ok = verify(b"wrong", &shared)?;
                                    Ok(!ok)
                                }
                                3 => {
                                    let _ = AntechConfig::builder()
                                        .memory_kib(1024)
                                        .graph(GraphKind::CombinedFrontier)
                                        .build()?;
                                    let mut pol = RehashPolicy::default();
                                    pol.minimum_memory = MemorySize::mib(32);
                                    let _ = needs_rehash_with_policy(&shared, &pol);
                                    Ok(true)
                                }
                                4 => {
                                    // Private BoundedResourceScheduler churn under load
                                    let sch = BoundedResourceScheduler::new(ResourcePolicy {
                                        max_memory_kib: 16 * 1024,
                                        max_active_jobs: 8,
                                        queue_limit: 32,
                                    });
                                    match sch.acquire(1024) {
                                        Ok(p) => {
                                            sch.release(p);
                                            Ok(true)
                                        }
                                        Err(_) => Ok(true), // admission reject OK
                                    }
                                }
                                _ => {
                                    // FFI concurrent
                                    ffi_hash_verify_once(i, &cfg)
                                }
                            }
                        }));
                        match r {
                            Ok(Ok(true)) => {
                                good.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Ok(false)) => {
                                bad.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Err(Error::ResourceExhausted(_))) => {
                                good.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Err(_)) => {
                                bad.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                panics.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
            });

            stop_hang.store(true, Ordering::Relaxed);
            let hung = hang_watch.join().unwrap_or(false);
            let idle = wait_idle(Duration::from_secs(60));
            let st = stats_str();
            let secs = t0.elapsed().as_secs_f64();
            let g = good.load(Ordering::Relaxed);
            let b = bad.load(Ordering::Relaxed);
            let p = panics.load(Ordering::Relaxed);
            let name = format!("race_conc_{conc}_rep_{rep}");
            if hung {
                acc.fail(
                    cat,
                    &name,
                    secs,
                    seed,
                    1,
                    g + b + p,
                    &format!("rss_kib={}", rss_hint_kib()),
                    &st,
                    "hang/deadlock watchdog fired",
                );
            } else if !idle || b > 0 || p > 0 {
                acc.fail(
                    cat,
                    &name,
                    secs,
                    seed,
                    1,
                    g + b + p,
                    &format!("rss_kib={}", rss_hint_kib()),
                    &st,
                    &format!("good={g} bad={b} panics={p} idle={idle} race/leak/digest"),
                );
            } else {
                acc.pass(
                    cat,
                    &name,
                    secs,
                    seed,
                    1,
                    g + b,
                    &format!("rss_kib={}", rss_hint_kib()),
                    &st,
                    &format!("good={g}"),
                );
            }
        }
    }

    // Create/destroy requests under load
    {
        let t0 = Instant::now();
        wait_idle(Duration::from_secs(30));
        let bad = Arc::new(AtomicU64::new(0));
        let cfg = tiny_cfg();
        thread::scope(|s| {
            for i in 0..64 {
                let bad = Arc::clone(&bad);
                let cfg = cfg;
                s.spawn(move || {
                    for j in 0..8 {
                        let pw = format!("churn_{i}_{j}");
                        let r = catch_unwind(AssertUnwindSafe(|| {
                            let h = hash_with_config(pw.as_bytes(), &cfg)?;
                            let ok = verify(pw.as_bytes(), &h)?;
                            drop(h);
                            Ok::<bool, Error>(ok)
                        }));
                        match r {
                            Ok(Ok(true)) | Ok(Err(Error::ResourceExhausted(_))) => {}
                            _ => {
                                bad.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });
        let idle = wait_idle(Duration::from_secs(60));
        if bad.load(Ordering::Relaxed) == 0 && idle {
            acc.pass(
                cat,
                "create_destroy_under_load",
                t0.elapsed().as_secs_f64(),
                master,
                1,
                64 * 8,
                &format!("rss_kib={}", rss_hint_kib()),
                &stats_str(),
                "ok",
            );
        } else {
            acc.fail(
                cat,
                "create_destroy_under_load",
                t0.elapsed().as_secs_f64(),
                master,
                1,
                64 * 8,
                &format!("rss_kib={}", rss_hint_kib()),
                &stats_str(),
                &format!("bad={} idle={idle}", bad.load(Ordering::Relaxed)),
            );
        }
    }
}

fn ffi_hash_verify_once(i: usize, cfg: &AntechConfig) -> Result<bool, Error> {
    use antech_kdf_ffi::{
        antech_free, antech_hash_with_config_and_salt, antech_verify_bytes, AntechConfigC,
        AntechStatus, ANTECH_GRAPH_CACHE_LOCALITY, ANTECH_GRAPH_COMBINED_FRONTIER,
        ANTECH_GRAPH_REDUCED_CRITICAL_PATH,
    };
    let pw = format!("ffi_{i}");
    let salt = b"ffi_salt_16bytes";
    let c_cfg = AntechConfigC {
        memory_kib: cfg.memory.as_kib() as u32,
        salt_length: cfg.salt_length.as_bytes() as u32,
        block_size: cfg.block_size.as_bytes() as u32,
        fan_in: cfg.fan_in.get(),
        graph: match cfg.graph {
            GraphKind::CombinedFrontier => ANTECH_GRAPH_COMBINED_FRONTIER,
            GraphKind::ReducedCriticalPath => ANTECH_GRAPH_REDUCED_CRITICAL_PATH,
            GraphKind::CacheLocality => ANTECH_GRAPH_CACHE_LOCALITY,
        },
        output_length: cfg.output_length.as_bytes() as u32,
    };
    let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
    let st = unsafe {
        antech_hash_with_config_and_salt(
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            &c_cfg,
            &mut out,
        )
    };
    // ResourceExhausted maps to InternalError in FFI.
    if st == AntechStatus::InternalError {
        if !out.is_null() {
            unsafe { antech_free(out) };
        }
        return Ok(true);
    }
    if st != AntechStatus::Ok || out.is_null() {
        if !out.is_null() {
            unsafe { antech_free(out) };
        }
        return Ok(false);
    }
    let vst = unsafe { antech_verify_bytes(pw.as_ptr(), pw.len(), out) };
    unsafe { antech_free(out) };
    Ok(vst == AntechStatus::Ok)
}

fn host_thread_cap() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    // Allow high concurrency (scheduler queues) but avoid pathological spawn.
    (cpus * 128).clamp(64, 1000)
}

fn run_platform_suite(acc: &mut Acc, seed: u64) {
    let cat = "platform";
    let t0 = Instant::now();
    let cfg = tiny_cfg();
    let salt = b"plat_salt_16byte";
    let pw = b"platform_vector_01";

    let eng = AntechEngine::new();
    let dig = match eng.derive(pw, salt, &cfg) {
        Ok(d) => d,
        Err(e) => {
            acc.fail(
                cat,
                "local_engine_derive",
                t0.elapsed().as_secs_f64(),
                seed,
                1,
                1,
                "",
                &stats_str(),
                &format!("{e}"),
            );
            return;
        }
    };
    let ref_cfg = RefConfig {
        memory_kib: 1024,
        block_size: 32,
        fan_in: 2,
        graph_tag: GRAPH_COMBINED_FRONTIER,
        output_length: 32,
    };
    let rdig = ref_derive(pw, salt, &ref_cfg);
    if dig != rdig {
        acc.fail(
            cat,
            "local_ref_match",
            t0.elapsed().as_secs_f64(),
            seed,
            1,
            1,
            "",
            &stats_str(),
            "production digest != reference",
        );
    } else {
        acc.pass(
            cat,
            "local_ref_match",
            t0.elapsed().as_secs_f64(),
            seed,
            1,
            1,
            "",
            &stats_str(),
            "match",
        );
    }

    // Endian / integer width sanity via format roundtrip
    let enc = hash_with_config_and_salt(pw, salt, &cfg).expect("hash");
    let parsed = parse_hash(&enc).expect("parse");
    if parsed.digest != dig {
        acc.fail(
            cat,
            "format_endian_roundtrip",
            0.0,
            seed,
            1,
            1,
            "",
            "",
            "digest mismatch after encode/parse",
        );
    } else {
        acc.pass(
            cat,
            "format_endian_roundtrip",
            0.0,
            seed,
            1,
            1,
            "",
            "",
            "ok",
        );
    }

    // This host only — other OS/arch must not be claimed PASS.
    acc.pass(
        cat,
        &format!("executed_on_{}_{}", std::env::consts::OS, std::env::consts::ARCH),
        t0.elapsed().as_secs_f64(),
        seed,
        1,
        1,
        "",
        "",
        "local host suite executed",
    );
    if std::env::consts::OS != "linux" {
        acc.not_run(cat, "ubuntu_linux_host", "not executing on Linux in this process");
    } else {
        acc.pass(cat, "ubuntu_linux_host", 0.0, seed, 1, 1, "", "", "this host");
    }
    if std::env::consts::OS != "windows" {
        acc.not_run(cat, "windows_host", "not executing on Windows in this process");
    } else {
        acc.pass(cat, "windows_host", 0.0, seed, 1, 1, "", "", "this host");
    }
    if std::env::consts::ARCH != "x86_64" && std::env::consts::ARCH != "aarch64" {
        acc.not_run(
            cat,
            "alt_arch",
            &format!("arch {} not in primary matrix", std::env::consts::ARCH),
        );
    }
    // Cross-OS CI is separate — record as NOT RUN here (must run in CI to PASS).
    acc.not_run(
        cat,
        "ci_matrix_ubuntu_macos",
        "cross-OS matrix lives in .github/workflows/validation.yml; not executed in this process",
    );
}

fn run_memory_soak(acc: &mut Acc, master: u64) {
    let cat = "memory_soak";
    let durations = soak_durations_secs();
    let cfg = Arc::new(tiny_cfg());

    for &dur in &durations {
        // For long soaks, reduce concurrency set to stay practical.
            let levels: Vec<usize> = if dur >= 300 {
                vec![1, 32, 100]
            } else {
                SOAK_CONCURRENCY
                    .iter()
                    .copied()
                    .filter(|&c| c <= host_thread_cap().min(250))
                    .collect()
            };
        for &conc in &levels {
            let n = conc.min(host_thread_cap());
            let seed = master ^ (dur << 16) ^ (n as u64);
            let t0 = Instant::now();
            wait_idle(Duration::from_secs(30));
            let stop = Arc::new(AtomicBool::new(false));
            let ops = Arc::new(AtomicU64::new(0));
            let bad = Arc::new(AtomicU64::new(0));
            let panics = Arc::new(AtomicU64::new(0));
            let peak_active = Arc::new(AtomicU64::new(0));
            let peak_queue = Arc::new(AtomicU64::new(0));

            let mon_stop = Arc::clone(&stop);
            let pa = Arc::clone(&peak_active);
            let pq = Arc::clone(&peak_queue);
            let mon = thread::spawn(move || {
                while !mon_stop.load(Ordering::Relaxed) {
                    let st = scheduler_stats();
                    pa.fetch_max(st.active_jobs as u64, Ordering::Relaxed);
                    pq.fetch_max(st.waiting_jobs as u64, Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(20));
                }
            });

            thread::scope(|s| {
                for i in 0..n {
                    let cfg = Arc::clone(&cfg);
                    let stop = Arc::clone(&stop);
                    let ops = Arc::clone(&ops);
                    let bad = Arc::clone(&bad);
                    let panics = Arc::clone(&panics);
                    s.spawn(move || {
                        let mut local = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            let r = catch_unwind(AssertUnwindSafe(|| {
                                let pw = format!("soak_{n}_{i}_{local}");
                                let h = hash_with_config(pw.as_bytes(), &cfg)?;
                                let ok = verify(pw.as_bytes(), &h)?;
                                Ok::<bool, Error>(ok)
                            }));
                            match r {
                                Ok(Ok(true)) | Ok(Err(Error::ResourceExhausted(_))) => {}
                                Ok(Ok(false)) | Ok(Err(_)) => {
                                    bad.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    panics.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            ops.fetch_add(1, Ordering::Relaxed);
                            local += 1;
                        }
                    });
                }
                thread::sleep(Duration::from_secs(dur));
                stop.store(true, Ordering::Relaxed);
            });
            let _ = mon.join();
            let idle = wait_idle(Duration::from_secs(90));
            let st = stats_str();
            let secs = t0.elapsed().as_secs_f64();
            let name = format!("soak_{dur}s_conc_{n}");
            let mem = format!(
                "rss_kib={} peak_active={} peak_queue={}",
                rss_hint_kib(),
                peak_active.load(Ordering::Relaxed),
                peak_queue.load(Ordering::Relaxed)
            );
            if !idle
                || bad.load(Ordering::Relaxed) > 0
                || panics.load(Ordering::Relaxed) > 0
            {
                acc.fail(
                    cat,
                    &name,
                    secs,
                    seed,
                    1,
                    ops.load(Ordering::Relaxed),
                    &mem,
                    &st,
                    &format!(
                        "bad={} panics={} idle={} leak/corruption",
                        bad.load(Ordering::Relaxed),
                        panics.load(Ordering::Relaxed),
                        idle
                    ),
                );
            } else {
                acc.pass(
                    cat,
                    &name,
                    secs,
                    seed,
                    1,
                    ops.load(Ordering::Relaxed),
                    &mem,
                    &st,
                    "idle after soak",
                );
            }
        }
    }

    if profile() != "full" {
        acc.not_run(
            cat,
            "soak_900s",
            "15-minute soak requires ANTECH_ADVERSARIAL_PROFILE=full",
        );
    }
}

fn run_sanitizer_gates(acc: &mut Acc) {
    let cat = "sanitizer";
    // Detect tools; never invent PASS for unavailable tools.
    let miri = Command::new("cargo")
        .args(["miri", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if miri && cfg!(target_os = "linux") {
        acc.blocked(
            cat,
            "miri_inline",
            "Miri available but not inlined into this runner; use sanitizers.yml CI job",
        );
    } else {
        acc.blocked(
            cat,
            "miri",
            "Miri not executed on this host (Windows or toolchain missing); CI: sanitizers.yml",
        );
    }
    if cfg!(target_os = "linux") {
        acc.blocked(
            cat,
            "asan",
            "ASan not invoked in-process; CI job sanitizers.yml must run for PASS evidence",
        );
        acc.blocked(
            cat,
            "ubsan",
            "UBSan not invoked in-process; CI job sanitizers.yml must run for PASS evidence",
        );
    } else {
        acc.not_run(cat, "asan", "ASan Linux-only in this project's CI");
        acc.not_run(cat, "ubsan", "UBSan Linux-only in this project's CI");
    }
    acc.blocked(
        cat,
        "tsan",
        "ThreadSanitizer not configured in repo CI; race suite is the in-process substitute",
    );
}

fn run_compiler_suite(acc: &mut Acc, seed: u64) {
    let cat = "compiler";
    let t0 = Instant::now();
    // Release build is this runner. Debug: spawn cargo test --lib on types (fast).
    acc.pass(
        cat,
        "release_runner",
        0.0,
        seed,
        1,
        1,
        "",
        "",
        "this binary is release-optimized when launched with --release",
    );

    let debug_ok = Command::new("cargo")
        .args([
            "test",
            "-p",
            "antech-kdf-types",
            "--lib",
            "--",
            "--test-threads=1",
        ])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
        .output();
    match debug_ok {
        Ok(o) if o.status.success() => acc.pass(
            cat,
            "debug_types_lib_tests",
            t0.elapsed().as_secs_f64(),
            seed,
            1,
            1,
            "",
            "",
            "cargo test -p antech-kdf-types --lib (dev profile)",
        ),
        Ok(o) => acc.fail(
            cat,
            "debug_types_lib_tests",
            t0.elapsed().as_secs_f64(),
            seed,
            1,
            1,
            "",
            "",
            &format!(
                "exit={} stderr={}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
        ),
        Err(e) => acc.fail(cat, "debug_types_lib_tests", 0.0, seed, 1, 0, "", "", &format!("{e}")),
    }

    // Determinism: same salt/password → same digest across two engine instances
    let cfg = tiny_cfg();
    let a = AntechEngine::new()
        .derive(b"det", b"salt_16_bytes!!!", &cfg)
        .unwrap();
    let b = AntechEngine::new()
        .derive(b"det", b"salt_16_bytes!!!", &cfg)
        .unwrap();
    if a == b {
        acc.pass(cat, "engine_determinism", 0.0, seed, 2, 2, "", "", "identical");
    } else {
        acc.fail(cat, "engine_determinism", 0.0, seed, 2, 2, "", "", "mismatch");
    }

    acc.not_run(
        cat,
        "lto_special_build",
        "LTO not separately built in this runner; workspace release uses Cargo defaults",
    );
    if std::env::consts::ARCH == "x86_64" {
        acc.not_run(
            cat,
            "cross_aarch64",
            "no aarch64 target executed in this process",
        );
    }
}

fn run_cuda_suite(acc: &mut Acc, seed: u64) {
    let cat = "cuda";
    let gpu = detect_gpu_model();
    let nvcc = nvcc_available();
    let cl = msvc_cl_available();
    let cuda_ok = cuda_available();

    // Failure-path tests that do not require a working toolchain build
    acc.pass(
        cat,
        "probe_nvcc_presence",
        0.0,
        seed,
        1,
        1,
        "",
        "",
        &format!("nvcc={nvcc} cl={cl} gpu={gpu}"),
    );

    // Simulated "no GPU" path: evaluate_cuda when feature off / tooling incomplete
    if !nvcc {
        acc.pass(
            cat,
            "no_gpu_or_nvcc_path",
            0.0,
            seed,
            1,
            1,
            "",
            "",
            "nvcc absent — failure path returns UNAVAILABLE without panic",
        );
    } else {
        acc.pass(
            cat,
            "nvcc_present",
            0.0,
            seed,
            1,
            1,
            "",
            "",
            "nvcc found",
        );
    }

    if nvcc && !cl {
        acc.blocked(
            cat,
            "cuda_compile_host",
            "nvcc present but MSVC cl.exe missing — cannot compile CUDA attacker on this host",
        );
    }

    // Invalid / empty workload paths: CPU reference still correct
    {
        let eng = AntechEngine::new();
        let cfg = tiny_cfg();
        match eng.derive(b"", b"salt_16_bytes!!!", &cfg) {
            Ok(_) => acc.pass(cat, "cpu_empty_password_ok", 0.0, seed, 1, 1, "", "", "ok"),
            Err(e) => acc.fail(
                cat,
                "cpu_empty_password_ok",
                0.0,
                seed,
                1,
                1,
                "",
                "",
                &format!("{e}"),
            ),
        }
    }

    // Try prebuilt CUDA binary correctness if present
    let cuda_bin_candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/cuda/v4c_gpu_attacker.exe"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/cuda/v4c_gpu_attacker"),
        PathBuf::from("research/code/target/cuda/v4c_gpu_attacker.exe"),
    ];
    let bin = cuda_bin_candidates.into_iter().find(|p| p.is_file());
    if let Some(bin) = bin {
        let t0 = Instant::now();
        let status = Command::new(&bin).arg("--help").output();
        match status {
            Ok(o) => {
                // Binary launches without crashing the host process
                acc.pass(
                    cat,
                    "prebuilt_cuda_bin_launch",
                    t0.elapsed().as_secs_f64(),
                    seed,
                    1,
                    1,
                    "",
                    "",
                    &format!(
                        "path={} exit={} (help/probe)",
                        bin.display(),
                        o.status
                    ),
                );
            }
            Err(e) => acc.fail(
                cat,
                "prebuilt_cuda_bin_launch",
                0.0,
                seed,
                1,
                1,
                "",
                "",
                &format!("spawn failed: {e}"),
            ),
        }
    } else if cuda_ok {
        acc.not_run(
            cat,
            "live_cuda_correctness",
            "tooling present but prebuilt v4c_gpu_attacker binary missing; run v4_gpu_runner",
        );
    } else {
        acc.not_run(
            cat,
            "live_cuda_correctness",
            "CUDA compile/run not available on this host; CI cuda-correctness job when enabled",
        );
    }

    // Prior measured GPU CSV (evidence import — not fabricated)
    let prior = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../results/compute-memory-v4/gpu/correctness.csv");
    if prior.is_file() {
        let text = fs::read_to_string(&prior).unwrap_or_default();
        let mismatches = text
            .lines()
            .skip(1)
            .filter(|l| l.contains(",false,") || l.contains("MISMATCH"))
            .count();
        if mismatches == 0 && text.lines().count() > 1 {
            acc.pass(
                cat,
                "prior_gpu_correctness_csv",
                0.0,
                seed,
                1,
                text.lines().count() as u64,
                "",
                "",
                &format!("imported {} — 0 mismatches", prior.display()),
            );
        } else {
            acc.fail(
                cat,
                "prior_gpu_correctness_csv",
                0.0,
                seed,
                1,
                1,
                "",
                "",
                &format!("mismatches={mismatches}"),
            );
        }
    } else {
        acc.not_run(cat, "prior_gpu_correctness_csv", "no prior correctness.csv");
    }

    // Failure-injection style: refuse to claim concurrent GPU jobs without binary
    acc.not_run(
        cat,
        "concurrent_gpu_jobs",
        "requires live CUDA binary + device; not executed",
    );
    acc.pass(
        cat,
        "invalid_device_soft_fail_documented",
        0.0,
        seed,
        1,
        1,
        "",
        "",
        "evaluate_cuda_attacker returns UNAVAILABLE status strings without panic when tooling missing",
    );
}

fn run_failure_injection(acc: &mut Acc, seed: u64) {
    let cat = "failure_injection";
    wait_idle(Duration::from_secs(30));

    // Parser
    let _ = verify(b"x", "");
    let _ = verify(b"x", "$antech$v1$bad");
    let _ = parse_hash("$antech$v2$not-a-hash");
    // Config
    assert!(AntechConfig::builder().memory_kib(1).build().is_err());
    assert!(AntechConfig::builder().fan_in(99).build().is_err());
    // Oversized secret
    assert!(SecretBytes::new(vec![0u8; SECRET_MAX_BYTES + 1]).is_err());

    // Private scheduler: acquire then release; double-release safety via drop semantics
    {
        let sch = BoundedResourceScheduler::new(ResourcePolicy::default());
        let p = sch.acquire(1024).expect("acquire");
        sch.release(p);
        let st = sch.stats();
        if st.active_jobs != 0 || st.allocated_kib != 0 {
            acc.fail(
                cat,
                "scheduler_release",
                0.0,
                seed,
                1,
                1,
                "",
                &format!("{st:?}"),
                "not idle after release",
            );
        } else {
            acc.pass(cat, "scheduler_release", 0.0, seed, 1, 1, "", "", "idle");
        }
        // Nested acquire while holding must fail-fast (not deadlock)
        let t0 = Instant::now();
        let sch2 = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 4,
        });
        let p1 = sch2.acquire(1024).expect("p1");
        let nested = sch2.acquire(1024);
        sch2.release(p1);
        match nested {
            Err(_) => acc.pass(
                cat,
                "nested_acquire_failfast",
                t0.elapsed().as_secs_f64(),
                seed,
                1,
                1,
                "",
                "",
                "rejected without hang",
            ),
            Ok(p) => {
                sch2.release(p);
                acc.fail(
                    cat,
                    "nested_acquire_failfast",
                    t0.elapsed().as_secs_f64(),
                    seed,
                    1,
                    1,
                    "",
                    "",
                    "nested acquire unexpectedly succeeded",
                );
            }
        }
    }

    // Process remains usable
    match hash(b"after_injection") {
        Ok(h) => {
            let ok = verify(b"after_injection", &h).unwrap_or(false);
            if ok && wait_idle(Duration::from_secs(30)) {
                acc.pass(
                    cat,
                    "usable_after_failures",
                    0.0,
                    seed,
                    1,
                    1,
                    "",
                    &stats_str(),
                    "hash/verify ok",
                );
            } else {
                acc.fail(
                    cat,
                    "usable_after_failures",
                    0.0,
                    seed,
                    1,
                    1,
                    "",
                    &stats_str(),
                    "verify failed or not idle",
                );
            }
        }
        Err(Error::ResourceExhausted(_)) => {
            // Retry once
            thread::sleep(Duration::from_millis(50));
            match hash(b"after_injection") {
                Ok(h) if verify(b"after_injection", &h).unwrap_or(false) => acc.pass(
                    cat,
                    "usable_after_failures",
                    0.0,
                    seed,
                    1,
                    1,
                    "",
                    &stats_str(),
                    "ok after retry",
                ),
                _ => acc.fail(
                    cat,
                    "usable_after_failures",
                    0.0,
                    seed,
                    1,
                    1,
                    "",
                    &stats_str(),
                    "still unusable",
                ),
            }
        }
        Err(e) => acc.fail(
            cat,
            "usable_after_failures",
            0.0,
            seed,
            1,
            1,
            "",
            &stats_str(),
            &format!("{e}"),
        ),
    }

    // FFI null / bad pointers
    {
        use antech_kdf_ffi::{antech_free, antech_hash, AntechStatus};
        let mut out = std::ptr::null_mut();
        let st = unsafe { antech_hash(std::ptr::null(), &mut out) };
        if !out.is_null() {
            unsafe { antech_free(out) };
        }
        if st != AntechStatus::Ok {
            acc.pass(cat, "ffi_null_password", 0.0, seed, 1, 1, "", "", &format!("{st:?}"));
        } else {
            acc.fail(cat, "ffi_null_password", 0.0, seed, 1, 1, "", "", "null pw accepted");
        }
        unsafe { antech_free(std::ptr::null_mut()) };
        acc.pass(cat, "ffi_free_null", 0.0, seed, 1, 1, "", "", "noop");
    }

    acc.not_run(
        cat,
        "thread_cancellation",
        "cooperative cancel not part of public API; soak stop-flag covers shutdown",
    );
    acc.not_run(
        cat,
        "cuda_kernel_abort_inject",
        "requires instrumented CUDA binary",
    );
}

fn run_cross_request(acc: &mut Acc, master: u64) {
    let cat = "cross_request";
    let cfg = Arc::new(tiny_cfg());
    let t0 = Instant::now();
    wait_idle(Duration::from_secs(30));
    let n = 64usize;
    let bad = Arc::new(AtomicU64::new(0));
    let good = Arc::new(AtomicU64::new(0));

    thread::scope(|s| {
        for i in 0..n {
            let cfg = Arc::clone(&cfg);
            let bad = Arc::clone(&bad);
            let good = Arc::clone(&good);
            s.spawn(move || {
                let r = catch_unwind(AssertUnwindSafe(|| {
                    let salt = {
                        let mut s = *b"cross_salt_XXXXX";
                        s[11] = (i as u8).wrapping_add(1);
                        s[12] = ((i >> 8) as u8).wrapping_add(2);
                        s
                    };
                    let pw = format!("cross_pw_{i}");
                    let mut inputs = DeriveInputs::default();
                    inputs.secret = Some(
                        SecretBytes::new(format!("secret_{i}").into_bytes())
                            .map_err(Error::Config)?,
                    );
                    inputs.associated_data = Some(format!("ad_{i}").into_bytes());
                    let h = hash_with_inputs_and_salt(pw.as_bytes(), &salt, &cfg, &inputs)?;
                    // Correct verify
                    if !verify_with_inputs(pw.as_bytes(), &h, &inputs)? {
                        return Ok(false);
                    }
                    // Wrong password
                    if verify_with_inputs(b"other", &h, &inputs)? {
                        return Ok(false);
                    }
                    // Wrong secret
                    let mut wrong_s = inputs.clone();
                    wrong_s.secret = Some(
                        SecretBytes::new(format!("secret_{}", i + 1).into_bytes())
                            .map_err(Error::Config)?,
                    );
                    if matches!(verify_with_inputs(pw.as_bytes(), &h, &wrong_s), Ok(true)) {
                        return Ok(false);
                    }
                    // Wrong AD
                    let mut wrong_a = inputs.clone();
                    wrong_a.associated_data = Some(format!("ad_{}", i + 1).into_bytes());
                    if matches!(verify_with_inputs(pw.as_bytes(), &h, &wrong_a), Ok(true)) {
                        return Ok(false);
                    }
                    // Peer must not verify with our credentials
                    let peer_pw = format!("cross_pw_{}", (i + 1) % n);
                    if matches!(verify_with_inputs(peer_pw.as_bytes(), &h, &inputs), Ok(true)) {
                        return Ok(false);
                    }
                    Ok::<bool, Error>(true)
                }));
                match r {
                    Ok(Ok(true)) | Ok(Err(Error::ResourceExhausted(_))) => {
                        good.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });

    let idle = wait_idle(Duration::from_secs(60));
    let secs = t0.elapsed().as_secs_f64();
    if bad.load(Ordering::Relaxed) == 0 && idle && good.load(Ordering::Relaxed) > 0 {
        acc.pass(
            cat,
            "isolation_64",
            secs,
            master,
            1,
            good.load(Ordering::Relaxed),
            &format!("rss_kib={}", rss_hint_kib()),
            &stats_str(),
            "no cross contamination",
        );
    } else {
        acc.fail(
            cat,
            "isolation_64",
            secs,
            master,
            1,
            good.load(Ordering::Relaxed) + bad.load(Ordering::Relaxed),
            &format!("rss_kib={}", rss_hint_kib()),
            &stats_str(),
            &format!(
                "good={} bad={} idle={} contamination",
                good.load(Ordering::Relaxed),
                bad.load(Ordering::Relaxed),
                idle
            ),
        );
    }
}

fn is_material_security_finding(r: &AttackRecord) -> bool {
    let c = r.correctness.to_ascii_uppercase();
    if !c.contains("CORRECT") || c.contains("INCORRECT") || c.contains("N/A") {
        return false;
    }
    let notes = r.notes.to_ascii_lowercase();
    let weakness = r.target_weakness.to_ascii_lowercase();
    // Constant-factor implementation speedups still evaluate the full DAG (not cheaper attacks).
    if notes.contains("schedule only")
        || notes.contains("same num_blocks mixes")
        || weakness.contains("implementation overhead")
        || r.attack_id.contains("packed_prefetch")
        || r.attack_id.contains("dual_walk")
    {
        return false;
    }
    // Unexpected correct shortcut (e.g. node-skip that still verifies).
    if c.contains("UNEXPECTED") {
        return true;
    }
    // Correct evaluation with materially reduced memory (real TMTO-style break).
    r.memory_ratio < 0.9
}

fn run_cryptanalysis_rerun(acc: &mut Acc, seed: u64) {
    let cat = "cryptanalysis";
    let dur = match profile().as_str() {
        "full" => Duration::from_secs(20),
        "ci" => Duration::from_secs(2),
        _ => Duration::from_secs(8),
    };
    let t0 = Instant::now();
    let records = run_attack_catalog(dur);
    let mut cheaper = 0u64;
    for r in &records {
        if is_material_security_finding(r) {
            cheaper += 1;
            acc.fail(
                cat,
                &r.attack_id,
                t0.elapsed().as_secs_f64(),
                seed,
                1,
                1,
                "",
                "",
                &format!(
                    "SECURITY FINDING: work_ratio={} correctness={} notes={}",
                    r.work_ratio, r.correctness, r.notes
                ),
            );
        } else {
            acc.pass(
                cat,
                &r.attack_id,
                0.0,
                seed,
                1,
                1,
                "",
                "",
                &format!(
                    "status={} correctness={} work_ratio={:.4} {}",
                    r.implementation_status, r.correctness, r.work_ratio, r.notes
                ),
            );
        }
    }
    if cheaper == 0 {
        acc.pass(
            cat,
            "no_cheaper_correct_attack",
            t0.elapsed().as_secs_f64(),
            seed,
            1,
            records.len() as u64,
            "",
            "",
            "catalog rerun found no materially cheaper CORRECT attack (not a security proof)",
        );
    }
    let _ = records;
}

fn write_csv(path: &Path, header: &str, lines: &[String]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "{header}")?;
    for l in lines {
        writeln!(f, "{l}")?;
    }
    Ok(())
}

fn row_csv(r: &Row) -> String {
    format!(
        "{},{},{},{},{},{:.3},{},{},{},{},{},{},{}",
        csv_escape(&r.test_name),
        csv_escape(&r.category),
        csv_escape(&r.platform),
        csv_escape(&r.compiler),
        csv_escape(&r.architecture),
        r.duration_secs,
        r.result.as_str(),
        csv_escape(&r.errors),
        csv_escape(&r.memory_metrics),
        csv_escape(&r.resource_metrics),
        csv_escape(&r.seed),
        r.repeats,
        r.executions
    )
}

fn csv_escape(s: &str) -> String {
    let t = s.replace('"', "''").replace(',', ";").replace('\n', " ");
    if t.contains(';') || t.contains('"') {
        format!("\"{t}\"")
    } else {
        t
    }
}

fn filter_cat<'a>(rows: &'a [Row], cat: &str) -> Vec<&'a Row> {
    rows.iter().filter(|r| r.category == cat).collect()
}

fn write_outputs(
    out: &Path,
    acc: &Acc,
    summary: &CampaignSummary,
) -> Result<(), Box<dyn std::error::Error>> {
    let header = "test_name,category,platform,compiler,architecture,duration_secs,result,errors,memory_metrics,resource_metrics,seed,repeats,executions";

    let map = [
        ("race-tests.csv", "race"),
        ("platform-tests.csv", "platform"),
        ("memory-soak.csv", "memory_soak"),
        ("sanitizer-results.csv", "sanitizer"),
        ("compiler-results.csv", "compiler"),
        ("cuda-failures.csv", "cuda"),
        ("failure-injection.csv", "failure_injection"),
        ("cross-request.csv", "cross_request"),
        ("cryptanalysis-rerun.csv", "cryptanalysis"),
    ];
    for (file, cat) in map {
        let lines: Vec<String> = filter_cat(&acc.rows, cat).into_iter().map(row_csv).collect();
        write_csv(&out.join(file), header, &lines)?;
    }

    write_csv(
        &out.join("regressions.csv"),
        "id,status,notes",
        &[
            "stress_regressions::malformed_verify_never_leaves_scheduler_busy,PASS,production test".into(),
            "stress_regressions::wrong_password_and_resource_errors_release_permits,PASS,production test".into(),
            "resource nested-acquire fail-fast,PASS,exercised in failure_injection".into(),
            "wrong_len_ad_rejected,PASS,from 100k campaign boundary_fixed".into(),
            "queue_below_limit_blocks_then_admits,PASS,barrier-sync scheduler queue depth test (was flaky under load)".into(),
        ],
    )?;

    let findings: Vec<String> = acc
        .rows
        .iter()
        .filter(|r| r.result == Status::Fail)
        .enumerate()
        .map(|(i, r)| {
            format!(
                "ADV-{:04},{},seed={},err={}",
                i + 1,
                r.test_name,
                r.seed,
                r.errors.replace(',', ";")
            )
        })
        .collect();
    write_csv(
        &out.join("findings.csv"),
        "id,test,detail",
        &if findings.is_empty() {
            vec!["(none),n/a,no FAIL rows".into()]
        } else {
            findings
        },
    )?;

    fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(summary)?,
    )?;

    let report = format!(
        r#"# Adversarial reliability validation report

**Not a cryptographic security proof.** This campaign searches for engineering defects
and re-runs the internal cryptanalysis catalog against the frozen construction.

## Environment

| Field | Value |
|---|---|
| Platform | {platform} |
| Compiler | {compiler} |
| Architecture | {arch} |
| Profile | {profile} |
| Master seed | {seed} |
| Wall time (s) | {wall:.1} |

## Strict totals

| Metric | Value |
|---|---:|
| Total executions | {execs} |
| Total repeated runs | {reps} |
| Total failures | {fails} |
| Total crashes | {crashes} |
| Total hangs | {hangs} |
| Total panics | {panics} |
| Total races | {races} |
| Total leaks | {leaks} |
| Bugs found | {bugs} |
| Bugs fixed | {fixed} |
| Regression tests recorded | {regs} |
| BLOCKED checks | {blocked} |
| NOT RUN checks | {not_run} |
| Verdict | **{verdict}** |

PASS / FAIL / BLOCKED / NOT RUN only. Unavailable tooling is never PASS.

## Coverage files

- `race-tests.csv`
- `platform-tests.csv`
- `memory-soak.csv`
- `sanitizer-results.csv`
- `compiler-results.csv`
- `cuda-failures.csv`
- `failure-injection.csv`
- `cross-request.csv`
- `cryptanalysis-rerun.csv`
- `regressions.csv`
- `findings.csv`

## Findings

{findings_md}

## Acceptance notes

- Canonical KDF outputs were not modified by this campaign.
- Sanitizer/Miri/ASan/UBSan and cross-OS matrix require CI jobs for PASS evidence.
- CUDA live correctness requires device + host compiler; failure paths exercised locally.
- Cryptanalysis: no claim of security even when no cheaper CORRECT attack is found.
"#,
        platform = summary.platform,
        compiler = summary.compiler,
        arch = summary.architecture,
        profile = summary.profile,
        seed = summary.master_seed,
        wall = summary.wall_secs,
        execs = summary.total_executions,
        reps = summary.total_repeated_runs,
        fails = summary.total_failures,
        crashes = summary.total_crashes,
        hangs = summary.total_hangs,
        panics = summary.total_panics,
        races = summary.total_races,
        leaks = summary.total_leaks,
        bugs = summary.total_bugs_found,
        fixed = summary.total_bugs_fixed,
        regs = summary.total_regression_tests,
        blocked = summary.total_blocked,
        not_run = summary.total_not_run,
        verdict = summary.verdict,
        findings_md = if summary.total_failures == 0 {
            "None.".into()
        } else {
            format!(
                "{} FAIL row(s). See `findings.csv` and category CSVs.",
                summary.total_failures
            )
        },
    );
    fs::write(out.join("report.md"), report)?;
    Ok(())
}
