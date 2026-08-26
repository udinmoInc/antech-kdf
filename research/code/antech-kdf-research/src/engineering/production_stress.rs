//! Production-path stress: real `hash` / `verify`, process-wide OnceLock scheduler.
//!
//! Does **not** change the KDF algorithm, public API, hash format, or ResourcePolicy defaults.
//! Research-only harness that drives and measures the production crates.

use antech_kdf::{hash, hash_with_config, verify, AntechConfig, Error};
use antech_kdf_core::{scheduler_stats, ResourcePolicy};
use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Default production ResourcePolicy ceilings (must match `BoundedResourceScheduler::default`).
pub const DEFAULT_MAX_MEMORY_KIB: usize = 131_072;
pub const DEFAULT_MAX_ACTIVE_JOBS: usize = 64;
pub const DEFAULT_QUEUE_LIMIT: usize = 256;

pub const MIXED_CONCURRENCY: &[usize] = &[1, 10, 32, 100, 250, 500, 1000];
pub const MIXED_DURATIONS_SECS: &[u64] = &[10, 30, 60];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyPercentiles {
    pub samples: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub mean_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressScenarioRow {
    pub scenario: String,
    pub duration_secs: u64,
    pub concurrency: usize,
    pub memory_kib_cfg: usize,
    pub ops_total: u64,
    pub hashes: u64,
    pub verify_valid_ok: u64,
    pub verify_wrong_ok: u64,
    pub rejected_resource: u64,
    pub expected_input_errors: u64,
    pub unexpected_errors: u64,
    pub panics: u64,
    pub throughput_ops_per_sec: f64,
    pub latency: LatencyPercentiles,
    pub peak_active_permits: u64,
    pub peak_queue_depth: u64,
    pub peak_allocated_kib: u64,
    pub peak_rss_bytes: u64,
    pub cpu_usage_pct: f64,
    pub final_active_permits: u64,
    pub final_queue_depth: u64,
    pub final_allocated_kib: u64,
    pub scheduler_idle: bool,
    pub budget_ok: bool,
    pub queue_limit_ok: bool,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressCampaignSummary {
    pub host: HostInfo,
    pub policy: PolicySnapshot,
    pub mixed_rows: Vec<StressScenarioRow>,
    pub malformed_rows: Vec<StressScenarioRow>,
    pub failure_release_rows: Vec<StressScenarioRow>,
    pub overload_queue_rows: Vec<StressScenarioRow>,
    pub all_idle: bool,
    pub unexplained_errors: u64,
    pub unexplained_panics: u64,
    pub budget_violations: u64,
    pub queue_limit_violations: u64,
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub os: String,
    pub arch: String,
    pub logical_cpus: usize,
    pub total_ram_hint_gb: Option<f64>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub max_memory_kib: usize,
    pub max_active_jobs: usize,
    pub queue_limit: usize,
}

#[derive(Default)]
struct Counters {
    ops: AtomicU64,
    hashes: AtomicU64,
    verify_valid_ok: AtomicU64,
    verify_wrong_ok: AtomicU64,
    rejected_resource: AtomicU64,
    expected_input_errors: AtomicU64,
    unexpected_errors: AtomicU64,
    panics: AtomicU64,
}

struct PeakMonitor {
    stop: AtomicBool,
    peak_active: AtomicU64,
    peak_waiting: AtomicU64,
    peak_alloc: AtomicU64,
    peak_rss: AtomicU64,
}

impl PeakMonitor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
            peak_active: AtomicU64::new(0),
            peak_waiting: AtomicU64::new(0),
            peak_alloc: AtomicU64::new(0),
            peak_rss: AtomicU64::new(0),
        })
    }

    fn start(self: &Arc<Self>) -> thread::JoinHandle<()> {
        let mon = Arc::clone(self);
        thread::spawn(move || {
            while !mon.stop.load(Ordering::Relaxed) {
                let st = scheduler_stats();
                mon.peak_active
                    .fetch_max(st.active_jobs as u64, Ordering::Relaxed);
                mon.peak_waiting
                    .fetch_max(st.waiting_jobs as u64, Ordering::Relaxed);
                mon.peak_alloc
                    .fetch_max(st.allocated_kib as u64, Ordering::Relaxed);
                if let Some(rss) = process_rss_bytes() {
                    mon.peak_rss.fetch_max(rss, Ordering::Relaxed);
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let n = sorted_ms.len();
    let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
    sorted_ms[idx.min(n - 1)]
}

fn latency_from_samples(mut samples: Vec<f64>) -> LatencyPercentiles {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples.len() as u64;
    let mean = if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / samples.len() as f64
    };
    let max = samples.last().copied().unwrap_or(0.0);
    LatencyPercentiles {
        samples: n,
        p50_ms: percentile(&samples, 50.0),
        p95_ms: percentile(&samples, 95.0),
        p99_ms: percentile(&samples, 99.0),
        mean_ms: mean,
        max_ms: max,
    }
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
        thread::sleep(Duration::from_millis(10));
    }
}

fn classify_resource(err: &Error) -> bool {
    matches!(err, Error::ResourceExhausted(_))
}

fn seed_credentials(count: usize) -> Vec<(String, String)> {
    let count = count.max(1);
    let out = Arc::new(Mutex::new(Vec::with_capacity(count)));
    thread::scope(|s| {
        for i in 0..count {
            let out = Arc::clone(&out);
            s.spawn(move || {
                let pw = format!("prod_stress_seed_{i}");
                let mut last = None;
                for _ in 0..64 {
                    match hash(&pw) {
                        Ok(h) => {
                            out.lock().expect("seed lock").push((pw, h));
                            return;
                        }
                        Err(e) => last = Some(e),
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                panic!("seed hash failed for {i}: {last:?}");
            });
        }
    });
    let mut v = out.lock().expect("seed lock").clone();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(v.len(), count);
    assert!(wait_idle(Duration::from_secs(60)));
    v
}

/// 70% valid verify / 20% wrong verify / 10% hash — production defaults.
pub fn run_mixed_scenario(duration_secs: u64, concurrency: usize) -> StressScenarioRow {
    let cfg = AntechConfig::default();
    let memory_kib = cfg.memory.as_kib();

    // Shared credential pool (auth-like): many concurrent verifies against few stored hashes.
    let pool_n = concurrency.min(32).max(1);
    let seed_hashes = Arc::new(seed_credentials(pool_n));

    let counters = Arc::new(Counters::default());
    let latencies = Arc::new(Mutex::new(Vec::<f64>::with_capacity(8192)));
    let stop = Arc::new(AtomicBool::new(false));
    let mon = PeakMonitor::new();
    let mon_h = mon.start();
    let cpu0 = process_cpu_times();

    let t0 = Instant::now();
    let duration = Duration::from_secs(duration_secs);
    thread::scope(|s| {
        for t in 0..concurrency {
            let counters = Arc::clone(&counters);
            let latencies = Arc::clone(&latencies);
            let stop = Arc::clone(&stop);
            let seed_hashes = Arc::clone(&seed_hashes);
            s.spawn(move || {
                let mut i = t as u64;
                while !stop.load(Ordering::Relaxed) {
                    let (pw, encoded) = &seed_hashes[t % seed_hashes.len()];
                    let lane = i % 10;
                    let start = Instant::now();
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        if lane < 7 {
                            // valid-password verify
                            match verify(pw.as_bytes(), encoded) {
                                Ok(true) => OpOutcome::VerifyValid,
                                Ok(false) => OpOutcome::Unexpected,
                                Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::Unexpected,
                            }
                        } else if lane < 9 {
                            // wrong-password verify
                            match verify(b"definitely_wrong_password", encoded) {
                                Ok(false) => OpOutcome::VerifyWrong,
                                Ok(true) => OpOutcome::Unexpected,
                                Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::Unexpected,
                            }
                        } else {
                            // new password hashing
                            let fresh = format!("prod_hash_{t}_{i}");
                            match hash(fresh.as_bytes()) {
                                Ok(_) => OpOutcome::Hash,
                                Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::Unexpected,
                            }
                        }
                    }));
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                    counters.ops.fetch_add(1, Ordering::Relaxed);
                    match result {
                        Ok(outcome) => {
                            apply_outcome(&counters, outcome);
                            if let Ok(mut v) = latencies.lock() {
                                if v.len() < 250_000 {
                                    v.push(elapsed_ms);
                                }
                            }
                        }
                        Err(_) => {
                            counters.panics.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    i = i.wrapping_add(1);
                }
            });
        }
        thread::sleep(duration);
        stop.store(true, Ordering::Relaxed);
    });

    mon.stop();
    let _ = mon_h.join();
    let cpu_pct = cpu_usage_pct(cpu0, t0.elapsed());
    let idle = wait_idle(Duration::from_secs(60));
    let st = scheduler_stats();
    let samples = latencies.lock().map(|g| g.clone()).unwrap_or_default();
    let peak_alloc = mon.peak_alloc.load(Ordering::Relaxed);
    let peak_q = mon.peak_waiting.load(Ordering::Relaxed);
    let ops = counters.ops.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64().max(1e-9);

    StressScenarioRow {
        scenario: "mixed_70_20_10".into(),
        duration_secs,
        concurrency,
        memory_kib_cfg: memory_kib,
        ops_total: ops,
        hashes: counters.hashes.load(Ordering::Relaxed),
        verify_valid_ok: counters.verify_valid_ok.load(Ordering::Relaxed),
        verify_wrong_ok: counters.verify_wrong_ok.load(Ordering::Relaxed),
        rejected_resource: counters.rejected_resource.load(Ordering::Relaxed),
        expected_input_errors: counters.expected_input_errors.load(Ordering::Relaxed),
        unexpected_errors: counters.unexpected_errors.load(Ordering::Relaxed),
        panics: counters.panics.load(Ordering::Relaxed),
        throughput_ops_per_sec: ops as f64 / elapsed,
        latency: latency_from_samples(samples),
        peak_active_permits: mon.peak_active.load(Ordering::Relaxed),
        peak_queue_depth: peak_q,
        peak_allocated_kib: peak_alloc,
        peak_rss_bytes: mon.peak_rss.load(Ordering::Relaxed),
        cpu_usage_pct: cpu_pct,
        final_active_permits: st.active_jobs as u64,
        final_queue_depth: st.waiting_jobs as u64,
        final_allocated_kib: st.allocated_kib as u64,
        scheduler_idle: idle && st.active_jobs == 0 && st.waiting_jobs == 0,
        budget_ok: peak_alloc <= DEFAULT_MAX_MEMORY_KIB as u64,
        queue_limit_ok: peak_q <= DEFAULT_QUEUE_LIMIT as u64,
        notes: format!(
            "production AntechConfig::default(); peak_active={} peak_q={} rejects={}",
            mon.peak_active.load(Ordering::Relaxed),
            peak_q,
            counters.rejected_resource.load(Ordering::Relaxed)
        ),
    }
}

#[derive(Clone, Copy)]
enum OpOutcome {
    Hash,
    VerifyValid,
    VerifyWrong,
    Rejected,
    ExpectedInput,
    Unexpected,
}

fn apply_outcome(c: &Counters, o: OpOutcome) {
    match o {
        OpOutcome::Hash => {
            c.hashes.fetch_add(1, Ordering::Relaxed);
        }
        OpOutcome::VerifyValid => {
            c.verify_valid_ok.fetch_add(1, Ordering::Relaxed);
        }
        OpOutcome::VerifyWrong => {
            c.verify_wrong_ok.fetch_add(1, Ordering::Relaxed);
        }
        OpOutcome::Rejected => {
            c.rejected_resource.fetch_add(1, Ordering::Relaxed);
        }
        OpOutcome::ExpectedInput => {
            c.expected_input_errors.fetch_add(1, Ordering::Relaxed);
        }
        OpOutcome::Unexpected => {
            c.unexpected_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Concurrent malformed verify + invalid config validation (no unbounded alloc / panic).
pub fn run_malformed_scenario(duration_secs: u64, concurrency: usize) -> StressScenarioRow {
    let counters = Arc::new(Counters::default());
    let latencies = Arc::new(Mutex::new(Vec::<f64>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let mon = PeakMonitor::new();
    let mon_h = mon.start();
    let cpu0 = process_cpu_times();
    let t0 = Instant::now();
    let duration = Duration::from_secs(duration_secs);

    let malformed: Arc<Vec<&'static str>> = Arc::new(vec![
        "",
        "$",
        "$antech$",
        "$antech$v1$m=16384$aa$bb",
        "$antech$v2$",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32$",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32$notahex$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
        "$antech$v2$m=999999999,s=16,b=32,f=2,g=3,l=32$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
        // Oversized hex intended to hit length checks before decode.
        // Keep bounded: stress runner must not itself OOM.
    ]);

    thread::scope(|s| {
        for t in 0..concurrency {
            let counters = Arc::clone(&counters);
            let latencies = Arc::clone(&latencies);
            let stop = Arc::clone(&stop);
            let malformed = Arc::clone(&malformed);
            s.spawn(move || {
                let mut i = t as u64;
                while !stop.load(Ordering::Relaxed) {
                    let start = Instant::now();
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        let lane = i % 5;
                        if lane < 3 {
                            let enc = malformed[(i as usize) % malformed.len()];
                            match verify(b"password", enc) {
                                Ok(_) => OpOutcome::Unexpected,
                                Err(Error::ResourceExhausted(_)) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::ExpectedInput,
                            }
                        } else if lane == 3 {
                            // Invalid config — must fail validation without taking a permit.
                            let bad = AntechConfig::builder().memory_kib(1).build();
                            match bad {
                                Err(_) => OpOutcome::ExpectedInput,
                                Ok(cfg) => match hash_with_config(b"x", &cfg) {
                                    Ok(_) => OpOutcome::Unexpected,
                                    Err(Error::ResourceExhausted(_)) => OpOutcome::Rejected,
                                    Err(_) => OpOutcome::ExpectedInput,
                                },
                            }
                        } else {
                            // Huge-but-bounded junk string (~8 KiB) to stress parser admission.
                            let junk = format!("$antech$v2${}", "A".repeat(8000));
                            match verify(b"x", &junk) {
                                Ok(_) => OpOutcome::Unexpected,
                                Err(Error::ResourceExhausted(_)) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::ExpectedInput,
                            }
                        }
                    }));
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                    counters.ops.fetch_add(1, Ordering::Relaxed);
                    match outcome {
                        Ok(o) => {
                            apply_outcome(&counters, o);
                            if let Ok(mut v) = latencies.lock() {
                                if v.len() < 250_000 {
                                    v.push(elapsed_ms);
                                }
                            }
                        }
                        Err(_) => {
                            counters.panics.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    i = i.wrapping_add(1);
                }
            });
        }
        thread::sleep(duration);
        stop.store(true, Ordering::Relaxed);
    });

    mon.stop();
    let _ = mon_h.join();
    let cpu_pct = cpu_usage_pct(cpu0, t0.elapsed());
    let idle = wait_idle(Duration::from_secs(30));
    let st = scheduler_stats();
    let samples = latencies.lock().map(|g| g.clone()).unwrap_or_default();
    let peak_alloc = mon.peak_alloc.load(Ordering::Relaxed);
    let peak_q = mon.peak_waiting.load(Ordering::Relaxed);
    let ops = counters.ops.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64().max(1e-9);

    StressScenarioRow {
        scenario: "malformed_input".into(),
        duration_secs,
        concurrency,
        memory_kib_cfg: 0,
        ops_total: ops,
        hashes: counters.hashes.load(Ordering::Relaxed),
        verify_valid_ok: counters.verify_valid_ok.load(Ordering::Relaxed),
        verify_wrong_ok: counters.verify_wrong_ok.load(Ordering::Relaxed),
        rejected_resource: counters.rejected_resource.load(Ordering::Relaxed),
        expected_input_errors: counters.expected_input_errors.load(Ordering::Relaxed),
        unexpected_errors: counters.unexpected_errors.load(Ordering::Relaxed),
        panics: counters.panics.load(Ordering::Relaxed),
        throughput_ops_per_sec: ops as f64 / elapsed,
        latency: latency_from_samples(samples),
        peak_active_permits: mon.peak_active.load(Ordering::Relaxed),
        peak_queue_depth: peak_q,
        peak_allocated_kib: peak_alloc,
        peak_rss_bytes: mon.peak_rss.load(Ordering::Relaxed),
        cpu_usage_pct: cpu_pct,
        final_active_permits: st.active_jobs as u64,
        final_queue_depth: st.waiting_jobs as u64,
        final_allocated_kib: st.allocated_kib as u64,
        scheduler_idle: idle && st.active_jobs == 0 && st.waiting_jobs == 0,
        budget_ok: peak_alloc <= DEFAULT_MAX_MEMORY_KIB as u64,
        queue_limit_ok: peak_q <= DEFAULT_QUEUE_LIMIT as u64,
        notes: "verify() + AntechConfig validation against untrusted / invalid input".into(),
    }
}

/// Error paths must release permits: resource rejection, bad config, malformed verify, wrong pw.
pub fn run_failure_release_scenario(duration_secs: u64, concurrency: usize) -> StressScenarioRow {
    let counters = Arc::new(Counters::default());
    let latencies = Arc::new(Mutex::new(Vec::<f64>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let mon = PeakMonitor::new();
    let mon_h = mon.start();
    let cpu0 = process_cpu_times();

    // Shared valid hash for wrong-password path.
    let encoded = loop {
        match hash("failure_release_seed") {
            Ok(h) => break h,
            Err(Error::ResourceExhausted(_)) => {
                let _ = wait_idle(Duration::from_millis(50));
            }
            Err(e) => panic!("seed hash: {e}"),
        }
    };
    assert!(wait_idle(Duration::from_secs(10)));

    let t0 = Instant::now();
    let duration = Duration::from_secs(duration_secs);
    let encoded = Arc::new(encoded);

    thread::scope(|s| {
        for t in 0..concurrency {
            let counters = Arc::clone(&counters);
            let latencies = Arc::clone(&latencies);
            let stop = Arc::clone(&stop);
            let encoded = Arc::clone(&encoded);
            s.spawn(move || {
                let mut i = t as u64;
                while !stop.load(Ordering::Relaxed) {
                    let start = Instant::now();
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        match i % 4 {
                            0 => match verify(b"wrong", encoded.as_str()) {
                                Ok(false) => OpOutcome::VerifyWrong,
                                Ok(true) => OpOutcome::Unexpected,
                                Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::Unexpected,
                            },
                            1 => match verify(b"x", "$antech$v2$not-a-hash") {
                                Ok(_) => OpOutcome::Unexpected,
                                Err(Error::ResourceExhausted(_)) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::ExpectedInput,
                            },
                            2 => {
                                let bad = AntechConfig::builder().salt_length(1).build();
                                match bad {
                                    Err(_) => OpOutcome::ExpectedInput,
                                    Ok(cfg) => match hash_with_config(b"x", &cfg) {
                                        Ok(_) => OpOutcome::Unexpected,
                                        Err(Error::ResourceExhausted(_)) => OpOutcome::Rejected,
                                        Err(_) => OpOutcome::ExpectedInput,
                                    },
                                }
                            }
                            _ => {
                                // Concurrent real hash — under overload returns ResourceExhausted
                                // (acquire failed) or Ok (permit released via PermitGuard).
                                let pw = format!("fail_hash_{t}_{i}");
                                match hash(pw.as_bytes()) {
                                    Ok(_) => OpOutcome::Hash,
                                    Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                                    Err(_) => OpOutcome::Unexpected,
                                }
                            }
                        }
                    }));
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                    counters.ops.fetch_add(1, Ordering::Relaxed);
                    match outcome {
                        Ok(o) => {
                            apply_outcome(&counters, o);
                            if let Ok(mut v) = latencies.lock() {
                                if v.len() < 250_000 {
                                    v.push(elapsed_ms);
                                }
                            }
                        }
                        Err(_) => {
                            counters.panics.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    i = i.wrapping_add(1);
                }
            });
        }
        thread::sleep(duration);
        stop.store(true, Ordering::Relaxed);
    });

    mon.stop();
    let _ = mon_h.join();
    let cpu_pct = cpu_usage_pct(cpu0, t0.elapsed());
    let idle = wait_idle(Duration::from_secs(60));
    let st = scheduler_stats();
    let samples = latencies.lock().map(|g| g.clone()).unwrap_or_default();
    let peak_alloc = mon.peak_alloc.load(Ordering::Relaxed);
    let peak_q = mon.peak_waiting.load(Ordering::Relaxed);
    let ops = counters.ops.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64().max(1e-9);

    StressScenarioRow {
        scenario: "failure_and_release".into(),
        duration_secs,
        concurrency,
        memory_kib_cfg: AntechConfig::default().memory.as_kib(),
        ops_total: ops,
        hashes: counters.hashes.load(Ordering::Relaxed),
        verify_valid_ok: counters.verify_valid_ok.load(Ordering::Relaxed),
        verify_wrong_ok: counters.verify_wrong_ok.load(Ordering::Relaxed),
        rejected_resource: counters.rejected_resource.load(Ordering::Relaxed),
        expected_input_errors: counters.expected_input_errors.load(Ordering::Relaxed),
        unexpected_errors: counters.unexpected_errors.load(Ordering::Relaxed),
        panics: counters.panics.load(Ordering::Relaxed),
        throughput_ops_per_sec: ops as f64 / elapsed,
        latency: latency_from_samples(samples),
        peak_active_permits: mon.peak_active.load(Ordering::Relaxed),
        peak_queue_depth: peak_q,
        peak_allocated_kib: peak_alloc,
        peak_rss_bytes: mon.peak_rss.load(Ordering::Relaxed),
        cpu_usage_pct: cpu_pct,
        final_active_permits: st.active_jobs as u64,
        final_queue_depth: st.waiting_jobs as u64,
        final_allocated_kib: st.allocated_kib as u64,
        scheduler_idle: idle && st.active_jobs == 0 && st.waiting_jobs == 0,
        budget_ok: peak_alloc <= DEFAULT_MAX_MEMORY_KIB as u64,
        queue_limit_ok: peak_q <= DEFAULT_QUEUE_LIMIT as u64,
        notes: "error paths + concurrent hash/verify under OnceLock contention".into(),
    }
}

/// Flood workers past queue_limit to prove rejections and peak_waiting ≤ queue_limit.
pub fn run_overload_queue_scenario(duration_secs: u64, concurrency: usize) -> StressScenarioRow {
    // Use production path; default 16 MiB ⇒ ~8 concurrent under 128 MiB.
    // With concurrency >> 256+8, queue fills and ResourceExhausted must appear.
    let counters = Arc::new(Counters::default());
    let latencies = Arc::new(Mutex::new(Vec::<f64>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let mon = PeakMonitor::new();
    let mon_h = mon.start();
    let cpu0 = process_cpu_times();
    let t0 = Instant::now();
    let duration = Duration::from_secs(duration_secs);

    thread::scope(|s| {
        for t in 0..concurrency {
            let counters = Arc::clone(&counters);
            let latencies = Arc::clone(&latencies);
            let stop = Arc::clone(&stop);
            s.spawn(move || {
                let mut i = t as u64;
                while !stop.load(Ordering::Relaxed) {
                    let start = Instant::now();
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        let pw = format!("overload_{t}_{i}");
                        match hash(pw.as_bytes()) {
                            Ok(h) => match verify(pw.as_bytes(), &h) {
                                Ok(true) => OpOutcome::Hash,
                                Ok(false) => OpOutcome::Unexpected,
                                Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                                Err(_) => OpOutcome::Unexpected,
                            },
                            Err(e) if classify_resource(&e) => OpOutcome::Rejected,
                            Err(_) => OpOutcome::Unexpected,
                        }
                    }));
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                    counters.ops.fetch_add(1, Ordering::Relaxed);
                    match outcome {
                        Ok(o) => {
                            apply_outcome(&counters, o);
                            if let Ok(mut v) = latencies.lock() {
                                if v.len() < 250_000 {
                                    v.push(elapsed_ms);
                                }
                            }
                        }
                        Err(_) => {
                            counters.panics.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    i = i.wrapping_add(1);
                }
            });
        }
        thread::sleep(duration);
        stop.store(true, Ordering::Relaxed);
    });

    mon.stop();
    let _ = mon_h.join();
    let cpu_pct = cpu_usage_pct(cpu0, t0.elapsed());
    let idle = wait_idle(Duration::from_secs(90));
    let st = scheduler_stats();
    let samples = latencies.lock().map(|g| g.clone()).unwrap_or_default();
    let peak_alloc = mon.peak_alloc.load(Ordering::Relaxed);
    let peak_q = mon.peak_waiting.load(Ordering::Relaxed);
    let rejects = counters.rejected_resource.load(Ordering::Relaxed);
    let ops = counters.ops.load(Ordering::Relaxed);
    let elapsed = t0.elapsed().as_secs_f64().max(1e-9);
    let queue_enforced = concurrency > DEFAULT_QUEUE_LIMIT && rejects > 0;

    StressScenarioRow {
        scenario: "overload_queue_limit".into(),
        duration_secs,
        concurrency,
        memory_kib_cfg: AntechConfig::default().memory.as_kib(),
        ops_total: ops,
        hashes: counters.hashes.load(Ordering::Relaxed),
        verify_valid_ok: counters.verify_valid_ok.load(Ordering::Relaxed),
        verify_wrong_ok: counters.verify_wrong_ok.load(Ordering::Relaxed),
        rejected_resource: rejects,
        expected_input_errors: counters.expected_input_errors.load(Ordering::Relaxed),
        unexpected_errors: counters.unexpected_errors.load(Ordering::Relaxed),
        panics: counters.panics.load(Ordering::Relaxed),
        throughput_ops_per_sec: ops as f64 / elapsed,
        latency: latency_from_samples(samples),
        peak_active_permits: mon.peak_active.load(Ordering::Relaxed),
        peak_queue_depth: peak_q,
        peak_allocated_kib: peak_alloc,
        peak_rss_bytes: mon.peak_rss.load(Ordering::Relaxed),
        cpu_usage_pct: cpu_pct,
        final_active_permits: st.active_jobs as u64,
        final_queue_depth: st.waiting_jobs as u64,
        final_allocated_kib: st.allocated_kib as u64,
        scheduler_idle: idle && st.active_jobs == 0 && st.waiting_jobs == 0,
        budget_ok: peak_alloc <= DEFAULT_MAX_MEMORY_KIB as u64,
        queue_limit_ok: peak_q <= DEFAULT_QUEUE_LIMIT as u64 && queue_enforced,
        notes: format!(
            "expects rejects when concurrency>{DEFAULT_QUEUE_LIMIT}; rejects={rejects} peak_q={peak_q} enforced={queue_enforced}"
        ),
    }
}

pub fn collect_host_info() -> HostInfo {
    HostInfo {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        logical_cpus: thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        total_ram_hint_gb: None,
        notes: "production stress host metadata".into(),
    }
}

pub fn policy_snapshot() -> PolicySnapshot {
    // Mirror defaults; ResourcePolicy is not reconfigured for production path.
    let _ = ResourcePolicy::default();
    PolicySnapshot {
        max_memory_kib: DEFAULT_MAX_MEMORY_KIB,
        max_active_jobs: DEFAULT_MAX_ACTIVE_JOBS,
        queue_limit: DEFAULT_QUEUE_LIMIT,
    }
}

/// Durations from env or full matrix when host is capable.
pub fn durations_for_host() -> Vec<u64> {
    if let Ok(s) = std::env::var("ANTECH_PROD_STRESS_SECS") {
        return s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    }
    let cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // This host class (≥8 logical CPUs, research machines with ≥16 GiB): full 10/30/60.
    if cpus >= 8 {
        MIXED_DURATIONS_SECS.to_vec()
    } else {
        vec![10, 30]
    }
}

pub fn concurrency_levels() -> Vec<usize> {
    if let Ok(s) = std::env::var("ANTECH_PROD_STRESS_CONC") {
        return s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    }
    MIXED_CONCURRENCY.to_vec()
}

pub fn run_full_campaign() -> StressCampaignSummary {
    let mut host = collect_host_info();
    host.total_ram_hint_gb = detect_ram_gb();
    let policy = policy_snapshot();
    let durs = durations_for_host();
    let concs = concurrency_levels();

    println!(
        "=== Production stress campaign ===\ncpus={} ram_gb={:?} durs={:?} conc={:?}",
        host.logical_cpus, host.total_ram_hint_gb, durs, concs
    );

    let mut mixed_rows = Vec::new();
    for &secs in &durs {
        for &conc in &concs {
            println!("mixed: {secs}s × {conc} workers …");
            let row = run_mixed_scenario(secs, conc);
            println!(
                "  ops={} thrpt={:.2}/s p50={:.1}ms p99={:.1}ms rejects={} unexpected={} panics={} idle={} budget_ok={} q_ok={}",
                row.ops_total,
                row.throughput_ops_per_sec,
                row.latency.p50_ms,
                row.latency.p99_ms,
                row.rejected_resource,
                row.unexpected_errors,
                row.panics,
                row.scheduler_idle,
                row.budget_ok,
                row.queue_limit_ok
            );
            mixed_rows.push(row);
        }
    }

    let mut malformed_rows = Vec::new();
    for &secs in &[10u64, 30] {
        for &conc in &[32usize, 100, 250] {
            println!("malformed: {secs}s × {conc} …");
            let row = run_malformed_scenario(secs, conc);
            println!(
                "  ops={} expected_err={} unexpected={} panics={} idle={}",
                row.ops_total,
                row.expected_input_errors,
                row.unexpected_errors,
                row.panics,
                row.scheduler_idle
            );
            malformed_rows.push(row);
        }
    }

    let mut failure_release_rows = Vec::new();
    for &(secs, conc) in &[(10u64, 100usize), (30, 250), (10, 500)] {
        println!("failure_release: {secs}s × {conc} …");
        let row = run_failure_release_scenario(secs, conc);
        println!(
            "  ops={} rejects={} unexpected={} panics={} idle={}",
            row.ops_total,
            row.rejected_resource,
            row.unexpected_errors,
            row.panics,
            row.scheduler_idle
        );
        failure_release_rows.push(row);
    }

    let mut overload_queue_rows = Vec::new();
    for &(secs, conc) in &[(10u64, 500usize), (30, 1000)] {
        println!("overload_queue: {secs}s × {conc} …");
        let row = run_overload_queue_scenario(secs, conc);
        println!(
            "  ops={} rejects={} peak_q={} q_ok={} idle={}",
            row.ops_total,
            row.rejected_resource,
            row.peak_queue_depth,
            row.queue_limit_ok,
            row.scheduler_idle
        );
        overload_queue_rows.push(row);
    }

    let all_rows: Vec<&StressScenarioRow> = mixed_rows
        .iter()
        .chain(malformed_rows.iter())
        .chain(failure_release_rows.iter())
        .chain(overload_queue_rows.iter())
        .collect();

    let unexplained_errors: u64 = all_rows.iter().map(|r| r.unexpected_errors).sum();
    let unexplained_panics: u64 = all_rows.iter().map(|r| r.panics).sum();
    let budget_violations: u64 = all_rows.iter().filter(|r| !r.budget_ok).count() as u64;
    let queue_limit_violations: u64 = all_rows.iter().filter(|r| !r.queue_limit_ok).count() as u64;
    let all_idle = all_rows.iter().all(|r| r.scheduler_idle);

    let verdict = if all_idle
        && unexplained_errors == 0
        && unexplained_panics == 0
        && budget_violations == 0
        && queue_limit_violations == 0
    {
        "PASS".into()
    } else {
        format!(
            "FAIL idle={all_idle} unexpected_errors={unexplained_errors} panics={unexplained_panics} budget_violations={budget_violations} queue_limit_violations={queue_limit_violations}"
        )
    };

    StressCampaignSummary {
        host,
        policy,
        mixed_rows,
        malformed_rows,
        failure_release_rows,
        overload_queue_rows,
        all_idle,
        unexplained_errors,
        unexplained_panics,
        budget_violations,
        queue_limit_violations,
        verdict,
    }
}

pub fn write_campaign_outputs(
    root: &Path,
    summary: &StressCampaignSummary,
) -> std::io::Result<()> {
    std::fs::create_dir_all(root)?;
    let json = serde_json::to_string_pretty(summary).unwrap();
    std::fs::write(root.join("summary.json"), json)?;

    write_rows_csv(
        &root.join("mixed-workload.csv"),
        &summary.mixed_rows,
    )?;
    write_rows_csv(
        &root.join("malformed-input.csv"),
        &summary.malformed_rows,
    )?;
    write_rows_csv(
        &root.join("failure-release.csv"),
        &summary.failure_release_rows,
    )?;
    write_rows_csv(
        &root.join("overload-queue.csv"),
        &summary.overload_queue_rows,
    )?;

    let mut all = Vec::new();
    all.extend(summary.mixed_rows.clone());
    all.extend(summary.malformed_rows.clone());
    all.extend(summary.failure_release_rows.clone());
    all.extend(summary.overload_queue_rows.clone());
    write_rows_csv(&root.join("all-scenarios.csv"), &all)?;

    write_human_report(root, summary)?;
    Ok(())
}

fn write_rows_csv(path: &Path, rows: &[StressScenarioRow]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    writeln!(
        f,
        "scenario,duration_secs,concurrency,memory_kib_cfg,ops_total,hashes,verify_valid_ok,verify_wrong_ok,rejected_resource,expected_input_errors,unexpected_errors,panics,throughput_ops_per_sec,latency_samples,p50_ms,p95_ms,p99_ms,mean_ms,max_ms,peak_active_permits,peak_queue_depth,peak_allocated_kib,peak_rss_bytes,cpu_usage_pct,final_active_permits,final_queue_depth,final_allocated_kib,scheduler_idle,budget_ok,queue_limit_ok,notes"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{},{},{:.2},{},{},{},{},{},{},\"{}\"",
            r.scenario,
            r.duration_secs,
            r.concurrency,
            r.memory_kib_cfg,
            r.ops_total,
            r.hashes,
            r.verify_valid_ok,
            r.verify_wrong_ok,
            r.rejected_resource,
            r.expected_input_errors,
            r.unexpected_errors,
            r.panics,
            r.throughput_ops_per_sec,
            r.latency.samples,
            r.latency.p50_ms,
            r.latency.p95_ms,
            r.latency.p99_ms,
            r.latency.mean_ms,
            r.latency.max_ms,
            r.peak_active_permits,
            r.peak_queue_depth,
            r.peak_allocated_kib,
            r.peak_rss_bytes,
            r.cpu_usage_pct,
            r.final_active_permits,
            r.final_queue_depth,
            r.final_allocated_kib,
            r.scheduler_idle,
            r.budget_ok,
            r.queue_limit_ok,
            r.notes.replace('"', "'")
        )?;
    }
    Ok(())
}

fn write_human_report(root: &Path, s: &StressCampaignSummary) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(root.join("stress-report.md"))?;
    writeln!(f, "# Antech KDF production stress report\n")?;
    writeln!(f, "**Verdict:** {}\n", s.verdict)?;
    writeln!(
        f,
        "Host: {} / {} / {} logical CPUs / RAM hint {:?} GiB\n",
        s.host.os, s.host.arch, s.host.logical_cpus, s.host.total_ram_hint_gb
    )?;
    writeln!(
        f,
        "ResourcePolicy (production defaults): max_memory_kib={} max_active_jobs={} queue_limit={}\n",
        s.policy.max_memory_kib, s.policy.max_active_jobs, s.policy.queue_limit
    )?;
    writeln!(
        f,
        "Summary: all_idle={} unexpected_errors={} panics={} budget_violations={} queue_limit_violations={}\n",
        s.all_idle,
        s.unexplained_errors,
        s.unexplained_panics,
        s.budget_violations,
        s.queue_limit_violations
    )?;

    writeln!(f, "## Mixed workload (70% valid verify / 20% wrong verify / 10% hash)\n")?;
    writeln!(
        f,
        "| secs | conc | ops | thrpt/s | p50 ms | p95 ms | p99 ms | rejects | unexpected | panics | peak_active | peak_q | peak_KiB | RSS peak | CPU% | idle | budget | q_ok |"
    )?;
    writeln!(
        f,
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|:---:|"
    )?;
    for r in &s.mixed_rows {
        writeln!(
            f,
            "| {} | {} | {} | {:.2} | {:.1} | {:.1} | {:.1} | {} | {} | {} | {} | {} | {} | {} | {:.1} | {} | {} | {} |",
            r.duration_secs,
            r.concurrency,
            r.ops_total,
            r.throughput_ops_per_sec,
            r.latency.p50_ms,
            r.latency.p95_ms,
            r.latency.p99_ms,
            r.rejected_resource,
            r.unexpected_errors,
            r.panics,
            r.peak_active_permits,
            r.peak_queue_depth,
            r.peak_allocated_kib,
            r.peak_rss_bytes,
            r.cpu_usage_pct,
            r.scheduler_idle,
            r.budget_ok,
            r.queue_limit_ok
        )?;
    }

    writeln!(f, "\n## Malformed input\n")?;
    for r in &s.malformed_rows {
        writeln!(
            f,
            "- {}s×{}: ops={} expected_err={} unexpected={} panics={} idle={}",
            r.duration_secs,
            r.concurrency,
            r.ops_total,
            r.expected_input_errors,
            r.unexpected_errors,
            r.panics,
            r.scheduler_idle
        )?;
    }

    writeln!(f, "\n## Failure / permit release\n")?;
    for r in &s.failure_release_rows {
        writeln!(
            f,
            "- {}s×{}: hashes={} wrong_ok={} rejects={} unexpected={} panics={} idle={}",
            r.duration_secs,
            r.concurrency,
            r.hashes,
            r.verify_wrong_ok,
            r.rejected_resource,
            r.unexpected_errors,
            r.panics,
            r.scheduler_idle
        )?;
    }

    writeln!(f, "\n## Overload / queue_limit enforcement\n")?;
    for r in &s.overload_queue_rows {
        writeln!(
            f,
            "- {}s×{}: rejects={} peak_q={} peak_KiB={} q_ok={} idle={} — {}",
            r.duration_secs,
            r.concurrency,
            r.rejected_resource,
            r.peak_queue_depth,
            r.peak_allocated_kib,
            r.queue_limit_ok,
            r.scheduler_idle,
            r.notes
        )?;
    }

    writeln!(
        f,
        "\n## Notes\n\n- Workload uses production `hash` / `verify` and the process-wide `OnceLock` scheduler.\n- `ResourceExhausted` under overload is counted as `rejected_resource`, not an unexplained error.\n- Peak KDF allocation is sampled from `scheduler_stats().allocated_kib` and must stay ≤ {} KiB.\n- No KDF algorithm, API, hash format, or ResourcePolicy defaults were changed for this campaign.\n",
        DEFAULT_MAX_MEMORY_KIB
    )?;
    Ok(())
}

pub fn default_out_dir() -> PathBuf {
    // Prefer repo-root relative path; fall back if launched from research/code.
    let candidates = [
        PathBuf::from("research/results/stress"),
        PathBuf::from("../results/stress"),
        PathBuf::from("../../research/results/stress"),
    ];
    for c in candidates {
        if let Some(parent) = c.parent() {
            if parent.exists() || c.components().any(|x| x.as_os_str() == "research") {
                return c;
            }
        }
    }
    PathBuf::from("research/results/stress")
}

// --- Process metrics (best-effort, no extra deps) ---

#[cfg(windows)]
fn process_rss_bytes() -> Option<u64> {
    // Working set via PSAPI.
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut core::ffi::c_void,
            ppsmem_counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }
    unsafe {
        let mut pmc = std::mem::zeroed::<ProcessMemoryCounters>();
        pmc.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        let ok = K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut pmc,
            pmc.cb,
        );
        if ok != 0 {
            Some(pmc.working_set_size as u64)
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[derive(Clone, Copy, Default)]
struct CpuTimes {
    busy_ns: u128,
}

#[cfg(windows)]
fn process_cpu_times() -> CpuTimes {
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetProcessTimes(
            process: *mut core::ffi::c_void,
            creation: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
    }
    unsafe {
        let mut creation = 0u64;
        let mut exit = 0u64;
        let mut kernel = 0u64;
        let mut user = 0u64;
        let ok = GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        );
        if ok == 0 {
            return CpuTimes::default();
        }
        // FILETIME is 100-ns units.
        let busy_100ns = kernel.saturating_add(user) as u128;
        CpuTimes {
            busy_ns: busy_100ns.saturating_mul(100),
        }
    }
}

#[cfg(not(windows))]
fn process_cpu_times() -> CpuTimes {
    let raw = std::fs::read_to_string("/proc/self/stat").ok();
    let Some(raw) = raw else {
        return CpuTimes::default();
    };
    // After comm, fields 14 and 15 are utime/stime in clock ticks.
    let after = raw.rsplit(')').next().unwrap_or("");
    let parts: Vec<&str> = after.split_whitespace().collect();
    if parts.len() < 13 {
        return CpuTimes::default();
    }
    let utime: u64 = parts[11].parse().unwrap_or(0);
    let stime: u64 = parts[12].parse().unwrap_or(0);
    let ticks = utime.saturating_add(stime) as u128;
    let tick_ns = 1_000_000_000u128 / 100; // assume USER_HZ=100
    CpuTimes {
        busy_ns: ticks.saturating_mul(tick_ns),
    }
}

fn cpu_usage_pct(start: CpuTimes, wall: Duration) -> f64 {
    let end = process_cpu_times();
    let busy = end.busy_ns.saturating_sub(start.busy_ns) as f64;
    let wall_ns = wall.as_nanos() as f64;
    if wall_ns <= 0.0 {
        return 0.0;
    }
    let cpus = thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0);
    // Percent of one core × cores → 0..100*cpus; normalize to 0..100 of machine.
    ((busy / wall_ns) / cpus) * 100.0
}

fn detect_ram_gb() -> Option<f64> {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct MemoryStatusEx {
            dw_length: u32,
            dw_memory_load: u32,
            ull_total_phys: u64,
            ull_avail_phys: u64,
            ull_total_page_file: u64,
            ull_avail_page_file: u64,
            ull_total_virtual: u64,
            ull_avail_virtual: u64,
            ull_avail_extended_virtual: u64,
        }
        extern "system" {
            fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
        }
        unsafe {
            let mut st = std::mem::zeroed::<MemoryStatusEx>();
            st.dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
            if GlobalMemoryStatusEx(&mut st) != 0 {
                return Some(st.ull_total_phys as f64 / (1024.0 * 1024.0 * 1024.0));
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: f64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb / (1024.0 * 1024.0));
            }
        }
        None
    }
}
