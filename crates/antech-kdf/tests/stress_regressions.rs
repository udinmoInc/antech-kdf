//! Stress-derived regressions: admission, malformed input, permit release, idle.

mod common;

use antech_kdf::{hash, hash_with_config, verify, AntechConfig, Error};
use antech_kdf_core::scheduler_stats;
use common::{scheduler_test_guard, wait_scheduler_idle};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn malformed_verify_never_leaves_scheduler_busy() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    let junk = [
        "",
        "$antech$",
        "$antech$v1$m=1$a$b",
        "$antech$v2$not-valid",
        &format!("$antech$v2${}", "A".repeat(4000)),
    ];
    for enc in junk {
        let _ = verify(b"password", enc);
    }
    // Invalid config must fail before admission.
    assert!(AntechConfig::builder().memory_kib(1).build().is_err());
    assert!(AntechConfig::builder().salt_length(1).build().is_err());

    wait_scheduler_idle(Duration::from_secs(10));
    let st = scheduler_stats();
    assert_eq!(st.active_jobs, 0);
    assert_eq!(st.waiting_jobs, 0);
    assert_eq!(st.allocated_kib, 0);
}

#[test]
fn wrong_password_and_resource_errors_release_permits() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    let encoded = hash("release_seed").expect("hash");
    assert!(!verify(b"wrong", &encoded).expect("verify wrong"));

    // Burst concurrent ops; ResourceExhausted is acceptable under default budget.
    let done = Arc::new(AtomicU64::new(0));
    let rejects = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for i in 0..64 {
        let done = Arc::clone(&done);
        let rejects = Arc::clone(&rejects);
        let encoded = encoded.clone();
        handles.push(thread::spawn(move || {
            let pw = format!("burst_{i}");
            match hash(&pw) {
                Ok(h) => {
                    let _ = verify(&pw, &h);
                    done.fetch_add(1, Ordering::Relaxed);
                }
                Err(Error::ResourceExhausted(_)) => {
                    rejects.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => panic!("unexpected: {e}"),
            }
            match verify(b"nope", &encoded) {
                Ok(false) => {}
                Ok(true) => panic!("wrong password accepted"),
                Err(Error::ResourceExhausted(_)) => {
                    rejects.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => panic!("unexpected verify err: {e}"),
            }
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    assert!(done.load(Ordering::Relaxed) + rejects.load(Ordering::Relaxed) >= 64);
    wait_scheduler_idle(Duration::from_secs(30));
    let st = scheduler_stats();
    assert_eq!(st.active_jobs, 0);
    assert_eq!(st.waiting_jobs, 0);
    assert_eq!(st.allocated_kib, 0);
}

#[test]
fn overload_respects_memory_budget_and_returns_idle() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    let peak_alloc = Arc::new(AtomicU64::new(0));
    let peak_waiting = Arc::new(AtomicU64::new(0));
    let rejects = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mon_stop = Arc::clone(&stop);
    let peak_alloc_m = Arc::clone(&peak_alloc);
    let peak_waiting_m = Arc::clone(&peak_waiting);
    let monitor = thread::spawn(move || {
        while !mon_stop.load(Ordering::Relaxed) {
            let st = scheduler_stats();
            peak_alloc_m.fetch_max(st.allocated_kib as u64, Ordering::Relaxed);
            peak_waiting_m.fetch_max(st.waiting_jobs as u64, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut handles = Vec::new();
    // Need workers > max_active(~8) + queue_limit(256) to observe ResourceExhausted.
    for i in 0..320 {
        let rejects = Arc::clone(&rejects);
        handles.push(thread::spawn(move || {
            let pw = format!("ov_{i}");
            match hash(&pw) {
                Ok(_) => {}
                Err(Error::ResourceExhausted(_)) => {
                    rejects.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => panic!("unexpected: {e}"),
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    monitor.join().unwrap();

    assert!(
        rejects.load(Ordering::Relaxed) > 0,
        "expected ResourceExhausted when workers exceed active+queue_limit"
    );
    assert!(
        peak_alloc.load(Ordering::Relaxed) <= 131_072,
        "KDF allocation exceeded 128 MiB budget: {}",
        peak_alloc.load(Ordering::Relaxed)
    );
    assert!(
        peak_waiting.load(Ordering::Relaxed) <= 256,
        "queue_limit exceeded: {}",
        peak_waiting.load(Ordering::Relaxed)
    );
    wait_scheduler_idle(Duration::from_secs(60));
}

#[test]
fn concurrent_hash_verify_mixed_ratio_idle() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    let encoded = hash("mix_ratio_seed").unwrap();
    let ok = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for t in 0..100 {
        let enc = encoded.clone();
        let ok = Arc::clone(&ok);
        handles.push(thread::spawn(move || {
            let lane = t % 10;
            if lane < 7 {
                assert!(verify("mix_ratio_seed", &enc).unwrap_or(false));
                ok.fetch_add(1, Ordering::Relaxed);
            } else if lane < 9 {
                assert!(!verify("wrong", &enc).unwrap_or(true));
                ok.fetch_add(1, Ordering::Relaxed);
            } else {
                let pw = format!("mix_new_{t}");
                match hash(&pw) {
                    Ok(h) => {
                        assert!(verify(&pw, &h).unwrap_or(false));
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(Error::ResourceExhausted(_)) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(ok.load(Ordering::Relaxed), 100);
    wait_scheduler_idle(Duration::from_secs(30));
}

#[test]
fn oversize_memory_config_fails_fast_not_deadlock() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    // Valid AntechConfig may request more KiB than the host ResourcePolicy ceiling.
    let cfg = AntechConfig::builder()
        .memory_kib(256 * 1024) // 256 MiB config; host ceiling is 128 MiB
        .build()
        .expect("config allows up to 1 GiB");
    let start = Instant::now();
    let err = hash_with_config(b"x", &cfg).expect_err("must reject");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "oversize request deadlocked/waited too long: {:?}",
        start.elapsed()
    );
    assert!(matches!(err, Error::ResourceExhausted(_)), "{err}");
    wait_scheduler_idle(Duration::from_secs(5));
}

#[test]
fn invalid_config_hash_does_not_consume_permit() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));
    let before = scheduler_stats();
    assert!(AntechConfig::builder().memory_kib(1023).build().is_err());
    // Builder rejects invalid memory before any hash/admission path runs.
    let after = scheduler_stats();
    assert_eq!(before.active_jobs, after.active_jobs);
    assert_eq!(before.waiting_jobs, after.waiting_jobs);
    assert_eq!(before.allocated_kib, after.allocated_kib);
}
