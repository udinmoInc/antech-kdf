//! Concurrent hash/verify and scheduler idle invariants.

mod common;

use antech_kdf::{hash, verify};
use common::{scheduler_test_guard, wait_scheduler_idle};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn concurrent_hash_verify_scheduler_idle() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    let ok = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for i in 0..32 {
        let ok = Arc::clone(&ok);
        handles.push(thread::spawn(move || {
            let pw = format!("worker_{i}");
            let h = hash(&pw).expect("hash");
            if verify(&pw, &h).expect("verify") {
                ok.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread join");
    }
    assert_eq!(ok.load(Ordering::Relaxed), 32);
    wait_scheduler_idle(Duration::from_secs(30));
}

#[test]
fn concurrent_mixed_workload() {
    let _guard = scheduler_test_guard();
    wait_scheduler_idle(Duration::from_secs(5));

    let encoded = hash("seed").unwrap();
    let mut handles = Vec::new();
    for t in 0..50 {
        let enc = encoded.clone();
        handles.push(thread::spawn(move || {
            if t % 3 == 0 {
                let pw = format!("mix_{t}");
                let h = hash(&pw).unwrap();
                assert!(verify(&pw, &h).unwrap());
            } else {
                assert!(verify("seed", &enc).unwrap());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    wait_scheduler_idle(Duration::from_secs(30));
}
