//! Shared helpers for scheduler-sensitive integration tests.

use antech_kdf_core::scheduler_stats;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// Serialize tests that assert on process-wide scheduler state.
pub static SCHEDULER_TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn scheduler_test_guard() -> std::sync::MutexGuard<'static, ()> {
    SCHEDULER_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Poll until the global scheduler has no active or waiting jobs.
pub fn wait_scheduler_idle(timeout: Duration) {
    let start = Instant::now();
    loop {
        let st = scheduler_stats();
        if st.active_jobs == 0 && st.waiting_jobs == 0 {
            return;
        }
        if start.elapsed() >= timeout {
            panic!("scheduler not idle after {timeout:?}: {st:?}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
