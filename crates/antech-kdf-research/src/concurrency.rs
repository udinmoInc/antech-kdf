//! Defender server login concurrency scaling test suite.

use crate::schema::{ConcurrencyResult, MeasurementSource};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Runs multi-threaded login concurrency tests collecting individual per-request latencies.
pub fn run_concurrency_benchmarks() -> Vec<ConcurrencyResult> {
    let concurrency_levels = [1, 10, 50, 100, 250, 500, 1000];
    let mut results = Vec::new();

    for &concurrency in &concurrency_levels {
        let failures = Arc::new(AtomicUsize::new(0));
        let latencies = Arc::new(Mutex::new(Vec::with_capacity(concurrency)));
        let password = "concurrency_test_password";

        let t_batch_start = Instant::now();

        let mut handles = Vec::with_capacity(concurrency);
        for i in 0..concurrency {
            let fail_counter = Arc::clone(&failures);
            let lat_store = Arc::clone(&latencies);
            let pass = format!("{}_{}", password, i);

            handles.push(thread::spawn(move || {
                let t_req_start = Instant::now();
                let res = antech_kdf::hash(&pass);
                let req_elapsed = t_req_start.elapsed();

                match res {
                    Ok(h) => {
                        if let Ok(valid) = antech_kdf::verify(&pass, &h) {
                            if !valid {
                                fail_counter.fetch_add(1, Ordering::SeqCst);
                            }
                        } else {
                            fail_counter.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Err(_) => {
                        fail_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                if let Ok(mut guard) = lat_store.lock() {
                    guard.push(req_elapsed);
                }
            }));
        }

        for handle in handles {
            let _ = handle.join();
        }

        let wall_clock_batch = t_batch_start.elapsed();
        let total_ops = concurrency as f64;
        let batch_sec = wall_clock_batch.as_secs_f64().max(0.000001);
        let throughput = total_ops / batch_sec;

        let lat_vec = latencies.lock().unwrap();
        let mut millis: Vec<f64> = lat_vec.iter().map(|d: &Duration| d.as_secs_f64() * 1000.0).collect();
        millis.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let len = millis.len();
        let per_req_median = if len > 0 { millis[len / 2] } else { 0.0 };
        let per_req_p95 = if len > 0 { millis[((len as f64 * 0.95) as usize).min(len - 1)] } else { 0.0 };
        let per_req_p99 = if len > 0 { millis[((len as f64 * 0.99) as usize).min(len - 1)] } else { 0.0 };

        let queueing_delay = (per_req_p95 - per_req_median).max(0.0);

        results.push(ConcurrencyResult {
            algorithm: "antech-kdf-placeholder".to_string(),
            concurrent_requests: concurrency,
            total_peak_ram_bytes: 65_536 * (concurrency as u64) * 1024,
            ram_per_request_bytes: 65_536 * 1024,
            per_request_median_ms: per_req_median,
            per_request_p95_ms: per_req_p95,
            per_request_p99_ms: per_req_p99,
            wall_clock_batch_ms: wall_clock_batch.as_secs_f64() * 1000.0,
            throughput_ops_per_sec: throughput,
            queueing_delay_ms: queueing_delay,
            failure_count: failures.load(Ordering::SeqCst),
            latency_classification: MeasurementSource::Measured,
        });
    }

    results
}
