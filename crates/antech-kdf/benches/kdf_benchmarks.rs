//! Criterion Benchmarks for Antech KDF.

use criterion::{criterion_group, criterion_main, Criterion};
use std::thread;

fn bench_single_hash(c: &mut Criterion) {
    c.bench_function("single_hash", |b| {
        b.iter(|| {
            let _ = antech_kdf::hash("bench_password_string");
        })
    });
}

fn bench_single_verify(c: &mut Criterion) {
    let hash_str = antech_kdf::hash("bench_password_string").unwrap();
    c.bench_function("single_verify", |b| {
        b.iter(|| {
            let _ = antech_kdf::verify("bench_password_string", &hash_str);
        })
    });
}

fn bench_concurrency(c: &mut Criterion) {
    let concurrency_levels = [1, 10, 50, 100, 500, 1000];

    for &concurrency in &concurrency_levels {
        c.bench_function(&format!("concurrency_{}_threads", concurrency), |b| {
            b.iter(|| {
                let mut handles = Vec::with_capacity(concurrency);
                for i in 0..concurrency {
                    handles.push(thread::spawn(move || {
                        let pass = format!("password_{}", i);
                        let h = antech_kdf::hash(&pass).unwrap();
                        let _ = antech_kdf::verify(&pass, &h);
                    }));
                }
                for handle in handles {
                    handle.join().unwrap();
                }
            });
        });
    }
}

criterion_group!(benches, bench_single_hash, bench_single_verify, bench_concurrency);
criterion_main!(benches);
