use antech_kdf::{hash_with_config_and_salt, AntechConfig, GraphKind};
use antech_kdf_research::compute_memory_v4::attacker_opt::{derive_packed_noring, PackedScratch};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn pct(s: &mut [f64], p: f64) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((p / 100.0) * (s.len() as f64 - 1.0)).round() as usize;
    s[i.min(s.len() - 1)]
}

fn main() {
    let cfg = AntechConfig::builder().memory_mib(16).graph(GraphKind::CombinedFrontier).build().unwrap();
    let salt = b"v5_cost_salt_16b";
    let mut ds = Vec::new();
    for i in 0..36 {
        let t0 = Instant::now();
        let _ = hash_with_config_and_salt(format!("d{i}").as_bytes(), salt, &cfg).unwrap();
        ds.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    println!("prod def p50={:.1} p95={:.1} p99={:.1}", pct(&mut ds.clone(), 50.), pct(&mut ds.clone(), 95.), pct(&mut ds, 99.));
    let window = Duration::from_millis(1200);
    let warmup = Duration::from_millis(300);
    for &threads in &[1usize, 8, 16, 32] {
        { let mut sc = PackedScratch::new(); let end = Instant::now()+warmup; let mut i=0u64; while Instant::now()<end { let _=derive_packed_noring(format!("w{i}").as_bytes(), salt, &cfg, &mut sc); i+=1; } }
        let c = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicU64::new(0));
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for t in 0..threads {
                let c=Arc::clone(&c); let stop=Arc::clone(&stop); let cfg=cfg;
                s.spawn(move || {
                    let mut sc = PackedScratch::new(); let mut i=t as u64;
                    while stop.load(Ordering::Relaxed)==0 {
                        let _=derive_packed_noring(format!("a{i}").as_bytes(), salt, &cfg, &mut sc);
                        c.fetch_add(1, Ordering::Relaxed); i += threads as u64;
                    }
                });
            }
            std::thread::sleep(window); stop.store(1, Ordering::Relaxed);
        });
        println!("noring T={threads} gps={:.2}", c.load(Ordering::Relaxed) as f64 / t0.elapsed().as_secs_f64());
    }
}
