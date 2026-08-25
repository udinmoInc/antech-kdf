//! Measured multi-target amortization against canonical Antech (independent salts).

use crate::compute_memory_v4::attacker_opt::{derive_packed_prefetch, PackedScratch};
use antech_kdf_core::engine::AntechEngine;
use antech_kdf_types::{AntechConfig, GraphKind};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultitargetEngRow {
    pub targets: u64,
    pub memory_mib: usize,
    pub strategy: String,
    pub total_secs: f64,
    pub sec_per_hash: f64,
    pub gps: f64,
    pub shared_dag_work: bool,
    pub kind: String,
    pub notes: String,
}

fn cfg_mib(mib: usize) -> AntechConfig {
    AntechConfig::builder()
        .memory_mib(mib)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap()
}

/// For large target counts use 1 MiB config so the campaign finishes; 16 MiB for small sets.
pub fn run_multitarget_campaign() -> Vec<MultitargetEngRow> {
    let mut rows = Vec::new();
    // 16 MiB: 1, 10 (full strength)
    for &n in &[1u64, 10] {
        rows.push(measure_targets(n, 16, "packed_prefetch"));
        rows.push(measure_targets(n, 16, "production_engine"));
    }
    // 1 MiB: 100, 1000 (and optionally larger with engine-only for speed notes)
    for &n in &[100u64, 1000] {
        rows.push(measure_targets_kib(n, 1024, "production_engine"));
    }
    // Modeled extrapolation for 100K / 1M (no shared DAG — seed binds password)
    for &n in &[100_000u64, 1_000_000] {
        let base = rows
            .iter()
            .find(|r| r.targets == 1000 && r.strategy == "production_engine")
            .map(|r| r.sec_per_hash)
            .unwrap_or(0.01);
        rows.push(MultitargetEngRow {
            targets: n,
            memory_mib: 1,
            strategy: "production_engine".into(),
            total_secs: base * n as f64,
            sec_per_hash: base,
            gps: 1.0 / base.max(1e-12),
            shared_dag_work: false,
            kind: "MODELED".into(),
            notes: "Linear extrapolation; seed binds password+salt — no cross-target DAG reuse observed at smaller N".into(),
        });
    }
    rows
}

fn measure_targets(n: u64, mib: usize, strategy: &str) -> MultitargetEngRow {
    let cfg = cfg_mib(mib);
    let t0 = Instant::now();
    let mut scratch = PackedScratch::new();
    for i in 0..n {
        let pw = format!("mt_eng_{i}");
        let salt = format!("salt_mt_{i:016}");
        let salt_b = salt.as_bytes();
        match strategy {
            "packed_prefetch" if mib == 16 => {
                let _ = derive_packed_prefetch(pw.as_bytes(), salt_b, &cfg, &mut scratch);
            }
            _ => {
                let _ = AntechEngine::new().derive(pw.as_bytes(), salt_b, &cfg);
            }
        }
    }
    let secs = t0.elapsed().as_secs_f64().max(1e-12);
    MultitargetEngRow {
        targets: n,
        memory_mib: mib,
        strategy: strategy.into(),
        total_secs: secs,
        sec_per_hash: secs / n as f64,
        gps: n as f64 / secs,
        shared_dag_work: false,
        kind: "MEASURED".into(),
        notes: "Independent password+salt per target; buffer reuse only".into(),
    }
}

fn measure_targets_kib(n: u64, kib: usize, strategy: &str) -> MultitargetEngRow {
    let cfg = AntechConfig::builder()
        .memory_kib(kib)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    let t0 = Instant::now();
    for i in 0..n {
        let pw = format!("mt_eng_{i}");
        let salt = format!("salt_mt_{i:016}");
        let _ = AntechEngine::new().derive(pw.as_bytes(), salt.as_bytes(), &cfg);
    }
    let secs = t0.elapsed().as_secs_f64().max(1e-12);
    MultitargetEngRow {
        targets: n,
        memory_mib: kib / 1024,
        strategy: strategy.into(),
        total_secs: secs,
        sec_per_hash: secs / n as f64,
        gps: n as f64 / secs,
        shared_dag_work: false,
        kind: "MEASURED".into(),
        notes: format!("1 MiB probe for large N; strategy={strategy}"),
    }
}
