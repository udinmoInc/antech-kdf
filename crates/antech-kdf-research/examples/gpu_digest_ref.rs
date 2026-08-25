//! Write CPU reference digests for GPU correctness under attacker-optimization output dir.

use antech_kdf_research::compute_memory_v4::{ComputeMemoryV4Config, GraphKind, V4Engine};
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = "research/results/compute-memory-v4/attacker-optimization";
    std::fs::create_dir_all(out)?;
    let eng = V4Engine::new(GraphKind::CombinedFrontier);
    let cfg = ComputeMemoryV4Config::default()
        .with_memory_mib(16)
        .with_graph(GraphKind::CombinedFrontier);
    let salt = b"v4_gpu_correct_salt";
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let mut f = File::create(format!("{out}/cpu_digests.txt"))?;
    for i in 0..n {
        let pw = format!("v4c_gpu_vector_{:02}", i);
        let d = eng.derive_cfg(pw.as_bytes(), salt, &cfg)?;
        let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
        writeln!(f, "{} {}", pw, hex)?;
    }
    println!("Wrote {n} CPU digests to {out}/cpu_digests.txt");
    Ok(())
}
