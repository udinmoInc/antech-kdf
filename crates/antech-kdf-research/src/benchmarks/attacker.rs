//! Attacker benchmark exporter.

use crate::attackers::{run_cpu_attacker_benchmark, run_gpu_attacker_benchmark};
use std::path::Path;

pub fn run_attacker_benchmarks(target_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cpu_recs = run_cpu_attacker_benchmark();
    let mut wtr_cpu = csv::Writer::from_path(target_dir.join("attacker.csv"))?;
    for c in &cpu_recs {
        wtr_cpu.serialize(c)?;
    }
    wtr_cpu.flush()?;

    let gpu_recs = run_gpu_attacker_benchmark();
    let mut wtr_gpu = csv::Writer::from_path(target_dir.join("gpu-attacker.csv"))?;
    for g in &gpu_recs {
        wtr_gpu.serialize(g)?;
    }
    wtr_gpu.flush()?;

    Ok(())
}
