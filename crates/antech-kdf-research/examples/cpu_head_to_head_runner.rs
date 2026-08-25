use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = Path::new("research/results/compute-memory");
    println!("CPU-only head-to-head: Antech Compute-Memory v2 vs Argon2id");
    println!("No CUDA / GPU. Thread counts: 1, 2, 4, 8, 16, 32");
    antech_kdf_research::compute_memory::run_cpu_head_to_head(target)?;
    println!("Wrote:");
    println!("  research/results/compute-memory/cpu-head-to-head.csv");
    println!("  research/results/compute-memory/defender-scaling.csv");
    println!("  research/results/compute-memory/attacker-scaling.csv");
    println!("  research/results/compute-memory/cpu-head-to-head.md");
    Ok(())
}
