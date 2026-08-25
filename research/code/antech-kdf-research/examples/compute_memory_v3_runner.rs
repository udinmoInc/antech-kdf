use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = Path::new("research/results/compute-memory-v3");
    println!("Compute-Memory v3 — graph variants (CPU attacker scaling)");
    antech_kdf_research::compute_memory_v3::run_compute_memory_v3_suite(target)?;
    println!("Results written to research/results/compute-memory-v3/");
    Ok(())
}
