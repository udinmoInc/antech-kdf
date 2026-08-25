use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = Path::new("research/results/compute-memory-v4");
    println!("Compute-Memory v4 — optimized narrow frontier");
    antech_kdf_research::compute_memory_v4::run_compute_memory_v4_suite(target)?;
    println!("Results written to research/results/compute-memory-v4/");
    Ok(())
}
