use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = Path::new("research/results/compute-memory");
    println!("Running Antech KDF Compute/Memory Research Benchmark Suite...");
    antech_kdf_research::compute_memory::run_compute_memory_suite(target)?;
    println!("Research benchmark suite completed successfully!");
    Ok(())
}
