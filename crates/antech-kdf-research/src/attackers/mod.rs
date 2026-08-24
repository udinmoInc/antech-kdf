//! Attacker benchmarks and hardware evaluation frameworks.

pub mod cpu;
pub mod cuda;

pub use cpu::{run_cpu_attacker_benchmark, CpuAttackerRecord};
pub use cuda::{run_gpu_attacker_benchmark, GpuAttackerRecord};
