//! Shared research utilities for compute-memory campaigns.
//!
//! Historical v2 engines were archived under `research/archive/code/compute-memory-v2/`.
//! Canonical digests come from `antech_kdf_core::AntechEngine` only.

pub mod config;
pub mod cpu_head_to_head;
pub mod cuda;

pub use config::ComputeMemoryConfig;
pub use cpu_head_to_head::run_cpu_head_to_head;
