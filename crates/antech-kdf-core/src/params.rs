//! Internal KDF parameter definitions and defaults.

use crate::error::CoreError;
use antech_kdf_types::AlgorithmVersion;

/// Internal parameters configuring memory, iterations, parallelism, and target bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalParams {
    /// Memory working set in KiB.
    pub memory_kib: u32,
    /// Number of sequential time passes / iterations.
    pub time_cost: u32,
    /// Parallel execution lanes.
    pub parallelism: u32,
    /// Simulated/Target memory bandwidth throughput (MB/s).
    pub bandwidth_target: u64,
}

impl InternalParams {
    /// Recommended default parameters for current production version.
    pub fn current_parameters() -> Self {
        Self {
            memory_kib: 65536,    // 64 MiB low-RAM footprint
            time_cost: 3,         // 3 iterations
            parallelism: 1,       // Single-lane sequential execution
            bandwidth_target: 100,// 100 MB/s sustained churn target
        }
    }

    /// Alias for current recommended profile.
    pub fn recommended_parameters() -> Self {
        Self::current_parameters()
    }

    /// Retrieve recommended parameters for a given algorithm version.
    pub fn parameters_for_version(version: AlgorithmVersion) -> Result<Self, CoreError> {
        match version {
            AlgorithmVersion::V1 => Ok(Self::current_parameters()),
        }
    }

    /// Validates whether parameter boundaries are safe.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.memory_kib < 1 || self.time_cost < 1 || self.parallelism < 1 {
            return Err(CoreError::InvalidParameters);
        }
        Ok(())
    }
}
