//! KDF internal parameters and profile presets.

use crate::error::CoreError;
use antech_kdf_types::AlgorithmVersion;

/// Internal parameters configuring memory, iterations, parallelism, and bandwidth targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub bandwidth_target: u64,
}

impl InternalParams {
    pub fn current_parameters() -> Self {
        Self {
            memory_kib: 16384,     // 16 MiB working memory
            time_cost: 3,          // Pass count
            parallelism: 1,        // Single-lane sequential execution
            bandwidth_target: 100, // 100 MB/s churn target
        }
    }

    pub fn parameters_for_version(version: AlgorithmVersion) -> Result<Self, CoreError> {
        match version {
            AlgorithmVersion::V1 => Ok(Self::current_parameters()),
        }
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        if self.memory_kib < 1 || self.time_cost < 1 || self.parallelism < 1 {
            return Err(CoreError::InvalidParameters);
        }
        Ok(())
    }
}
