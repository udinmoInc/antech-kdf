//! Research candidate implementations for Phase C Bandwidth-Hard Password KDF research.

pub mod cand_001;
pub mod cand_002;
pub mod cand_003;
pub mod cand_004;
pub mod cand_005;
pub mod cand_006;
pub mod cand_007;
pub mod cand_008;

use serde::{Deserialize, Serialize};

/// Experimental candidate parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentalParams {
    pub working_set_bytes: usize,
    pub rounds: u64,
    pub dependency_depth: u64,
    pub churn_factor: u64,
}

impl Default for ExperimentalParams {
    fn default() -> Self {
        Self {
            working_set_bytes: 16 * 1024 * 1024, // 16 MiB
            rounds: 4,
            dependency_depth: 100,
            churn_factor: 16,
        }
    }
}

/// Core trait for experimental research KDF candidate algorithms.
pub trait ExperimentalKdf: Sync + Send {
    fn name(&self) -> &'static str;
    fn family(&self) -> &'static str;
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String>;
}
