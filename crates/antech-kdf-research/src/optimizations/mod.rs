//! Candidate 004 optimization research variants for Phase D.

pub mod baseline;
pub mod opt_001;
pub mod opt_002;
pub mod opt_003;
pub mod opt_004;

use serde::{Deserialize, Serialize};

/// Research optimization parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptParams {
    pub working_set_bytes: usize,
    pub rounds: u64,
    pub dependency_depth: u64,
    pub churn_factor: u64,
}

impl Default for OptParams {
    fn default() -> Self {
        Self {
            working_set_bytes: 16 * 1024 * 1024, // 16 MiB
            rounds: 4,
            dependency_depth: 200,
            churn_factor: 16,
        }
    }
}

/// Trait for Candidate 004 optimization research variants.
pub trait Candidate004Variant: Sync + Send {
    fn variant_id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &OptParams,
    ) -> Result<Vec<u8>, String>;
}
