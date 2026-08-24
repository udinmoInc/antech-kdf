//! Phase E Cost-Asymmetric Low-Resource KDF research candidates.

pub mod cand_e1;
pub mod cand_e2;
pub mod cand_e3;
pub mod cand_e4;
pub mod cand_e5;
pub mod cand_e6;

use serde::{Deserialize, Serialize};

/// Parameters for Phase E cost-asymmetric research candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseEParams {
    pub working_set_bytes: usize,
    pub dependency_depth: u64,
    pub server_secret: Option<Vec<u8>>,
    pub is_correct_password_scenario: bool,
}

impl Default for PhaseEParams {
    fn default() -> Self {
        Self {
            working_set_bytes: 16 * 1024 * 1024, // 16 MiB
            dependency_depth: 150,
            server_secret: Some(b"antech_research_server_secret_key_32b!".to_vec()),
            is_correct_password_scenario: true,
        }
    }
}

/// Trait for Phase E cost-asymmetric KDF candidate algorithms.
pub trait PhaseEKdf: Sync + Send {
    fn name(&self) -> &'static str;
    fn family(&self) -> &'static str;
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &PhaseEParams,
    ) -> Result<Vec<u8>, String>;
}
