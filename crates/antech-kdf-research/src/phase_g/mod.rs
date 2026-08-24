//! Phase G Candidate-004 Attacker-Cost Equalization module.

use crate::phase_f::ResearchParams;
use serde::{Deserialize, Serialize};

/// Equalization parameter sweep candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqualizationConfig {
    pub label: String,
    pub memory_kib: u32,
    pub dependency_depth: u32,
    pub passes: u32,
}

impl EqualizationConfig {
    pub fn to_research_params(&self) -> ResearchParams {
        ResearchParams {
            memory_kib: self.memory_kib,
            passes: self.passes,
            dependency_depth: self.dependency_depth,
            block_size: 32,
        }
    }
}
