//! Phase H submodules: Resource Controller, Concurrency, Contention, GPU Attacker, Cryptographic Hardening & Pareto Analysis.

pub mod concurrency;
pub mod contention;
pub mod cpu_attacker;
pub mod crypto_analysis;
pub mod gpu_attacker;
pub mod multitarget;
pub mod pareto;
pub mod resource_controller;
pub mod tmto;

use serde::{Deserialize, Serialize};

/// Budget profiles for 1-core / 1-GB tiny server research.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerBudgetProfile {
    pub name: String,
    pub server_ram_mb: usize,
    pub max_kdf_memory_budget_mb: usize,
    pub max_active_slots: usize,
}

impl ServerBudgetProfile {
    pub fn profile_a() -> Self {
        Self {
            name: "Profile A (64MB Budget)".to_string(),
            server_ram_mb: 1024,
            max_kdf_memory_budget_mb: 64,
            max_active_slots: 4, // 4 x 16MB = 64MB
        }
    }

    pub fn profile_b() -> Self {
        Self {
            name: "Profile B (128MB Budget)".to_string(),
            server_ram_mb: 1024,
            max_kdf_memory_budget_mb: 128,
            max_active_slots: 8, // 8 x 16MB = 128MB
        }
    }

    pub fn profile_c() -> Self {
        Self {
            name: "Profile C (192MB Budget)".to_string(),
            server_ram_mb: 1024,
            max_kdf_memory_budget_mb: 192,
            max_active_slots: 12, // 12 x 16MB = 192MB
        }
    }
}
