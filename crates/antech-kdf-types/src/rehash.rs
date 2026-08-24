//! Rehash Policy configuration for checking stored password hash freshness.

use crate::config::{AntechConfig, MemorySize, Parallelism, PassCount};

/// Policy specification used by `needs_rehash_with_policy` to evaluate stored password hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RehashPolicy {
    pub minimum_memory: MemorySize,
    pub preferred_memory: MemorySize,
    pub preferred_passes: PassCount,
    pub preferred_parallelism: Parallelism,
}

impl Default for RehashPolicy {
    fn default() -> Self {
        Self {
            minimum_memory: MemorySize::mib(16),
            preferred_memory: MemorySize::mib(16),
            preferred_passes: PassCount::new(1),
            preferred_parallelism: Parallelism::new(1),
        }
    }
}

impl RehashPolicy {
    pub fn builder() -> RehashPolicyBuilder {
        RehashPolicyBuilder::default()
    }

    /// Evaluate whether a target configuration satisfies this rehash policy.
    pub fn needs_rehash(&self, config: &AntechConfig) -> bool {
        config.memory.as_kib() < self.minimum_memory.as_kib()
            || config.memory.as_kib() < self.preferred_memory.as_kib()
            || config.passes.get() < self.preferred_passes.get()
            || config.parallelism.get() < self.preferred_parallelism.get()
    }
}

/// Builder pattern for `RehashPolicy`.
#[derive(Debug, Clone, Default)]
pub struct RehashPolicyBuilder {
    policy: RehashPolicy,
}

impl RehashPolicyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn minimum_memory_mib(mut self, mib: usize) -> Self {
        self.policy.minimum_memory = MemorySize::mib(mib);
        self
    }

    pub fn preferred_memory_mib(mut self, mib: usize) -> Self {
        self.policy.preferred_memory = MemorySize::mib(mib);
        self
    }

    pub fn preferred_passes(mut self, passes: u32) -> Self {
        self.policy.preferred_passes = PassCount::new(passes);
        self
    }

    pub fn preferred_parallelism(mut self, lanes: u32) -> Self {
        self.policy.preferred_parallelism = Parallelism::new(lanes);
        self
    }

    pub fn build(self) -> RehashPolicy {
        self.policy
    }
}
