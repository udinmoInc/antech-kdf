//! Rehash policy comparing stored parameters against an application target.

use crate::config::{AntechConfig, FanIn, MemorySize, OutputLength};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RehashPolicy {
    pub minimum_memory: MemorySize,
    pub preferred_memory: MemorySize,
    pub preferred_fan_in: FanIn,
    pub preferred_output_length: OutputLength,
    pub preferred_secret_required: bool,
    pub preferred_associated_data: bool,
}

impl Default for RehashPolicy {
    fn default() -> Self {
        Self {
            minimum_memory: MemorySize::mib(16),
            preferred_memory: MemorySize::mib(16),
            preferred_fan_in: FanIn::new(2),
            preferred_output_length: OutputLength::bytes(32),
            preferred_secret_required: false,
            preferred_associated_data: false,
        }
    }
}

impl RehashPolicy {
    pub fn builder() -> RehashPolicyBuilder {
        RehashPolicyBuilder::default()
    }

    /// Returns true when stored parameters are below this policy's targets.
    ///
    /// Does not inspect or compare any secret material — only public flags on the config.
    pub fn needs_rehash(&self, config: &AntechConfig) -> bool {
        config.memory.as_kib() < self.minimum_memory.as_kib()
            || config.memory.as_kib() < self.preferred_memory.as_kib()
            || config.fan_in.get() < self.preferred_fan_in.get()
            || config.output_length.as_bytes() < self.preferred_output_length.as_bytes()
            || (self.preferred_secret_required && !config.secret_required)
            || (self.preferred_associated_data && config.associated_data_length.is_none())
    }
}

/// Builder for [`RehashPolicy`].
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

    pub fn preferred_fan_in(mut self, fan_in: u32) -> Self {
        self.policy.preferred_fan_in = FanIn::new(fan_in);
        self
    }

    pub fn preferred_output_length(mut self, bytes: usize) -> Self {
        self.policy.preferred_output_length = OutputLength::bytes(bytes);
        self
    }

    pub fn preferred_secret_required(mut self, required: bool) -> Self {
        self.policy.preferred_secret_required = required;
        self
    }

    pub fn preferred_associated_data(mut self, required: bool) -> Self {
        self.policy.preferred_associated_data = required;
        self
    }

    pub fn build(self) -> RehashPolicy {
        self.policy
    }
}
