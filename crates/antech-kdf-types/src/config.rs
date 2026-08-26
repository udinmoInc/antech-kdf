//! Structural configuration for the canonical Antech construction.
//!
//! Work is derived from `memory / block_size`. There is no iteration-count or
//! dependency-depth security knob.

use crate::algorithm::{Algorithm, GraphKind};
use crate::errors::ConfigError;

/// Protocol constants for the compute-memory construction.
pub const FRONTIER_WIDTH: usize = 64;
pub const TILE_BLOCKS: usize = FRONTIER_WIDTH * 8;
pub const MIX_ROUNDS: u32 = 4;

/// Working memory allocation size in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemorySize(pub usize);

impl MemorySize {
    pub const MIN_KIB: usize = 1024;
    pub const MAX_KIB: usize = 1_048_576;

    pub fn mib(mib: usize) -> Self {
        Self(mib.saturating_mul(1024))
    }

    pub fn kib(kib: usize) -> Self {
        Self(kib)
    }

    pub fn as_kib(&self) -> usize {
        self.0
    }

    pub fn as_mib(&self) -> usize {
        self.0 / 1024
    }

    pub fn as_bytes(&self) -> usize {
        self.0.saturating_mul(1024)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < Self::MIN_KIB || self.0 > Self::MAX_KIB {
            Err(ConfigError::InvalidMemorySize {
                kib: self.0,
                min_kib: Self::MIN_KIB,
                max_kib: Self::MAX_KIB,
            })
        } else {
            Ok(())
        }
    }
}

/// Salt length in bytes (8..=256).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SaltLength(pub usize);

impl SaltLength {
    pub const MIN_BYTES: usize = 8;
    pub const MAX_BYTES: usize = 256;

    pub fn bytes(len: usize) -> Self {
        Self(len)
    }

    pub fn as_bytes(&self) -> usize {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < Self::MIN_BYTES || self.0 > Self::MAX_BYTES {
            Err(ConfigError::InvalidSaltLength {
                len: self.0,
                min: Self::MIN_BYTES,
                max: Self::MAX_BYTES,
            })
        } else {
            Ok(())
        }
    }
}

/// Memory block size in bytes. Must be a power of two in **16..=64**
/// (matches the production engine stack scratch limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockSize(pub usize);

impl BlockSize {
    pub const MIN_BYTES: usize = 16;
    /// Production engine scratch arrays are sized to this limit.
    pub const MAX_BYTES: usize = 64;

    pub fn bytes(size: usize) -> Self {
        Self(size)
    }

    pub fn as_bytes(&self) -> usize {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < Self::MIN_BYTES || self.0 > Self::MAX_BYTES || !self.0.is_power_of_two() {
            Err(ConfigError::InvalidBlockSize { size: self.0 })
        } else {
            Ok(())
        }
    }
}

/// Parent fan-in mixed into each DAG node (2..=8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FanIn(pub u32);

impl FanIn {
    pub const MIN: u32 = 2;
    pub const MAX: u32 = 8;

    pub fn new(fan_in: u32) -> Self {
        Self(fan_in)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < Self::MIN || self.0 > Self::MAX {
            Err(ConfigError::InvalidFanIn { fan_in: self.0 })
        } else {
            Ok(())
        }
    }
}

/// Output digest length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutputLength(pub usize);

impl OutputLength {
    pub const MIN_BYTES: usize = 8;
    pub const MAX_BYTES: usize = 128;

    pub fn bytes(len: usize) -> Self {
        Self(len)
    }

    pub fn as_bytes(&self) -> usize {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < Self::MIN_BYTES || self.0 > Self::MAX_BYTES {
            Err(ConfigError::InvalidOutputLength {
                len: self.0,
                min: Self::MIN_BYTES,
                max: Self::MAX_BYTES,
            })
        } else {
            Ok(())
        }
    }
}

/// Canonical hashing configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AntechConfig {
    pub algorithm: Algorithm,
    pub memory: MemorySize,
    pub salt_length: SaltLength,
    pub block_size: BlockSize,
    pub fan_in: FanIn,
    pub graph: GraphKind,
    pub output_length: OutputLength,
}

impl Default for AntechConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Antech,
            memory: MemorySize::mib(16),
            salt_length: SaltLength::bytes(16),
            block_size: BlockSize::bytes(32),
            fan_in: FanIn::new(2),
            graph: GraphKind::CombinedFrontier,
            output_length: OutputLength::bytes(32),
        }
    }
}

impl AntechConfig {
    pub fn builder() -> AntechConfigBuilder {
        AntechConfigBuilder::default()
    }

    pub fn num_blocks(&self) -> usize {
        self.memory.as_bytes() / self.block_size.as_bytes().max(1)
    }

    /// Critical-node period derived from frontier width (not a user work knob).
    pub fn critical_period(&self) -> usize {
        (FRONTIER_WIDTH / 16).max(2)
    }

    /// Tile length in blocks for locality variants.
    pub fn tile_len(&self) -> usize {
        TILE_BLOCKS.min(self.num_blocks().max(1))
    }

    pub fn with_memory_mib(mut self, mib: usize) -> Self {
        self.memory = MemorySize::mib(mib);
        self
    }

    pub fn with_memory_kib(mut self, kib: usize) -> Self {
        self.memory = MemorySize::kib(kib);
        self
    }

    pub fn with_block_size(mut self, bytes: usize) -> Self {
        self.block_size = BlockSize::bytes(bytes);
        self
    }

    pub fn with_fan_in(mut self, fan_in: u32) -> Self {
        self.fan_in = FanIn::new(fan_in);
        self
    }

    pub fn with_graph(mut self, graph: crate::algorithm::GraphKind) -> Self {
        self.graph = graph;
        self
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.memory.validate()?;
        self.salt_length.validate()?;
        self.block_size.validate()?;
        self.fan_in.validate()?;
        self.output_length.validate()?;
        if self.num_blocks() < 64 {
            return Err(ConfigError::InvalidParameterValue(
                "memory/block_size must yield at least 64 blocks".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for [`AntechConfig`].
#[derive(Debug, Clone, Default)]
pub struct AntechConfigBuilder {
    config: AntechConfig,
}

impl AntechConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn algorithm(mut self, algo: Algorithm) -> Self {
        self.config.algorithm = algo;
        self
    }

    pub fn memory_mib(mut self, mib: usize) -> Self {
        self.config.memory = MemorySize::mib(mib);
        self
    }

    pub fn memory_kib(mut self, kib: usize) -> Self {
        self.config.memory = MemorySize::kib(kib);
        self
    }

    pub fn salt_length(mut self, bytes: usize) -> Self {
        self.config.salt_length = SaltLength::bytes(bytes);
        self
    }

    pub fn block_size(mut self, size: usize) -> Self {
        self.config.block_size = BlockSize::bytes(size);
        self
    }

    pub fn fan_in(mut self, fan_in: u32) -> Self {
        self.config.fan_in = FanIn::new(fan_in);
        self
    }

    pub fn graph(mut self, graph: GraphKind) -> Self {
        self.config.graph = graph;
        self
    }

    pub fn output_length(mut self, bytes: usize) -> Self {
        self.config.output_length = OutputLength::bytes(bytes);
        self
    }

    pub fn build(self) -> Result<AntechConfig, ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}
