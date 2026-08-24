//! Decoupled configuration types and builder API for Antech KDF.

use crate::algorithm::Algorithm;
use crate::errors::ConfigError;

/// Working memory allocation size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemorySize(pub usize); // Memory in KiB

impl MemorySize {
    pub const MIN_KIB: usize = 1024; // 1 MiB minimum
    pub const MAX_KIB: usize = 1048576; // 1 GiB maximum

    pub fn mib(mib: usize) -> Self {
        Self(mib * 1024)
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
        self.0 * 1024
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

/// Salt length in bytes (supported range: 8 to 256 bytes).
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

/// Execution pass count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PassCount(pub u32);

impl PassCount {
    pub fn new(passes: u32) -> Self {
        Self(passes)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < 1 {
            Err(ConfigError::InvalidPassCount { passes: self.0 })
        } else {
            Ok(())
        }
    }
}

/// Sequential dependency depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DependencyDepth(pub u32);

impl DependencyDepth {
    pub fn new(depth: u32) -> Self {
        Self(depth)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < 10 {
            Err(ConfigError::InvalidDependencyDepth { depth: self.0 })
        } else {
            Ok(())
        }
    }
}

/// Memory block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockSize(pub usize);

impl BlockSize {
    pub fn bytes(size: usize) -> Self {
        Self(size)
    }

    pub fn as_bytes(&self) -> usize {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < 16 || (self.0 & (self.0 - 1)) != 0 {
            Err(ConfigError::InvalidBlockSize { size: self.0 })
        } else {
            Ok(())
        }
    }
}

/// Parallelism lanes factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parallelism(pub u32);

impl Parallelism {
    pub fn new(lanes: u32) -> Self {
        Self(lanes)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.0 < 1 {
            Err(ConfigError::InvalidParallelism { lanes: self.0 })
        } else {
            Ok(())
        }
    }
}

/// Output hash digest length in bytes.
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

/// Main public configuration type for Antech KDF.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AntechConfig {
    pub algorithm: Algorithm,
    pub memory: MemorySize,
    pub salt_length: SaltLength,
    pub passes: PassCount,
    pub dependency_depth: DependencyDepth,
    pub block_size: BlockSize,
    pub parallelism: Parallelism,
    pub output_length: OutputLength,
}

impl Default for AntechConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Antech,
            memory: MemorySize::mib(16),
            salt_length: SaltLength::bytes(16),
            passes: PassCount::new(1),
            dependency_depth: DependencyDepth::new(650000),
            block_size: BlockSize::bytes(32),
            parallelism: Parallelism::new(1),
            output_length: OutputLength::bytes(32),
        }
    }
}

impl AntechConfig {
    pub fn builder() -> AntechConfigBuilder {
        AntechConfigBuilder::default()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.memory.validate()?;
        self.salt_length.validate()?;
        self.passes.validate()?;
        self.dependency_depth.validate()?;
        self.block_size.validate()?;
        self.parallelism.validate()?;
        self.output_length.validate()?;
        Ok(())
    }
}

/// Builder pattern for `AntechConfig`.
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

    pub fn passes(mut self, passes: u32) -> Self {
        self.config.passes = PassCount::new(passes);
        self
    }

    pub fn dependency_depth(mut self, depth: u32) -> Self {
        self.config.dependency_depth = DependencyDepth::new(depth);
        self
    }

    pub fn block_size(mut self, size: usize) -> Self {
        self.config.block_size = BlockSize::bytes(size);
        self
    }

    pub fn parallelism(mut self, lanes: u32) -> Self {
        self.config.parallelism = Parallelism::new(lanes);
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
