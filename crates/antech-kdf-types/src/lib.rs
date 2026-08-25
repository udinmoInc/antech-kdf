//! Shared types for Antech KDF configuration, encoding, and errors.

pub mod algorithm;
pub mod config;
pub mod errors;
pub mod rehash;

pub use algorithm::{Algorithm, AlgorithmVersion, GraphKind};
pub use config::{
    AntechConfig, AntechConfigBuilder, BlockSize, FanIn, MemorySize, OutputLength, SaltLength,
    FRONTIER_WIDTH, MIX_ROUNDS, TILE_BLOCKS,
};
pub use errors::{ConfigError, KdfError};
pub use rehash::{RehashPolicy, RehashPolicyBuilder};

/// Parsed fields from a self-describing password hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHashComponents {
    pub version: AlgorithmVersion,
    pub algorithm: Algorithm,
    pub memory_kib: u32,
    pub salt_len: usize,
    pub block_size: usize,
    pub fan_in: u32,
    pub graph: GraphKind,
    pub output_len: usize,
    pub salt: Vec<u8>,
    pub digest: Vec<u8>,
}
