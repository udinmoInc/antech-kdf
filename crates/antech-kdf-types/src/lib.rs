//! Shared types for Antech KDF configuration, encoding, and errors.

pub mod algorithm;
pub mod config;
pub mod errors;
pub mod rehash;
pub mod secret;

pub use algorithm::{Algorithm, AlgorithmVersion, GraphKind};
pub use config::{
    AntechConfig, AntechConfigBuilder, BlockSize, FanIn, MemorySize, OutputLength, SaltLength,
    FRONTIER_WIDTH, MIX_ROUNDS, TILE_BLOCKS,
};
pub use errors::{ConfigError, KdfError};
pub use rehash::{RehashPolicy, RehashPolicyBuilder};
pub use secret::{
    validate_associated_data_len, validate_secret_len, DeriveInputs, SecretBytes,
    ASSOCIATED_DATA_MAX_BYTES, SECRET_MAX_BYTES,
};

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
    /// When true, verification must supply a secret (bytes never appear in the string).
    pub secret_required: bool,
    /// When `Some(n)`, verification must supply associated data of exactly `n` bytes
    /// (`n` may be 0 for empty AD). `None` means AD was not used.
    pub associated_data_length: Option<u32>,
    pub salt: Vec<u8>,
    pub digest: Vec<u8>,
}
