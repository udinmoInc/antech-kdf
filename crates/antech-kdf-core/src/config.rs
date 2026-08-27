//! Protocol constants for engine internals.

pub use antech_kdf_types::{FRONTIER_WIDTH, MIX_ROUNDS, TILE_BLOCKS};

/// Construction version bound into the seed (must stay aligned with domain separators).
pub const CONSTRUCTION_VERSION: u32 = 4;

pub const DEFAULT_BLOCK_SIZE: u32 = 32;
pub const DEFAULT_FAN_IN: u32 = 2;
pub const DEFAULT_MEMORY_KIB: u32 = 16 * 1024;
