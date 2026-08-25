//! Protocol constants re-exported for engine internals.

pub use antech_kdf_types::{FRONTIER_WIDTH, MIX_ROUNDS, TILE_BLOCKS};

/// Construction version bound into the seed.
pub const CONSTRUCTION_VERSION: u32 = 4;

/// Default block size (bytes).
pub const DEFAULT_BLOCK_SIZE: u32 = 32;

/// Default graph fan-in.
pub const DEFAULT_FAN_IN: u32 = 2;

/// Default working set (16 MiB).
pub const DEFAULT_MEMORY_KIB: u32 = 16 * 1024;
