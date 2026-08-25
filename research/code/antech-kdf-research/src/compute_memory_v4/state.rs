//! Re-exports from the canonical core state module (research naming preserved).

pub use antech_kdf_core::mixing::state_to_block;
pub use antech_kdf_core::state::{
    bind_seed as bind_seed_v4, finalize as finalize_v4, mix_parent_views, phantom_block,
    seed_to_state as state_from_seed, state_to_block_fast, xor_state_into_block_fast,
    xor_state_into_block_fast as xor_state_into_block,
};
