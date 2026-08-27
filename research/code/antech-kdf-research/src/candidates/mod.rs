//! Research candidate constructions (non-shipping experiments).

pub mod cand_004;
pub mod k1;
pub mod k2;

pub use cand_004::{Candidate004, ResearchError, ResearchKdf, ResearchParams};
pub use k1::VariantK1;
pub use k2::VariantK2;
