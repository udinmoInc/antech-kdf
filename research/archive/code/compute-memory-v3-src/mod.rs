//! Compute-Memory v3 — graph variants that reduce attacker multi-core scaling.
//!
//! Reuses v2 crypto primitives and config patterns. Work bound remains
//! `num_blocks = memory_bytes / block_size` (no depth/passes knobs).

pub mod attacker;
pub mod benchmarks;
pub mod config;
pub mod engine;
pub mod frontier;
pub mod graph;
pub mod state;
pub mod tmto;
pub mod variants;

pub use benchmarks::run_compute_memory_v3_suite;
pub use config::{ComputeMemoryV3Config, GraphKind};
pub use engine::V3Engine;
pub use variants::{VariantA, VariantB, VariantC};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidates::cand_004::{ResearchKdf, ResearchParams};

    fn tiny() -> ResearchParams {
        ResearchParams {
            memory_kib: 1024,
            dependency_depth: 0,
            passes: 0,
            block_size: 32,
        }
    }

    #[test]
    fn variants_deterministic_and_distinct() {
        let p = tiny();
        let a = VariantA::new()
            .derive(b"pwd", b"salt_16_bytes!!", &p)
            .unwrap();
        let b = VariantB::new()
            .derive(b"pwd", b"salt_16_bytes!!", &p)
            .unwrap();
        let c = VariantC::new()
            .derive(b"pwd", b"salt_16_bytes!!", &p)
            .unwrap();
        assert_eq!(
            a,
            VariantA::new()
                .derive(b"pwd", b"salt_16_bytes!!", &p)
                .unwrap()
        );
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn work_bound_is_num_blocks() {
        let cfg = ComputeMemoryV3Config::default().memory_mib(16);
        assert_eq!(cfg.num_blocks(), 16 * 1024 * 1024 / 32);
        assert!(cfg.epoch_len() >= 16);
    }

    #[test]
    fn depth_ignored() {
        let mut p1 = tiny();
        let mut p2 = tiny();
        p1.dependency_depth = 10;
        p2.dependency_depth = 999999;
        let a = VariantC::new()
            .derive(b"x", b"salt_16_bytes!!", &p1)
            .unwrap();
        let b = VariantC::new()
            .derive(b"x", b"salt_16_bytes!!", &p2)
            .unwrap();
        assert_eq!(a, b);
    }
}
