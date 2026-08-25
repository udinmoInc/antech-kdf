//! Compute/Memory hardness research module v2 (12–32 MiB).
//!
//! Work is derived from the memory-sized dependency DAG — not an exposed
//! depth/iteration parameter.

pub mod attacker;
pub mod benchmarks;
pub mod config;
pub mod contention;
pub mod core;
pub mod crypto_mixing;
pub mod cuda;
pub mod dependency_graph;
pub mod gpu;
pub mod memory_layout;
pub mod optimized;
pub mod profiling;
pub mod reference;
pub mod state_transition;
pub mod tmto;
pub mod variant_a;
pub mod variant_b;
pub mod variant_c;
pub mod variant_d;

pub use benchmarks::run_compute_memory_suite;
pub use config::ComputeMemoryConfig;
pub use optimized::OptimizedEngine;
pub use reference::ReferenceEngine;
pub use variant_a::VariantA;
pub use variant_b::VariantB;
pub use variant_c::VariantC;
pub use variant_d::VariantD;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidates::cand_004::{ResearchKdf, ResearchParams};
    use antech_kdf_types::AntechConfig;

    fn small_params() -> ResearchParams {
        ResearchParams {
            memory_kib: 1024, // 1 MiB → 32768 DAG nodes
            dependency_depth: 0, // ignored by v2
            passes: 0,           // ignored by v2
            block_size: 32,
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn work_equals_num_blocks() {
        let cfg = ComputeMemoryConfig::default().memory_mib(1);
        assert_eq!(cfg.num_blocks(), 1024 * 1024 / 32);
        // No depth/passes fields on the structural config.
        let _ = cfg.fan_in;
    }

    #[test]
    fn reference_matches_optimized() {
        let params = small_params();
        let a = ReferenceEngine::new()
            .derive(b"pwd", b"salt_16_bytes!!", &params)
            .unwrap();
        let b = OptimizedEngine::new()
            .derive(b"pwd", b"salt_16_bytes!!", &params)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn deterministic_and_binding() {
        let params = small_params();
        let eng = OptimizedEngine::new();
        let a = eng.derive(b"pwd", b"salt_16_bytes!!", &params).unwrap();
        let b = eng.derive(b"pwd", b"salt_16_bytes!!", &params).unwrap();
        assert_eq!(a, b);
        let c = eng.derive(b"pwd2", b"salt_16_bytes!!", &params).unwrap();
        let d = eng.derive(b"pwd", b"salt_16_BYTES!!", &params).unwrap();
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn depth_param_ignored() {
        let eng = OptimizedEngine::new();
        let mut p1 = small_params();
        let mut p2 = small_params();
        p1.dependency_depth = 10;
        p2.dependency_depth = 999_999;
        p1.passes = 1;
        p2.passes = 99;
        let a = eng.derive(b"pwd", b"salt_16_bytes!!", &p1).unwrap();
        let b = eng.derive(b"pwd", b"salt_16_bytes!!", &p2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn tmto_matches_full() {
        let params = small_params();
        let eng = OptimizedEngine::new();
        let full = eng.derive(b"tmto", b"salt_16_bytes!!", &params).unwrap();
        assert_eq!(
            full,
            eng.derive_tmto(b"tmto", b"salt_16_bytes!!", &params, 1.0)
                .unwrap()
        );
        assert_eq!(
            full,
            eng.derive_tmto(b"tmto", b"salt_16_bytes!!", &params, 0.5)
                .unwrap()
        );
        assert_eq!(
            full,
            eng.derive_tmto(b"tmto", b"salt_16_bytes!!", &params, 0.125)
                .unwrap()
        );
    }

    #[test]
    fn config_from_antech_ignores_depth() {
        let antech = AntechConfig::builder()
            .memory_mib(16)
            .dependency_depth(650000)
            .passes(7)
            .block_size(32)
            .build()
            .unwrap();
        let cfg = ComputeMemoryConfig::from_antech_config(&antech);
        assert_eq!(cfg.memory_kib, 16 * 1024);
        assert_eq!(cfg.block_size, 32);
        assert_eq!(cfg.num_blocks(), 16 * 1024 * 1024 / 32);
    }

    #[test]
    fn variant_d_matches_optimized() {
        let params = small_params();
        let a = VariantD::new()
            .derive(b"pwd", b"salt_16_bytes!!", &params)
            .unwrap();
        let b = OptimizedEngine::new()
            .derive(b"pwd", b"salt_16_bytes!!", &params)
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn frozen_test_vector_v2() {
        let params = ResearchParams {
            memory_kib: 1024,
            dependency_depth: 0,
            passes: 0,
            block_size: 32,
        };
        let out = OptimizedEngine::new()
            .derive(b"antech-kat-password", b"antech-kat-salt!", &params)
            .unwrap();
        assert_eq!(
            to_hex(&out),
            "d2675d5422a98993886e9014728bcf4d72f8d587ffb57131321851c19d09ba63"
        );
    }
}
