//! Compute/Memory hardness research module (12–32 MiB working sets).
//!
//! Cost model: sequential state dependency + cryptographic mixing +
//! recomputation under TMTO — not giant empty loops or DRAM saturation.

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
            memory_kib: 1024, // 1 MiB — fast tests
            dependency_depth: 64,
            passes: 1,
            block_size: 32,
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn reference_matches_optimized() {
        let params = small_params();
        let reference = ReferenceEngine::new();
        let optimized = OptimizedEngine::new();
        let a = reference
            .derive(b"pwd", b"salt_16_bytes!!", &params)
            .unwrap();
        let b = optimized
            .derive(b"pwd", b"salt_16_bytes!!", &params)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn deterministic_derivation() {
        let params = small_params();
        let eng = OptimizedEngine::new();
        let a = eng.derive(b"pwd", b"salt_16_bytes!!", &params).unwrap();
        let b = eng.derive(b"pwd", b"salt_16_bytes!!", &params).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn password_and_salt_binding() {
        let params = small_params();
        let eng = OptimizedEngine::new();
        let a = eng.derive(b"pwd1", b"salt_16_bytes!!", &params).unwrap();
        let b = eng.derive(b"pwd2", b"salt_16_bytes!!", &params).unwrap();
        let c = eng.derive(b"pwd1", b"salt_16_BYTES!!", &params).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn tmto_reduced_memory_matches_full() {
        let params = small_params();
        let eng = OptimizedEngine::new();
        let full = eng.derive(b"tmto", b"salt_16_bytes!!", &params).unwrap();
        let sparse = eng
            .derive_tmto(b"tmto", b"salt_16_bytes!!", &params, 1.0)
            .unwrap();
        assert_eq!(full, sparse);

        let half = eng
            .derive_tmto(b"tmto", b"salt_16_bytes!!", &params, 0.5)
            .unwrap();
        assert_eq!(full, half);

        let eighth = eng
            .derive_tmto(b"tmto", b"salt_16_bytes!!", &params, 0.125)
            .unwrap();
        assert_eq!(full, eighth);
    }

    #[test]
    fn config_from_antech_config() {
        let antech = AntechConfig::builder()
            .memory_mib(16)
            .dependency_depth(128)
            .passes(1)
            .block_size(32)
            .build()
            .unwrap();
        let cfg = ComputeMemoryConfig::from_antech_config(&antech);
        assert_eq!(cfg.memory_kib, 16 * 1024);
        assert_eq!(cfg.dependency_depth, 128);
    }

    #[test]
    fn variant_d_matches_optimized_defaults() {
        let params = small_params();
        let d = VariantD::new();
        let o = OptimizedEngine::new();
        let a = d.derive(b"pwd", b"salt_16_bytes!!", &params).unwrap();
        let b = o.derive(b"pwd", b"salt_16_bytes!!", &params).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn frozen_test_vector_v1() {
        // KAT: memory=1024 KiB, depth=64, passes=1, block=32, mix_rounds=4, segment=1024
        let params = ResearchParams {
            memory_kib: 1024,
            dependency_depth: 64,
            passes: 1,
            block_size: 32,
        };
        let eng = OptimizedEngine::new();
        let out = eng
            .derive(b"antech-kat-password", b"antech-kat-salt!", &params)
            .unwrap();
        assert_eq!(
            to_hex(&out),
            "22bc254b5312ffd0cd57f3ebf5074a831f5b843cfb4d68c06a884cd0d0993f85"
        );
    }
}
