#![no_main]
//! Fuzz AntechConfig builder / validation with boundary and overflow-ish inputs.

use antech_kdf::{AntechConfig, GraphKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let memory = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let salt = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
    let block = u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize;
    let fan = u32::from(data[8]);
    let graph_tag = u32::from(data[9]);
    let out_len = u16::from_le_bytes(data[10..12].try_into().unwrap()) as usize;

    let graph = GraphKind::from_tag(graph_tag);
    let mut b = AntechConfig::builder()
        .memory_kib(memory)
        .salt_length(salt)
        .block_size(block)
        .fan_in(fan)
        .output_length(out_len);
    if let Some(g) = graph {
        b = b.graph(g);
    }
    let built = b.build();

    // Invalid combinations must error, never panic (catch via no-unwind fuzz harness).
    if let Ok(cfg) = built {
        // Engine-aligned invariants
        assert!(cfg.block_size.as_bytes() <= 64);
        assert!(cfg.num_blocks() >= 64);
        assert!((2..=8).contains(&cfg.fan_in.get()));
    }
});
