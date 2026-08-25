//! Readable reference implementation of the Antech KDF review target.
//!
//! Clarity over speed. Corresponds to `research/security-review/specification.md`.
//! Not for production use.

use sha2::{Digest, Sha256};

pub const CONSTRUCTION_VERSION: u32 = 4;
pub const MIX_ROUNDS: u32 = 4;
pub const FRONTIER_WIDTH: usize = 64;
pub const TILE_BLOCKS: usize = 512;

pub const DOMAIN_SEED: &[u8] = b"antech-compute-memory-v4-seed";
pub const DOMAIN_FINAL: &[u8] = b"antech-compute-memory-v4-final";
pub const DOMAIN_NODE0: &[u8] = b"antech-compute-memory-v2-node0";

pub const C1: u64 = 0xBF58476D1CE4E5B9;
pub const C2: u64 = 0x94D049BB133111EB;
pub const GOLDEN: u64 = 0x9E3779B97F4A7C15;

pub const GRAPH_COMBINED_FRONTIER: u32 = 3;

#[derive(Debug, Clone, Copy)]
pub struct RefConfig {
    pub memory_kib: usize,
    pub block_size: usize,
    pub fan_in: u32,
    pub graph_tag: u32,
    pub output_length: usize,
}

impl RefConfig {
    pub fn canonical_default() -> Self {
        Self {
            memory_kib: 16 * 1024,
            block_size: 32,
            fan_in: 2,
            graph_tag: GRAPH_COMBINED_FRONTIER,
            output_length: 32,
        }
    }

    pub fn num_blocks(&self) -> usize {
        (self.memory_kib * 1024) / self.block_size.max(1)
    }

    pub fn critical_period(&self) -> usize {
        (FRONTIER_WIDTH / 16).max(2)
    }

    pub fn tile_len(&self) -> usize {
        TILE_BLOCKS.min(self.num_blocks().max(1))
    }

    pub fn memory_bytes(&self) -> usize {
        self.memory_kib * 1024
    }
}

pub fn bind_seed(password: &[u8], salt: &[u8], cfg: &RefConfig) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_SEED);
    h.update(CONSTRUCTION_VERSION.to_le_bytes());
    h.update(cfg.graph_tag.to_le_bytes());
    h.update((password.len() as u32).to_le_bytes());
    h.update(password);
    h.update((salt.len() as u32).to_le_bytes());
    h.update(salt);
    h.update((cfg.memory_kib as u32).to_le_bytes());
    h.update((cfg.block_size as u32).to_le_bytes());
    h.update(cfg.fan_in.to_le_bytes());
    h.update(MIX_ROUNDS.to_le_bytes());
    h.update((cfg.critical_period() as u32).to_le_bytes());
    h.update((cfg.tile_len() as u32).to_le_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

pub fn state_from_seed(seed: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(seed[0..8].try_into().unwrap()),
        u64::from_le_bytes(seed[8..16].try_into().unwrap()),
        u64::from_le_bytes(seed[16..24].try_into().unwrap()),
        u64::from_le_bytes(seed[24..32].try_into().unwrap()),
    ]
}

fn load_u64(block: &[u8], offset: usize) -> u64 {
    if offset + 8 <= block.len() {
        u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap())
    } else {
        0
    }
}

/// Spec §11.1 — multi-round ARX mix of state with two block views.
pub fn mix_pair(state: &mut [u64; 4], block1: &[u8], block2: &[u8]) {
    let b10 = load_u64(block1, 0);
    let b11 = load_u64(block1, 8);
    let b12 = load_u64(block1, 16);
    let b13 = load_u64(block1, 24);
    let b20 = load_u64(block2, 0);
    let b21 = load_u64(block2, 8);
    let b22 = load_u64(block2, 16);
    let b23 = load_u64(block2, 24);

    for r in 0..MIX_ROUNDS {
        let rr = r as u64;
        state[0] = state[0]
            .wrapping_add(b10 ^ b20.wrapping_add(rr))
            .rotate_left(13)
            ^ state[3];
        state[1] = state[1]
            .wrapping_add(b11.wrapping_mul(C1) ^ b21)
            .rotate_left(17)
            ^ state[0];
        state[2] = state[2]
            .wrapping_add(b12 ^ b22.wrapping_mul(C2))
            .rotate_left(19)
            ^ state[1];
        state[3] = state[3]
            .wrapping_add(b13.wrapping_add(b23) ^ GOLDEN.wrapping_mul(rr + 1))
            .rotate_left(23)
            ^ state[2];
    }
}

pub fn mix_views(state: &mut [u64; 4], views: &[&[u8]]) {
    if views.is_empty() {
        return;
    }
    if views.len() == 1 {
        mix_pair(state, views[0], views[0]);
        return;
    }
    let mut i = 0;
    while i + 1 < views.len() {
        mix_pair(state, views[i], views[i + 1]);
        i += 2;
    }
    if i < views.len() {
        mix_pair(state, views[i], views[i]);
    }
}

pub fn phantom_block(seed: &[u8; 32], slot: u32, block_size: usize) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(DOMAIN_NODE0);
    h.update(seed);
    h.update(slot.to_le_bytes());
    let digest = h.finalize();
    let mut out = vec![0u8; block_size];
    let copy = block_size.min(32);
    out[..copy].copy_from_slice(&digest[..copy]);
    if block_size > 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&digest);
        let mut s = state_from_seed(&k);
        let mut off = 32;
        while off < block_size {
            s[0] = s[0].wrapping_add(GOLDEN).wrapping_mul(C1);
            s[1] ^= s[0].rotate_left(17);
            s[2] = s[2].wrapping_add(s[1]).wrapping_mul(C2);
            s[3] ^= s[2].rotate_left(41);
            for (i, word) in s.iter().enumerate() {
                let bytes = word.to_le_bytes();
                let start = off + i * 8;
                if start >= block_size {
                    break;
                }
                let end = (start + 8).min(block_size);
                out[start..end].copy_from_slice(&bytes[..end - start]);
            }
            off += 32;
        }
    }
    out
}

fn state_to_block(state: &[u64; 4], block: &mut [u8]) {
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        for (j, b) in bytes.iter().enumerate() {
            let idx = i * 8 + j;
            if idx < block.len() {
                block[idx] = *b;
            }
        }
    }
}

fn xor_state_into_block(state: &[u64; 4], block: &mut [u8]) {
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        for (j, b) in bytes.iter().enumerate() {
            let idx = i * 8 + j;
            if idx < block.len() {
                block[idx] ^= *b;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParentSet {
    pub indices: Vec<usize>,
    pub scatter_dest: Option<usize>,
    pub scatter_dest2: Option<usize>,
}

fn push_unique(indices: &mut Vec<usize>, addr: usize, i: usize) {
    if addr >= i || indices.len() >= 8 {
        return;
    }
    if indices.contains(&addr) {
        return;
    }
    indices.push(addr);
}

/// CombinedFrontier parent selection (canonical review graph).
pub fn parents_combined_frontier(
    state: &[u64; 4],
    i: usize,
    fan_in: u32,
    critical_period: usize,
    tile_len: usize,
) -> ParentSet {
    if i == 0 {
        return ParentSet {
            indices: Vec::new(),
            scatter_dest: None,
            scatter_dest2: None,
        };
    }

    let tile = tile_len.max(TILE_BLOCKS.min(512));
    let tile_start = (i / tile) * tile;
    let critical =
        (critical_period > 0 && i % critical_period == 0) || (i > 0 && i % FRONTIER_WIDTH == 0);

    let mut indices = Vec::new();

    // Local frontier (aim for 2)
    indices.push(i - 1);
    let fw = FRONTIER_WIDTH.min(i);
    let slot = (state[0] as usize) % fw;
    push_unique(&mut indices, i - 1 - slot, i);
    let mut guard = 0usize;
    while indices.len() < 2 && guard < 2 + 4 {
        guard += 1;
        let mix = state[indices.len() % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let slot = (mix as usize) % fw;
        let before = indices.len();
        push_unique(&mut indices, i - 1 - slot, i);
        if indices.len() == before {
            let slot2 = (state[2].wrapping_add(guard as u64) as usize) % fw;
            push_unique(&mut indices, i - 1 - slot2, i);
            if indices.len() == before {
                break;
            }
        }
    }

    if i > tile_start + 1 {
        let span = i - tile_start;
        let local_remote = tile_start + ((state[1] as usize) % span);
        push_unique(&mut indices, local_remote, i);
    }

    if i > fw + 1 {
        let remote_span = i - fw;
        if critical || (i & 1) == 0 {
            let far = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
            push_unique(&mut indices, far, i);
        }
        if critical {
            let far2 = ((state[0] ^ GOLDEN) as usize) % remote_span;
            push_unique(&mut indices, far2, i);
        }
    }

    let mut guard = 0usize;
    while indices.len() < fan_in as usize && guard < 4 {
        guard += 1;
        let mix = state[indices.len() % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = indices.len();
        let addr = if i > tile_start {
            tile_start + ((mix as usize) % (i - tile_start).max(1))
        } else {
            (mix as usize) % i
        };
        push_unique(&mut indices, addr, i);
        if indices.len() == before {
            break;
        }
    }

    let (scatter_dest, scatter_dest2) = if i > fw {
        let span = i - fw;
        (
            Some(((state[2] ^ GOLDEN) as usize) % span),
            Some(((state[3] ^ state[0].rotate_left(7)) as usize) % span),
        )
    } else {
        (None, None)
    };

    ParentSet {
        indices,
        scatter_dest,
        scatter_dest2,
    }
}

pub fn finalize(
    seed: &[u8; 32],
    state: &[u64; 4],
    last_block: &[u8],
    graph_tag: u32,
    output_length: usize,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(DOMAIN_FINAL);
    h.update(CONSTRUCTION_VERSION.to_le_bytes());
    h.update(graph_tag.to_le_bytes());
    h.update(seed);
    for w in state {
        h.update(w.to_le_bytes());
    }
    h.update(last_block);
    let mut digest = h.finalize().to_vec();
    if digest.len() > output_length {
        digest.truncate(output_length);
    } else if digest.len() < output_length {
        digest.resize(output_length, 0);
    }
    digest
}

/// Normative Derive for CombinedFrontier (review target).
pub fn derive(password: &[u8], salt: &[u8], cfg: &RefConfig) -> Vec<u8> {
    assert_eq!(
        cfg.graph_tag, GRAPH_COMBINED_FRONTIER,
        "reference Derive covers CombinedFrontier only"
    );
    let n = cfg.num_blocks();
    assert!(n >= 64);
    let seed = bind_seed(password, salt, cfg);
    let mut state = state_from_seed(&seed);
    let mut memory = vec![0u8; cfg.memory_bytes()];
    let b = cfg.block_size;
    let fan = cfg.fan_in as usize;
    let phantoms: Vec<Vec<u8>> = (0..fan)
        .map(|t| phantom_block(&seed, t as u32, b))
        .collect();
    let period = cfg.critical_period();
    let tile_len = cfg.tile_len();

    for i in 0..n {
        let parents = if i == 0 {
            ParentSet {
                indices: Vec::new(),
                scatter_dest: None,
                scatter_dest2: None,
            }
        } else {
            parents_combined_frontier(&state, i, cfg.fan_in, period, tile_len)
        };

        let mut view_bufs: Vec<&[u8]> = Vec::new();
        if i == 0 {
            for ph in &phantoms {
                view_bufs.push(ph.as_slice());
            }
        } else {
            for &p in &parents.indices {
                let start = p * b;
                view_bufs.push(&memory[start..start + b]);
            }
        }
        mix_views(&mut state, &view_bufs);

        {
            let out = &mut memory[i * b..(i + 1) * b];
            state_to_block(&state, out);
        }

        for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
            if let Some(dest) = dest_opt {
                if dest < n && dest != i {
                    let block = &mut memory[dest * b..(dest + 1) * b];
                    xor_state_into_block(&state, block);
                }
            }
        }
    }

    let last = &memory[(n - 1) * b..n * b];
    finalize(&seed, &state, last, cfg.graph_tag, cfg.output_length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    fn vectors_path() -> PathBuf {
        // research/code/reference → research/security-review/test-vectors.json
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../security-review/test-vectors.json")
    }

    fn cfg_from_json(c: &Value) -> RefConfig {
        RefConfig {
            memory_kib: c["memory_kib"].as_u64().unwrap() as usize,
            block_size: c["block_size"].as_u64().unwrap() as usize,
            fan_in: c["fan_in"].as_u64().unwrap() as u32,
            graph_tag: GRAPH_COMBINED_FRONTIER,
            output_length: c["output_length"].as_u64().unwrap() as usize,
        }
    }

    #[test]
    fn matches_published_test_vectors() {
        let raw = fs::read_to_string(vectors_path()).expect("test-vectors.json");
        let v: Value = serde_json::from_str(&raw).unwrap();
        for section in [
            "boundary_1mib",
            "small_1mib_with_intermediates",
            "canonical_default_16mib",
        ] {
            let Some(arr) = v.get(section).and_then(|x| x.as_array()) else {
                continue;
            };
            for item in arr {
                let cfg = cfg_from_json(&item["config"]);
                let password = hex::decode(item["password_hex"].as_str().unwrap()).unwrap();
                let salt = hex::decode(item["salt_hex"].as_str().unwrap()).unwrap();
                let expect = hex::decode(item["digest_hex"].as_str().unwrap()).unwrap();
                let got = derive(&password, &salt, &cfg);
                assert_eq!(
                    got,
                    expect,
                    "mismatch on {}",
                    item["id"].as_str().unwrap_or("?")
                );
            }
        }
    }

    #[test]
    fn matches_production_engine_sample() {
        use antech_kdf_core::engine::AntechEngine;
        use antech_kdf_types::{AntechConfig, GraphKind};
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .graph(GraphKind::CombinedFrontier)
            .build()
            .unwrap();
        let password = b"ref_cross_check";
        let salt = b"salt_16_bytes_!!";
        let prod = AntechEngine::new().derive(password, salt, &cfg).unwrap();
        let refer = derive(
            password,
            salt,
            &RefConfig {
                memory_kib: 1024,
                block_size: 32,
                fan_in: 2,
                graph_tag: GRAPH_COMBINED_FRONTIER,
                output_length: 32,
            },
        );
        assert_eq!(prod, refer);
    }
}
