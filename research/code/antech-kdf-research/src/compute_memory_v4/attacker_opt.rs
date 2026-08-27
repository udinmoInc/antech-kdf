//! Attacker-only v4-C walks. Same CombinedFrontier graph and mix as production;
//! layout, allocation, and scheduling may differ. Does not change the defender.

use antech_kdf_core::state::{bind_seed, finalize, phantom_block, seed_to_state};
use antech_kdf_types::AntechConfig;
use sha2::{Digest, Sha256};

const C1: u64 = 0xBF58476D1CE4E5B9;
const C2: u64 = 0x94D049BB133111EB;
const GOLDEN: u64 = 0x9E3779B97F4A7C15;
const MIX_ROUNDS: u32 = 4;
const FW: usize = 64;
const FAN: usize = 2;
pub const NUM_BLOCKS_16MIB: usize = 16 * 1024 * 1024 / 32;

#[inline(always)]
fn mix_pair_words(state: &mut [u64; 4], a: &[u64; 4], b: &[u64; 4]) {
    let (b10, b11, b12, b13) = (a[0], a[1], a[2], a[3]);
    let (b20, b21, b22, b23) = (b[0], b[1], b[2], b[3]);
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

#[inline(always)]
fn mix_views(state: &mut [u64; 4], views: &[[u64; 4]; 8], n: usize) {
    if n == 0 {
        return;
    }
    if n == 1 {
        mix_pair_words(state, &views[0], &views[0]);
        return;
    }
    let mut i = 0;
    while i + 1 < n {
        mix_pair_words(state, &views[i], &views[i + 1]);
        i += 2;
    }
    if i < n {
        mix_pair_words(state, &views[i], &views[i]);
    }
}

#[inline(always)]
fn push_unique(indices: &mut [u32; 8], len: &mut usize, addr: u32, i: u32) {
    if (addr as usize) >= i as usize || *len >= 8 {
        return;
    }
    for j in 0..*len {
        if indices[j] == addr {
            return;
        }
    }
    indices[*len] = addr;
    *len += 1;
}

/// v5 phase-1: sequential + frontier only.
#[inline(always)]
fn parents_local(state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut indices = [0u32; 8];
    let mut len = 0usize;
    if i == 0 {
        return (indices, 0);
    }
    let i_us = i as usize;
    push_unique(&mut indices, &mut len, (i_us - 1) as u32, i);
    let fw = FW.min(i_us);
    let slot = (state[0] as usize) % fw;
    push_unique(&mut indices, &mut len, (i_us - 1 - slot) as u32, i);
    let mut guard = 0usize;
    while len < FAN && guard < FAN + 4 {
        guard += 1;
        let mix = state[len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let slot = (mix as usize) % fw;
        let before = len;
        push_unique(&mut indices, &mut len, (i_us - 1 - slot) as u32, i);
        if len == before {
            let slot2 = (state[2].wrapping_add(guard as u64) as usize) % fw;
            push_unique(&mut indices, &mut len, (i_us - 1 - slot2) as u32, i);
            if len == before {
                break;
            }
        }
    }
    (indices, len)
}

/// v5 phase-2: global + always-2 far from *post-local* state. Scatter filled separately post-mix.
#[inline(always)]
fn parents_remote(state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut indices = [0u32; 8];
    let mut len = 0usize;
    if i == 0 {
        return (indices, 0);
    }
    let i_us = i as usize;
    let fw = FW.min(i_us);

    if i_us > 1 {
        push_unique(
            &mut indices,
            &mut len,
            ((state[1] as usize) % i_us) as u32,
            i,
        );
    }

    if i_us > fw + 1 {
        let remote_span = i_us - fw;
        let far = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
        push_unique(&mut indices, &mut len, far as u32, i);
        let far2 = ((state[0] ^ GOLDEN) as usize) % remote_span;
        push_unique(&mut indices, &mut len, far2 as u32, i);
    }

    let mut guard = 0usize;
    while len < FAN && guard < 4 {
        guard += 1;
        let mix = state[len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = len;
        let addr = (mix as usize) % i_us;
        push_unique(&mut indices, &mut len, addr as u32, i);
        if len == before {
            break;
        }
    }
    (indices, len)
}

#[inline(always)]
fn scatter_from_state(state: &[u64; 4], i: u32) -> (i32, i32) {
    let i_us = i as usize;
    let fw = FW.min(i_us);
    if i_us > fw {
        let span = i_us - fw;
        (
            (((state[2] ^ GOLDEN) as usize) % span) as i32,
            (((state[3] ^ state[0].rotate_left(7)) as usize) % span) as i32,
        )
    } else {
        (-1, -1)
    }
}

#[inline(always)]
fn load_views(buf: &[[u64; 4]], indices: &[u32; 8], npar: usize) -> ([[u64; 4]; 8], usize) {
    let mut views = [[0u64; 4]; 8];
    for k in 0..npar {
        views[k] = buf[indices[k] as usize];
    }
    (views, npar)
}

#[inline(always)]
fn load_block_bytes(src: &[u8]) -> [u64; 4] {
    [
        u64::from_le_bytes(src[0..8].try_into().unwrap()),
        u64::from_le_bytes(src[8..16].try_into().unwrap()),
        u64::from_le_bytes(src[16..24].try_into().unwrap()),
        u64::from_le_bytes(src[24..32].try_into().unwrap()),
    ]
}

#[inline(always)]
fn xor_into(block: &mut [u64; 4], state: &[u64; 4]) {
    block[0] ^= state[0];
    block[1] ^= state[1];
    block[2] ^= state[2];
    block[3] ^= state[3];
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn prefetch_block(buf: &[[u64; 4]], idx: u32) {
    let ptr = buf.as_ptr().wrapping_add(idx as usize) as *const i8;
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr, core::arch::x86_64::_MM_HINT_T0);
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn prefetch_block(_buf: &[[u64; 4]], _idx: u32) {}

/// Per-thread scratch: one 16 MiB word-packed buffer. Reused across guesses.
pub struct PackedScratch {
    pub buf: Vec<[u64; 4]>,
    ring: [[u64; 4]; FW],
}

impl PackedScratch {
    pub fn new() -> Self {
        Self {
            buf: vec![[0u64; 4]; NUM_BLOCKS_16MIB],
            ring: [[0u64; 4]; FW],
        }
    }
}

fn bind_and_phantoms(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
) -> ([u8; 32], [[u64; 4]; 2]) {
    let seed = bind_seed(password, salt, cfg);
    let mut ph_bytes = [[0u8; 32]; 2];
    phantom_block(&seed, 0, 32, &mut ph_bytes[0]);
    phantom_block(&seed, 1, 32, &mut ph_bytes[1]);
    let ph = [
        load_block_bytes(&ph_bytes[0]),
        load_block_bytes(&ph_bytes[1]),
    ];
    (seed, ph)
}

fn digest_from(seed: &[u8; 32], state: &[u64; 4], last: &[u64; 4], cfg: &AntechConfig) -> [u8; 32] {
    let mut last_bytes = [0u8; 32];
    for i in 0..4 {
        last_bytes[i * 8..(i + 1) * 8].copy_from_slice(&last[i].to_le_bytes());
    }
    let v = finalize(seed, state, &last_bytes, cfg.graph);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[inline(always)]
fn apply_scatter(buf: &mut [[u64; 4]], i: u32, state: &[u64; 4], s1: i32, s2: i32) {
    if s1 >= 0 {
        let dest = s1 as u32;
        if dest < NUM_BLOCKS_16MIB as u32 && dest != i {
            xor_into(&mut buf[dest as usize], state);
        }
    }
    if s2 >= 0 {
        let dest = s2 as u32;
        if dest < NUM_BLOCKS_16MIB as u32 && dest != i {
            xor_into(&mut buf[dest as usize], state);
        }
    }
}

/// Packed words + frontier ring (same hits as production ring).
pub fn derive_packed_ring(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    scratch: &mut PackedScratch,
) -> [u8; 32] {
    let (seed, ph) = bind_and_phantoms(password, salt, cfg);
    let mut state = seed_to_state(&seed);
    let buf = &mut scratch.buf;
    let ring = &mut scratch.ring;
    let mut newest: i32 = -1;
    let mut count = 0u32;

    for i in 0..NUM_BLOCKS_16MIB as u32 {
        if i == 0 {
            let mut views = [[0u64; 4]; 8];
            views[0] = ph[0];
            views[1] = ph[1];
            mix_views(&mut state, &views, FAN);
        } else {
            let (li, ln) = parents_local(&state, i);
            let mut views = [[0u64; 4]; 8];
            let mut nv = 0usize;
            for k in 0..ln {
                let p = li[k];
                let in_ring = newest >= 0
                    && (p as i32) <= newest
                    && ((newest as u32).wrapping_sub(p) < count.min(FW as u32));
                views[nv] = if in_ring {
                    ring[(p as usize) % FW]
                } else {
                    buf[p as usize]
                };
                nv += 1;
            }
            mix_views(&mut state, &views, nv);

            let (ri, rn) = parents_remote(&state, i);
            nv = 0;
            for k in 0..rn {
                let p = ri[k];
                let in_ring = newest >= 0
                    && (p as i32) <= newest
                    && ((newest as u32).wrapping_sub(p) < count.min(FW as u32));
                views[nv] = if in_ring {
                    ring[(p as usize) % FW]
                } else {
                    buf[p as usize]
                };
                nv += 1;
            }
            mix_views(&mut state, &views, nv);
        }
        buf[i as usize] = state;
        ring[(i as usize) % FW] = state;
        newest = i as i32;
        count = (count + 1).min(FW as u32);
        let (s1, s2) = scatter_from_state(&state, i);
        apply_scatter(buf, i, &state, s1, s2);
    }
    digest_from(&seed, &state, &buf[NUM_BLOCKS_16MIB - 1], cfg)
}

/// Packed words, no ring (rely on store buffer / L1 of `buf[i]`).
pub fn derive_packed_noring(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    scratch: &mut PackedScratch,
) -> [u8; 32] {
    let (seed, ph) = bind_and_phantoms(password, salt, cfg);
    let mut state = seed_to_state(&seed);
    let buf = &mut scratch.buf;

    for i in 0..NUM_BLOCKS_16MIB as u32 {
        if i == 0 {
            let mut views = [[0u64; 4]; 8];
            views[0] = ph[0];
            views[1] = ph[1];
            mix_views(&mut state, &views, FAN);
        } else {
            let (li, ln) = parents_local(&state, i);
            let (views, nv) = load_views(buf, &li, ln);
            mix_views(&mut state, &views, nv);
            let (ri, rn) = parents_remote(&state, i);
            let (views, nv) = load_views(buf, &ri, rn);
            mix_views(&mut state, &views, nv);
        }
        buf[i as usize] = state;
        let (s1, s2) = scatter_from_state(&state, i);
        apply_scatter(buf, i, &state, s1, s2);
    }
    digest_from(&seed, &state, &buf[NUM_BLOCKS_16MIB - 1], cfg)
}

/// Packed + prefetch of gathered parents before each phase mix.
pub fn derive_packed_prefetch(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    scratch: &mut PackedScratch,
) -> [u8; 32] {
    let (seed, ph) = bind_and_phantoms(password, salt, cfg);
    let mut state = seed_to_state(&seed);
    let buf = &mut scratch.buf;

    for i in 0..NUM_BLOCKS_16MIB as u32 {
        if i == 0 {
            let mut views = [[0u64; 4]; 8];
            views[0] = ph[0];
            views[1] = ph[1];
            mix_views(&mut state, &views, FAN);
        } else {
            let (li, ln) = parents_local(&state, i);
            for k in 0..ln {
                prefetch_block(buf, li[k]);
            }
            let (views, nv) = load_views(buf, &li, ln);
            mix_views(&mut state, &views, nv);

            let (ri, rn) = parents_remote(&state, i);
            for k in 0..rn {
                prefetch_block(buf, ri[k]);
            }
            let (views, nv) = load_views(buf, &ri, rn);
            mix_views(&mut state, &views, nv);
        }
        buf[i as usize] = state;
        let (s1, s2) = scatter_from_state(&state, i);
        if s1 >= 0 {
            prefetch_block(buf, s1 as u32);
        }
        if s2 >= 0 {
            prefetch_block(buf, s2 as u32);
        }
        apply_scatter(buf, i, &state, s1, s2);
    }
    digest_from(&seed, &state, &buf[NUM_BLOCKS_16MIB - 1], cfg)
}

/// Two independent walks lock-stepped to hide far-gather latency.
pub fn derive_packed_dual(
    pw0: &[u8],
    pw1: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    a: &mut PackedScratch,
    b: &mut PackedScratch,
) -> ([u8; 32], [u8; 32]) {
    let (seed0, ph0) = bind_and_phantoms(pw0, salt, cfg);
    let (seed1, ph1) = bind_and_phantoms(pw1, salt, cfg);
    let mut s0 = seed_to_state(&seed0);
    let mut s1 = seed_to_state(&seed1);
    let buf0 = &mut a.buf;
    let buf1 = &mut b.buf;

    for i in 0..NUM_BLOCKS_16MIB as u32 {
        walk_one(i, &mut s0, buf0, &ph0);
        walk_one(i, &mut s1, buf1, &ph1);
    }
    (
        digest_from(&seed0, &s0, &buf0[NUM_BLOCKS_16MIB - 1], cfg),
        digest_from(&seed1, &s1, &buf1[NUM_BLOCKS_16MIB - 1], cfg),
    )
}

#[inline(always)]
fn walk_one(i: u32, state: &mut [u64; 4], buf: &mut [[u64; 4]], ph: &[[u64; 4]; 2]) {
    if i == 0 {
        let mut views = [[0u64; 4]; 8];
        views[0] = ph[0];
        views[1] = ph[1];
        mix_views(state, &views, FAN);
    } else {
        let (li, ln) = parents_local(state, i);
        for k in 0..ln {
            prefetch_block(buf, li[k]);
        }
        let (views, nv) = load_views(buf, &li, ln);
        mix_views(state, &views, nv);
        let (ri, rn) = parents_remote(state, i);
        for k in 0..rn {
            prefetch_block(buf, ri[k]);
        }
        let (views, nv) = load_views(buf, &ri, rn);
        mix_views(state, &views, nv);
    }
    buf[i as usize] = *state;
    let (s1, s2) = scatter_from_state(state, i);
    apply_scatter(buf, i, state, s1, s2);
}

/// Domain-separated SHA-256 is password-specific; precompute only constant hasher prefix
/// is not valid for the seed (password length is mixed in). Exposed so the report can
/// record that this reduction was attempted and rejected.
pub fn try_precompute_note() -> &'static str {
    "graph addresses are state-dependent; parent index tables cannot be precomputed per password. Seed SHA-256 includes password bytes. No cross-guess intermediate reuse without changing the digest."
}

/// Cheap output mix used only to keep SHA-256 off the hot path in microbench of the DAG
/// walk — NOT a valid attacker (digest would differ). Kept unused; real attackers always finalize.
#[allow(dead_code)]
fn dummy_fold(state: &[u64; 4]) -> u64 {
    state[0] ^ state[1] ^ state[2] ^ state[3]
}

pub fn sha256_hex(d: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(d);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_memory_v4::{GraphKind, V4Engine};
    use antech_kdf_types::AntechConfig;

    fn cfg() -> AntechConfig {
        AntechConfig::default()
            .with_memory_mib(16)
            .with_graph(GraphKind::CombinedFrontier)
    }

    #[test]
    fn packed_matches_reference_small_set() {
        let eng = V4Engine::new(GraphKind::CombinedFrontier);
        let cfg = cfg();
        let mut scratch = PackedScratch::new();
        let salt = b"v4_gpu_correct_salt";
        for i in 0..3 {
            let pw = format!("v4c_gpu_vector_{:02}", i);
            let refer = eng.derive_cfg(pw.as_bytes(), salt, &cfg).unwrap();
            let a = derive_packed_ring(pw.as_bytes(), salt, &cfg, &mut scratch);
            let b = derive_packed_noring(pw.as_bytes(), salt, &cfg, &mut scratch);
            let c = derive_packed_prefetch(pw.as_bytes(), salt, &cfg, &mut scratch);
            assert_eq!(refer.as_slice(), a.as_slice());
            assert_eq!(refer.as_slice(), b.as_slice());
            assert_eq!(refer.as_slice(), c.as_slice());
        }
    }
}
