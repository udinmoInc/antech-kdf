//! Screen small CombinedFrontier remote-parent variants vs packed attacker / defender.
//! Does not change production until a winner is selected.

use antech_kdf::{hash_with_config_and_salt, AntechConfig, GraphKind};
use antech_kdf_core::state::{bind_seed, finalize, phantom_block, seed_to_state};
use antech_kdf_research::compute_memory_v4::attacker_opt::PackedScratch;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const C1: u64 = 0xBF58476D1CE4E5B9;
const C2: u64 = 0x94D049BB133111EB;
const GOLDEN: u64 = 0x9E3779B97F4A7C15;
const MIX_ROUNDS: u32 = 4;
const FW: usize = 64;
const TILE: usize = 512;
const FAN: usize = 2;
const N: usize = 16 * 1024 * 1024 / 32;

#[derive(Clone, Copy, Debug)]
enum Variant {
    V5,
    FarAlways2,
    GlobalTile,
    FarMul,
    FarAlways2Global,
    FarAlways2Mul,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::V5 => "v5",
            Variant::FarAlways2 => "far_always2",
            Variant::GlobalTile => "global_tile",
            Variant::FarMul => "far_mul",
            Variant::FarAlways2Global => "far2_global",
            Variant::FarAlways2Mul => "far2_mul",
        }
    }
    fn all() -> &'static [Variant] {
        &[
            Variant::V5,
            Variant::FarAlways2,
            Variant::GlobalTile,
            Variant::FarMul,
            Variant::FarAlways2Global,
            Variant::FarAlways2Mul,
        ]
    }
}

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

#[inline(always)]
fn parents_remote(v: Variant, state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut indices = [0u32; 8];
    let mut len = 0usize;
    if i == 0 {
        return (indices, 0);
    }
    let i_us = i as usize;
    let tile = TILE;
    let tile_start = (i_us / tile) * tile;
    let critical = (i_us % 4 == 0) || (i_us % FW == 0);
    let fw = FW.min(i_us);
    let always2 = matches!(
        v,
        Variant::FarAlways2 | Variant::FarAlways2Global | Variant::FarAlways2Mul
    );
    let global_tile = matches!(v, Variant::GlobalTile | Variant::FarAlways2Global);
    let far_mul = matches!(v, Variant::FarMul | Variant::FarAlways2Mul);

    if global_tile {
        if i_us > 1 {
            push_unique(
                &mut indices,
                &mut len,
                ((state[1] as usize) % i_us) as u32,
                i,
            );
        }
    } else if i_us > tile_start + 1 {
        let span = i_us - tile_start;
        let local_remote = tile_start + ((state[1] as usize) % span);
        push_unique(&mut indices, &mut len, local_remote as u32, i);
    }

    if i_us > fw + 1 {
        let remote_span = i_us - fw;
        let far = if far_mul {
            (state[1]
                .wrapping_mul(GOLDEN)
                .wrapping_add(state[3].rotate_left(11)) as usize)
                % remote_span
        } else {
            ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span
        };
        push_unique(&mut indices, &mut len, far as u32, i);
        if always2 || critical {
            let far2 = if far_mul {
                (state[0]
                    .wrapping_mul(C1)
                    .wrapping_add(GOLDEN.wrapping_mul(i as u64)) as usize)
                    % remote_span
            } else {
                ((state[0] ^ GOLDEN) as usize) % remote_span
            };
            push_unique(&mut indices, &mut len, far2 as u32, i);
        }
    }

    let mut guard = 0usize;
    while len < FAN && guard < 4 {
        guard += 1;
        let mix = state[len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = len;
        let addr = if global_tile {
            (mix as usize) % i_us
        } else if i_us > tile_start {
            tile_start + ((mix as usize) % (i_us - tile_start).max(1))
        } else {
            (mix as usize) % i_us
        };
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

fn load_block_bytes(src: &[u8]) -> [u64; 4] {
    [
        u64::from_le_bytes(src[0..8].try_into().unwrap()),
        u64::from_le_bytes(src[8..16].try_into().unwrap()),
        u64::from_le_bytes(src[16..24].try_into().unwrap()),
        u64::from_le_bytes(src[24..32].try_into().unwrap()),
    ]
}

fn derive_variant(
    v: Variant,
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    scratch: &mut PackedScratch,
) -> [u8; 32] {
    let seed = bind_seed(password, salt, cfg);
    let mut ph_bytes = [[0u8; 32]; 2];
    phantom_block(&seed, 0, 32, &mut ph_bytes[0]);
    phantom_block(&seed, 1, 32, &mut ph_bytes[1]);
    let ph = [
        load_block_bytes(&ph_bytes[0]),
        load_block_bytes(&ph_bytes[1]),
    ];
    let mut state = seed_to_state(&seed);
    let buf = &mut scratch.buf;

    for i in 0..N as u32 {
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
            let mut views = [[0u64; 4]; 8];
            for k in 0..ln {
                views[k] = buf[li[k] as usize];
            }
            mix_views(&mut state, &views, ln);

            let (ri, rn) = parents_remote(v, &state, i);
            for k in 0..rn {
                prefetch_block(buf, ri[k]);
            }
            for k in 0..rn {
                views[k] = buf[ri[k] as usize];
            }
            mix_views(&mut state, &views, rn);
        }
        buf[i as usize] = state;
        let (s1, s2) = scatter_from_state(&state, i);
        if s1 >= 0 {
            let d = s1 as usize;
            if d < N && d != i as usize {
                buf[d][0] ^= state[0];
                buf[d][1] ^= state[1];
                buf[d][2] ^= state[2];
                buf[d][3] ^= state[3];
            }
        }
        if s2 >= 0 {
            let d = s2 as usize;
            if d < N && d != i as usize {
                buf[d][0] ^= state[0];
                buf[d][1] ^= state[1];
                buf[d][2] ^= state[2];
                buf[d][3] ^= state[3];
            }
        }
    }
    let mut last_bytes = [0u8; 32];
    for w in 0..4 {
        last_bytes[w * 8..(w + 1) * 8].copy_from_slice(&buf[N - 1][w].to_le_bytes());
    }
    let dig = finalize(&seed, &state, &last_bytes, cfg.graph);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

fn main() {
    let cfg = AntechConfig::builder()
        .memory_mib(16)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    let salt = b"v5_cost_salt_16b";
    assert_eq!(salt.len(), 16);
    let window = Duration::from_millis(900);
    let warmup = Duration::from_millis(250);

    println!("=== production engine defender (packed TLS path) ===");
    let mut samples = Vec::new();
    for i in 0..36 {
        let pw = format!("def_{i}");
        let t0 = Instant::now();
        let _ = hash_with_config_and_salt(pw.as_bytes(), salt, &cfg).unwrap();
        samples.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "prod_defender_ms p50={:.1} p95={:.1} p99={:.1}",
        percentile(&samples, 50.0),
        percentile(&samples, 95.0),
        percentile(&samples, 99.0)
    );

    println!("=== variant screen (defender=variant walk; attacker=same+prefetch) ===");
    println!("variant,def_p50_ms,att_1t,att_16t,att_32t,cyc_16t,eff_16t");

    for &v in Variant::all() {
        // Defender: variant walk (matches what production would be if this graph landed)
        let mut ds = Vec::new();
        let mut scratch = PackedScratch::new();
        for i in 0..28 {
            let pw = format!("vd_{i}");
            let t0 = Instant::now();
            let _ = derive_variant(v, pw.as_bytes(), salt, &cfg, &mut scratch);
            ds.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        ds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let def_p50 = percentile(&ds, 50.0);

        let mut gps = [0.0f64; 3];
        let mut cyc16 = 0.0f64;
        let thread_set = [1usize, 16, 32];
        for (ti, &threads) in thread_set.iter().enumerate() {
            {
                let mut scratch = PackedScratch::new();
                let end = Instant::now() + warmup;
                let mut i = 0u64;
                while Instant::now() < end {
                    let pw = format!("w_{i}");
                    let _ = derive_variant(v, pw.as_bytes(), salt, &cfg, &mut scratch);
                    i += 1;
                }
            }
            let counter = Arc::new(AtomicU64::new(0));
            let cycles = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(AtomicU64::new(0));
            let t0 = Instant::now();
            std::thread::scope(|s| {
                for t in 0..threads {
                    let counter = Arc::clone(&counter);
                    let cycles = Arc::clone(&cycles);
                    let stop = Arc::clone(&stop);
                    let cfg = cfg;
                    s.spawn(move || {
                        let mut scratch = PackedScratch::new();
                        let mut i = t as u64;
                        while stop.load(Ordering::Relaxed) == 0 {
                            let pw = format!("a_{i}");
                            let c0 = rdtsc();
                            let _ = derive_variant(v, pw.as_bytes(), salt, &cfg, &mut scratch);
                            let c1 = rdtsc();
                            cycles.fetch_add(c1.wrapping_sub(c0), Ordering::Relaxed);
                            counter.fetch_add(1, Ordering::Relaxed);
                            i += threads as u64;
                        }
                    });
                }
                std::thread::sleep(window);
                stop.store(1, Ordering::Relaxed);
            });
            let total = counter.load(Ordering::Relaxed);
            let secs = t0.elapsed().as_secs_f64();
            gps[ti] = total as f64 / secs;
            if threads == 16 && total > 0 {
                cyc16 = cycles.load(Ordering::Relaxed) as f64 / total as f64;
            }
        }
        let eff16 = if gps[0] > 0.0 {
            gps[1] / (gps[0] * 16.0)
        } else {
            0.0
        };
        println!(
            "{},{:.1},{:.2},{:.2},{:.2},{:.0},{:.3}",
            v.name(),
            def_p50,
            gps[0],
            gps[1],
            gps[2],
            cyc16,
            eff16
        );
    }
}
