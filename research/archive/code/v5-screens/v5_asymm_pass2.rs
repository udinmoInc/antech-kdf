//! Second-pass screen: best asymm candidates + combos, longer windows.

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
const FAN: usize = 2;
const N: usize = 16 * 1024 * 1024 / 32;

#[derive(Clone, Copy, Debug)]
enum Variant {
    Far2Global,
    FarXorAll,
    Global2Far2,
    Global2XorAll,
    FarChain,
    ChainOldHalf,
    /// Phase A: global only; Phase B: both fars from post-global state.
    ChainLite,
    /// Phase A: global; B: far1; C: far2 (full triple serialize).
    TripleChain,
    XorAllOldHalf,
    /// global2 + far_chain
    Global2Chain,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Far2Global => "far2_global",
            Variant::FarXorAll => "far_xorall",
            Variant::Global2Far2 => "global2_far2",
            Variant::Global2XorAll => "global2_xorall",
            Variant::FarChain => "far_chain",
            Variant::ChainOldHalf => "chain_oldhalf",
            Variant::ChainLite => "chain_lite",
            Variant::TripleChain => "triple_chain",
            Variant::XorAllOldHalf => "xorall_oldhalf",
            Variant::Global2Chain => "global2_chain",
        }
    }
    fn all() -> &'static [Variant] {
        &[
            Variant::Far2Global,
            Variant::FarXorAll,
            Variant::Global2Far2,
            Variant::Global2XorAll,
            Variant::XorAllOldHalf,
            Variant::ChainLite,
            Variant::FarChain,
            Variant::ChainOldHalf,
            Variant::Global2Chain,
            Variant::TripleChain,
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
fn map_oldhalf(idx: usize, remote_span: usize) -> usize {
    idx % (remote_span / 2).max(1)
}

#[inline(always)]
fn use_xorall(v: Variant) -> bool {
    matches!(
        v,
        Variant::FarXorAll | Variant::Global2XorAll | Variant::XorAllOldHalf
    )
}

#[inline(always)]
fn use_oldhalf(v: Variant) -> bool {
    matches!(
        v,
        Variant::ChainOldHalf | Variant::XorAllOldHalf
    )
}

#[inline(always)]
fn use_global2(v: Variant) -> bool {
    matches!(
        v,
        Variant::Global2Far2 | Variant::Global2XorAll | Variant::Global2Chain
    )
}

#[inline(always)]
fn far1_addr(v: Variant, state: &[u64; 4], remote_span: usize) -> usize {
    let raw = if use_xorall(v) {
        (state[0] ^ state[1].rotate_left(11) ^ state[2].wrapping_mul(C1) ^ state[3]) as usize
            % remote_span
    } else {
        ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span
    };
    if use_oldhalf(v) {
        map_oldhalf(raw, remote_span)
    } else {
        raw
    }
}

#[inline(always)]
fn far2_addr(v: Variant, state: &[u64; 4], remote_span: usize) -> usize {
    let raw = if use_xorall(v) {
        (state[0]
            .wrapping_mul(GOLDEN)
            .wrapping_add(state[1] ^ state[2].rotate_left(7))
            .wrapping_add(state[3].rotate_left(19)) as usize)
            % remote_span
    } else {
        ((state[0] ^ GOLDEN) as usize) % remote_span
    };
    if use_oldhalf(v) {
        map_oldhalf(raw, remote_span)
    } else {
        raw
    }
}

#[derive(Clone, Copy)]
enum PhaseKind {
    /// Current: global(+g2)+far1+far2 in one shot; no phase B/C.
    Flat,
    /// A: global(+g2)+far1; B: far2
    ChainFar2,
    /// A: global(+g2); B: far1+far2
    ChainLite,
    /// A: global(+g2); B: far1; C: far2
    Triple,
}

fn phase_kind(v: Variant) -> PhaseKind {
    match v {
        Variant::FarChain | Variant::ChainOldHalf | Variant::Global2Chain => PhaseKind::ChainFar2,
        Variant::ChainLite => PhaseKind::ChainLite,
        Variant::TripleChain => PhaseKind::Triple,
        _ => PhaseKind::Flat,
    }
}

fn push_globals(indices: &mut [u32; 8], len: &mut usize, v: Variant, state: &[u64; 4], i: u32) {
    let i_us = i as usize;
    if i_us > 1 {
        push_unique(indices, len, ((state[1] as usize) % i_us) as u32, i);
        if use_global2(v) {
            push_unique(
                indices,
                len,
                ((state[2] ^ state[0].rotate_left(13)) as usize % i_us) as u32,
                i,
            );
        }
    }
}

fn fill_fan(indices: &mut [u32; 8], len: &mut usize, state: &[u64; 4], i: u32) {
    let i_us = i as usize;
    let mut guard = 0usize;
    while *len < FAN && guard < 4 {
        guard += 1;
        let mix = state[*len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = *len;
        push_unique(indices, len, ((mix as usize) % i_us) as u32, i);
        if *len == before {
            break;
        }
    }
}

fn parents_phase_a(v: Variant, state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut indices = [0u32; 8];
    let mut len = 0usize;
    if i == 0 {
        return (indices, 0);
    }
    let i_us = i as usize;
    let fw = FW.min(i_us);
    let pk = phase_kind(v);
    push_globals(&mut indices, &mut len, v, state, i);
    if i_us > fw + 1 {
        let remote_span = i_us - fw;
        match pk {
            PhaseKind::Flat => {
                push_unique(
                    &mut indices,
                    &mut len,
                    far1_addr(v, state, remote_span) as u32,
                    i,
                );
                push_unique(
                    &mut indices,
                    &mut len,
                    far2_addr(v, state, remote_span) as u32,
                    i,
                );
            }
            PhaseKind::ChainFar2 => {
                push_unique(
                    &mut indices,
                    &mut len,
                    far1_addr(v, state, remote_span) as u32,
                    i,
                );
            }
            PhaseKind::ChainLite | PhaseKind::Triple => {}
        }
    }
    fill_fan(&mut indices, &mut len, state, i);
    (indices, len)
}

fn parents_phase_b(v: Variant, state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut indices = [0u32; 8];
    let mut len = 0usize;
    if i == 0 {
        return (indices, 0);
    }
    let i_us = i as usize;
    let fw = FW.min(i_us);
    if i_us <= fw + 1 {
        return (indices, 0);
    }
    let remote_span = i_us - fw;
    match phase_kind(v) {
        PhaseKind::Flat => {}
        PhaseKind::ChainFar2 => {
            push_unique(
                &mut indices,
                &mut len,
                far2_addr(v, state, remote_span) as u32,
                i,
            );
        }
        PhaseKind::ChainLite => {
            push_unique(
                &mut indices,
                &mut len,
                far1_addr(v, state, remote_span) as u32,
                i,
            );
            push_unique(
                &mut indices,
                &mut len,
                far2_addr(v, state, remote_span) as u32,
                i,
            );
        }
        PhaseKind::Triple => {
            push_unique(
                &mut indices,
                &mut len,
                far1_addr(v, state, remote_span) as u32,
                i,
            );
        }
    }
    (indices, len)
}

fn parents_phase_c(v: Variant, state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut indices = [0u32; 8];
    let mut len = 0usize;
    if !matches!(phase_kind(v), PhaseKind::Triple) || i == 0 {
        return (indices, 0);
    }
    let i_us = i as usize;
    let fw = FW.min(i_us);
    if i_us > fw + 1 {
        let remote_span = i_us - fw;
        push_unique(
            &mut indices,
            &mut len,
            far2_addr(v, state, remote_span) as u32,
            i,
        );
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

fn gather_mix(
    state: &mut [u64; 4],
    buf: &[[u64; 4]],
    indices: &[u32; 8],
    len: usize,
) {
    if len == 0 {
        return;
    }
    for k in 0..len {
        prefetch_block(buf, indices[k]);
    }
    let mut views = [[0u64; 4]; 8];
    for k in 0..len {
        views[k] = buf[indices[k] as usize];
    }
    mix_views(state, &views, len);
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
            gather_mix(&mut state, buf, &li, ln);
            let (a, an) = parents_phase_a(v, &state, i);
            gather_mix(&mut state, buf, &a, an);
            let (b, bn) = parents_phase_b(v, &state, i);
            gather_mix(&mut state, buf, &b, bn);
            let (c, cn) = parents_phase_c(v, &state, i);
            gather_mix(&mut state, buf, &c, cn);
        }
        buf[i as usize] = state;
        let (s1, s2) = scatter_from_state(&state, i);
        for s in [s1, s2] {
            if s >= 0 {
                let d = s as usize;
                if d < N && d != i as usize {
                    buf[d][0] ^= state[0];
                    buf[d][1] ^= state[1];
                    buf[d][2] ^= state[2];
                    buf[d][3] ^= state[3];
                }
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
    let window = Duration::from_millis(1200);
    let warmup = Duration::from_millis(300);

    println!("=== production defender ===");
    let mut samples = Vec::new();
    for i in 0..40 {
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

    println!("=== pass2 screen ===");
    println!("variant,def_p50,def_p95,att_1,att_2,att_4,att_8,att_16,att_32,cyc16,eff16");

    for &v in Variant::all() {
        let mut ds = Vec::new();
        let mut scratch = PackedScratch::new();
        for i in 0..32 {
            let pw = format!("vd_{i}");
            let t0 = Instant::now();
            let _ = derive_variant(v, pw.as_bytes(), salt, &cfg, &mut scratch);
            ds.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        ds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let def_p50 = percentile(&ds, 50.0);
        let def_p95 = percentile(&ds, 95.0);

        let mut gps = [0.0f64; 6];
        let mut cyc16 = 0.0f64;
        for (ti, &threads) in [1usize, 2, 4, 8, 16, 32].iter().enumerate() {
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
            gps[ti] = total as f64 / t0.elapsed().as_secs_f64();
            if threads == 16 && total > 0 {
                cyc16 = cycles.load(Ordering::Relaxed) as f64 / total as f64;
            }
        }
        let eff16 = if gps[0] > 0.0 {
            gps[4] / (gps[0] * 16.0)
        } else {
            0.0
        };
        println!(
            "{},{:.1},{:.1},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.0},{:.3}",
            v.name(),
            def_p50,
            def_p95,
            gps[0],
            gps[1],
            gps[2],
            gps[3],
            gps[4],
            gps[5],
            cyc16,
            eff16
        );
    }
}
