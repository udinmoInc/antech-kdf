//! Quick measure: global2 baseline vs critical-only far2 chaining.

use antech_kdf_core::state::{bind_seed, finalize, phantom_block, seed_to_state};
use antech_kdf_research::compute_memory_v4::attacker_opt::PackedScratch;
use antech_kdf_types::{AntechConfig, GraphKind};
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

#[derive(Clone, Copy)]
enum V {
    Global2,
    Global2ChainCrit,
}

#[inline(always)]
fn mix_pair(state: &mut [u64; 4], a: &[u64; 4], b: &[u64; 4]) {
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
        mix_pair(state, &views[0], &views[0]);
        return;
    }
    let mut i = 0;
    while i + 1 < n {
        mix_pair(state, &views[i], &views[i + 1]);
        i += 2;
    }
    if i < n {
        mix_pair(state, &views[i], &views[i]);
    }
}

#[inline(always)]
fn push_u(ix: &mut [u32; 8], len: &mut usize, addr: u32, i: u32) {
    if (addr as usize) >= i as usize || *len >= 8 {
        return;
    }
    for j in 0..*len {
        if ix[j] == addr {
            return;
        }
    }
    ix[*len] = addr;
    *len += 1;
}

fn local_p(state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut ix = [0u32; 8];
    let mut len = 0;
    let i_us = i as usize;
    push_u(&mut ix, &mut len, (i_us - 1) as u32, i);
    let fw = FW.min(i_us);
    push_u(&mut ix, &mut len, (i_us - 1 - ((state[0] as usize) % fw)) as u32, i);
    let mut g = 0;
    while len < FAN && g < FAN + 4 {
        g += 1;
        let mix = state[len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = len;
        push_u(&mut ix, &mut len, (i_us - 1 - ((mix as usize) % fw)) as u32, i);
        if len == before {
            break;
        }
    }
    (ix, len)
}

fn is_crit(i: usize) -> bool {
    i % 4 == 0 || i % FW == 0
}

fn remote_a(v: V, state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut ix = [0u32; 8];
    let mut len = 0;
    let i_us = i as usize;
    let fw = FW.min(i_us);
    if i_us > 1 {
        push_u(&mut ix, &mut len, ((state[1] as usize) % i_us) as u32, i);
        push_u(
            &mut ix,
            &mut len,
            (((state[2] ^ state[0].rotate_left(13)) as usize) % i_us) as u32,
            i,
        );
    }
    if i_us > fw + 1 {
        let rs = i_us - fw;
        let far = ((state[1] ^ state[3].rotate_left(11)) as usize) % rs;
        push_u(&mut ix, &mut len, far as u32, i);
        let chain = matches!(v, V::Global2ChainCrit) && is_crit(i_us);
        if !chain {
            let far2 = ((state[0] ^ GOLDEN) as usize) % rs;
            push_u(&mut ix, &mut len, far2 as u32, i);
        }
    }
    (ix, len)
}

fn remote_b(v: V, state: &[u64; 4], i: u32) -> ([u32; 8], usize) {
    let mut ix = [0u32; 8];
    let mut len = 0;
    let i_us = i as usize;
    if !matches!(v, V::Global2ChainCrit) || !is_crit(i_us) {
        return (ix, len);
    }
    let fw = FW.min(i_us);
    if i_us > fw + 1 {
        let rs = i_us - fw;
        let far2 = ((state[0] ^ GOLDEN) as usize) % rs;
        push_u(&mut ix, &mut len, far2 as u32, i);
    }
    (ix, len)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn pref(buf: &[[u64; 4]], idx: u32) {
    let ptr = buf.as_ptr().wrapping_add(idx as usize) as *const i8;
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr, core::arch::x86_64::_MM_HINT_T0);
    }
}
#[cfg(not(target_arch = "x86_64"))]
fn pref(_: &[[u64; 4]], _: u32) {}

fn gather(state: &mut [u64; 4], buf: &[[u64; 4]], ix: &[u32; 8], n: usize) {
    if n == 0 {
        return;
    }
    for k in 0..n {
        pref(buf, ix[k]);
    }
    let mut views = [[0u64; 4]; 8];
    for k in 0..n {
        views[k] = buf[ix[k] as usize];
    }
    mix_views(state, &views, n);
}

fn derive(v: V, pw: &[u8], salt: &[u8], cfg: &AntechConfig, scratch: &mut PackedScratch) -> [u8; 32] {
    let seed = bind_seed(pw, salt, cfg);
    let mut phb = [[0u8; 32]; 2];
    phantom_block(&seed, 0, 32, &mut phb[0]);
    phantom_block(&seed, 1, 32, &mut phb[1]);
    let ph = [
        [
            u64::from_le_bytes(phb[0][0..8].try_into().unwrap()),
            u64::from_le_bytes(phb[0][8..16].try_into().unwrap()),
            u64::from_le_bytes(phb[0][16..24].try_into().unwrap()),
            u64::from_le_bytes(phb[0][24..32].try_into().unwrap()),
        ],
        [
            u64::from_le_bytes(phb[1][0..8].try_into().unwrap()),
            u64::from_le_bytes(phb[1][8..16].try_into().unwrap()),
            u64::from_le_bytes(phb[1][16..24].try_into().unwrap()),
            u64::from_le_bytes(phb[1][24..32].try_into().unwrap()),
        ],
    ];
    let mut state = seed_to_state(&seed);
    let buf = &mut scratch.buf;
    for i in 0..N as u32 {
        if i == 0 {
            let mut views = [[0u64; 4]; 8];
            views[0] = ph[0];
            views[1] = ph[1];
            mix_views(&mut state, &views, 2);
        } else {
            let (li, ln) = local_p(&state, i);
            gather(&mut state, buf, &li, ln);
            let (a, an) = remote_a(v, &state, i);
            gather(&mut state, buf, &a, an);
            let (b, bn) = remote_b(v, &state, i);
            gather(&mut state, buf, &b, bn);
        }
        buf[i as usize] = state;
        let fw = FW.min(i as usize);
        if (i as usize) > fw {
            let span = (i as usize) - fw;
            for d in [
                ((state[2] ^ GOLDEN) as usize) % span,
                ((state[3] ^ state[0].rotate_left(7)) as usize) % span,
            ] {
                if d < N && d != i as usize {
                    buf[d][0] ^= state[0];
                    buf[d][1] ^= state[1];
                    buf[d][2] ^= state[2];
                    buf[d][3] ^= state[3];
                }
            }
        }
    }
    let mut last = [0u8; 32];
    for w in 0..4 {
        last[w * 8..(w + 1) * 8].copy_from_slice(&buf[N - 1][w].to_le_bytes());
    }
    let dig = finalize(&seed, &state, &last, cfg.graph);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

fn pct(s: &[f64], p: f64) -> f64 {
    let i = ((p / 100.0) * (s.len() as f64 - 1.0)).round() as usize;
    s[i.min(s.len() - 1)]
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
    for (name, v) in [("global2", V::Global2), ("g2_chain_crit", V::Global2ChainCrit)] {
        let mut ds = Vec::new();
        let mut scratch = PackedScratch::new();
        for i in 0..32 {
            let t0 = Instant::now();
            let _ = derive(v, format!("d{i}").as_bytes(), salt, &cfg, &mut scratch);
            ds.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        ds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        print!("{name} def_p50={:.1} def_p95={:.1}", pct(&ds, 50.0), pct(&ds, 95.0));
        for &threads in &[1usize, 16, 32] {
            {
                let mut scratch = PackedScratch::new();
                let end = Instant::now() + warmup;
                let mut i = 0u64;
                while Instant::now() < end {
                    let _ = derive(v, format!("w{i}").as_bytes(), salt, &cfg, &mut scratch);
                    i += 1;
                }
            }
            let counter = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(AtomicU64::new(0));
            let t0 = Instant::now();
            std::thread::scope(|s| {
                for t in 0..threads {
                    let counter = Arc::clone(&counter);
                    let stop = Arc::clone(&stop);
                    let cfg = cfg;
                    s.spawn(move || {
                        let mut scratch = PackedScratch::new();
                        let mut i = t as u64;
                        while stop.load(Ordering::Relaxed) == 0 {
                            let _ = derive(v, format!("a{i}").as_bytes(), salt, &cfg, &mut scratch);
                            counter.fetch_add(1, Ordering::Relaxed);
                            i += threads as u64;
                        }
                    });
                }
                std::thread::sleep(window);
                stop.store(1, Ordering::Relaxed);
            });
            print!(
                " att_{threads}t={:.2}",
                counter.load(Ordering::Relaxed) as f64 / t0.elapsed().as_secs_f64()
            );
        }
        println!();
    }
}
