# Construction v5 asymmetry pass — dual-global + cold far

**Date:** 2026-08-27  
**Host:** Windows / RTX 3050 8 GiB / CUDA 13.3  
**Public API / `$antech$v2$` / `CONSTRUCTION_VERSION = 5`:** unchanged. Digests changed vs prior far2+global.

Not a security proof. Figures are **MEASURED**.

## Verdict

**20–30 g/s at 16/32T was not reached** under honest work with defender p50 ≤ 140 ms.

**Best measured under-budget ship:** dual independent global gathers + always-2 far with a **colder** far span (`cold = max(512, frontier)`), still two-phase post-local, dual scatter preserved.

| Metric | Prior far2+global | **This ship** |
|---|---:|---:|
| Defender p50 | ~118–126 ms | **~131 ms** |
| Peak CPU @ 16T | ~43–45 g/s | **~43.1 g/s** (`packed_prefetch`) |
| Peak CPU @ 32T | ~45 g/s | **~44.4 g/s** (`packed_prefetch`) |
| Best GPU | ~86 g/s | **~74.9 g/s** (`packed_t32_b256`) |
| Argon2id CPU @16T | ~23 g/s | **23.0 g/s** |

Still ≈ **1.9×** Argon2id CPU. Gap to 20–25 g/s remains structural.

## What was tried (and rejected / kept)

| Candidate | def p50 (screen) | att 16/32 | Decision |
|---|---:|---:|---|
| far2_global (prior) | ~114–126 | ~38–43 | baseline |
| far_xorall | mixed / noisy | no stable win | reject |
| **global2_far2** | ~113–135 | screen ~34; prod ~41 | **keep (core of ship)** |
| far_chain (serialize far2) | **146–136** | ~34–35 | **reject** (p50 > 140) |
| chain_oldhalf / chain_lite / triple | ≥150 / ≥160 / ~190 | ~29–35 | **reject** |
| g2 + chain_crit | ~150 | ~36 | **reject** |
| remote_serial mix | ~110 | ~40 | reject (no MT win) |
| **cold far span (512)** | ~131 | ~41–44 | **keep** (forces colder fars; p50 OK) |

Full far chaining cuts MT toward ~30–35 g/s but pushes defender past 140 ms. Critical-only chaining still overshot. No screened change delivered 20–30 g/s inside the latency budget without artificial delay / pass inflation / node doubling.

## What shipped into production

In `combined_remote_parents` (post-local phase):

1. **Dual global gathers:** `(S[1] % i)` and `((S[2] ⊕ rotl(S[0],13)) % i)`.
2. **Always-2 far** with `remote_span = i − cold`, `cold = max(min(TILE_BLOCKS,512), frontier)`.
3. Dual scatter still from final post-mix state.
4. Word-packed CombinedFrontier engine unchanged.

Synced: CPU packed attackers, reference, CUDA (`d_parents_remote` + `_fast`), spec §10.2, vectors.

## Defender

Source: `v5-asymm/microbench-g2-cold.log` (production `hash`).

| | p50 | p95 | p99 | mean |
|---|---:|---:|---:|---:|
| Prior far2+global | 118.4 | 128.1 | 148.0 | 119.8 |
| **dual-global + cold** | **131.2** | **184.2** | **225.6** | **141.9** |

p50 is inside ≤140 ms. Tail latency is noisier on this host (thermal / contention).

## Strongest CPU attacker (full suite)

Source: `attacker-optimization/cpu-scaling.csv` (1.2 s window). Peak = **packed_prefetch**.

| Impl | 1T | 8T | 16T | 32T |
|---|---:|---:|---:|---:|
| production_engine | 7.81 | 31.69 | 39.81 | 34.14 |
| packed_ring | 8.73 | 33.45 | 42.90 | 41.95 |
| packed_noring | 6.18 | 34.07 | 42.46 | 42.48 |
| **packed_prefetch** | **8.79** | **34.32** | **43.10** | **44.41** |
| packed_dual_lockstep | 7.12 | 31.08 | 32.48 | 39.68 |
| Argon2id | 9.82 | 23.27 | 23.04 | 25.34 |

## GPU (RTX 3050)

CUDA **100/100** match for baseline / packed / packed_noring / packed_persistent.

| Mode | g/s |
|---|---:|
| packed | 54.65 |
| packed_noring | 56.83 |
| packed_t16_b192 | 63.20 |
| **packed_t32_b256 (best)** | **74.94** |

Argon2id GPU: **434.7 g/s**.

## Correctness / TMTO

| Check | Result |
|---|---|
| CPU packed vs production | 10/50/100 OK |
| CUDA vs production | 10/50/100 OK |
| `word_path_matches_byte_path_1mib` | PASS |
| `full_packed_matches_engine` | PASS |
| `scatter_log_full_matches_engine` | PASS |
| Cryptanalysis catalog | no digest-preserving DAG shortcut |
| Sparse TMTO | FAIL/WALL; scatter-log correct but slower / more RAM |

Instrumented walk (16 MiB): parent_gathers ≈ **3.14e6**, far hits ≈ **2.09e6** (up vs prior far2+global — expected from dual-global + cold fars).

## Why 20–25 g/s is not available here

Far chaining (true post-far1 dependency for far2) is the only screened lever that moved MT toward the low-30s, and it costs ~15–25 ms defender p50 — enough to break 140 ms. Extra global gathers and colder far spans increase gather count and cache hostility but only shave a few g/s at 16/32T once the packed attacker is already memory-bound on 16 MiB × N walks.

Bottleneck remains: **524288 serial state-dependent nodes** + dual scatter over a live 16 MiB buffer.

## Reproduce

```bash
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example v5_cost_microbench
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example attacker_optimization_runner
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example tmto_advanced_runner
```

Screen logs: `research/results/compute-memory-v4/v5-asymm/`.
