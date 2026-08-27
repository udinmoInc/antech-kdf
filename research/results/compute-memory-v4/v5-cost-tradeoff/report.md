# Construction v5 cost tradeoff (CombinedFrontier, 16 MiB) — far2+global iteration

**Date:** 2026-08-27  
**Host:** Windows box (RTX 3050 8 GiB, CUDA 13.3).  
**Public API / `$antech$v2$` / `CONSTRUCTION_VERSION = 5`:** unchanged. Digests changed vs early-v5 because remote-parent addressing changed.

This is **not** a cryptographic security proof. Figures are **MEASURED** unless labeled otherwise.

## Verdict

The **20–25 g/s** (or even 20–30 g/s) CPU target at 16/32 threads was **not reached** under honest work and defender p50 ≤ 140 ms.

**Best measured Pareto candidate (shipped):** word-packed CombinedFrontier path + **always-2 far** + **global** (not tile-local) remote secondary gather.

| Metric | Early two-phase v5 | **far2+global (current)** |
|---|---:|---:|
| Defender p50 | 128.9 ms | **118.4 ms** |
| Strongest CPU @ 16T | ~52.4 g/s (`packed_prefetch`) | **~43.6 g/s** (`packed_ring`; suite) |
| Strongest CPU @ 32T | ~49.9 g/s | **~45.4 g/s** (`packed_noring`; suite) |
| Best GPU | 97.7 g/s | **86.0 g/s** (`packed_t32_b256`) |

Still ≈ **1.9×** Argon2id CPU @ 16T on this host (~22.7 g/s). Gap to 20–25 g/s remains structural (see below).

## What changed in this iteration

1. **Production engine:** CombinedFrontier @ 32 B uses `derive_combined_frontier_words` + TLS `WORD_BUF` reuse (digest-preserving; byte path retained for other graphs).
2. **Graph remotes (`combined_remote_parents`):**
   - Secondary gather: `state[1] % i` **globally** (was tile-local).
   - Far: **always two** post-local far parents on every eligible node (was one far always + second far on critical only).
   - Dual scatter unchanged (still from post-both-mixes state).
3. Attackers / CUDA / reference synced. Vectors regenerated.

No MIX_ROUNDS inflation, no extra DAG passes, no sleeps / fake work.

## Variant screen (evidence)

Source: `research/results/v5-tradeoff-variants.log`.

| Variant | def p50 ms | att 16T | att 32T |
|---|---:|---:|---:|
| early v5 (screen walk) | 100.7 | 43.15 | 50.86 |
| far_always2 | 122.8 | 38.79 | 46.97 |
| global_tile | 99.8 | 41.85 | 42.73 |
| far_mul | 90.9 | 52.02 | 48.82 |
| **far2_global** | **105.6** | **45.56** | **45.42** |
| far2_mul | 102.4 | 44.86 | 40.60 |

Microbench after shipping into production (`v5-cost-microbench-far2-global.log`): defender **p50=118.4** / p95=128.1 / p99=148.0; packed_prefetch 47.1 / 39.1 g/s @ 16/32T.

`far3+*` variants pushed defender toward/over ~131–135 ms for only modest attacker cuts — rejected under the 140 ms budget.

## Defender (production `hash`, 16 MiB CombinedFrontier)

| | p50 | p95 | p99 | mean |
|---|---:|---:|---:|---:|
| Early two-phase v5 | 128.9 | 153.5 | 172.7 | 132.6 |
| **far2+global** | **118.4** | **128.1** | **148.0** | **119.8** |

p50 is inside the 100–140 ms window; p99 still can exceed 140 ms on this host.

## Strongest CPU attacker (full suite)

Source: `research/results/compute-memory-v4/attacker-optimization/` (synced from this session’s run; 1.2 s window, 400 ms warmup).

| Impl | 1T | 8T | 16T | 32T | 16T eff |
|---|---:|---:|---:|---:|---:|
| production_engine | 8.06 | 31.59 | 39.59 | 35.48 | 0.307 |
| packed_ring | 9.11 | 35.24 | **43.59** | 43.79 | 0.299 |
| packed_noring | 9.37 | 35.31 | 42.30 | **45.42** | 0.282 |
| packed_prefetch | 9.50 | 35.60 | 41.58 | 41.86 | 0.273 |
| packed_dual_lockstep | 7.77 | 32.68 | 40.54 | 38.47 | 0.326 |
| Argon2id (64 MiB) | 9.81 | 23.81 | 22.67 | 23.24 | 0.144 |

**Peak CPU in this suite:** **45.42 g/s** (`packed_noring` @ 32T). Independent microbench of prefetch alone saw ~47 g/s @ 16T — same ballpark; do not treat single-window noise as a new construction.

### Before / after (strongest class)

| | Early v5 packed_prefetch | far2+global peak |
|---|---:|---:|
| 16T g/s | 52.4 | **~43.6** |
| 32T g/s | 49.9 | **~45.4** |

## GPU attacker (RTX 3050)

CUDA correctness **100/100** for baseline / packed / packed_noring / packed_persistent after syncing `d_parents_remote_fast` to always-2 + global.

| Mode | tpb | batch | g/s | k_p50 ms | VRAM MiB |
|---|---:|---:|---:|---:|---:|
| baseline | 1 | 64 | 16.68 | 3837 | 2061 |
| packed | 32 | 192 | 62.74 | 3062 | 4113 |
| packed_noring | 32 | 192 | 65.37 | 2937 | 4113 |
| packed_t16_b192 | 16 | 192 | 72.88 | 2635 | 4113 |
| **packed_t32_b256 (best)** | **32** | **256** | **85.98** | **2979** | **5137** |
| packed_t64_b128 | 64 | 128 | 42.29 | 3025 | 3089 |

Argon2id GPU (same runner stdout): **435.8 g/s**. Antech GPU remains ~5× slower than that Argon2id attacker on this card.

## Correctness (this campaign)

| Check | Result |
|---|---|
| CPU packed_* vs production | 10 / 50 / 100 match |
| CUDA kernels vs production | 10 / 50 / 100 match |
| `word_path_matches_byte_path_1mib` | PASS |
| `full_packed_matches_engine` | PASS |
| `scatter_log_full_matches_engine` | PASS |

Vectors: `research/security-review/test-vectors.json`, `sdk/conformance/vectors.json` (construction_version 5, far2+global digests).

## Cryptanalysis / TMTO (rerun on far2+global)

Sources: `research/results/cryptanalysis/report.md`, `research/results/cryptanalysis/tmto-advanced/report.md`.

| Check | Result |
|---|---|
| Instrumented 16 MiB walk | mix_pairs **1.573e6**; parent_gathers **2.621e6**; far hits **1.572e6** (up vs early-v5 ~977k — expected from always-2 far) |
| Skip-every-other-node | INCORRECT |
| Naive / sparse checkpoint TMTO | FAIL/WALL (recompute abort); not a cheaper correct digest |
| Scatter-log full | Correct but **slower / more RAM** than full packed |
| Strongest cheaper *correct* attack | packed layout full eval (~0.84× defender 1T work; layout only) |
| GPU reduced-VRAM TMTO | does not beat full-memory packed |

Absence of a found shortcut is **not** a proof.

## Why 20–25 g/s is not available here

Defender p50 is already **118 ms** with peak offline CPU still **~43–47 g/s**. Halving that toward 20–25 g/s while staying ≤140 ms would need roughly another **~2×** serial cost per node on a construction whose defender already spent most of the latency budget. Linear extrapolation from the early-v5 → far2+global move does not close that gap inside 140 ms without artificial delay, pass inflation, or a different public construction.

Bottleneck remains: **524288 serial state-dependent nodes** + dual far-scatter over a live 16 MiB buffer.

## What was not done (on purpose)

- No extra `MIX_ROUNDS`, second full DAG pass, sleeps, or busy-waits.
- No public-API / encoding / version bump beyond the existing construction 5 binding.
- DRAM-saturation-as-cost was not the mechanism.

## Reproduce

```bash
# from repo root
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example v5_cost_microbench
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example attacker_optimization_runner
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example tmto_advanced_runner
```
