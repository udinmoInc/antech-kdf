# Antech v5 CUDA attacker optimization-v2

**Scope:** attacker-only GPU engineering. Production KDF / `$antech$v2$` / construction / digests **unchanged**.
**GPU:** NVIDIA GeForce RTX 3050 (8 GiB), same session for Antech + Argon2id.
**Correctness:** 10 / 50 / 100 vectors exact match vs `AntechEngine` — PASS (`correctness.csv`).

## Headline numbers (MEASURED)

| Metric | Prior best (`packed_t32_b256` user) | Session baseline (`packed_t32_b256` + opt-v2 kernel) | Optimized best (`opt_v2` b256/t16) | Low-batch (32/t32) | Argon2id GPU |
|---|---:|---:|---:|---:|---:|
| guesses/sec | ~74.9 | 81.141 | **90.251** | 10.613 | **434.947** |
| kernel p50 (ms) | ~3413 | 3154.7 | **2836.6** | 3025.0 | **220.7** |
| ms / guess (normalized) | ~13.33 | 12.326 | **11.082** | 94.23 | 2.299 |
| batch | 256 | 256 | 256 | 32 | 96 |
| tpb | 32 | 32 | **16** | 32 | — |

Normalized: `ms_per_guess = kernel_p50 / batch` (fair attacker metric).

## Throughput / latency / normalized

- **Throughput:** **90.251 guesses/sec** (best; `batch=256`, `tpb=16`)
- **Latency (complete batch):** **2836.6 ms** kernel p50
- **Normalized:** **11.082 ms/guess**
- Check: `256 / 2836.6 ms ≈ 90.25 g/s`

Low-batch does **not** buy useful latency: batch 32 still has ~3.0 s kernel p50 (one walk still takes ~3 s), so throughput collapses to ~10.6 g/s while wall time barely improves.

---

## Answers

### 1. Why is the current Antech kernel ~3413 ms?

It is essentially the **wall-clock duration of one full CombinedFrontier walk on a GPU thread** (524288 nodes, 16 MiB buffer, state-dependent far gathers + dual scatter), not “batch × 13 ms of serial work.”

With `batch=B` concurrent threads, all walks run together; the kernel finishes when the slowest thread finishes ≈ **one walk’s time** (~2.8–3.4 s on this RTX 3050). Larger `B` raises guesses/sec (`B / walk_time`) without shrinking that ~3 s walk.

User’s ~3413 ms @ batch 256 ↔ ~75 g/s is the same relationship: `256 / 3.413 ≈ 75`.

### 2. How much of that is actual KDF work?

**>99.9%.** Phase profile for best config (`best_profile_detail.txt`):

| Phase | ms |
|---|---:|
| kernel p50 | 2836.63 |
| alloc (once) | 8.59 |
| H2D | 0.090 |
| memset | **0** (packed overwrite) |
| D2H | 0.071 |
| finalize (host SHA) | 0.296 |

Overhead / kernel ≈ **0.00016**.

### 3. How much is implementation overhead?

Negligible vs the DAG. Historical baselines paid large `cudaMemset` of 16 MiB×batch; packed_noring removed that. Remaining overhead is seeds/phantoms copies and host finalize.

Opt-v2 engineering (dedicated noring kernel, stack 2480→**432** B, `__ldg` + L2 prefetch, Prefer-L1, pinned + async streams) cut walk time ~3413→~2837 ms and raised GPS ~75→**90**.

### 4. What batch size gives the best attacker throughput?

**256** (largest that fits with ~1.5 GiB headroom). Batch **512** skipped — VRAM. From `batch-sweep.csv`, peak GPS:

`batch=256, tpb=16 → 90.52 g/s` (sweep) / **90.25 g/s** (confirm re-run).

### 5. What batch size gives the best practical latency?

- **Batch wall time** stays ~2.6–3.2 s across batch 32–256 (walk-bound).
- **Normalized ms/guess** is best at **batch=256** (11.05–11.08 ms).
- Batch 32 looks “similar ms on the clock” but is a **worse attacker** (10.6 g/s, 94 ms/guess).

Practical choice: **batch=256** for both throughput and normalized latency. Do not shrink batch to chase a ~200 ms kernel — that would require a shorter walk (forbidden) or fewer concurrent guesses (weaker attacker).

### 6. Final guesses/sec

**90.251 g/s** (confirmed `opt_v2`, batch 256, tpb 16).

### 7. Final kernel p50

**2836.6 ms** at that config.

### 8. Did optimization accidentally make the attack materially stronger?

**Modestly yes, by removing GPU overhead — not by weakening the KDF.**

| | g/s | kernel p50 |
|---|---:|---:|
| Prior reported best | ~74.9 | ~3413 |
| This session baseline (same mode, new kernel) | 81.14 | 3155 |
| Optimized best | **90.25** | **2837** |

≈ **1.20×** vs prior 74.9; ≈ **1.11×** vs session baseline. Digests unchanged; full node count preserved. Correctness 100/100.

### 9. Does Antech remain substantially slower to attack than Argon2id on this RTX 3050?

**Yes.** Same-session Argon2id CUDA attacker (`m=65536`, `t=2`, `p=1`, batch 96):

| | Antech opt-v2 | Argon2id |
|---|---:|---:|
| g/s | 90.25 | **434.95** |
| kernel p50 | 2836.6 ms | **220.7 ms** |

Argon2id ≈ **4.8×** higher attack throughput on this GPU.

### 10. What GPU bottleneck remains?

**Dependency-serialized memory latency of CombinedFrontier**, not launch/transfer:

- One thread owns one sequential 524288-step walk; no intra-guess parallelism.
- Far parent indices are **state-dependent** → uncoalesced global loads/stores.
- Dual scatter RMWs force a full resident 16 MiB buffer per concurrent guess → **VRAM caps concurrency**.
- Occupancy theoretical figure is misleading: concurrency is VRAM-bound (~16 MiB × batch), not SM-bound.
- Registers 60, local/stack **432 B**, **0 spills** after noring split — compiler pressure is secondary.

---

## Engineering applied (attacker only)

1. Dedicated `v4c_guess_kernel_packed_noring` (no frontier-ring stack; ptxas **432 B** vs 2480 B packed-with-ring).
2. `__ldg` + L2 prefetch on remote parents; `cudaFuncCachePreferL1`.
3. Pinned host buffers; non-blocking copy/compute streams; no packed memset.
4. Phase timers: alloc / H2D / memset / launch / kernel / D2H / sync / finalize.
5. Sweep: batches `{32,64,128,256}` × TPB `{16,32,64,128,256}` (512 omitted — VRAM).

## Artifacts

| File | Contents |
|---|---|
| `baseline.csv` | Session profile of `packed_t32_b256` |
| `batch-sweep.csv` / `launch-sweep.csv` / `profile.csv` | Full grid |
| `optimized.csv` | Best throughput config |
| `correctness.csv` | 10/50/100 PASS |
| `comparison.csv` | Antech vs Argon2id |
| `best_profile_detail.txt` | Confirmed best phases |
| `argon2id_gpu_raw.txt` | Same-session Argon2id |
| `ptxas.txt` | Compiler register/stack info |
| `report.md` | This document |
