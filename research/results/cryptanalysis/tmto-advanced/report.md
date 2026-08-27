# Advanced TMTO Analysis

Target: production CombinedFrontier Antech KDF (unchanged). Digests must match `AntechEngine`.

## Full-memory baseline

| Config | Strategy | GPS |
|---|---|---|
| 1 MiB | full_packed | 330.81 |
| 1 MiB | scatter_log (full pristine+index) | 132.78 |
| 16 MiB | full_packed | 7.94 |

16 MiB ⇒ 524288 × 32 B. Dual far-scatter performs ~2×N historical XORs. Prior strongest schedule-only CPU attack remains **packed_prefetch**; this campaign focuses on *memory reduction*.

## Memory reduction strategies

1. **full_packed** — full mutated buffer (reference).
2. **scatter_log** — full pristine + compact dest→src index; correct but **more** RAM than packed (~+0.5 MiB at 1 MiB / ~+8 MiB at 16 MiB).
3. **sparse_checkpoint** — LRU mutated window + prefix-replay on miss; aborts at recompute budget (practical wall).
4. **regen_recompute** — no index; cold cache is incorrect/pathological (skipped below compact-index floor).

## Checkpointing

Best **scatter_log** stride on 1 MiB: stride=8 cost_factor=2.34 gps=141.55 (still slower than full_packed; stride mainly affects bookkeeping).

Sparse stride sweep at ~75% budget: any correct finishes? **no — recompute wall**. See `checkpoint-sweep.csv`.

## Pebbling/recomputation

Far parents + dual scatter keep nearly the entire address space live. Window-miss probes (see `pebbling.csv` / `scatter-replay.csv`) estimate recomputation from parent-miss × ~window/2.

## Scatter replay

- Compact scatter index floor: **4.00 MiB** at 16 MiB KDF (2×N×4 B), **0.25 MiB** at 1 MiB.
- Storing full scatter *states* instead of indices ≈ 36.0 MiB at 16 MiB — strictly worse.
- Index alone already consumes half of a 16 MiB working set before any pristine/hot window.

## State compression

- Blocks already packed 4×u64.
- No useful lossless delta compression found on ARX state.
- Lossy compression forbidden.

## CPU results

Strongest *correct cheaper* attack remains schedule optimization on full memory (prior packed_prefetch), not TMTO. Multi-thread scaling: `cpu.csv`.

## GPU results

- Full-memory **packed_t32_b256 ≈ 97.69 g/s** (v5 RTX 3050 attacker-opt, 100/100 digest match).
- Reduced-VRAM TMTO does not beat full-memory batching: prefix replay destroys occupancy; compact index ≈8 MiB/guess side structure.

## Multi-target results

No cross-password DAG reuse (seed binds password). Only allocator/layout reuse. See `multitarget.csv`.

## Memory/Time frontier (1 MiB probe)

| frac | strategy | correct | gps | cost_factor | est_attacker_MiB |
|---|---|---|---|---|---|
| 1 | full_packed | true | 335.738 | 0.99 | 1.00 |
| 0.75 | sparse_checkpoint | false | 0.000 | 1256.88 | 1.00 |
| 0.5 | sparse_checkpoint | false | 0.000 | 3788.50 | 0.75 |
| 0.375 | sparse_checkpoint | false | 0.000 | 4750.75 | 0.62 |
| 0.25 | sparse_checkpoint | false | 0.000 | 4948.62 | 0.50 |
| 0.1875 | sparse_checkpoint | false | 0.000 | 4582.75 | 0.44 |
| 0.125 | sparse_checkpoint | false | 0.000 | 3776.88 | 0.38 |
| 0.09375 | sparse_checkpoint | false | 0.000 | 3157.84 | 0.34 |
| 0.0625 | sparse_checkpoint | false | 0.000 | 2355.06 | 0.31 |
| 0.03125 | sparse_checkpoint | false | 0.000 | 1328.58 | 0.28 |
| 0.015625 | sparse_checkpoint | false | 0.000 | 710.41 | 0.27 |

## 16 MiB key points

| frac | strategy | correct | gps | cost | est_MiB |
|---|---|---|---|---|---|
| 1 | full_packed | true | 7.604 | 1.04 | 16.0 |
| 0.75 | sparse_checkpoint | false | 0.000 | 20269.38 | 16.0 |
| 0.5 | sparse_checkpoint | false | 0.000 | 60310.75 | 12.0 |
| 0.25 | sparse_checkpoint | false | 0.000 | 79442.50 | 8.0 |
| 0.125 | sparse_checkpoint | false | 0.000 | 60549.50 | 6.0 |

## Strongest valid TMTO attack

Correctness OK rows: 5/16.

**No correct attack simultaneously reduced peak memory below the full working set *and* beat full_packed throughput.**
- `scatter_log` is correct but **increases** attacker RAM and is ~2.5× slower on 1 MiB.
- `sparse_checkpoint` at ≤75% hits the recompute budget wall (far-parent thrashing).
- Below the compact-index floor, only regen remains — skipped as impractical/incorrect when cold.

## Remaining TMTO margin

- Entire address space stays live under CombinedFrontier dual scatter.
- Compact metadata floor ≈ 50% of 16 MiB before any working set.
- Practical wall: ≤75% sparse already aborts under bounded recompute; ≤25% is far beyond interactive attack rates.

## Security implications

1. **How low can attacker memory go?** Correct *efficient* evaluation needs the full ~16 MiB mutated buffer. Reduced-memory correct paths need either ≥ full buffer or pay a recompute wall.
2. **Minimum correct recomputation?** 0 with full_packed; sparse hits budget (≫32×N node-steps) before finishing at mid fractions.
3. **50%?** Compact index alone is ~8 MiB at 16 MiB KDF — little room left; sparse probes show massive parent-miss rates.
4. **25%?** Below index+window feasibility; regen skipped / wall.
5. **12.5%?** Same wall, worse.
6. **<10%?** Computationally impractical for cracking rates.
7. **Scatter compressible?** Index helps vs storing states (~8 MiB vs ~36 MiB) but does not unlock sub-working-set attacks.
8. **Checkpoints?** Help bookkeeping; do not remove liveness of far blocks.
9. **GPU?** Does not change the TMTO curve favorably vs full VRAM packed kernels.
10. **Unexpected low-memory shortcut?** **None found** that is both correct and cheaper than full_packed.


Empirical attack-surface measurement — not a formal proof. Production KDF / v2 format / public API were not modified.

