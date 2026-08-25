# Advanced TMTO Analysis

Target: production CombinedFrontier Antech KDF (unchanged). Digests must match `AntechEngine`.

## Full-memory baseline

| Config | Strategy | GPS |
|---|---|---|
| 1 MiB | full_packed | 448.86 |
| 1 MiB | scatter_log (full pristine+index) | 179.82 |
| 16 MiB | full_packed | 12.87 |

16 MiB ⇒ 524288 × 32 B. Dual far-scatter performs ~2×N historical XORs. Prior strongest schedule-only CPU attack remains **packed_prefetch**; this campaign focuses on *memory reduction*.

## Memory reduction strategies

1. **full_packed** — full mutated buffer (reference).
2. **scatter_log** — full pristine + compact dest→src index; correct but **more** RAM than packed (~+0.5 MiB at 1 MiB / ~+8 MiB at 16 MiB).
3. **sparse_checkpoint** — LRU mutated window + prefix-replay on miss; aborts at recompute budget (practical wall).
4. **regen_recompute** — no index; cold cache is incorrect/pathological (only for extreme tiny caps).

## Checkpointing

Best **scatter_log** stride on 1 MiB: stride=64 cost_factor=2.33 gps=192.80 (still slower than full_packed; stride mainly affects bookkeeping).

Sparse stride sweep at ~75% budget: any correct finishes? **no — recompute wall**. See `checkpoint-sweep.csv`.

## Pebbling/recomputation

Far parents + dual scatter keep nearly the entire address space live. Window-miss probes (see `pebbling.csv` / `scatter-replay.csv`) estimate recomputation from parent-miss × ~window/2. Actual `sparse_checkpoint` runs abort after ~1.0e6 recomputed node-steps (budget ≈32×N) at every fraction ≤75% — a hard practical wall independent of stride.

## Scatter replay

- Compact scatter index floor: **4.00 MiB** at 16 MiB KDF (2×N×4 B), **0.25 MiB** at 1 MiB.
- Storing full scatter *states* instead of indices ≈ 36.0 MiB at 16 MiB — strictly worse.
- Index alone is a large side structure relative to the 16 MiB working set; it does not unlock a cheaper reduced-memory attack than full_packed.

## State compression

- Blocks already packed 4×u64.
- No useful lossless delta compression found on ARX state.
- Lossy compression forbidden.

## CPU results

Strongest *correct cheaper* attack remains schedule optimization on full memory (prior packed_prefetch), not TMTO. Multi-thread scaling: `cpu.csv`.

## GPU results

- Full-memory **packed_t32_b256 ≈ 100.5 g/s** (prior RTX 3050 campaign).
- Reduced-VRAM TMTO does not beat full-memory batching: prefix replay destroys occupancy; compact index ≈4 MiB/guess side structure at 16 MiB KDF.

## Multi-target results

No cross-password DAG reuse (seed binds password). Only allocator/layout reuse. See `multitarget.csv`.

## Memory/Time frontier (1 MiB probe)

| frac | strategy | correct | gps | cost_factor | est_attacker_MiB |
|---|---|---|---|---|---|
| 1 | full_packed | true | 445.297 | 1.01 | 1.00 |
| 0.75 | sparse_checkpoint | false | 0.000 | 306.62 | 1.00 |
| 0.5 | sparse_checkpoint | false | 0.000 | 926.75 | 0.75 |
| 0.375 | sparse_checkpoint | false | 0.000 | 1178.69 | 0.62 |
| 0.25 | sparse_checkpoint | false | 0.000 | 1243.50 | 0.50 |
| 0.1875 | sparse_checkpoint | false | 0.000 | 1152.06 | 0.44 |
| 0.125 | sparse_checkpoint | false | 0.000 | 945.44 | 0.38 |
| 0.09375 | sparse_checkpoint | false | 0.000 | 787.38 | 0.34 |
| 0.0625 | sparse_checkpoint | false | 0.000 | 588.03 | 0.31 |
| 0.03125 | sparse_checkpoint | false | 0.000 | 331.38 | 0.28 |
| 0.015625 | sparse_checkpoint | false | 0.000 | 178.20 | 0.27 |

## 16 MiB key points

| frac | strategy | correct | gps | cost | est_MiB |
|---|---|---|---|---|---|
| 1 | full_packed | true | 13.902 | 0.93 | 16.0 |
| 0.75 | sparse_checkpoint | false | 0.000 | 5066.12 | 16.0 |
| 0.5 | sparse_checkpoint | false | 0.000 | 15069.25 | 12.0 |
| 0.25 | sparse_checkpoint | false | 0.000 | 19791.50 | 8.0 |
| 0.125 | sparse_checkpoint | false | 0.000 | 15100.56 | 6.0 |

## Strongest valid TMTO attack

Correctness OK rows: 5/16.

**No correct attack simultaneously reduced peak memory below the full working set *and* beat full_packed throughput.**
- `scatter_log` is correct but **increases** attacker RAM and is ~2.5× slower on 1 MiB.
- `sparse_checkpoint` at every tested fraction ≤75% hits the recompute budget wall (far-parent thrashing; ~1e6 node-steps aborted).

## Remaining TMTO margin

- Entire address space stays live under CombinedFrontier dual scatter.
- Compact metadata floor ≈ 4 MiB at 16 MiB KDF (index-only).
- Practical wall: ≤75% sparse already aborts under bounded recompute; 50%/25%/12.5% probe lower bounds are thousands× on 16 MiB.

## Security implications

1. **How low can attacker memory go?** Correct *efficient* evaluation needs the full ~16 MiB mutated buffer. Reduced-memory correct paths need either ≥ full buffer or pay a recompute wall.
2. **Minimum correct recomputation?** 0 with full_packed; sparse hits budget (≈32×N node-steps) before finishing at every fraction ≤75%.
3. **50%?** Sparse aborts; miss-probe lower bound ~15 000× on 16 MiB. Compact index alone is ~4 MiB.
4. **25%?** Sparse aborts; probe lower bound ~20 000× on 16 MiB.
5. **12.5%?** Sparse aborts; probe lower bound ~15 000× on 16 MiB.
6. **<10%?** Still aborts under budget; not a viable cracking path.
7. **Scatter compressible?** Index helps vs storing states (~4 MiB vs ~36 MiB) but does not unlock sub-working-set attacks.
8. **Checkpoints?** Help bookkeeping; do not remove liveness of far blocks; stride sweeps do not rescue sparse.
9. **GPU?** Does not change the TMTO curve favorably vs full VRAM packed kernels.
10. **Unexpected low-memory shortcut?** **None found** that is both correct and cheaper than full_packed.


Empirical attack-surface measurement — not a formal proof. Production KDF / v2 format / public API were not modified.

