# ASIC/FPGA cost analysis — CombinedFrontier Antech (frozen)

Research-only model. Production KDF, v2 format, and public API unchanged.

## Canonical parameters verified

| Item | Value |
|---|---|
| Construction | compute-memory-v4 / `$antech$v2$` |
| Graph | CombinedFrontier (`g=3`) |
| Memory | **16 MiB** |
| Block size | **32 B** |
| Nodes **N** | **524 288** |
| Fan-in | 2 |
| MIX_ROUNDS | 4 |
| State | 256-bit (4×u64) |
| Dual far-scatter | yes (`scatter_dest` + `scatter_dest2`) |

Evidence: `crates/antech-kdf-types` defaults + `crates/antech-kdf-core` `engine.rs` / `graph.rs`.

## What disappears on custom hardware vs CPU/GPU

**MEASURED software context (CPU defender ~96 ms p50; CPU attacker ~40 g/s @16t; GPU ~33 g/s on RTX 3050)** includes instruction stream, cache hierarchy soft costs, and occupancy limits from 16 MiB/guess.

On an ASIC/FPGA datapath we **ASSUME** removal of decode, rename, branch prediction, and general-purpose runtime. What **remains** (MODELED):

1. **Sequential critical path** of length N: each node updates a 256-bit state that feeds the next address generation.
2. **Data-dependent parent reads** (fan-in ≥ 2 blocks).
3. **ARX `mix_pair`** work (~1.171e6 mix_pairs MEASURED at 16 MiB).
4. **Dual far-scatter RMW** (~2×(N−64) historical XOR writes) — irregular, hazard-prone.

Rough fraction: a large share of CPU time is memory + dependency, not ALU. Removing SW overhead may improve **per-pipeline** rate by a modest factor (ASSUMED ~2–5× vs a tight CPU core) but **does not** remove the N-step chain or the 16 MiB footprint. GPU’s poor Antech rate vs Argon2id (MEASURED 33 vs 436 g/s) already shows occupancy/scatter pain that custom silicon only partially cures.

## True hardware critical path

Within one guess: **node i → mix → write i → dual scatter RMW → node i+1**. Deep cross-node pipelining is blocked by:

- carried state;
- parents that may be recent or far (including scatter-mutated blocks);
- RMW hazards on scatter destinations.

Inside a node, `mix_pair` rounds can be a shallow pipeline (MODELED). Across nodes, expect essentially **one active node per pipeline**.

## Memory per parallel guess

| Requirement | Bytes | Label |
|---|---:|---|
| Efficient correct evaluation | **16 777 216** | MEASURED TMTO: full_packed best |
| Compact scatter index alone | **4 194 304** | MEASURED floor @16 MiB |
| Storing scatter states | ~36 MiB | MEASURED worse |

Independent pipelines need **~16 MiB each** (plus tiny scratch). No cross-password DAG sharing (MEASURED multitarget).

## Can many guesses run independently?

**Yes.** Replication is the attacker’s main lever. Limits are capacity, bandwidth, and power — not algorithmic coupling.

| Parallel guesses | Working set | Physically plausible? |
|---:|---:|---|
| 1 | 16 MiB | yes (BRAM/URAM large FPGA or ASIC SRAM) |
| 10 | 160 MiB | ASIC SRAM unlikely; HBM/DDR yes |
| 100 | 1.6 GiB | HBM/DDR |
| 1 000 | 16 GiB | large HBM / multi-die ASSUMED |
| 10 000 | 160 GiB | multi-package / server DRAM ASSUMED |

## Dual far-scatter hardware cost

CombinedFrontier always programs two historical XOR destinations (when `i > FRONTIER_WIDTH`). Effects:

- Keeps nearly the **entire address space live** (MEASURED TMTO / pebbling).
- Adds ~2N random RMW ops — bad for DDR latency hiding, bad for BRAM banking conflicts.
- Compact index replay does **not** unlock a cheaper reduced-memory path than full_packed (MEASURED).

ASIC can implement scatter as XOR+write ports; it does **not** erase the persistence requirement.

## Reduced memory / recomputation

From `tmto-hardware.csv` (CPU MEASURED factors mapped to HW):

- 75%/50%/25% sparse_checkpoint: **incorrect / abort** with enormous cost factors (~5e3–2e4× at 16 MiB).
- SRAM savings are overwhelmed by recompute energy; **reduced memory does not help a rational ASIC attacker**.

## External memory bottleneck

When the working set leaves on-chip SRAM:

- Traffic per guess ≈ **reads + writes including scatter RMW** (~3.2e7 block ops × 32 B order — see `operation-count.csv`).
- DDR (ASSUMED 50 GB/s) caps multi-pipe scaling quickly (`bottleneck=external_memory_bandwidth` in CSVs).
- HBM (ASSUMED 460 GB/s) raises the ceiling but the **per-pipe sequential path** remains.

## Modeled single-chip throughputs (order-of-magnitude)

| Design | Parallel | Throughput (g/s) | Bottleneck |
|---|---:|---:|---|
| ASIC on-chip SRAM | 1 | **119.21** | sequential state |
| ASIC on-chip SRAM | 4 | **476.84** | SRAM capacity/power |
| ASIC HBM | 10 | **254.31** | see CSV |
| ASIC DDR | 1 | **8.48** | DDR latency/BW |
| FPGA BRAM/URAM | 1 | **15.89** | fabric clock + util |

Values are **MODELED** from ASSUMED clocks/cycles — not silicon measurements. See `asic-model.csv` / `fpga-model.csv`.

## Antech vs Argon2id

MEASURED GPU: Argon2id ≫ Antech on RTX 3050. MEASURED CPU attacker at 16t: Antech CombinedFrontier ~40 g/s vs Argon2id ~23 g/s at **64 MiB** in that table (not an equal-memory ASIC claim).

MODELED custom silicon: both need large memory per guess; Antech’s dual far-scatter adds irregular RMW relative to Argon2’s more regular fill. **We do not claim Antech is ASIC-resistant.** Custom hardware removes much CPU/GPU overhead for both; Antech’s remaining advantage is full-buffer liveness + TMTO wall, not “unimplementable in silicon.”

## Answers to the ten questions

1. **How much CPU/GPU cost disappears?** Soft control overhead: much of it (ASSUMED). Memory traffic + N-step dependency: remains. Expect better than GPU Antech, not Argon2id-GPU-like blowups without huge parallel memory.
2. **True critical path?** Sequential node chain with dual scatter RMW.
3. **Memory per parallel guess?** ~16 MiB for efficient correct eval.
4. **Deep DAG pipeline?** No across nodes; shallow inside mix.
5. **Many independent guesses?** Yes, with linear memory.
6. **Dual far-scatter real HW cost?** Yes — liveness + irregular RMW.
7. **Reduced memory vs SRAM savings?** Recompute wall dominates (MEASURED).
8. **External memory bottleneck?** When parallel×traffic exceeds DDR/HBM; see CSV bottlenecks.
9. **Throughput per chip?** MODELED rows above / CSVs; single-pipe ASIC SRAM ~119.2 g/s under stated ASSUMED cycles.
10. **vs Argon2id?** GPU favors Argon2id strongly (MEASURED). ASIC: both memory-hard; Antech not claimed resistant; scatter makes bandwidth/latency harder.

## Files

- `assumptions.md` — parameters and tech ranges  
- `operation-count.csv` — per-guess ops  
- `memory-model.csv` — footprints / scatter index  
- `fpga-model.csv` / `asic-model.csv` — architecture grid  
- `tmto-hardware.csv` — TMTO → area/power/throughput  
- `sensitivity.csv` — axes requested  
- `antech-vs-argon2.csv` — comparison table  

Labels: MEASURED / MODELED / ASSUMED as marked.
