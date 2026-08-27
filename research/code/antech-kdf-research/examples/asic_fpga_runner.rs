//! Generate research/results/asic-fpga/* from the frozen CombinedFrontier model.
//! Research only — does not touch production KDF behavior.

use antech_kdf_research::engineering::asic_fpga::{
    antech_vs_argon2, canonical_config, construction_facts, estimate_chip, operation_count,
    reduced_memory_cfgs, replication_counts, sensitivity_rows, tmto_hardware_rows, MemArch,
    TechAssumptions,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("results")
        .join("asic-fpga")
}

fn write_csv(path: &std::path::Path, header: &str, rows: &[String]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "{header}")?;
    for r in rows {
        writeln!(f, "{r}")?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = results_dir();
    fs::create_dir_all(&out)?;
    let cfg = canonical_config();
    let facts = construction_facts(&cfg);
    let ops = operation_count(&cfg);
    let tech = TechAssumptions::default();

    // --- assumptions.md ---
    let assumptions = format!(
        r#"# ASIC/FPGA model assumptions

## Canonical construction (frozen)

| Parameter | Value | Evidence |
|---|---|---|
| Construction | {construction} | production core |
| Graph | {graph} | `GraphKind::CombinedFrontier` |
| Memory | {mem_mib} MiB ({mem_bytes} B) | `AntechConfig::default` |
| Block size | {block} B | default |
| Nodes N | {nodes} | memory/block_size |
| Fan-in | {fan} | default |
| MIX_ROUNDS | {mix} | `antech_kdf_types::MIX_ROUNDS` |
| State | {state} B (4×u64) | `mixing.rs` / engine |
| FRONTIER_WIDTH | {fw} | types |
| TILE_BLOCKS | {tile} | types |
| Dual far-scatter | {dual} | `graph.rs` combined() sets scatter_dest + scatter_dest2 |
| Sequential within guess | true | state carries node→node; parents data-dependent |
| Independent across guesses | true | MEASURED multitarget — no DAG reuse |

## What is removed on custom hardware

ASSUMED removed (software-only): instruction decode, GP register renaming, branch prediction, OS/runtime, CPU cache-miss soft costs beyond the actual memory ops.

MODELED retained (algorithmic): sequential 256-bit state updates, parent gathers, ARX `mix_pair` rounds, block writes, dual historical scatter RMW XORs, full working-set liveness under CombinedFrontier.

## Technology ranges (ASSUMED unless noted)

| Quantity | Range / value | Label |
|---|---|---|
| ASIC clock | 0.8–1.5 GHz | ASSUMED |
| FPGA clock | 0.2–0.4 GHz | ASSUMED |
| Cycles/node on-chip SRAM | 24 | ASSUMED (custom ARX + multi-port SRAM) |
| Cycles/node FPGA BRAM | 48 | ASSUMED |
| Cycles/node DDR | 180 | ASSUMED (random RMW dominated) |
| Cycles/node HBM | 60 | ASSUMED |
| DDR bandwidth | 50 GB/s | ASSUMED |
| HBM bandwidth | 460 GB/s | ASSUMED |
| On-chip SRAM budget | 64 MiB/chip | ASSUMED large ASIC |
| HBM capacity | 16 GiB | ASSUMED |
| Chip power budget | 75 W | ASSUMED |
| SRAM density | 0.8 MB/mm² | ASSUMED (order-of-magnitude) |

No transistor counts or dollar prices are invented beyond these labeled ranges.

## MEASURED inputs reused

- mix_pairs @ 16 MiB full_packed = {mix_pairs} (`tmto-advanced/memory-sweep-16mib.csv`)
- Dual scatter ≈ 2×(N−64) historical RMW (`graph.rs` + TMTO report)
- TMTO sparse walls / cost factors (`tmto-advanced/report.md`)
- CPU/GPU defender & attacker rates (`compute-memory-v4/`)
- GPU Argon2id vs Antech (`compute-memory-v4/gpu/report.md`)

## Labels

Every numeric claim in CSVs is tagged MEASURED, MODELED, or ASSUMED.
"#,
        construction = facts.construction,
        graph = facts.graph,
        mem_mib = facts.memory_mib,
        mem_bytes = facts.memory_bytes,
        block = facts.block_bytes,
        nodes = facts.num_blocks,
        fan = facts.fan_in,
        mix = facts.mix_rounds,
        state = facts.state_bytes,
        fw = facts.frontier_width,
        tile = facts.tile_blocks,
        dual = facts.dual_far_scatter,
        mix_pairs = ops.mix_pairs,
    );
    fs::write(out.join("assumptions.md"), assumptions)?;

    // --- operation-count.csv ---
    let mut op_rows = Vec::new();
    for (c, tag) in reduced_memory_cfgs() {
        let o = operation_count(&c);
        op_rows.push(format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            c.memory.as_mib().max(1), // show fractional via kib
            c.memory.as_kib(),
            tag,
            o.num_blocks,
            o.mix_pairs,
            o.parent_block_reads,
            o.block_writes,
            o.scatter_rmw,
            o.bytes_read,
            o.bytes_written,
            o.arx_rounds_total,
            o.kind
        ));
    }
    // Fix mib display for sub-MiB: use kib column as primary
    write_csv(
        &out.join("operation-count.csv"),
        "memory_mib_floor,memory_kib,config_tag,num_blocks,mix_pairs,parent_block_reads,block_writes,scatter_rmw,bytes_read,bytes_written,arx_rounds_total,kind",
        &op_rows,
    )?;

    // --- memory-model.csv ---
    let mut mem_rows = Vec::new();
    for (c, tag) in reduced_memory_cfgs() {
        let n = c.num_blocks() as u64;
        let index_floor = n.saturating_mul(2).saturating_mul(4); // 2 scatters × 4 B dest index
        mem_rows.push(format!(
            "{},{},{},{},{},{},{},{},{},{}",
            c.memory.as_kib(),
            tag,
            c.memory.as_bytes(),
            n,
            c.block_size.as_bytes(),
            n.saturating_sub(64).saturating_mul(2),
            index_floor,
            "full_mutated_buffer_required_for_efficient_eval",
            "scatter_index_does_not_beat_full_packed",
            "MEASURED+MODELED"
        ));
    }
    write_csv(
        &out.join("memory-model.csv"),
        "memory_kib,config_tag,working_set_bytes,num_blocks,block_bytes,scatter_rmw_ops,compact_scatter_index_bytes,liveness,scatter_note,kind",
        &mem_rows,
    )?;

    // --- fpga-model.csv / asic-model.csv ---
    let mut fpga = Vec::new();
    let mut asic = Vec::new();
    for &p in replication_counts() {
        for arch in [
            MemArch::FpgaBramUram,
            MemArch::ExternalDdr,
            MemArch::Hbm,
        ] {
            let e = estimate_chip("fpga", arch, &cfg, &ops, p, &tech);
            fpga.push(format!(
                "{},{},{},{},{},{},{},{:.3e},{:.3e},{:.3e},{:.6e},{:.4},{:.4},{:.4e},{:.4e},{:.4e},{},{},{}",
                e.platform,
                e.mem_arch,
                e.memory_mib_per_guess,
                e.parallel_guesses,
                e.on_chip_mem_bytes,
                e.external_mem_bytes,
                e.bytes_per_guess_traffic,
                e.mem_bandwidth_needed_bytes_s,
                e.cycles_per_guess,
                e.clock_hz,
                e.throughput_gps,
                e.area_mm2_or_fpga_util,
                e.power_w,
                e.energy_j_per_guess,
                e.area_per_gps,
                e.power_per_gps,
                e.bottleneck,
                e.kind,
                e.notes.replace(',', ";")
            ));
        }
        for arch in [MemArch::OnChipSram, MemArch::ExternalDdr, MemArch::Hbm] {
            let e = estimate_chip("asic", arch, &cfg, &ops, p, &tech);
            asic.push(format!(
                "{},{},{},{},{},{},{},{:.3e},{:.3e},{:.3e},{:.6e},{:.4},{:.4},{:.4e},{:.4e},{:.4e},{},{},{}",
                e.platform,
                e.mem_arch,
                e.memory_mib_per_guess,
                e.parallel_guesses,
                e.on_chip_mem_bytes,
                e.external_mem_bytes,
                e.bytes_per_guess_traffic,
                e.mem_bandwidth_needed_bytes_s,
                e.cycles_per_guess,
                e.clock_hz,
                e.throughput_gps,
                e.area_mm2_or_fpga_util,
                e.power_w,
                e.energy_j_per_guess,
                e.area_per_gps,
                e.power_per_gps,
                e.bottleneck,
                e.kind,
                e.notes.replace(',', ";")
            ));
        }
    }
    let hdr = "platform,mem_arch,memory_mib_per_guess,parallel_guesses,on_chip_mem_bytes,external_mem_bytes,bytes_per_guess_traffic,mem_bandwidth_needed_bytes_s,cycles_per_guess,clock_hz,throughput_gps,area_mm2_or_fpga_util,power_w,energy_j_per_guess,area_per_gps,power_per_gps,bottleneck,kind,notes";
    write_csv(&out.join("fpga-model.csv"), hdr, &fpga)?;
    write_csv(&out.join("asic-model.csv"), hdr, &asic)?;

    // --- tmto-hardware.csv ---
    let tmto: Vec<String> = tmto_hardware_rows()
        .into_iter()
        .map(|r| {
            format!(
                "{},{:.4},{},{},{:.4},{:.4},{:.6e},{:.6e},{:.6e},{},{}",
                r.memory_frac,
                r.working_set_mib,
                r.strategy,
                r.correct,
                r.cpu_cost_factor,
                r.hw_recompute_factor,
                r.area_relative,
                r.power_relative,
                r.throughput_relative,
                r.kind,
                r.notes.replace(',', ";")
            )
        })
        .collect();
    write_csv(
        &out.join("tmto-hardware.csv"),
        "memory_frac,working_set_mib,strategy,correct,cpu_cost_factor,hw_recompute_factor,area_relative,power_relative,throughput_relative,kind,notes",
        &tmto,
    )?;

    // --- sensitivity.csv ---
    let base = estimate_chip("asic", MemArch::OnChipSram, &cfg, &ops, 1, &tech);
    let sens: Vec<String> = sensitivity_rows(base.throughput_gps)
        .into_iter()
        .map(|r| {
            format!(
                "{},{},{:.6e},{:.6e},{},{}",
                r.axis,
                r.value,
                r.relative_throughput,
                r.relative_energy,
                r.kind,
                r.notes.replace(',', ";")
            )
        })
        .collect();
    write_csv(
        &out.join("sensitivity.csv"),
        "axis,value,relative_throughput,relative_energy,kind,notes",
        &sens,
    )?;

    // --- antech-vs-argon2.csv ---
    let vs: Vec<String> = antech_vs_argon2()
        .into_iter()
        .map(|r| {
            format!(
                "{},{},{},{},{}",
                r.metric,
                r.antech.replace(',', ";"),
                r.argon2id.replace(',', ";"),
                r.kind,
                r.notes.replace(',', ";")
            )
        })
        .collect();
    write_csv(
        &out.join("antech-vs-argon2.csv"),
        "metric,antech,argon2id,kind,notes",
        &vs,
    )?;

    // Reference single-pipe numbers for the report
    let asic1 = estimate_chip("asic", MemArch::OnChipSram, &cfg, &ops, 1, &tech);
    let asic4 = estimate_chip("asic", MemArch::OnChipSram, &cfg, &ops, 4, &tech);
    let asic_hbm10 = estimate_chip("asic", MemArch::Hbm, &cfg, &ops, 10, &tech);
    let fpga1 = estimate_chip("fpga", MemArch::FpgaBramUram, &cfg, &ops, 1, &tech);
    let asic_ddr1 = estimate_chip("asic", MemArch::ExternalDdr, &cfg, &ops, 1, &tech);

    let report = format!(
        r#"# ASIC/FPGA cost analysis — CombinedFrontier Antech (frozen)

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
| ASIC on-chip SRAM | 1 | **{asic1:.2}** | sequential state |
| ASIC on-chip SRAM | 4 | **{asic4:.2}** | SRAM capacity/power |
| ASIC HBM | 10 | **{asic_hbm10:.2}** | see CSV |
| ASIC DDR | 1 | **{asic_ddr1:.2}** | DDR latency/BW |
| FPGA BRAM/URAM | 1 | **{fpga1:.2}** | fabric clock + util |

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
9. **Throughput per chip?** MODELED rows above / CSVs; single-pipe ASIC SRAM ~{asic1:.1} g/s under stated ASSUMED cycles.
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
"#,
        asic1 = asic1.throughput_gps,
        asic4 = asic4.throughput_gps,
        asic_hbm10 = asic_hbm10.throughput_gps,
        asic_ddr1 = asic_ddr1.throughput_gps,
        fpga1 = fpga1.throughput_gps,
    );
    fs::write(out.join("report.md"), report)?;

    println!("wrote {}", out.display());
    println!(
        "asic_sram_1pipe={:.3} g/s  fpga_bram_1pipe={:.3} g/s  mix_pairs={}",
        asic1.throughput_gps, fpga1.throughput_gps, ops.mix_pairs
    );
    Ok(())
}
