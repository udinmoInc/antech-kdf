# ASIC/FPGA model assumptions

## Canonical construction (frozen)

| Parameter | Value | Evidence |
|---|---|---|
| Construction | compute-memory-v4 / $antech$v2$ | production core |
| Graph | CombinedFrontier | `GraphKind::CombinedFrontier` |
| Memory | 16 MiB (16777216 B) | `AntechConfig::default` |
| Block size | 32 B | default |
| Nodes N | 524288 | memory/block_size |
| Fan-in | 2 | default |
| MIX_ROUNDS | 4 | `antech_kdf_types::MIX_ROUNDS` |
| State | 32 B (4×u64) | `mixing.rs` / engine |
| FRONTIER_WIDTH | 64 | types |
| TILE_BLOCKS | 512 | types |
| Dual far-scatter | true | `graph.rs` combined() sets scatter_dest + scatter_dest2 |
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

- mix_pairs @ 16 MiB full_packed = 1171024 (`tmto-advanced/memory-sweep-16mib.csv`)
- Dual scatter ≈ 2×(N−64) historical RMW (`graph.rs` + TMTO report)
- TMTO sparse walls / cost factors (`tmto-advanced/report.md`)
- CPU/GPU defender & attacker rates (`compute-memory-v4/`)
- GPU Argon2id vs Antech (`compute-memory-v4/gpu/report.md`)

## Labels

Every numeric claim in CSVs is tagged MEASURED, MODELED, or ASSUMED.
