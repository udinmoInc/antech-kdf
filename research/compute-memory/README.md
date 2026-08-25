# Compute-Memory Research Construction (12–32 MiB)

Research-only password KDF construction for Antech. Attacker cost comes from **sequential state dependency**, **cryptographic mixing**, and **recomputation under TMTO** — not a giant empty CPU loop (`t ≈ 700k–2.5M`) and not maximum DRAM bandwidth.

Public production APIs (`hash`, `verify`, `needs_rehash`) are unchanged.

## Design

| Piece | Role |
|-------|------|
| `config` | Tunables via `ComputeMemoryConfig` / `AntechConfig` / `ResearchParams` |
| `memory_layout` | Exact byte accounting for 12/16/20/24/28/32 MiB |
| `crypto_mixing` | SHA-256 password+salt binding; ARX mix (SplitMix constants) |
| `dependency_graph` | Dual state-derived parents + logarithmic back-reference |
| `state_transition` | Prior state + memory → new state + XOR writeback |
| `core` | Shared derive (reference / optimized / sparse TMTO) |
| `reference` / `optimized` | Matching digests; optimized used for attacker harnesses |
| `attacker` | Real CPU scaling: 1/2/4/8/16/32 workers |
| `tmto` | Real reduced-resident derives at 100/75/50/25/12.5/6.25% |
| `cuda` | Real CUDA path when `nvcc` + `cuda` feature; honest unavailable otherwise |

Default research parameters (all overridable):

- Memory: **16 MiB** (suite sweeps **12–32 MiB**)
- Depth: **4096** sequential transitions
- Mix rounds: **4** per transition
- Segment fill: **1024 B** (SHA-256 key + ARX expand — moderate DRAM)
- Fold stride: **4** (final coverage fold commits the working set)

Frozen KAT (1 MiB, depth 64, password `antech-kat-password`, salt `antech-kat-salt!`):

`22bc254b5312ffd0cd57f3ebf5074a831f5b843cfb4d68c06a884cd0d0993f85`

## Run

From the workspace root:

```bash
# Unit tests + KATs
cargo test -p antech-kdf-research compute_memory

# Full research suite → research/results/compute-memory/
cargo run --release -p antech-kdf-research --example compute_memory_runner
```

Optional CUDA feature (requires `nvcc`):

```bash
cargo test -p antech-kdf-research --features cuda
```

## Outputs

Written under `research/results/compute-memory/`:

- `defender.csv` — RAM, p50/p95 latency, cycle/instruction estimates
- `cpu-attacker.csv` — guesses/sec vs workers
- `tmto.csv` — recomputation factor vs memory fraction
- `gpu-attacker.csv` — measured GPU throughput or honest unavailable status
- `argon2-baseline.csv` — measured Argon2id matrix
- `bandwidth.csv`, `cache.csv`, `contention.csv`, `concurrency.csv`, `pareto.csv`
- `memory-layout.md`, `baseline.csv`, `report.md`

## Configuration

```rust
use antech_kdf_research::compute_memory::{ComputeMemoryConfig, OptimizedEngine};
use antech_kdf_types::AntechConfig;

let cfg = ComputeMemoryConfig::default()
    .memory_mib(16)
    .dependency_depth(4096)
    .mix_rounds(4)
    .fold_stride(4);

// Or map from the production config API:
let antech = AntechConfig::builder().memory_mib(16).dependency_depth(2048).build()?;
let cfg = ComputeMemoryConfig::from_antech_config(&antech);
```
