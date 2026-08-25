# Compute-Memory Research Construction v2 (12–32 MiB)

Research-only password KDF. **Total work is structure-derived** from the configured working set and dependency graph — not an exposed `dependency_depth` / iteration count.

Public production APIs (`hash`, `verify`, `needs_rehash`) are unchanged.

## Design

Work bound:

```text
num_blocks = memory_bytes / block_size
for i in 0..num_blocks:   # only implementation loop
    parents = graph(state, i, fan_in)   # i-1 + state-dependent earlier nodes
    state   = Mix(state, memory[parents])
    memory[i] = Encode(state)
```

| Piece | Role |
|-------|------|
| `config` | Structural only: `memory_kib`, `block_size`, `fan_in` |
| `dependency_graph` | Parents from live state + sequential predecessor |
| `state_transition` | Cryptographic ARX mix (protocol-constant rounds) |
| `core` | Reference / optimized / stride-checkpoint TMTO |
| `attacker` / `tmto` / `cuda` | Real harnesses |

**Removed as security knobs:** `dependency_depth()`, `passes()`, iteration counts.  
`ResearchParams.dependency_depth` / `passes` are ignored when present (trait bridge only).

Defaults: **16 MiB**, block **32 B**, fan-in **2** → **524 288** DAG nodes.

Frozen KAT (1 MiB, fan-in 2, password `antech-kat-password`, salt `antech-kat-salt!`):

`d2675d5422a98993886e9014728bcf4d72f8d587ffb57131321851c19d09ba63`

## Run

```bash
cargo test -p antech-kdf-research compute_memory
cargo run --release -p antech-kdf-research --example compute_memory_runner
```

## Configuration

```rust
use antech_kdf_research::compute_memory::ComputeMemoryConfig;

let cfg = ComputeMemoryConfig::default()
    .memory_mib(16)
    .block_size(32)
    .fan_in(2);
// cfg.num_blocks() == work bound
```

Mapping from `AntechConfig` uses only memory + block size; depth/passes are ignored.
