# 03 — Design

The shipping construction is a compute-memory DAG:

1. Bind password, salt, and structural parameters into a seed (domain-separated).
2. Allocate a contiguous buffer of `memory / block_size` nodes.
3. Walk the graph, mixing a fixed fan-in of parents into each node with a fixed ARX mix.
4. Finalize to a digest.

Work is `memory / block_size` nodes. There is no separate iteration-count or “depth” security knob in the public API.

**Production defaults** (must match `AntechConfig::default()` and `specification.md`):

| Parameter | Value |
|---|---|
| Memory | 16 MiB |
| Block size | 32 B |
| Fan-in | 2 |
| Graph | CombinedFrontier (`g=3` in `$antech$v2$`) |
| Construction version | 4 |
| Domain separators | `antech-compute-memory-v4-*` constants in core |

Other graph families (reduced-critical-path, cache-locality) appear in research benchmarks for comparison. Only CombinedFrontier is the public default.

Normative write-up: [`../security-review/specification.md`](../security-review/specification.md).  
Readable reference: [`../code/reference/`](../code/reference/).  
Production engine: `crates/antech-kdf-core`.
