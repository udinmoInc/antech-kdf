# 03 — Design

Early research used a Candidate-004 core: bind password/salt/parameters into a seed, fill a contiguous buffer, then walk a long chain of state-dependent block reads with a fixed ARX mix. Two forks were studied in detail:

- **K1** — password-dependent rotation / feedback aimed at SIMD and warp divergence. Spec: [candidates/k1.md](candidates/k1.md).
- **K2** — higher fan-in (quad parents) for a steeper TMTO curve. Spec: [candidates/k2.md](candidates/k2.md).

Those variants used explicit depth/pass knobs. Later compute-memory work dropped those as security parameters: work is `memory / block_size` nodes, with parents chosen by a graph family.

Graph families explored in v3/v4 include reduced-critical-path, cache-locality, and **combined-frontier**. Combined-frontier is what production `AntechEngine` runs today (hash format `g=3`). Domain separators in the current engine are protocol constants (`antech-compute-memory-v4-seed`, `antech-compute-memory-v4-final`, etc.).

See also [compute-memory/README.md](compute-memory/README.md) and [compute-memory-v3/README.md](compute-memory-v3/README.md).
