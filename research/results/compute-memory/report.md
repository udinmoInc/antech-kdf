# Antech KDF Compute-Memory v2 Research Report

## 1. Executive Summary

Work is **structure-derived**: one traversal of a `memory_bytes/block_size` dependency DAG with fixed fan-in. There is no exposed `dependency_depth` / iteration work knob. Compared against Candidate-004 (depth-loop Antech) and Argon2id.

## 2. Measured Comparison (16 MiB band)

| Metric | Argon2id | Candidate-004 (Antech) | Compute-memory v2 |
|---|---:|---:|---:|
| Working memory | 65536 KiB | 16 MiB | 16 MiB |
| Defender p50 | 99.78 ms | 28.04 ms | 85.70 ms |
| DAG nodes / work bound | (Argon2 lanes×blocks) | depth=120 loop | **524288 nodes** |
| CPU cycles/guess (est.) | — | 7.53e3 | 3.29e7 |
| CPU attacker g/s (1t) | — | — | 10.1073 |
| GPU g/s | — | — | 0.0000 (CUDA UNAVAILABLE (nvcc found, MSVC cl.exe host compiler missing) — no fabricated GPU throughput) |
| DRAM bandwidth (est.) | — | 0.561 GB/s | 0.198 GB/s |
| TMTO @50% recompute | — | — | 10.12× |

## 3. Construction

- **Determinism**: SHA-256 seed over password, salt, version, memory, block size, fan-in.
- **Work**: `for i in 0..num_blocks` only — bounds equal the memory layout.
- **Graph**: sequential parent `i-1` + state-dependent parents in `[0,i)` (fan-in).
- **TMTO**: stride checkpoints; parent misses recompute up to `stride` nodes (not extra iterations).

## 4. Verdict

Compute-memory v2 removes depth/passes as security parameters. Public `hash` / `verify` / `needs_rehash` are unchanged; this module remains research-only.
