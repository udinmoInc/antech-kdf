# Antech KDF Compute/Memory Hardness Research Report

## 1. Executive Summary

This report evaluates the compute-memory research construction (reference + optimized) on a **12–32 MiB** working-memory grid. Attacker cost comes from sequential state dependency and recomputation, not giant empty CPU loops or DRAM bus saturation.

## 2. Comparison against Argon2id (measured)

| Metric | Argon2id | Antech compute-memory (16 MiB) |
|---|---:|---:|
| Working memory | 65536 KiB | 16 MiB |
| Defender p50 | 92.06 ms | 11.74 ms |
| Defender p95 | (≈ mean) 92.06 ms | 11.97 ms |
| CPU cycles/guess (est.) | — | 1.74e6 |
| CPU attacker g/s (1 thread) | — | 80.9986 |
| GPU attacker g/s | — | 0.0000 (CUDA UNAVAILABLE (nvcc found, MSVC cl.exe host compiler missing) — no fabricated GPU throughput) |
| DRAM bytes/guess (est.) | — | 16.01 MiB |
| DRAM bandwidth (est.) | — | 1.338 GB/s |
| L3 cache misses (est.) | — | 245 |
| TMTO @50% recompute | — | 14.43× |

## 3. Design Notes

- **Password & salt binding**: SHA-256 domain-separated seed over password, salt, and all tunables.
- **Init**: segmented SHA-256 keys + ARX expand (moderate DRAM, no per-block SHA-256 storm).
- **Transitions**: dual state-derived parents, multi-round ARX mix, XOR writeback.
- **TMTO**: real reduced-resident derive with write-log replay (digests match at every fraction).

## 4. Verdict

Research construction is ready for comparative evaluation in the 12–32 MiB band. Public `hash` / `verify` / `needs_rehash` APIs are unchanged; this module is research-only.
