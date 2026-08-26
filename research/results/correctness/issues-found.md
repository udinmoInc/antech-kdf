# Correctness campaign — issues found

## Issue R12 — Oversize KDF request deadlocks scheduler (HIGH)

| Field | Detail |
|---|---|
| Root cause | `acquire(memory_kib)` waited on `Condvar` even when `memory_kib > max_memory_kib`, so admission could never succeed |
| Reproducer | `hash_with_config` with 256 MiB config under 128 MiB host ceiling |
| Fix | Fail fast in `BoundedResourceScheduler::acquire` when request exceeds host ceiling |
| Regression | `resource::tests::request_exceeding_ceiling_fails_immediately`, `stress_regressions::oversize_memory_config_fails_fast_not_deadlock` |

## Issue R13 — Config accepted block sizes the engine cannot run (HIGH)

| Field | Detail |
|---|---|
| Root cause | `BlockSize::validate` allowed any power of two ≥ 16; production engine scratch is fixed at **64** bytes (`MAX_BLOCK`) |
| Reproducer | `AntechConfig::builder().block_size(128).build()` Ok, then `derive` → `block size exceeds engine stack scratch` |
| Fix | Cap `BlockSize` to **16..=64** (aligned with engine); docs updated |
| Regression | `reliability_matrix::config_boundary_validation` asserts `block_size(128)` Err |

## Harness false positives (not product bugs)

| Case | Cause |
|---|---|
| `parser/uppercase_hex` | Verified with wrong password (`pw` vs `p`) |
| `rehash/default_equal` | Used 1 MiB config vs 16 MiB default policy (correctly needs rehash) |
| `small_graph/nodes_64` | Invalid test math for exact-64 under MIN memory + MAX block |

## Final campaign status

**PASS** after R12/R13 fixes (see `summary.md` / `report.md`). Zero unexplained failures; panics=0.

## Environment blockers

- Live CUDA attacker re-run (prior GPU CSV imported)
- Miri / ASan not enabled on this host run
- Node/Go/Kotlin SDK runners not invoked in-process (Python blocked if native missing; CLI uses lib path when binary absent)
