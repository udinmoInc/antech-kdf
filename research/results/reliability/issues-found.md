# Reliability audit — issues found and fixed

Scope: production crates, FFI, CLI, resource scheduler, parser hardening, concurrency/stress/fuzz-style property tests. **No KDF algorithm, hash/verify/needs_rehash semantics, or v2 format changes.**

## Issue R1 — Resource permit leak on derive failure (CRITICAL)

| Field | Detail |
|---|---|
| Root cause | `release()` only on success path in `core_hash_with_config` |
| Reproducer | Force derive failure after `acquire` → scheduler counters stuck |
| Fix | RAII `PermitGuard` in `crates/antech-kdf-core/src/lib.rs` |
| Regression test | `integration_tests::hash_verify_roundtrip_releases_resources` |

## Issue R2 — Scheduler not global (HIGH)

| Field | Detail |
|---|---|
| Root cause | Fresh `BoundedResourceScheduler` per call |
| Fix | Process-wide `OnceLock` singleton |
| Regression test | `resource::tests::concurrent_admission_respects_global_budget`, `reliability_concurrency` |

## Issue R3 — verify() bypassed admission (HIGH)

| Field | Detail |
|---|---|
| Root cause | `core_verify` never called scheduler |
| Fix | Same `PermitGuard` as hash |
| Regression test | `reliability_concurrency::concurrent_mixed_workload` |

## Issue R4 — Parser DoS via unbounded hex (MEDIUM)

| Field | Detail |
|---|---|
| Root cause | Hex decoded before length validation |
| Fix | Exact `2 × declared_len` hex; max encoded length 8192 |
| Regression test | `parser_property::rejects_huge_encoded_string`, `rejects_oversized_salt_hex_before_decode` |

## Issue R5 — FFI rejected binary passwords (MEDIUM)

| Field | Detail |
|---|---|
| Root cause | `CStr::to_str()` on password |
| Fix | `CStr::to_bytes()` |
| Regression test | `ffi_tests::binary_password_roundtrip` |

## Issue R6 — queue_limit unenforced (MEDIUM)

| Field | Detail |
|---|---|
| Root cause | Field defined but unused in admission |
| Fix | `Mutex` + `Condvar` blocking queue; reject when `waiting_jobs >= queue_limit`; `queue_limit == 0` fails immediately |
| Regression test | `resource::tests::queue_at_limit_rejects_additional_waiters`, `queue_below_limit_blocks_then_admits`, `queue_recovers_after_release` |

## Issue R7 — Duplicate hash params accepted (LOW)

| Field | Detail |
|---|---|
| Root cause | Parser had no duplicate detection |
| Fix | `seen_*` flags per parameter key |
| Regression test | `parser_property::rejects_duplicate_parameters`, `tests::rejects_duplicate_m_param` |

## Issue R8 — FFI panic could cross ABI (LOW)

| Field | Detail |
|---|---|
| Root cause | No unwind boundary |
| Fix | `catch_unwind` on all exported C functions |
| Regression test | Design + null-pointer tests in `ffi_tests` |

## Issue R9 — Serde build break with `--all-features` (LOW)

| Field | Detail |
|---|---|
| Root cause | `AntechConfig` derives serde but `Algorithm`/`GraphKind` did not |
| Fix | `#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]` on both enums |
| Regression test | `cargo clippy --workspace --all-targets --all-features` |

## Issue R10 — Flaky scheduler idle assertion (TEST INFRA)

| Field | Detail |
|---|---|
| Root cause | Parallel test crates share global scheduler; stats checked while other tests still running |
| Fix | `SCHEDULER_TEST_LOCK` + `wait_scheduler_idle()` in `tests/common/mod.rs` |
| Regression test | `reliability_concurrency` (stable under parallel `cargo test`) |

## Issue R11 — Incorrect memory boundary test (TEST BUG)

| Field | Detail |
|---|---|
| Root cause | Test used `memory_mib(1023)` expecting failure; 1023 MiB is valid |
| Fix | Use `memory_kib(1023)` vs min 1024 KiB |
| Regression test | `reliability_matrix::config_boundary_validation` |

## Remaining / not fixed (documented)

| Item | Status |
|---|---|
| `cargo-fuzz` / libFuzzer on Windows | **BLOCKED** — toolchain not installed; replaced with 512-iteration rand property tests |
| Nsight / Linux `perf` | **BLOCKED** — not in PATH on Windows host |
| CUDA failure injection in CI | Research-only; production builds do not link CUDA |
| Research clippy style warnings | 16 warnings; no functional impact |
| Per-derive 16 MiB heap in engine | Required by construction; not a leak |

## Security invariants verified

- Constant-time verify digest comparison (`subtle::ConstantTimeEq`)
- No correct/wrong-password branch timing shortcuts in production path
- v1 legacy hashes rejected, not reinterpreted
- Resource admission applies to both hash and verify
- Permits released on success, error, and unwind (via `PermitGuard`)
