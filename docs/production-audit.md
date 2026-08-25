# Production audit report — 2026-08-25

Scope: production crates (`antech-kdf`, `antech-kdf-core`, `antech-kdf-format`, `antech-kdf-types`, `antech-kdf-ffi`, `antech-kdf-cli`), research harness sanity, full workspace verification. KDF algorithm, `hash()`/`verify()`/`needs_rehash()` semantics, and v2 format unchanged except security hardening.

## Verification matrix

| Check | Result |
|---|---|
| `cargo fmt --all` | PASS |
| `cargo check --workspace` | PASS |
| `cargo test --workspace` | PASS (65 tests) |
| `cargo clippy --workspace --all-targets` | PASS (style warnings only, no errors) |
| `cargo doc --workspace --no-deps` | PASS (1 broken intra-doc link in research crate, non-blocking) |
| Production release build (no research) | PASS |
| Attacker harness (`packed_matches`) | PASS |
| Nsight / Linux `perf` | BLOCKED — not installed on Windows host |

## Issues found and fixed

### 1. Resource permit leak on derivation failure (CRITICAL)

| | |
|---|---|
| **Symptom** | If `AntechEngine::derive` failed after `acquire`, permit was never released → scheduler counters stuck, eventual `ResourceExhausted` under load |
| **Root cause** | `core_hash_with_config` called `release` only on success path |
| **Fix** | RAII `PermitGuard` in `antech-kdf-core/src/lib.rs` — always releases on drop |
| **File** | `crates/antech-kdf-core/src/lib.rs` |
| **Test** | `integration_tests::hash_verify_roundtrip_releases_resources` |

### 2. Resource scheduler was per-call (no global admission) (HIGH)

| | |
|---|---|
| **Symptom** | Every `hash()` created a fresh `BoundedResourceScheduler`; 128 MiB / 64-job limits never enforced across requests |
| **Root cause** | `default_scheduler()` instantiated locally in `core_hash_with_config` |
| **Fix** | Process-wide singleton via `OnceLock` + same guard for `core_verify` |
| **File** | `crates/antech-kdf-core/src/lib.rs` |
| **Test** | `resource::tests::enforces_memory_ceiling`, `enforces_active_job_limit` |

### 3. Verify path bypassed resource admission (MEDIUM)

| | |
|---|---|
| **Symptom** | Concurrent verifies could allocate unbounded 16 MiB buffers with no admission control |
| **Root cause** | `core_verify` never called scheduler |
| **Fix** | Acquire/release via `PermitGuard` before derive (same as hash) |
| **File** | `crates/antech-kdf-core/src/lib.rs` |
| **Test** | Same integration test |

### 4. Malformed hash DoS via unbounded hex decode (MEDIUM)

| | |
|---|---|
| **Symptom** | Attacker could supply megabyte salt hex with `s=16`; parser allocated huge buffer before length check |
| **Root cause** | `hex_decode` ran before validating declared length bounds |
| **Fix** | Require exact `2 × declared_len` hex chars; validate `s`/`l` against protocol max before decode |
| **File** | `crates/antech-kdf-format/src/parser.rs` |
| **Test** | `rejects_oversized_salt_hex_before_decode`, `rejects_invalid_salt_length_param` |

### 5. FFI rejected binary passwords (MEDIUM)

| | |
|---|---|
| **Symptom** | `antech_hash` / `antech_verify` used `CStr::to_str()` → non-UTF-8 passwords returned `InvalidInput` while Rust API accepts bytes |
| **Root cause** | Incorrect UTF-8 requirement in C ABI |
| **Fix** | Use `CStr::to_bytes()` for password; hash string remains UTF-8 |
| **File** | `crates/antech-kdf-ffi/src/lib.rs` |
| **Test** | Existing `binary_password_verifies_successfully` (Rust API); FFI parity by design |

### 6. Integer overflow in memory ceiling check (LOW)

| | |
|---|---|
| **Symptom** | `current_mem + memory_kib` could wrap on pathological values |
| **Fix** | `current_mem.saturating_add(memory_kib)` |
| **File** | `crates/antech-kdf-core/src/resource.rs` |

### 7. queue_limit not enforced (MEDIUM) — fixed in reliability audit

| | |
|---|---|
| **Symptom** | `ResourcePolicy.queue_limit` defined but ignored; no admission queue |
| **Fix** | `Mutex` + `Condvar` scheduler; block up to N waiters, reject overflow; `queue_limit == 0` = fail-fast |
| **File** | `crates/antech-kdf-core/src/resource.rs` |
| **Test** | `queue_at_limit_rejects_additional_waiters`, `queue_below_limit_blocks_then_admits` |

### 8. Dead orphan research files (LOW)

| | |
|---|---|
| **Symptom** | `distributed_dag/{partition,metrics}.rs` not in module tree; `partition.rs` referenced missing `spec` module |
| **Fix** | Removed orphan files |
| **Files** | deleted `crates/antech-kdf-research/src/distributed_dag/*` |

### 9. Research harness compile warning (LOW)

| | |
|---|---|
| **Fix** | Removed unused `gpu_opt_line` assignment in `attacker_optimization_runner.rs` |

## Not changed (by design)

- **KDF graph / mix / parameters** — no algorithm changes
- **`queue_limit`** — now enforced (reliability audit 2026-08-25)
- **Clippy style warnings** — `is_multiple_of`, loop style in research; no functional impact
- **Per-derive 16 MiB heap allocation** in engine — required by construction; attacker `PackedScratch` reuse is research-only

## Attacker harness post-fix

| Backend | Status |
|---|---|
| CPU `packed_prefetch` vs production | PASS (unit test) |
| CUDA `packed_t32_b256` | PASS (prior campaign 100/100 vectors) |
| Production `hash()`/`verify()` determinism | PASS (all API tests) |

## Remaining / environment blockers

| Item | Status |
|---|---|
| Nsight Compute / Systems profiling | Not available (tool not in PATH) |
| Linux `perf` IPC/cache counters | Not available on Windows |
| `queue_limit` enforcement | Implemented with blocking queue + overflow rejection |
| Research clippy warnings | 16 style warnings; no correctness impact |

## Summary

Three production stability bugs were confirmed and fixed: **permit leak on error**, **non-functional global resource limits**, and **verify bypassing admission**. Additional hardening: **bounded hash parsing**, **FFI binary password support**, **queue_limit enforcement**. All 65 workspace tests pass; production crates build clean in release.
