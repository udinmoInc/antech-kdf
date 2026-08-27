# Miri campaign summary

| Field | Value |
|---|---|
| Date (UTC) | 2026-08-27 |
| Rustc | rustc 1.100.0-nightly (bff8e12ff 2026-08-26) |
| Miri | miri 0.1.0 (bff8e12ff5 2026-08-26) |
| Target | `x86_64-pc-windows-gnu` |
| MIRIFLAGS | `-Zmiri-strict-provenance` |
| Overall | **PASS** |
| Host notes | `nightly-msvc` Miri setup **BLOCKED** (`link.exe` / missing `kernel32.lib`). Campaign executed on `nightly-x86_64-pc-windows-gnu`. |

## Suite status

| Suite | Status | Passed | Failed | Ignored |
|---|---|---:|---:|---:|
| antech-kdf-types --lib | PASS | 15 | 0 | 0 |
| antech-kdf-format --lib | PASS | 15 | 0 | 0 |
| antech-kdf-format --test parser_property | PASS | 4 | 0 | 0 |
| antech-kdf-core --lib (selected) | PASS | 10 | 0 | 7 |
| antech-kdf --lib | PASS | 3 | 0 | 6 |

Measured engine derive under Miri: `engine::tests::deterministic_small_config` **ok** in ~1053s (1 MiB CombinedFrontier; exercises `_mm_prefetch` unsafe).

## Exclusions

| Target | Verdict | Reason |
|---|---|---|
| antech-kdf-ffi | NOT APPLICABLE | Unsafe C ABI / foreign pointers |
| antech-kdf-cli | NOT APPLICABLE | Thin CLI I/O |
| CUDA / research attackers | NOT APPLICABLE | Non-Rust / research-only |
| conformance.rs | NOT APPLICABLE | Filesystem vectors under isolation |
| Multi 1 MiB hash/verify suites | SKIPPED under Miri | Wall-clock (`#[cfg_attr(miri, ignore)]`); covered by `cargo test` |
| Heavy Condvar queue stress (4 tests) | SKIPPED via CLI filter | Still in normal `cargo test` (and resource suite partially under Miri) |
| Reference == production | NOT APPLICABLE (research crate) | Outside production workspace members |

See `unsafe-audit.md`, `report.md`, `tests.csv`, `failures.csv`, `regressions.csv`, `environment.txt`, and `logs/`.
