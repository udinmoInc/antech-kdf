# Sanitizer campaign summary

| Field | Value |
|---|---|
| Date (UTC) | 2026-08-28T04:15:47Z |
| Commit | `402d9d3cfb8367c630dbc201b05fdf4c92916244` |
| CI run | [33140604849](https://github.com/udinmoInc/antech-kdf/actions/runs/33140604849) |
| ASan overall | **PASS** |
| UB checks (`-Zub-checks`) overall | **PASS** |
| LLVM UBSan (`-Zsanitizer=undefined`) | **BLOCKED** |
| Combined | **PASS** |

## Suite matrix

| Suite | Debug | Release |
|---|---|---|
| production (types/format/core/kdf/ffi) | PASS (97 tests) | PASS (97 tests) |
| reference (`antech-kdf-reference`) | PASS (2 tests) | PASS (2 tests) |

See `asan.csv`, `ubsan.csv`, `skipped.csv`, `regressions.csv`, and `logs/` (CI artifacts).

## Environment

```
last_run_utc=2026-08-28T04:02:01Z
commit_sha=402d9d3cfb8367c630dbc201b05fdf4c92916244
rustc=rustc 1.100.0-nightly (e457a7b0d 2026-08-27)
target=x86_64-unknown-linux-gnu
ASan: RUSTFLAGS=-Zsanitizer=address; ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:print_summary=1
UB checks: RUSTFLAGS=-Zub-checks (LLVM -Zsanitizer=undefined unavailable on rustc)
```

## Exclusions

| Target | Verdict |
|---|---|
| CUDA / GPU | NOT APPLICABLE |
| antech-kdf-research runners | NOT APPLICABLE |
| antech-kdf-cli (no tests) | NOT APPLICABLE |
| Windows host | BLOCKED (use Ubuntu CI) |
| LLVM UBSan | BLOCKED (rustc does not support `-Zsanitizer=undefined`) |

Reference crate (`antech-kdf-reference`) runs under separate rows in CSVs — research parity, not production SOT.
