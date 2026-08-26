# Fuzz campaign summary

**Verdict:** PASS

| Metric | Value |
|---|---:|
| TOTAL TARGETS | 6 |
| TOTAL EXECUTIONS | 632,029,386 |
| TOTAL CORPUS ENTRIES | 27 |
| TOTAL UNIQUE CRASHES (panics) | 0 (final clean re-run) |
| TOTAL ASSERTION FAILURES | 0 |
| TOTAL HANGS | 0 (after R15 fix) |
| TOTAL BUGS FOUND (campaign) | 2 (R14, R15) |
| TOTAL BUGS FIXED | 2 |
| REGRESSION TESTS | 3 (R12 covered, R14, R15) |
| SECS PER TARGET (configured) | 180 |
| TOTAL CAMPAIGN TIME (s) | 1080.0 |
| TOOLS ACTUALLY EXECUTED | fallback harness (`antech-kdf-fuzz-harness`) |
| libFuzzer / ASan / Miri | **NOT run on this host** (BLOCKED) |

## Per target (final clean re-run)

| Target | Executions | Corpus | Panics | Asserts | Time (s) | Status |
|---|---:|---:|---:|---:|---:|---|
| parser | 172067934 | 20 | 0 | 0 | 180.0 | PASS |
| config | 375716310 | 2 | 0 | 0 | 180.0 | PASS |
| hash_verify | 56037 | 1 | 0 | 0 | 180.0 | PASS |
| ffi | 26365 | 1 | 0 | 0 | 180.0 | PASS |
| scheduler | 71182122 | 1 | 0 | 0 | 180.0 | PASS |
| malformed_v2 | 12980618 | 2 | 0 | 0 | 180.0 | PASS |

## Bugs found and fixed

| ID | Surface | Symptom | Fix |
|---|---|---|---|
| **R14** | `parse_hash` / `hex_decode` | Panic on non-ASCII UTF-8 in salt/digest hex (`s[i..i+2]` char-boundary) | Require ASCII hex; decode via `as_bytes()` |
| **R15** | `BoundedResourceScheduler::acquire` | Same-thread acquire-while-holding + `queue_limit > 0` Condvar hang | Fail-fast nested wait; track held permits per scheduler/thread |

Minimized R14 sample: `crashes/minimized_r14_unicode_hex.txt`.

## Blockers

- `cargo-fuzz` install failed on Windows GNU (`dlltool.exe` missing)
- `cargo-fuzz` install failed on Windows MSVC nightly (`link.exe` / VS Build Tools missing)
- Real libFuzzer campaigns: Ubuntu CI via `.github/workflows/fuzz.yml` (not claimed as executed locally)
