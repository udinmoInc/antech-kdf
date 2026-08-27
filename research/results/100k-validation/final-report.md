# 100k adversarial validation report

## Strict totals

| Metric | Value |
|---|---:|
| Target executed cases | 100000 |
| **Actual executed cases** | **100000** |
| PASS | 100000 |
| FAIL | 0 |
| BLOCKED | 3 |
| NOT RUN | 3 |
| Reached ≥100,000 executed? | true |
| Bugs found this campaign | 0 |
| Bugs fixed this campaign | 1 |
| Wall time (s) | 49.1 |
| Master seed | 0xa71ec4100cad1000 |
| Verdict | **PASS** |

Executed = PASS + FAIL only. BLOCKED / NOT RUN are **never** counted as PASS.

## Production / reference

- Production: `antech-kdf / antech-kdf-core / antech-kdf-format (workspace)`
- Reference: `antech-kdf-reference (research/code/reference)`
- Differential cases exercised under `differential` (1 MiB CombinedFrontier).

## What was exercised

Parser (malformed/truncated/duplicate/non-ASCII/huge/trailing), config boundaries, secret/AD None vs empty vs wrong, hash→verify, wrong password, determinism, encode/parse, needs_rehash policies, scheduler idle after concurrency waves (1–64), long-run contamination, reference==production.

## Environment limits (not passes)

See `sanitizer-fuzz.csv` and coverage rows for `ffi_c_abi`, `cuda`, `libfuzzer`, `miri`, `asan_ubsan`, `concurrency_100_to_1000`.

## Failures

None.

## Final statement

**100000** validation cases were executed (PASS+FAIL). **0** failed. **0** bugs found and **1** fixed in this run. Untested/blocked items remain as listed (FFI C ABI direct calls, CUDA antech cross in-runner, libFuzzer/Miri/ASan/UBSan, concurrency ≥100). Final status: **PASS**.
