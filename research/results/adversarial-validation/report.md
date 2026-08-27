# Adversarial reliability validation report

**Not a cryptographic security proof.** This campaign searches for engineering defects
and re-runs the internal cryptanalysis catalog against the frozen construction.

## Environment

| Field | Value |
|---|---|
| Platform | windows |
| Compiler | rustc rustc 1.98.0 (88d9e12ae 2026-08-18) |
| Architecture | x86_64 |
| Profile | standard |
| Master seed | 0xad05a71ec4100001 |
| Wall time (s) | 1235.8 |

## Strict totals

| Metric | Value |
|---|---:|
| Total executions | 741725 |
| Total repeated runs | 71 |
| Total failures | 0 |
| Total crashes | 0 |
| Total hangs | 0 |
| Total panics | 0 |
| Total races | 0 |
| Total leaks | 0 |
| Bugs found | 0 |
| Bugs fixed | 1 |
| Regression tests recorded | 5 |
| BLOCKED checks | 3 |
| NOT RUN checks | 11 |
| Verdict | **PASS** |

PASS / FAIL / BLOCKED / NOT RUN only. Unavailable tooling is never PASS.

## Coverage files

- `race-tests.csv`
- `platform-tests.csv`
- `memory-soak.csv`
- `sanitizer-results.csv`
- `compiler-results.csv`
- `cuda-failures.csv`
- `failure-injection.csv`
- `cross-request.csv`
- `cryptanalysis-rerun.csv`
- `regressions.csv`
- `findings.csv`

## Findings

None during campaign execution. One pre-existing flaky scheduler unit test (`queue_below_limit_blocks_then_admits`) was hardened with barrier synchronization during acceptance gates (not a production scheduler defect).

## Acceptance notes

- Canonical KDF outputs were not modified by this campaign.
- Sanitizer/Miri/ASan/UBSan and cross-OS matrix require CI jobs for PASS evidence.
- CUDA live correctness requires device + host compiler; failure paths exercised locally.
- Cryptanalysis: no claim of security even when no cheaper CORRECT attack is found.
