# Side-channel campaign summary (Windows + Linux)

| Field | Value |
|---|---|
| Verdict | **PASS** |
| Date (UTC) | 2026-08-28T06:39:10Z |
| CI run (Linux) | [33148612384](https://github.com/udinmoInc/antech-kdf/actions/runs/33148612384) |
| Windows timing | **MEASURED** |
| Linux timing | **MEASURED** |
| Linux PMU/cache | **BLOCKED** (hosted VM; see `perf-probe.log`) |
| PMU significant equal-length leaks | 0 (NOT RUN) |

## T01 correct vs wrong (timing, full derive)

| Host | ratio_median | welch_t | significant |
|---|---|---|---|
| Windows | 0.998 | 0.41 | no |
| Linux | 1.000 | 0.90 | no |

**Conclusion unchanged:** no exploitable correct-vs-wrong verify shortcut on either host.

## Status by layer

| Layer | Windows | Linux |
|---|---|---|
| Wall-clock timing | MEASURED | MEASURED |
| PMU / cache-miss / branch HW | BLOCKED (no perf) | **BLOCKED** (`perf-probe.log`) |
| Static branch audit | MODELED | MODELED |
| FFI overhead | MEASURED | MEASURED |
| Scheduler contention | MEASURED | MEASURED |

## Artifacts

`timing-windows.csv`, `timing-linux.csv`, `cache-analysis.csv`, `cache-comparison.csv`, `perf-probe.log`, `branch-analysis.csv`, `contention.csv`, `ffi.csv`, `regressions.csv`, `report.md`
