# Reliability audit — final report

**Date:** 2026-08-25  
**Host:** Windows 10, Rust 1.98  
**Scope:** Full production reliability audit per test matrix; no cryptographic redesign.

## Executive summary

The audit confirmed and fixed **8 production stability/security issues** from the prior pass plus **3 additional issues** discovered during expanded testing (serde `--all-features` build, flaky global-scheduler test infra, incorrect boundary test). **`ResourcePolicy.queue_limit` is now enforced** via a blocking admission queue with overflow rejection.

All **65 workspace tests pass**. Stress/concurrency CSVs recorded under this directory. Arbitrary untrusted input paths (parser, verify, FFI null pointers) do not panic the process in tested scenarios.

## Totals

| Metric | Count |
|---|---|
| Tests run | **65** (+ reliability runner stress scenarios) |
| Issues found | **11** (8 production + 3 test/infra) |
| Issues fixed | **11** |
| Regression tests added | **22+** (new integration/property/queue/FFI tests) |
| Remaining reproducible issues | **0** in production path |
| Environmental blockers | **3** (cargo-fuzz, Nsight/perf, proptest dlltool — mitigated) |

## Resource scheduler stress

See `resource-results.csv`. Key observations:

- Peak memory stays within 64 KiB budget cap in isolated scheduler test (`peak_mem_kib ≤ 65536`).
- At 50–100 threads with tight limits, queue rejects dominate (`admissions_err` ≫ `admissions_ok`) — **queue_limit enforcement working**.
- Global hash/verify stress (`stress-results.csv`): **0 errors**, scheduler idle after each run.

## Concurrency throughput

See `concurrency-results.csv`. 250 concurrent `hash()` calls complete without crash; linear latency scaling expected under default 16 MiB admission.

## Fuzz / property testing

See `fuzz-results.csv`. libFuzzer targets exist but could not run on this host. Substituted:

- 512-iteration rand loops for `parse_hash` and `verify` (`reliability_property`, `parser_property`)
- Existing malformed-hash matrix (`reliability_matrix`)

**Invariant verified:** arbitrary UTF-8 / byte inputs to parser and verify return `Result`, never panic.

## Fixes unchanged from constraints

- `hash()`, `verify()`, `needs_rehash()` semantics unchanged
- v2 encoded hash format unchanged
- Canonical production parameters unchanged
- KDF graph/mix/engine logic unchanged

## Not claimed

This audit does **not** assert 100% coverage of all failure modes. Items not fully exercised:

- Long-duration (60s+) stress at 1000 threads (runner uses 2–3s windows; design supports higher scale)
- libFuzzer minimization campaigns
- CUDA kernel failure injection (research-only binary)
- OOM simulation / allocation failure hooks

## Artifacts

| File | Description |
|---|---|
| `issues-found.md` | Per-issue root cause, fix, regression test |
| `regressions.csv` | Machine-readable issue tracker |
| `resource-results.csv` | Scheduler admission stress |
| `stress-results.csv` | Global hash/verify stress |
| `concurrency-results.csv` | Concurrent hash throughput |
| `fuzz-results.csv` | Fuzz/property status |
| `build-matrix.md` | Build/test matrix results |

## Before / after (resource policy)

| Behavior | Before | After |
|---|---|---|
| Global scheduler | Per-call instance | `OnceLock` singleton |
| verify admission | Bypassed | Same as hash |
| Permit on error | Leaked | RAII guard |
| queue_limit | Ignored | Enforced (block up to N, then reject) |
| Parser max input | Unbounded hex alloc | 8192 char cap + exact hex length |
