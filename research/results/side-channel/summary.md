# Side-channel campaign summary

| Field | Value |
|---|---|
| Verdict | **PASS** |
| Host | windows / x86_64 |
| Profile | derive_samples=80 fast_samples=800 |
| Timing tests | 11 |
| Significant derive-path leaks | 0 |
| Fast-path timing oracles (expected) | 4 |
| Cache PMU | **BLOCKED** on this host |

## Key questions

| Question | Answer |
|---|---|
| Correct vs wrong verification distinguishable (full derive)? | **NO** (median ratio 0.998, Welch t 0.41) |
| Password length leaks beyond SHA bind? | **NO practical leak** — T03 shows length-dependent hash time dominated by memory-hard phase; not a verify shortcut. |
| Secret/AD values create exploitable verify timing difference? | **NO cheaper verify** — wrong secret/AD still runs full derive; timing differences are password-independent digest mismatch. |
| Parent selection / memory access leaks (cache)? | **MODELED risk** — data-dependent graph addressing is intentional; micro-architectural cache attacks not measured here unless Linux perf row present. |
| Concurrency / scheduler oracle on password correctness? | **NO password oracle** — contention changes latency, not verify outcome branches on peer secrets. |
| LLVM/perf cache counters measured? | BLOCKED on Windows; run Linux CI job |

## Artifacts

`timing.csv`, `branch-analysis.csv`, `cache-analysis.csv`, `contention.csv`, `ffi.csv`, `regressions.csv`, `report.md`
