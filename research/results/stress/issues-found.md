# Production stress — issues discovered

Campaign: `production_stress_runner` (real `hash` / `verify`, OnceLock scheduler).  
Scope rule: **no** KDF algorithm, public API, hash format, ResourcePolicy default, or production behavior changes.

## Results

| Check | Outcome |
|---|---|
| Mixed 70/20/10 at 1,10,32,100,250,500,1000 × 10s/30s/60s | PASS — idle after every run |
| Malformed verify + config validation | PASS — 0 panics, 0 unexpected accepts |
| Failure / permit release under contention | PASS — idle, permits released |
| Overload queue_limit enforcement | PASS — `peak_queue_depth=256`, rejects ≫ 0 |
| Peak KDF memory vs 128 MiB budget | PASS — `peak_allocated_kib ≤ 131072` always |
| Unexpected errors / panics / crashes | **0** |

## New production defects

**None.** Prior reliability fixes (R1–R11 in `research/results/reliability/issues-found.md`) remain in force; this campaign did not surface additional scheduler leaks, admission bypasses, or parser panics.

## Harness / test notes (not product bugs)

| Item | Detail |
|---|---|
| Reject-dominated latency at ≥500 concurrency | Expected: queue full → immediate `ResourceExhausted`; all-ops p50≈0 ms. Admitted capacity still ~41–42 ops/s (see ≤250 rows). |
| Binding concurrency | Default 16 MiB × 8 jobs = 128 MiB ceiling → `peak_active_permits=8` |
| Regression coverage | `crates/antech-kdf/tests/stress_regressions.rs` |

## Artifacts

- `research/results/stress/summary.json`
- `research/results/stress/all-scenarios.csv` (+ per-scenario CSVs)
- `research/results/stress/stress-report.md`
- `research/results/stress/runner-console.log`
