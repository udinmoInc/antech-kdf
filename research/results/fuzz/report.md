# Fuzz campaign report — real libFuzzer (CI)

**Final status: PASS**

| Field | Value |
|---|---|
| Engine | **libFuzzer** via `cargo-fuzz` (Ubuntu) |
| Host | GitHub Actions `ubuntu-latest` |
| Workflow | `.github/workflows/fuzz.yml` |
| Run | https://github.com/udinmoInc/antech-kdf/actions/runs/33067507461 |
| SHA | `2a85cf9e666e4ad3c47fac038f9e11d77dba1b88` |
| Campaign | **full** (parser 900s, heavy 600s, light 600s) |
| KDF / API / `$antech$v2$` | **unchanged** |

## Distinction (mandatory)

| Kind | Location | Status |
|---|---|---|
| **CI libFuzzer (this report)** | `libfuzzer-ci-summary.json`, `ci/` | **PASS** — executed |
| Local Windows fallback harness | older `summary.md` / CSVs if present | **NOT libFuzzer** — do not equate |

A prior CI attempt (`33064928424`) ran `hash_parser` for ~901s (~55M execs) then **failed reporting** (JSON helper choked on tabbed coverage lines). That was a harness bug, not a product crash. Fixed in `fuzz/ci_run_and_report.sh`; this run completed all six targets.

## Exact totals

| Metric | Value |
|---|---:|
| Targets executed | **6** |
| Total libFuzzer executions | **509,208,002** |
| Crashes (artifact files) | **0** |
| Hangs flagged | **0** |
| Bugs found this run | **0** |
| Bugs fixed this run | **0** (reporter-only fix) |
| Regression tests added this run | **0** (prior R14/R15 already in-tree) |
| CI/toolchain blockers remaining | **none** for Ubuntu libFuzzer |

## Per target

| Target | Status | Duration (s) | Executions | Corpus before→after | cov / ft (DONE line) |
|---|---|---:|---:|---:|---|
| hash_parser | PASS | 901 | 56,125,930 | 21→356 | 585 / 1342 |
| hash_verify | PASS | 602 | 10,030 | 6→93 | 647 / 935 |
| config_builder | PASS | 601 | 399,274,898 | 8→19 | 62 / 64 |
| malformed_v2 | PASS | 602 | 6,976,942 | 6→315 | 536 / 1013 |
| ffi_api | PASS | 601 | 11,233 | 4→98 | 598 / 929 |
| scheduler | PASS | 602 | 46,808,969 | 4→73 | 157 / 652 |

Configured budgets: parser **900s**, hash_verify **600s**, others **600s**. Elapsed ≈ budget + overhead.

## Corpus / seeds

Seeds included valid `$antech$v2$` shapes, malformed / v1 / duplicate-key cases, boundary configs, R14 unicode-hex regression, FFI/scheduler policy bytes. CI grew corpora substantially (see table). Grown corpora are in the Actions artifact `fuzz-libfuzzer-results` under `fuzz/corpus/` and `research/results/fuzz/ci/corpus/`.

## Crashes / hangs / failures

- `fuzz/artifacts/**`: **empty** (no crash/timeout artifacts).
- No unresolved panic/abort/hang in this campaign.
- Historical (already fixed, regression corpus retained): **R14** non-ASCII hex panic; **R15** nested scheduler Condvar hang.

## Artifacts on disk

| Path | Contents |
|---|---|
| `libfuzzer-ci-summary.json` | Machine-readable CI summary |
| `libfuzzer-ci-report.md` | CI table |
| `libfuzzer-ci-per-target.csv` | Per-target CSV |
| `ci/libfuzzer.jsonl` | One JSON object per target |
| `ci/logs/*.log` | Full libFuzzer logs (in CI artifact) |
| `ci/campaign-meta.txt` | `campaign=full`, budgets, `target_fail_flag=0` |
| `report.md` | This human report |

## Reproducibility

```bash
# From repo root on Linux / CI:
cargo fuzz build <target>
./fuzz/ci_run_and_report.sh <target> <secs> research/results/fuzz/ci/libfuzzer.jsonl
# Or: Actions → Fuzz Testing → Run workflow → campaign=full|deep
```

**Verdict:** every configured libFuzzer target **ran successfully** with **no unresolved crash or hang** → **PASS**.
