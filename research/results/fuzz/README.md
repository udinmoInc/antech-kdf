# Fuzz results directory

## CI libFuzzer (authoritative for “did we fuzz?”)

- **Report:** [`report.md`](./report.md)
- **Summary:** [`libfuzzer-ci-summary.json`](./libfuzzer-ci-summary.json)
- **Table:** [`libfuzzer-ci-report.md`](./libfuzzer-ci-report.md)
- **Raw JSONL:** [`ci/libfuzzer.jsonl`](./ci/libfuzzer.jsonl)

Latest successful Ubuntu run: Actions `33067507461`, SHA `2a85cf9`, status **PASS**, ~509M executions, 0 crashes/hangs.

## Local Windows fallback (NOT libFuzzer)

Files such as `summary.md`, `parser.csv`, `campaign-log.md` may describe the **fallback harness**. They are useful for Windows hosts without a fuzz toolchain but **must not** be cited as libFuzzer PASS.
