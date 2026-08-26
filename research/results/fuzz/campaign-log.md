# Fuzz campaign log

- Host: windows / x86_64
- Mode: **fallback harness** (`fuzz/harness`) — cargo-fuzz not installable (missing `dlltool.exe` / `link.exe`)
- Duration: 180s per target (final clean re-run after R14 + R15)
- Earlier: 300s/target run hung on `scheduler` (R15); aborted and fixed

## Tools

| Tool | Status |
|---|---|
| antech-kdf-fuzz-harness | Executed (this host) |
| cargo-fuzz / libFuzzer | BLOCKED locally; configured in CI |
| ASan / UBSan / Miri | Not run |

## Targets

### parser

executions=172067934 corpus=20 panics=0 asserts=0 elapsed=180.000s

### config

executions=375716310 corpus=2 panics=0 asserts=0 elapsed=180.000s

### hash_verify

executions=56037 corpus=1 panics=0 asserts=0 elapsed=180.006s

### ffi

executions=26365 corpus=1 panics=0 asserts=0 elapsed=180.002s

### scheduler

executions=71182122 corpus=1 panics=0 asserts=0 elapsed=180.000s

### malformed_v2

executions=12980618 corpus=2 panics=0 asserts=0 elapsed=180.000s

## Findings timeline

1. **R14** — parser panic on Unicode hex (pre-fix campaign flooded `parser_panic_*`); fixed in `antech-kdf-format`; regression + corpus seed.
2. **R15** — scheduler hang during 300s campaign when fuzz held permits then waited; fixed in `antech-kdf-core` resource admission; regression test `nested_acquire_while_holding_fails_instead_of_deadlock`.
3. Final 180s×6 re-run: **0 panics, 0 asserts, 0 hangs**.
