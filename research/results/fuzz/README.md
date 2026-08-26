# Fuzz results

**Verdict: PASS** (fallback harness; libFuzzer blocked on this Windows host).

| Artifact | Description |
|---|---|
| `summary.md` / `summary.json` | Campaign metrics + verdict |
| `campaign-log.md` | Host, tools, per-target log |
| `parser.csv` / `parser_malformed_v2.csv` | Parser surfaces |
| `config.csv` | Config builder |
| `hash_verify.csv` | Hash/verify |
| `ffi.csv` | C ABI |
| `scheduler.csv` | Resource scheduler |
| `regressions.csv` | R12 / R14 / R15 |
| `crashes/` | Minimized inputs (R14 sample retained) |

## How to reproduce

```bash
# Windows / any host without cargo-fuzz
set ANTECH_FUZZ_SECS=180
cargo run --manifest-path fuzz/harness/Cargo.toml --release

# Linux CI / libFuzzer
cargo fuzz run hash_parser -- -max_total_time=600
```

See `fuzz/README.md` and `.github/workflows/fuzz.yml`.
