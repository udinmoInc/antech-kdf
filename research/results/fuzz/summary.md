# Fuzz campaign summary

**Verdict:** PASS

| Metric | Value |
|---|---:|
| TOTAL TARGETS | 6 |
| TOTAL EXECUTIONS | 6240981 |
| TOTAL CORPUS ENTRIES | 27 |
| TOTAL UNIQUE CRASHES (panics) | 0 |
| TOTAL ASSERTION FAILURES | 0 |
| TOTAL HANGS | 0 |
| TOTAL BUGS FOUND | 0 |
| SECS PER TARGET (configured) | 2 |
| TOTAL CAMPAIGN TIME (s) | 12.0 |
| TOOLS ACTUALLY EXECUTED | fallback harness (libFuzzer BLOCKED on this host) |

## Per target

- **parser**: execs=1928567 panics=0 asserts=0 corpus=20 time=2.0s
- **config**: execs=3239294 panics=0 asserts=0 corpus=2 time=2.0s
- **hash_verify**: execs=616 panics=0 asserts=0 corpus=1 time=2.0s
- **malformed_v2**: execs=156824 panics=0 asserts=0 corpus=2 time=2.0s
- **ffi**: execs=201 panics=0 asserts=0 corpus=1 time=2.0s
- **scheduler**: execs=915479 panics=0 asserts=0 corpus=1 time=2.0s
