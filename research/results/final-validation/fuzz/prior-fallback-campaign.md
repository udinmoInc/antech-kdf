# Fuzz campaign summary

**Verdict:** PASS

| Metric | Value |
|---|---:|
| TOTAL TARGETS | 6 |
| TOTAL EXECUTIONS | 98397540 |
| TOTAL CORPUS ENTRIES | 27 |
| TOTAL UNIQUE CRASHES (panics) | 0 |
| TOTAL ASSERTION FAILURES | 0 |
| TOTAL HANGS | 0 |
| TOTAL BUGS FOUND | 0 |
| SECS PER TARGET (configured) | 30 |
| TOTAL CAMPAIGN TIME (s) | 180.0 |
| TOOLS ACTUALLY EXECUTED | fallback harness (libFuzzer BLOCKED on this host) |

## Per target

- **parser**: execs=27417893 panics=0 asserts=0 corpus=20 time=30.0s
- **config**: execs=57177825 panics=0 asserts=0 corpus=2 time=30.0s
- **hash_verify**: execs=6854 panics=0 asserts=0 corpus=1 time=30.0s
- **ffi**: execs=3384 panics=0 asserts=0 corpus=1 time=30.0s
- **scheduler**: execs=11648848 panics=0 asserts=0 corpus=1 time=30.0s
- **malformed_v2**: execs=2142736 panics=0 asserts=0 corpus=2 time=30.0s
