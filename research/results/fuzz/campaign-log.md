# Fuzz campaign log

- Host: windows / x86_64
- Mode: **fallback harness** (cargo-fuzz not installable: missing dlltool.exe / link.exe)
- Duration: 30s per target

## parser

executions=27417893 corpus=20 panics=0 asserts=0 elapsed=30.000s

## config

executions=57177825 corpus=2 panics=0 asserts=0 elapsed=30.000s

## hash_verify

executions=6854 corpus=1 panics=0 asserts=0 elapsed=30.011s

## ffi

executions=3384 corpus=1 panics=0 asserts=0 elapsed=30.010s

## scheduler

executions=11648848 corpus=1 panics=0 asserts=0 elapsed=30.000s

## malformed_v2

executions=2142736 corpus=2 panics=0 asserts=0 elapsed=30.000s

