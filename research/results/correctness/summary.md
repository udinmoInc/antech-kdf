# Correctness campaign summary

**Verdict:** PASS

Host: windows x86_64 cpus=12

| Metric | Count |
|---|---:|
| Total cases | 421 |
| PASS | 398 |
| FAIL | 0 |
| BLOCKED | 7 |
| NOT_APPLICABLE | 16 |
| Randomized | 2564 |
| Boundary | 83 |
| Malformed | 32 |
| Concurrency ops | 2009 |
| Cross-impl comparisons | 923 |
| GPU comparisons | 480 |
| Panics caught | 0 |
| Bugs fixed | 2 |
| Regression tests added | 3 |

## Per-suite

- **block_size**: cases=15 pass=15 fail=0 blocked=0 n/a=0
- **concurrency**: cases=11 pass=11 fail=0 blocked=0 n/a=0
- **determinism**: cases=6 pass=6 fail=0 blocked=0 n/a=0
- **differential**: cases=42 pass=42 fail=0 blocked=0 n/a=0
- **fan_in**: cases=10 pass=10 fail=0 blocked=0 n/a=0
- **ffi**: cases=8 pass=8 fail=0 blocked=0 n/a=0
- **gpu**: cases=3 pass=2 fail=0 blocked=1 n/a=0
- **graph**: cases=13 pass=11 fail=0 blocked=0 n/a=2
- **hash_verify**: cases=109 pass=109 fail=0 blocked=0 n/a=0
- **legacy**: cases=3 pass=3 fail=0 blocked=0 n/a=0
- **long_run**: cases=1 pass=1 fail=0 blocked=0 n/a=0
- **memory**: cases=27 pass=23 fail=0 blocked=0 n/a=4
- **output_length**: cases=9 pass=9 fail=0 blocked=0 n/a=0
- **parser**: cases=22 pass=22 fail=0 blocked=0 n/a=0
- **property**: cases=11 pass=11 fail=0 blocked=0 n/a=0
- **rehash**: cases=3 pass=3 fail=0 blocked=0 n/a=0
- **resource_failure**: cases=3 pass=3 fail=0 blocked=0 n/a=0
- **salt**: cases=68 pass=68 fail=0 blocked=0 n/a=0
- **sanitizers**: cases=3 pass=1 fail=0 blocked=2 n/a=0
- **sdk_cli**: cases=6 pass=2 fail=0 blocked=4 n/a=0
- **serialization**: cases=27 pass=27 fail=0 blocked=0 n/a=0
- **small_graph**: cases=21 pass=11 fail=0 blocked=0 n/a=10

## Blockers (sample)

- gpu:live_cuda_compare:nvcc/GPU present; live CUDA attacker re-run via v4_gpu_runner separately; prior CSV imported
- sanitizers:miri:nightly miri not installed
- sanitizers:asan:AddressSanitizer not enabled for this campaign run
- sdk_cli:cli_binary:antech-kdf CLI binary not found under target/
- sdk_cli:node_sdk:not executed in this Rust campaign (see sdk/conformance CI)
- sdk_cli:go_sdk:not executed in this Rust campaign (see sdk/conformance CI)
- sdk_cli:kotlin_sdk:not executed in this Rust campaign (see sdk/conformance CI)
