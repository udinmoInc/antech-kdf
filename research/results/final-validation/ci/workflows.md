# CI integration

Production CI (`.github/workflows/ci.yml`): fmt, clippy, `cargo test --workspace`.

Research / security validation (separate workflows):
| Workflow | Purpose |
|---|---|
| `fuzz.yml` | Real libFuzzer via cargo-fuzz on Ubuntu + fallback harness |
| `sanitizers.yml` | Miri, ASan, UBSan on Ubuntu nightly |
| `validation.yml` | Reference conformance, correctness CI profile, cross-OS matrix, optional CUDA |

Local Windows host cannot run libFuzzer / Miri / ASan — those are **BLOCKED** here and **NOT** claimed PASS.
