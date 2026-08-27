# Antech KDF fuzzing

LibFuzzer targets under `fuzz_targets/` call shared runners in `fuzz/harness`
(via **cargo-fuzz** on Linux/macOS/CI). The same runners power the Windows fallback.

| Target | Surface |
|---|---|
| `hash_parser` | v2 `parse_hash`, seed-hash mutations |
| `hash_verify` | parse/verify + occasional tiny deterministic hash |
| `config_builder` | `AntechConfig` validation / boundaries |
| `malformed_v2` | near-grammar malformed strings |
| `ffi_api` | C ABI nulls, lengths, tiny config, panic containment |
| `scheduler` | `BoundedResourceScheduler` admit/queue/release |

## Linux / CI (real libFuzzer)

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
./fuzz/ci_run_and_report.sh hash_parser 600 research/results/final-validation/fuzz/libfuzzer.jsonl
```

Workflow: `.github/workflows/fuzz.yml`

**Do not claim libFuzzer PASS unless the Ubuntu `fuzz-libfuzzer` job executed.**

## Windows fallback (not libFuzzer)

```bash
set ANTECH_FUZZ_SECS=180
cargo run --manifest-path fuzz/Cargo.toml -p antech-kdf-fuzz-harness --release
```

Results: `research/results/fuzz/`

Campaign findings fixed in-tree: **R14** (non-ASCII hex panic), **R15** (nested acquire Condvar hang).

## Corpora

Seed inputs live in `fuzz/corpus/<target>/`.
