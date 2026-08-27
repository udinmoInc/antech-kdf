# Antech KDF fuzzing

LibFuzzer targets under `fuzz_targets/` (via **cargo-fuzz** on Linux/macOS/CI).

| Target | Surface |
|---|---|
| `hash_parser` | v2 `parse_hash`, seed-hash mutations |
| `verify_input` | password/hash split → `verify` |
| `hash_verify` | parse/verify + occasional tiny `hash_with_config_and_salt` |
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
- PR: timed libFuzzer per target + JSONL metrics under `research/results/final-validation/fuzz/`  
- Weekly schedule: longer campaigns  

**Do not claim libFuzzer PASS unless the Ubuntu `fuzz-libfuzzer` job executed.**

## Windows fallback (not libFuzzer)

`cargo-fuzz` is **BLOCKED** on this Windows host (missing `dlltool.exe` / `link.exe`). Use:

```bash
set ANTECH_FUZZ_SECS=180
cargo run --manifest-path fuzz/harness/Cargo.toml --release
```

Results: `research/results/fuzz/` (and copied into `research/results/final-validation/fuzz/fallback-summary.json`).

Campaign findings fixed in-tree: **R14** (non-ASCII hex panic), **R15** (nested acquire Condvar hang).

## Corpora

Seed inputs live in `fuzz/corpus/<target>/` (valid/invalid hashes, vectors, R14 regression seed).
