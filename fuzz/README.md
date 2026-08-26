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

## Linux / CI (libFuzzer)

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo fuzz run hash_parser -- -max_total_time=600
# … same for other targets
```

Workflow: `.github/workflows/fuzz.yml` (PR: minutes; weekly schedule: longer).

## Windows fallback

`cargo-fuzz` / libFuzzer are **not** available on this Windows host (install fails: missing `dlltool.exe` on GNU toolchain; missing `link.exe`/VS Build Tools on MSVC nightly). Use:

```bash
# default 300s per target; raise for deeper campaigns
set ANTECH_FUZZ_SECS=600
cargo run --manifest-path fuzz/harness/Cargo.toml --release
```

Results: `research/results/fuzz/`.

Campaign findings fixed in-tree: **R14** (non-ASCII hex panic in parser), **R15** (nested acquire-while-holding Condvar hang in scheduler).

## Corpora

Seed inputs live in `fuzz/corpus/<target>/` (valid/invalid hashes, vectors, boundary blobs).
