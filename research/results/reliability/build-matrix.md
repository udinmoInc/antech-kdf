# Build matrix — reliability audit 2026-08-25

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | PASS (auto-formatted during run) |
| Workspace check | `cargo check --workspace` | PASS |
| Production no-default-features | `cargo check -p antech-kdf --no-default-features` | PASS |
| Workspace tests | `cargo test --workspace` | PASS (**65** tests) |
| Clippy all targets | `cargo clippy --workspace --all-targets --all-features` | PASS (warnings only) |
| Doc | `cargo doc --workspace --no-deps` | PASS (1 research broken intra-doc link warning) |
| Core crate | `cargo test -p antech-kdf-core` | PASS (11 tests) |
| Format crate | `cargo test -p antech-kdf-format` | PASS (9 tests) |
| Production crate | `cargo test -p antech-kdf` | PASS (24 tests) |
| FFI crate | `cargo test -p antech-kdf-ffi` | PASS (5 tests) |
| Research crate | `cargo test -p antech-kdf-research` | PASS (15 tests) |
| Release reliability runner | `cargo run --release -p antech-kdf --example reliability_runner` | PASS |
| CLI malformed input | missing args / bad hash | PASS (clap error / clean KdfError, no panic) |
| cargo-fuzz | `fuzz/hash_parser`, `fuzz/verify_input` | **BLOCKED** on Windows |
| Nsight / perf | GPU/CPU profiling | **BLOCKED** — tools not installed |

## Per-crate test counts

| Crate | Tests |
|---|---|
| antech-kdf (integration) | 24 |
| antech-kdf-core | 11 |
| antech-kdf-format | 9 |
| antech-kdf-ffi | 5 |
| antech-kdf-research | 15 |
| antech-kdf doc-test | 1 |
| **Total** | **65** |

## Regression tests added this audit

- `crates/antech-kdf/tests/reliability_matrix.rs` (4)
- `crates/antech-kdf/tests/reliability_concurrency.rs` (2)
- `crates/antech-kdf/tests/reliability_property.rs` (2)
- `crates/antech-kdf/tests/common/mod.rs` (shared helper)
- `crates/antech-kdf-format/tests/parser_property.rs` (4)
- `crates/antech-kdf-core/src/resource.rs` queue tests (4 new)
- `crates/antech-kdf-ffi` FFI tests expanded (5)
- `crates/antech-kdf-format` duplicate param test (1)

## Environmental blockers

1. **cargo-fuzz / libFuzzer** — requires Linux/macOS or MSVC+fuzz toolchain; property tests substitute with 512 random iterations each.
2. **proptest + getrandom 0.3** — `dlltool.exe` missing on this Windows host; switched to workspace `rand 0.8` property loops.
3. **Nsight Compute/Systems, perf** — not available for GPU failure / IPC profiling on this host.
4. **cargo doc** — occasional file-lock contention on `target/doc` (transient Windows AV/indexer).
