# Final validation report

Engineering validation gaps closed for infrastructure and local execution. **BLOCKED** / **NOT RUN** are never treated as **PASS**.

## Overall

| Gate | Status |
|---|---|
| Production fmt / check / test / clippy | **PASS** |
| Package tests (`antech-kdf`, `core`, `format`) | **PASS** |
| `antech-kdf --no-default-features` | **PASS** |
| Reference == production | **PASS** |
| Final-validation conformance runner | **PASS** (8 PASS, 0 FAIL, 3 BLOCKED) |
| Fallback fuzz harness (non-libFuzzer) | **PASS** (0 panics/asserts) |
| Real libFuzzer / cargo-fuzz (this host) | **BLOCKED** |
| Miri (this host) | **BLOCKED** |
| ASan / UBSan (this host) | **BLOCKED** |
| Linux CI libFuzzer / Miri / ASan / UBSan | **NOT RUN** on this machine (workflows added; execute on GitHub) |

## Platform (this host)

| Field | Value |
|---|---|
| OS | windows / x86_64 |
| CPU | AMD Ryzen 5 4600G with Radeon Graphics |
| Logical CPUs | 12 |
| RAM | 31.87 GiB |
| GPU | NVIDIA GeForce RTX 3050 |
| VRAM | 8192 MiB |
| CUDA | 13.3 |
| rustc / cargo | 1.98.0 |

## 1. Fuzz

### Targets (all present)

`hash_parser`, `verify_input`, `hash_verify`, `config_builder`, `malformed_v2`, `ffi_api`, `scheduler`

### libFuzzer

| Item | Status |
|---|---|
| Local cargo-fuzz | **BLOCKED** (no `dlltool.exe` / `link.exe`) |
| CI workflow | `.github/workflows/fuzz.yml` — Ubuntu libFuzzer + `fuzz/ci_run_and_report.sh` metrics |
| Executions / coverage (libFuzzer) | **NOT RUN** locally |
| Crashes / hangs (libFuzzer this run) | **NOT RUN** |

### Fallback harness (executed)

30s/target on this host: **0 panics, 0 asserts**, ~98M combined executions. See `fuzz/fallback-summary.json` and prior deeper campaign under `research/results/fuzz/` (180s/target, 632M execs, PASS after R14/R15).

### Bugs previously found & fixed (regressions retained)

| ID | Issue | Status |
|---|---|---|
| R14 | Non-ASCII hex panic in parser | fixed + corpus seed + unit test |
| R15 | Nested acquire Condvar hang | fixed + unit test |

## 2. Sanitizers

| Tool | Local | CI |
|---|---|---|
| Miri (`types`, `format`, `core` lib) | **BLOCKED** (MSVC `link.exe` missing for miri sysroot) | `sanitizers.yml` → Ubuntu nightly |
| ASan | **BLOCKED** (Linux `-Zsanitizer=address` + build-std) | `sanitizers.yml` |
| UBSan | **BLOCKED** | `sanitizers.yml` |

Explicit exclusions (documented, not silent): `antech-kdf-ffi` C ABI, CUDA device code.

## 3. Hardware / cross-implementation

| Check | Status | Notes |
|---|---|---|
| Production vs reference digests (1 MiB + 16 MiB) | **PASS** | |
| Randomized cross (32 configs) | **PASS** | mismatches=0 |
| v2 parse / reencode / verify | **PASS** | |
| GPU CPU digest cross (RTX 3050 CSV) | **PASS** | 480/480 OK in MEASURED `compute-memory-v4/gpu/correctness.csv` |
| Second OS/toolchain locally | **BLOCKED** | No WSL/Docker; CI matrix `ubuntu`/`windows`/`macos` in `validation.yml` |
| Second GPU class | **BLOCKED** | Only RTX 3050 on this host |

## 4. CI integration added

| Workflow | Role |
|---|---|
| `ci.yml` | Production only |
| `fuzz.yml` | libFuzzer + fallback (research) |
| `sanitizers.yml` | Miri / ASan / UBSan (research) |
| `validation.yml` | Reference, correctness CI profile, cross-OS, optional CUDA |

## 5. Commands executed (this host)

```text
cargo fmt --all -- --check                          → PASS
cargo check --workspace                             → PASS
cargo test --workspace                               → PASS
cargo clippy --workspace --all-targets --all-features -D warnings → PASS
cargo check -p antech-kdf --no-default-features      → PASS
cargo test -p antech-kdf -p antech-kdf-core -p antech-kdf-format → PASS
cargo test --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release → PASS
cargo run … final_validation_runner                  → PASS
cargo run … fuzz/harness (30s/target)                → PASS (fallback)
cargo +nightly-msvc miri …                           → BLOCKED
cargo fuzz …                                         → BLOCKED
```

## 6. Regression tests

Already in tree from prior campaigns: parser non-ASCII hex, scheduler nested-acquire, stress admissions, correctness regressions. No new crash found in this validation pass requiring an additional fix.

## 7. Remaining engineering gaps

1. **Execute** Ubuntu CI jobs for libFuzzer, Miri, ASan, UBSan and archive artifacts into `research/results/final-validation/` (local host cannot).
2. Optional self-hosted CUDA runner (`ANTECH_CUDA_RUNNER=true`) for live GPU re-runs beyond the stored MEASURED CSV.
3. Broader CPU SKUs / ARM once CI macos/ubuntu matrix results are collected.
4. Dedicated FFI sanitizer harness (explicitly excluded today).

## Artifact layout

```text
research/results/final-validation/
  final-report.md
  summary.json
  conformance/
  hardware/
  fuzz/
  sanitizers/
  ci/
```
