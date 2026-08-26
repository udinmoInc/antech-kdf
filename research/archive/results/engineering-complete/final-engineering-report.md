# Final Engineering Report

Scope: finish engineering/research infrastructure only. **No** external cryptanalysis conclusion. Canonical KDF / `hash` / `verify` / `needs_rehash` / v2 format **unchanged**.

## Engineering areas completed

- CPU attacker bake-off (production vs packed_* strategies, thread sweep)
- GPU attacker result capture (prior MEASURED + environment probe)
- Multi-target amortization measurements + modeled large-N
- Side-channel timing / malformed / design notes
- ASIC/FPGA analytical model + sensitivity
- Hardware metadata schema
- Property harness + fuzz target expansion
- Configurable stress runner
- Reference vs production check

## Code files changed (primary)

- `research/code/antech-kdf-research/src/engineering/**`
- `research/code/antech-kdf-research/examples/engineering_complete_runner.rs`
- `fuzz/fuzz_targets/*` (expanded)
- workspace wiring for research → antech-kdf (API stress/side-channel)

## Strongest CPU attacker

This bake-off (1s cells): `packed_noring` @ 32 threads → **88.00 g/s** (16 MiB, correct=true). Kind: MEASURED.

Prior longer cryptanalysis campaign champion remains `packed_prefetch` (~0.51× vs byte-buffer full walk @ 1 thread). Short-cell ranking can jitter between packed_* variants.

## Strongest GPU attacker

Prior MEASURED: **packed_t32_b256 ≈ 100.53 g/s** (RTX 3050 campaign, digests matched). This run: cuda_available=true, GPU=RTX 3050; fresh kernel rebuild not executed in this pass (binary may be stale — see `gpu-attacker/results.csv`).

## Multi-target results

Shared DAG across independent salts: **false** (seed binds password). See `multitarget/`. Sample rows: 8.

## Side-channel findings

- **SC1_verify_correct_vs_wrong_timing** [info/MEASURED]: SIMILAR_MEDIANS correct_ms=3.314 wrong_ms=3.316 ratio=0.999

- **SC2_malformed_hash_fast_fail** [info/MEASURED]: avg_us_per_call=0.100

- **SC3_parser_no_panic_fuzzish** [info/MEASURED]: panics=0

- **SC4_secret_dependent_memory** [accepted_design/MODELED]: Parent/scatter addresses depend on rolling state derived from password; access pattern is secret-dependent by design (memory-hard KDF).

- **SC5_digest_compare** [info/MEASURED]: verify uses subtle::ConstantTimeEq on digests after full derive.

Constant-time w.r.t. password **not claimed** (memory-hard access pattern is secret-dependent by design).

## ASIC/FPGA model status

MODELED only — see `asic-fpga/model.json`. Sequential 256-bit state + full working set on-chip assumed.

## Hardware portability status

Metadata in `hardware/meta.json`. Env overrides: `ANTECH_CPU_SECS`, `ANTECH_STRESS_SECS`, `ANTECH_STRESS_CONC`.

## Fuzz/property status

cargo-fuzz targets under `/fuzz`; deterministic harness results in `fuzz/property-harness.json`.

## Long-duration stress status

- 10s × 1 workers: hashes=957 errors=0 idle=true

- 10s × 4 workers: hashes=3545 errors=0 idle=true

## Independent-reference status

See `reference/status.txt` and `research/code/reference/`.

## Remaining environmental blockers

- Fresh GPU kernel rebuild may require CUDA toolkit + MSVC on Windows.
- Full stress matrix (60s/300s, 250–1000 workers) via env vars (defaults are shorter).
- cargo-fuzz requires nightly in CI.
- `cargo doc --workspace --no-deps` failed on this host: Windows file lock on `target/doc/antech_kdf` (os error 32). Retry after closing doc viewers / IDE preview.

## Regression tests

- Existing production/reliability tests unchanged in semantics.
- Reference crate tests vs vectors.
- Property harness failures would be recorded in fuzz/ JSON.

## Confirmation

Canonical production KDF and public API were **not** changed by this engineering campaign.

