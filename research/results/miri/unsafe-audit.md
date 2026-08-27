# Production `unsafe` audit (Miri campaign)

## Inventory

| Location | Kind | Purpose | Safety claim | Miri exercised? |
|---|---|---|---|---|
| `antech-kdf-core/src/engine.rs` `gather_mix_words` | `_mm_prefetch` | Soft hardware prefetch on parent word blocks | Hint only; no load/store; pointer from `buf.as_ptr().wrapping_add(p)` | Yes — `deterministic_small_config` (CombinedFrontier word path) |
| `antech-kdf-core/src/engine.rs` `gather_and_mix` | `_mm_prefetch` | Soft prefetch on parent byte blocks | Hint only; pointer within `buffer` | Covered by normal `word_path_matches_byte_path_1mib`; ignored under Miri for wall-time (same intrinsic family) |
| `antech-kdf-ffi/src/lib.rs` (all entry points) | C ABI / `from_raw_parts` / `CStr` / `CString` | Foreign callers supply pointers | Documented null/len/UTF-8 contracts | **NOT APPLICABLE** — excluded from Miri |

No other `unsafe` in `antech-kdf-types`, `antech-kdf-format`, `antech-kdf`, or `antech-kdf-cli`.

## Assessment

- Prefetch intrinsics are non-functional for correctness; Miri treats them as no-ops.
- FFI safety depends on C callers; validated by FFI unit tests + ASan/UBSan jobs, not Miri.
- `SecretBytes`, scheduler, and parser use only safe Rust; covered by boundary and scheduler Miri suites.

## Justified exclusions

| Target | Verdict | Reason |
|---|---|---|
| `antech-kdf-ffi` | NOT APPLICABLE | Foreign memory / C ABI |
| CUDA / research GPU | NOT APPLICABLE | Non-host Rust |
| `conformance.rs` | NOT APPLICABLE | Filesystem vectors under isolation |
| Multi 1 MiB derive/hash/verify suites | SKIPPED under Miri | Wall-clock (`#[cfg_attr(miri, ignore)]`); still in normal `cargo test` |
| Reference crate (research) | NOT APPLICABLE | Outside production workspace; parity via normal research tests |
