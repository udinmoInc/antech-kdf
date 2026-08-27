# Core SOT migration notes

Date: 2026-08-27

## Verdict

Canonical production KDF is solely `crates/antech-kdf-core` (`AntechEngine`, construction version 5, `$antech$v2$`). Research may import core; production never imports research.

## Digest parity

`digest-before-migration.txt` ≡ `digest-after-migration.txt` (salt `v5_cost_salt_16b`):

| password | digest |
|---|---|
| migration-kat | `75aba288…37f5` |
| def_0 | `92fdf4ba…435f` |
| a_0 | `c2819549…3595` |

Published `boundary-1mib-fan4-salt32` still matches `AntechEngine`.

## Cleanup

- Historical v2/v3 engines and spent v5 screens → `research/archive/code/`
- Live `compute_memory/` is bench helpers only (Argon2 H2H / CUDA probe)
- `compute_memory_v4::V4Engine` delegates to core; attackers/CUDA/TMTO kept
- Reference aligned: CombinedFrontier node 0 always two phantoms (matches core)
- Spec §9 / §15 updated accordingly

## Verification (MEASURED this host)

- `cargo test --workspace --release` (production) — pass
- `cargo clippy --workspace --all-targets -- -D warnings` — pass
- `cargo test --workspace --manifest-path research/code/Cargo.toml --release` — pass
