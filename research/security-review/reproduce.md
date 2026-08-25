# Reproducing the Security Review Package

## Prerequisites

- Rust **1.70+** (edition 2021)
- `cargo`
- Optional: **CUDA** / NVIDIA GPU for GPU attacker examples
- Optional: Windows was used for some campaign measurements; Linux should build the core crates

## Build production crates

```bash
cargo test -p antech-kdf -p antech-kdf-core -p antech-kdf-format --release
```

## Hash / verify (CLI)

```bash
cargo run -p antech-kdf-cli -- hash "password"
cargo run -p antech-kdf-cli -- verify "password" "$HASH"
```

Or via the library API (`antech_kdf::hash` / `verify`).

## Reference implementation

```bash
cargo test --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release
cargo run  --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release -- derive \
  --password password --salt-hex 73616c745f31365f62797465735f2121 --memory-kib 1024
```

The reference crate reimplements the specification with clarity prioritized over speed. Its tests load `research/security-review/test-vectors.json`.

## Regenerate test vectors (maintainers)

```bash
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example gen_security_review_vectors
```

## Main cryptanalysis campaigns (optional, heavy)

```bash
# Prior DAG / schedule / GPU campaign artifacts live under:
#   research/results/cryptanalysis/

cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example cryptanalysis_runner

# Advanced TMTO campaign:
cargo run --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example tmto_advanced_runner
```

### Hardware / tool dependencies

| Component | Dependency |
|---|---|
| Core vectors / reference | CPU + Rust only |
| GPU attacker numbers in evidence | CUDA + NVIDIA GPU (RTX 3050 used in campaign) |
| Some Windows path notes in research runners | Windows host for those exact scripts |
| Energy / DRAM profilers | **Not required**; often unavailable |

If CUDA is absent, skip GPU sections; CPU evidence and vectors remain reproducible.
