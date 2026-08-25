# Research

Antech explores whether a password KDF can run in roughly 16 MiB of defender memory without collapsing offline attacker cost relative to a conventional Argon2id profile. Early work used Candidate-004 / K1 / K2. The construction that landed in production is the compute-memory **combined-frontier** graph (research label v4-C), implemented as `AntechEngine` in `antech-kdf-core`.

Research code lives in `antech-kdf-research` and imports core. Production never imports research.

## Chapters

| | |
|---|---|
| [01 — Problem](01-problem.md) | Why 16 MiB matters for small servers |
| [02 — Background](02-background.md) | PBKDF2, bcrypt, scrypt, Argon2id |
| [03 — Design](03-design.md) | Historical candidates and current graph |
| [04 — Evaluation](04-evaluation.md) | CPU numbers and later GPU runs |
| [05 — Security](05-security.md) | Attacker cost, TMTO, caveats |
| [06 — Limitations](06-limitations.md) | What is still open |
| [07 — Future work](07-future-work.md) | Audit, hardware, side channels |

Older specs: [candidates/k1.md](candidates/k1.md), [candidates/k2.md](candidates/k2.md). Rules of the road: [benchmark-methodology.md](benchmark-methodology.md).

## Data

- [data/hardware.md](data/hardware.md)
- [data/baseline.csv](data/baseline.csv), [defender.csv](data/defender.csv), [attacker.csv](data/attacker.csv), [tmto.csv](data/tmto.csv)

GPU head-to-head (RTX 3050, 16 MiB): [results/compute-memory-v4/gpu/report.md](results/compute-memory-v4/gpu/report.md). Best Antech GPU mode was about **33 g/s**; Argon2id about **436 g/s**.

## Runners

```bash
cargo run --release -p antech-kdf-research --example compute_memory_v4_runner
cargo run --release -p antech-kdf-research --example v4_gpu_runner
cargo run --release -p antech-kdf-research --example argon2_gpu_runner
```

Mark results as `MEASURED`, `MODELED`, or `UNAVAILABLE`. Do not mix them.
