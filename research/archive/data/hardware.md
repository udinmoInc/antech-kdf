# Hardware notes

Host used for the early CSV tables under `research/data/` and later GPU work:

- CPU: 16 physical / 32 logical x86_64
- RAM: 32 GB
- GPU: NVIDIA GeForce RTX 3050, 8 GiB VRAM (driver noted in GPU result files)
- OS: Windows 11, `x86_64-pc-windows-gnu`
- Rust: 1.98.x class toolchain; release profile with `opt-level=3`

CUDA/`nvcc` was unavailable for some early campaigns (those rows stay `UNAVAILABLE` or `MODELED`). Later v4-C GPU runs on this RTX 3050 are `MEASURED` under `results/compute-memory-v4/gpu/`.

CSV index: [baseline.csv](baseline.csv), [defender.csv](defender.csv), [attacker.csv](attacker.csv), [tmto.csv](tmto.csv).
