# 06 — Limitations

- No third-party cryptanalysis or formal reduction for the production construction.
- ASIC / FPGA cost is mostly unmeasured; CPU and one GPU class do not cover custom silicon.
- Data-dependent walks may be cache-timing sensitive in multi-tenant settings.
- Early chapters still quote K1/K2 numbers; production is combined-frontier / v4-C. Compare like with like.
- GPU work is real on RTX 3050 for v4-C vs Argon2id, but that is one card and one kernel family. Broader GPU coverage is still thin.
- Resource scheduling prevents host OOM; it does not add cryptographic hardness.

See [07-future-work.md](07-future-work.md).
