# 06 — Limitations

- No third-party cryptanalysis or formal reduction for the production construction.
- ASIC / FPGA cost is mostly unmeasured; CPU and one GPU class do not cover custom silicon.
- Data-dependent walks may be cache-timing sensitive in multi-tenant settings.
- GPU work is real on RTX 3050 for v4-C vs Argon2id, but that is one card and one kernel family.
- TMTO search covered specific checkpoint / sparse / scatter-log strategies; other pebbling schedules may exist.
- Resource scheduling prevents host OOM; it does not add cryptographic hardness.
- Early archived campaigns (K1/K2, v2/v3) must not be cited as current production evidence.

See [07-future-work.md](07-future-work.md) and [`../security-review/known-limitations.md`](../security-review/known-limitations.md).
