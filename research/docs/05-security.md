# 05 — Security

Lower defender memory only helps if offline cost stays painful. On the **v4-C** CPU campaign, combined-frontier @ 16 MiB measured about **40.6 g/s** at 16 threads while Argon2id @ 64 MiB on the same campaign sat near **23 g/s** (**MEASURED**; see [`../results/compute-memory-v4/`](../results/compute-memory-v4/)). That is one host class, not a general proof.

TMTO sweeps for the production graph show a steep recomputation curve when only a fraction of the buffer is kept (about **16.45×** at half memory in the v4 campaign). Cryptanalysis campaigns did not find a correct cheaper-than-full-memory attack on the tested schedules ([`../results/cryptanalysis/`](../results/cryptanalysis/), [`../security-review/evidence.md`](../security-review/evidence.md)).

Salts and structural parameters are bound into the seed so multi-target amortization across users is not free. Memory addressing is state-dependent, which helps TMTO resistance and parallel divergence but can leak via cache timing on shared hardware.

GPU results on RTX 3050 show Argon2id still much faster to attack than Antech at 16 MiB (~436 g/s vs ~33 g/s, **MEASURED**). That is an attacker throughput comparison on one card and one kernel family.

Nothing here claims the algorithm is audited or production-safe. See [`../security-review/known-limitations.md`](../security-review/known-limitations.md).
