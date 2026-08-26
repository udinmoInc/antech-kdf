# 02 — Background

PBKDF2 is mostly compute and almost no memory, so GPUs and ASICs parallelize it easily. bcrypt keeps a few kilobytes of Blowfish state — better than nothing, but small enough to live in L1 or on-chip SRAM for many concurrent lanes. scrypt raised the bar with large pseudo-random fills; TMTO attacks still matter. Argon2id (PHC winner) mixes data-independent and data-dependent fills and is the baseline we compare against.

Any lower-memory Antech profile has to be judged against measured Argon2id attacker rates on the **same** campaign host and methodology, not against marketing claims. Current head-to-head datasets:

- CPU: [`../results/compute-memory-v4/`](../results/compute-memory-v4/)
- GPU (RTX 3050): [`../results/compute-memory-v4/gpu/`](../results/compute-memory-v4/gpu/)

Label every figure **MEASURED**, **MODELED**, **BLOCKED**, or **UNKNOWN**. Do not paste early archived K1/K2 tables onto the production engine.
