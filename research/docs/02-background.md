# 02 — Background

PBKDF2 is mostly compute and almost no memory, so GPUs and ASICs parallelize it easily. bcrypt keeps a few kilobytes of Blowfish state — better than nothing, but small enough to live in L1 or on-chip SRAM for many concurrent lanes. scrypt raised the bar with large pseudo-random fills; TMTO attacks still matter. Argon2id (PHC winner) mixes data-independent and data-dependent fills and is the baseline we compare against.

On the reference host used for early tables, Argon2id at **64 MiB, t=1, p=4** landed around **138 ms** defender p50 and about **24 g/s** for a 16-core CPU attacker (`MEASURED`; see [data/](data/hardware.md)).

Any lower-memory Antech profile has to be judged against those kinds of numbers, not against marketing claims. GPU work came later and is reported separately under `results/`.
