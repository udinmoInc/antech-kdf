# 05 — Security

Lower defender memory only helps if offline cost stays painful. Early K1/K2 CPU attackers were slower than the Argon2id 64 MiB profile on the same 16-core host (~19 g/s vs ~24 g/s). That is one datapoint on one machine class, not a general proof.

TMTO sweeps for K2 showed a steep recomputation curve when only a fraction of the buffer is kept (about **14×** at half memory in that campaign; much higher at 12.5%). Combined-frontier / v4 work changes the graph; do not paste K2 TMTO numbers onto the production engine without re-running the sweep.

Salts and structural parameters are bound into the seed so multi-target amortization across users is not free. Memory addressing is state-dependent, which helps TMTO and parallel divergence but can leak via cache timing on shared hardware.

GPU results on RTX 3050 show Argon2id still much faster to attack than Antech at 16 MiB (~436 g/s vs ~33 g/s). Treat that as an attacker-side measurement, not as "Antech is more secure than Argon2id."
