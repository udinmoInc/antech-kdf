# Known Limitations

This construction is **submitted for independent review**. The following have **not** been established:

1. **ASIC cost** — no taped-out or carefully costed ASIC model for Antech vs Argon2-class baselines.
2. **FPGA cost** — no complete FPGA attacker with energy/area accounting.
3. **Long-term cryptanalysis** — no multi-year public attack surface history.
4. **Complete TMTO search** — only specific checkpoint/sparse/scatter-log strategies were implemented; other pebbling schedules may exist.
5. **Exhaustive side-channel analysis** — no formal leakage proofs; cache/timing behaviour under secrets was not systematically audited for all platforms.
6. **All GPU optimizations** — measured kernels are strong on one GPU class (RTX 3050 campaign); other architectures/vendors may differ.
7. **All multi-target attacks** — seed binding blocks naive sharing; exotic table methods were not exhaustively ruled out.
8. **Formal reduction proofs** — there is no proof reducing Antech security to a standard assumption.
9. **Parameter agility** — non-default graphs/fan-ins/block sizes are less heavily attacked than the 16 MiB CombinedFrontier default.
10. **Quantum / non-classical models** — not analyzed.

Do not treat benchmark wins, or “no attack found,” as certification.
