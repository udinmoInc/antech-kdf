# Attack catalog — canonical Antech KDF

| ID | Idea | Correctness | work_ratio | mem_ratio | gps | Notes |
|---|---|---|---|---|---|---|
| A1_dag_skip_nodes | Skip nodes not on gather-path to last block | INCORRECT | 1.000 | 1.0000 | 0.00 | gather_reachable=32768/32768 (100.0%); state_chain_requires_all=true; skip every-other INCORRECT |
| A2_algebraic_mix | Linearize/cancel ARX mix_pair | N/A (no shortcut found) | 1.000 | 1.0000 | 0.00 | collisions=0/256; linear_xor=false; zero_id=false; ARX mix_pair uses add/xor/rotate/mul; no linear shortcut found |
| A3_parent_prediction | Predict parents from partial state | FAILED to predict | 1.000 | 1.0000 | 0.00 | exact_matches=1/32767 (0.00%); Exact local+remote parent-set match using only state[0] from pre-node state (no local mix before far addresses) |
| A4a_tmto_naive_frac_0.5 | Naive checkpoint TMTO at 0.5 without scatter log | INCORRECT | 1.000 | 0.5000 | 0.00 | Measured on 1 MiB; dual scatter mutates past blocks so eviction without scatter log breaks digests (same graph as 16 MiB). |
| A4b_tmto_scatterlog_frac_0.5 | Scatter-log TMTO at window frac 0.5 | INCORRECT | inf | 3.0000 | 0.00 | 1 MiB prototype; correct=false; no correct cheaper reduced-memory attack found for CombinedFrontier |
| A4a_tmto_naive_frac_0.25 | Naive checkpoint TMTO at 0.25 without scatter log | INCORRECT | 1.000 | 0.2500 | 0.00 | Measured on 1 MiB; dual scatter mutates past blocks so eviction without scatter log breaks digests (same graph as 16 MiB). |
| A4b_tmto_scatterlog_frac_0.25 | Scatter-log TMTO at window frac 0.25 | INCORRECT | inf | 2.7500 | 0.00 | 1 MiB prototype; correct=false; no correct cheaper reduced-memory attack found for CombinedFrontier |
| A4a_tmto_naive_frac_0.125 | Naive checkpoint TMTO at 0.125 without scatter log | INCORRECT | 1.000 | 0.1250 | 0.00 | Measured on 1 MiB; dual scatter mutates past blocks so eviction without scatter log breaks digests (same graph as 16 MiB). |
| A4b_tmto_scatterlog_frac_0.125 | Scatter-log TMTO at window frac 0.125 | INCORRECT | inf | 2.6250 | 0.00 | 1 MiB prototype; correct=false; no correct cheaper reduced-memory attack found for CombinedFrontier |
| A5_mitm_split | Meet-in-the-middle split at mid DAG | CORRECT (no savings) | 1.000 | 1.0000 | 7.61 | State-dependent parents prevent independent half-DAG evaluation. |
| A6_precomputation | Precompute salt/password-independent intermediates | N/A | 1.000 | 1.0000 | 0.00 | Seed binds password+salt; parent indices bind rolling state; no cross-guess DAG reuse. |
| A7_frontier_only_store | Store only FRONTIER_WIDTH=64 recent blocks | Requires TMTO recompute for far parents | 1.000 | 0.0001 | 0.00 | Far gathers + dual scatter need random history access. |
| A8_packed_prefetch_full_eval | Full DAG with packed u64 layout + prefetch (no node skip) | CORRECT | 0.843 | 1.0000 | 9.03 | Same num_blocks mixes; attack_work/full_work≈0.843 via schedule only |
| A9_dual_walk_multitarget | Interleave two independent password walks | CORRECT (2 digests) | 1.000 | 2.0000 | 0.00 | No work reduction per guess; may improve multi-target wall-clock. |
| A10_cse_reuse | Share mix results across nodes | N/A | 1.000 | 1.0000 | 0.00 | Each node writes unique state-derived block; no identical subgraph CSE. |

work_ratio = attack_latency / full_latency ≈ baseline_gps / attack_gps for equal-correctness full walks.

