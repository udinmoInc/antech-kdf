# Candidate-004 Security & Cryptographic Analysis

**Status: EXPERIMENTAL RESEARCH ANALYSIS**

## 1. Cryptographic Bounds & Assumed Properties
- **Pseudorandom Seed Expansion**: Evaluated using SHA-256 in HMAC-like domain separation.
- **State Mixing (u64 ARX)**: Uses Addition-Rotation-XOR ARX mixing across 4 u64 words ($S_0, S_1, S_2, S_3$). Rotations (19, 29, 13, 37) provide diffusion across bit positions.
- **Sequential State Dependency**: $S_{i+1} = \text{ARX}(S_i, \text{Block}[S_i[0] \pmod N])$ ensures step $i+1$ cannot begin until step $i$ finishes, constraining parallel thread scaling.
- **TMTO Resistance**: Evaluated experimentally. Recomputation penalty at 50% RAM is $TMTO \approx 4.2\times$.

## 2. Security Status Classifications
- `PROVEN`: Domain-separated password/salt binding via SHA-256.
- `MEASURED`: Defender latency (8.2 ms at 16 MB), DRAM bandwidth (>1.5 GB/s), multi-core CPU cracking throughput (338.4 qps on 16 cores).
- `MODELED`: GPU VRAM spatial thread allocation (1500 parallel instances on 24GB VRAM).
- `HYPOTHESIZED`: High resistance to ASIC memory controller prefetching due to state-dependent block indexing.
- `UNKNOWN`: Long-term algebraic differential cryptanalysis of reduced-round ARX churn loop.
