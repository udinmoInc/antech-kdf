# Antech KDF Phase K Formal Cryptographic Audit

## 1. Security Rationale & Primitive Audit

| Property | Primary Primitive | Security Rationale | Status |
| :--- | :--- | :--- | :--- |
| Attacker Parallelism Reduction (K1) | Candidate-Dependent Dynamic S-Box State Feedback | Prevents vectorization/SIMD batching across candidate passwords | **MEASURED** |
| Quad-Node Directed Acyclic Memory Graph (K2) | 4-way XOR State Mixing | Imposes a steep O((N/M)^4) recomputation penalty on TMTO memory reduction | **MEASURED** |
| GPU-Unfriendly Memory Stride (K3) | Unpredictable Branchless Memory Indexing | Induces GPU thread warp divergence and L1/L2 cache misses on SIMT architecture | **MODELED** |
