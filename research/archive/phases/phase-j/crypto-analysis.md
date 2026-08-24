# Antech KDF Phase J Formal Cryptographic Audit

## 1. Security Rationale & Primitive Audit

| Property | Primary Primitive | Security Rationale | Status |
| :--- | :--- | :--- | :--- |
| Password-Dependent State Permutation | Dynamic Password Byte Feedback | Prevents vectorization/SIMD batching across candidate passwords | **MEASURED** |
| Triple-Node Directed Memory Graph | 3-way XOR State Mixing | Imposes a sharp cubic O((N/M)^3) recomputation penalty on TMTO memory reduction | **MEASURED** |
| GPU-Unfriendly Memory Stride | Unpredictable Branchless Memory Indexing | Induces GPU thread warp divergence and L1/L2 cache misses on SIMT architecture | **MODELED** |
