# Chapter 5: Adversarial Cost & Security Analysis

Assessing the security of a key derivation function requires analyzing how architectural choices impact adversarial cracking economics. Lowering server working memory from 64 MB to 16 MB reduces physical hardware costs for legitimate defenders, but it could potentially advantage adversaries if not counterbalanced by strict algorithmic resistance.

### Offline Password Guessing Resistance
Our empirical measurements in [Chapter 4: Evaluation](04-evaluation.md) demonstrate that Antech Variant K1 and Variant K2 restrict 16-core CPU cracking throughput to **19.20 g/s** and **18.80 g/s**, respectively. This represents a **1.25–1.28x reduction in CPU attacker speed** compared to Argon2id (24.20 g/s). 

However, measured CPU throughput alone does not prove equivalent overall security. CPU benchmarking measures execution speed on a specific x86 architecture; it does not account for specialized hardware acceleration or alternative memory trade-offs.

### Time-Memory Trade-Off (TMTO) Resistance
A critical vulnerability in memory-reduced KDFs is the susceptibility to TMTO attacks, where an adversary allocates only a fraction of the required memory ($M < N$) and dynamically recalculates missing blocks. 

* In **Variant K1**, memory addresses depend on sequential ARX state evolution. Storing only 50% of the memory buffer forces an attacker to perform **4.00x additional recomputation steps**.
* In **Variant K2**, the 4-way directed acyclic graph requires reading 4 pseudo-random blocks simultaneously per step. Storing 50% of the memory buffer forces an **13.93x recomputation multiplier**. Reducing memory to 12.5% increases recomputation penalty to over **1,200x**, rendering low-memory cracking economically unviable for an attacker. Dataset details are exported in [TMTO Sweep Data](data/tmto.csv).

### Multi-Target & Precomputation Resistance
To prevent adversaries from amortizing cracking costs across millions of stolen password hashes, Antech incorporates unique salt and parameter binding in its initial domain-separated seed expansion (`$antech$v1$...`). Because every salt generates a distinct initial buffer filling sequence, multi-target work-amortization attacks are rendered ineffective.

### Side-Channel & Memory Access Considerations
Because block addresses in Candidate-004 depend on intermediate state variables, memory accesses are data-dependent. While data-dependent indexing maximizes TMTO and GPU warp divergence resistance, it introduces potential cache-timing side-channel risks on multi-tenant shared hardware.

For explicit discussion of unresolved hardware risks and security bounds, see [Chapter 6: Limitations](06-limitations.md).
