# Chapter 2: Background & Baseline Cryptographic Functions

Password key derivation functions have evolved through distinct design paradigms to address advancing adversarial hardware capabilities. Understanding this evolution helps contextualize the design decisions evaluated in [Chapter 1: The Problem](01-problem.md).

Early algorithms like **PBKDF2** rely entirely on computationally expensive cryptographic primitives, such as HMAC-SHA256, iterated over many thousands of rounds. Because PBKDF2 requires virtually no working memory (storing only a 64-byte state), adversaries can efficiently parallelize password guessing on massively parallel architectures like GPUs or custom ASICs.

**bcrypt** introduced memory requirements by incorporating a 4 KB working state array into its internal Blowfish cipher expansion phase. While 4 KB exceeds the register capacity of simple hardware processors, it fits entirely within the L1 CPU cache. Consequently, modern high-end GPUs can maintain thousands of concurrent bcrypt state arrays in on-chip SRAM, mitigating the intended memory penalty.

To impose genuine memory hardness, **scrypt** introduced pseudo-random memory filling and indexing phases operating over larger memory buffers. By requiring megabytes of RAM, scrypt forced attackers to allocate physical memory per cracking thread. However, scrypt's memory access patterns are susceptible to time-memory trade-off (TMTO) attacks, allowing adversaries to trade memory storage for additional recomputation.

**Argon2**, winner of the Password Hashing Competition, established the modern standard for memory-hard functions. Argon2id combines data-independent memory filling (to resist side-channel timing attacks) with data-dependent memory filling (to maximize resistance against TMTO and GPU trade-offs). When configured with standard recommended parameters (**64 MB working memory, 1 pass, 4 parallel lanes**), Argon2id provides robust security. On our reference benchmark host, standard Argon2id exhibits a **138.20 ms p50 defender latency** and restricts a 16-core CPU attacker to **24.20 guesses/sec**.

Because Argon2id represents the primary industry baseline, any alternative construction attempting lower server memory usage must be evaluated directly against its performance and attacker cost metrics. For full hardware platform specifications and raw baseline datasets, see [Hardware & Reproducibility](data/hardware.md) and [Baseline Benchmark Data](data/baseline.csv).

In [Chapter 3: Design](03-design.md), we detail the construction designed to achieve comparable attacker resistance at a 16 MB memory allocation.
