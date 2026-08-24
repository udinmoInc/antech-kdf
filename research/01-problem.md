# Chapter 1: The Server Memory Problem in Password Hashing

Modern password security relies fundamentally on memory-hard key derivation functions (KDFs) to protect stored user credentials against offline password-guessing attacks. By forcing the derivation process to consume significant random-access memory (RAM), memory-hard functions increase the hardware cost for adversaries attempting to build parallel cracking clusters on graphics processing units (GPUs) or application-specific integrated circuits (ASICs).

However, high memory requirements create operational challenges for legitimate authentication servers. Standard deployments of established memory-hard functions, most notably Argon2id, typically specify a working memory allocation of **64 MB per password verification attempt**. While a 64 MB memory footprint is negligible for an idle server processing isolated requests, it presents severe scaling challenges under realistic production workloads.

On low-cost virtual private servers (such as entry-level 1 GB VPS instances) or tightly bounded microservice containers, memory resources are strictly constrained. During peak traffic bursts or automated credential-stuffing events, concurrent authentication requests rapidly consume available host DRAM. When concurrent memory demands exceed host limits, operating system kernel mechanisms trigger Out-Of-Memory (OOM) process termination, unceremoniously shutting down authentication services.

Simply reducing the memory parameter of an algorithm like Argon2id to fit within smaller memory bounds degrades offline attacker cost proportionally. An adversary targeting a reduced-memory configuration can evaluate password candidates faster or utilize smaller hardware allocations, compromising the primary security guarantee of the KDF.

This research investigates a specific question: Is it possible to construct a password key derivation function that operates within a **16 MB server memory footprint**—achieving a **4x memory reduction** compared to standard 64 MB Argon2id configurations—while preserving or exceeding the offline attacker cost of the 64 MB benchmark?

To answer this question, we evaluate memory access patterns, candidate-dependent permutation logic, and time-memory trade-off structures. The goal of Antech is to explore whether bandwidth-hard design choices can protect resource-constrained servers without sacrificing offline password-guessing resistance.

For technical context on existing memory-hard functions and baseline performance measurements, see [Chapter 2: Background](02-background.md). For details on the construction under evaluation, see [Chapter 3: Design](03-design.md).
