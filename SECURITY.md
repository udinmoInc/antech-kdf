# Security Policy & Disclosure Guidelines

## ⚠️ Experimental Research Notice

**Antech KDF is an experimental research project.**

The experimental candidate constructions (Variant K1 and Variant K2) are actively under research and cryptanalysis evaluation. They have **not** undergone third-party cryptographic review or formal security reductions.

> [!CAUTION]
> **Do NOT use experimental Antech KDF candidate constructions for production password storage or sensitive security infrastructure.** Standard, established memory-hard functions such as **Argon2id** should be used for production applications.

---

## 🔒 Reporting Security Concerns

We welcome security reports, vulnerability disclosures, and cryptanalysis feedback from engineers and cryptographic researchers.

If you identify a security issue, implementation bug, or cryptanalytic weakness in Antech KDF, please submit your findings to the repository maintainers.

### Implementation Bugs vs. Cryptographic Concerns

When reporting issues, please distinguish between implementation bugs and cryptographic design concerns:

* **Implementation Vulnerabilities**: Code defects such as buffer overflows, out-of-bounds memory accesses, panic triggers, memory leaks, or non-constant-time string comparisons.
* **Cryptographic Weaknesses**: Cryptanalytic findings such as algebraic short-cuts, time-memory trade-off optimizations superior to theoretical bounds, state recovery techniques, SIMD vectorization methods, or side-channel vulnerabilities.

---

## 🛡️ Security Guarantees in Stable API

The public Rust crate [`antech-kdf`](crates/antech-kdf) enforces the following implementation guarantees:

1. **Constant-Time Verification**: Password string comparisons use `subtle::ConstantTimeEq` to prevent timing side-channel attacks during hash verification.
2. **Domain Separation**: All input parameters, domain headers, and salt bytes are bound using SHA-256 domain-separated contexts.
3. **No Dynamic Branch Asymmetry**: Verification paths execute strictly constant-time iterations regardless of password correctness.
