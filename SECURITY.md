# Security

Antech KDF is experimental. It has not had a third-party cryptographic audit. Do not use it as the sole password hash in production systems that need established assurance; prefer Argon2id (or another audited memory-hard KDF) for that.

Report implementation bugs and cryptanalytic findings to **antech-kdf@udinmo.com**. Please say whether you think the issue is an implementation defect (panics, memory safety, non-constant-time compare, etc.) or a design weakness (shortcut, TMTO better than claimed, side channel, …).

What the library currently does:

- Constant-time digest compare via `subtle` in verification
- Fixed domain separators in the seed / finalize path
- Optional host admission control (`BoundedResourceScheduler`) so concurrent hashes fail closed under a memory ceiling

None of that makes the algorithm “proven secure.”
