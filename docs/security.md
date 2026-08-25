# Security notes

Antech is experimental and has not been independently audited. Do not treat it as production-ready password hashing.

What the implementation does today:

- Digest comparison in `verify` uses `subtle::ConstantTimeEq`.
- Seed and finalize steps use fixed domain separators (`antech-compute-memory-v4-seed`, `antech-compute-memory-v4-final`, and related node labels). Those strings are part of the protocol and must not be changed lightly.
- `BoundedResourceScheduler` caps concurrent memory and job count (default 128 MiB / 64 jobs) so a burst of hashes fails closed instead of OOM-killing the process. That is host policy, not a cryptographic property.

What it does not claim:

- Equivalence to Argon2id under all attack models.
- Resistance to ASIC/FPGA-specific designs (largely unmeasured).
- Freedom from cache-timing leakage on data-dependent memory walks.

Report implementation bugs and cryptanalytic findings to `antech-kdf@udinmo.com`. See [SECURITY.md](../SECURITY.md).
