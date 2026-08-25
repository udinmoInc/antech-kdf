# Security Review Package

Antech KDF materials for **independent cryptanalysis**.

**Start here:** [REQUEST_FOR_REVIEW.md](./REQUEST_FOR_REVIEW.md)

| Document | Description |
|---|---|
| [specification.md](./specification.md) | Normative construction (CombinedFrontier, v2, construction version 4) |
| [threat-model.md](./threat-model.md) | Attacker model |
| [review-questions.md](./review-questions.md) | Attack-oriented questions |
| [evidence.md](./evidence.md) | Prior MEASURED / MODELED / UNKNOWN results |
| [known-limitations.md](./known-limitations.md) | What is not established |
| [test-vectors.json](./test-vectors.json) | Digests (+ intermediates on 1 MiB) |
| [reference/](../code/reference/) | Readable reference implementation (`research/code/reference`) |
| [reproduce.md](./reproduce.md) | Build / run instructions |
| [checklist.md](./checklist.md) | Reviewer checklist |

This package does **not** claim the algorithm is audited, proven, or production-safe.
