# Request for Independent Cryptanalysis — Antech KDF

We are looking for **independent cryptanalysis** of the current Antech password KDF construction.

We are especially interested in finding ways to **reduce the work** (or peak memory without catastrophic recomputation) required for an offline password guess, while still matching the normative digest.

Please **do not** treat defender or attacker benchmark performance as evidence of cryptographic security.

We are specifically asking reviewers to try to **break the assumptions** of the construction: DAG hardness, sequential state dependence, dual-scatter memory liveness, seed binding, and the absence of cheap TMTO.

## Review package

| Document | Path |
|---|---|
| Formal specification | [specification.md](./specification.md) |
| Threat model | [threat-model.md](./threat-model.md) |
| Review questions | [review-questions.md](./review-questions.md) |
| Existing evidence | [evidence.md](./evidence.md) |
| Known limitations | [known-limitations.md](./known-limitations.md) |
| Test vectors | [test-vectors.json](./test-vectors.json) |
| Reference implementation | [reference/](./reference/) |
| Reproducibility | [reproduce.md](./reproduce.md) |
| Checklist | [checklist.md](./checklist.md) |

## Source (production)

- Public API: `crates/antech-kdf`
- Engine: `crates/antech-kdf-core` (`AntechEngine::derive`)
- Encoding: `crates/antech-kdf-format` (v2)

## How to report

Prefer a structured write-up (see `.github/ISSUE_TEMPLATE/cryptanalysis.md`). For severe implementation issues that could harm deployments, use responsible disclosure via the repository security policy / maintainers.

Thank you for examining the construction critically.
