---
name: Cryptanalysis of Antech KDF
about: Report an attack idea or cryptanalytic finding against the review-target construction
title: "Cryptanalysis: "
labels: ["cryptanalysis"]
---

## Attack idea

<!-- Short description of the proposed attack or weakness. -->

## Affected construction

- [ ] Canonical default (16 MiB, CombinedFrontier, construction version 5, hash encoding v2)
- [ ] Other parameters (specify memory / graph / fan-in / block size)
- [ ] Implementation bug (parser, FFI, verify), not a KDF shortcut

## Assumptions

<!-- What the attacker knows / has (matches threat-model.md unless noted). -->

## Reduced work

<!-- Work relative to full honest evaluation (e.g. 0.5× mixes, or wall-clock on stated hardware). -->

## Required memory

<!-- Peak RAM / VRAM per guess or amortized. -->

## Correctness evidence

<!-- Digests match production / test-vectors.json? Attach vectors or hex digests. -->

## Reproduction steps

```text
1.
2.
3.
```

## Suggested mitigation

<!-- Optional. -->

## Disclosure

For severe issues that could harm real deployments, prefer private/responsible disclosure to the maintainers before public detail. Benchmark-only observations without a correct reduced-work attack can be filed publicly.
