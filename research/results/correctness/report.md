# Antech KDF correctness report

**Verdict:** PASS

This campaign exercised the **current canonical** production implementation without changing algorithm, API, v2 format, or defaults.

## Status legend

- **PASS** — executed and correct
- **FAIL** — mismatch, panic, or incorrect accept/reject
- **BLOCKED** — tool/environment unavailable
- **NOT_APPLICABLE** — outside production invariants (e.g. <64-block graphs, non-CombinedFrontier reference)

## Failures

None.


## Notes

- Reference `derive` covers **CombinedFrontier only**; other graphs compared for self-determinism + hash/verify.
- Host `ResourcePolicy` caps concurrent KDF memory at 128 MiB; configs up to 1 GiB validate but public `hash`/`verify` correctly return `ResourceExhausted` above the host budget.
- GPU: prior v4 correctness CSV imported when present; live CUDA attacker re-run left BLOCKED unless dedicated runner invoked.

