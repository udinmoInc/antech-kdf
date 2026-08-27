# libFuzzer (local host)

**Status:** BLOCKED

Reason: cargo-fuzz / libFuzzer cannot be installed or linked on this Windows host (missing dlltool.exe / link.exe).

Real libFuzzer campaigns run on Linux via .github/workflows/fuzz.yml (`fuzz-libfuzzer` job). Do not treat the Windows fallback harness as a libFuzzer PASS.

Fallback harness (non-libFuzzer) was executed locally; see `fallback-summary.json`.
