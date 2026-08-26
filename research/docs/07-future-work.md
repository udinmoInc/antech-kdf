# 07 — Future work

Useful next steps:

- Independent cryptanalysis of the production combined-frontier engine and its domain separators.
- More GPU hardware (desktop and server) under the same fairness rules as [benchmark-methodology.md](benchmark-methodology.md).
- Rough ASIC/FPGA area and bandwidth estimates for the ARX + graph walk.
- Optional hybrid (data-independent then data-dependent) if cache-timing becomes a deployment requirement.
- CPU attacker coverage beyond the current x86 hosts (ARM, etc.).
- Broader libFuzzer / sanitizer campaigns on Linux (CI already runs timed libFuzzer; local Windows uses the fallback harness).

Back to [README.md](README.md).
