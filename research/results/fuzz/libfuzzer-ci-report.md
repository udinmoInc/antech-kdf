# libFuzzer campaign (GitHub Actions / Ubuntu)

**Status:** PASS
**Engine:** libFuzzer via cargo-fuzz (NOT the Windows fallback harness)
**SHA:** `2a85cf9e666e4ad3c47fac038f9e11d77dba1b88`
**Run id:** `33067507461`
**Total executions (approx):** 509208002
**Artifact files (crashes/timeouts):** 0
**Hangs flagged in logs:** 0

| Target | Status | Execs | Corpus before→after | Artifacts | Secs | Cov line |
|---|---|---:|---:|---:|---:|---|
| hash_parser | PASS | 56125930 | 21→356 | 0 | 901 | `#56125930	DONE   cov: 585 ft: 1342 corp: 316/35Kb lim: 9000 exec/s: 62292 rss: 557Mb` |
| hash_verify | PASS | 10030 | 6→93 | 0 | 602 | `#10030	DONE   cov: 647 ft: 935 corp: 87/5188b lim: 138 exec/s: 16 rss: 93Mb` |
| config_builder | PASS | 399274898 | 8→19 | 0 | 601 | `#399274898	DONE   cov: 62 ft: 64 corp: 15/173b lim: 4096 exec/s: 664350 rss: 538Mb` |
| malformed_v2 | PASS | 6976942 | 6→315 | 0 | 602 | `#6976942	DONE   cov: 536 ft: 1013 corp: 271/22Kb lim: 4096 exec/s: 11608 rss: 540Mb` |
| ffi_api | PASS | 11233 | 4→98 | 0 | 601 | `#11233	DONE   cov: 598 ft: 929 corp: 93/2295b lim: 45 exec/s: 18 rss: 93Mb` |
| scheduler | PASS | 46808969 | 4→73 | 0 | 602 | `#46808969	DONE   cov: 157 ft: 652 corp: 67/766b lim: 4096 exec/s: 77885 rss: 482Mb` |

## Distinction
- **CI / this file:** real libFuzzer on Ubuntu.
- **Local Windows `research/results/fuzz/summary.md` (if present):** may be fallback-only — do not equate.
