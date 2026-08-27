# Construction v5 cost tradeoff (CombinedFrontier, 16 MiB) — dual-global + cold far

**Date:** 2026-08-27  
**See also:** `research/results/compute-memory-v4/v5-asymm/report.md` for the full asymmetry screen.

**Public API / `$antech$v2$` / `CONSTRUCTION_VERSION = 5`:** unchanged. Digests changed.

## Verdict

**20–25 / 20–30 g/s CPU target not reached** under honest work with p50 ≤ 140 ms.

**Shipped:** word-packed CombinedFrontier + dual-global post-local gathers + always-2 far with cold span (`cold = max(512, frontier)`) + dual scatter.

| | Prior far2+global | **Current** |
|---|---:|---:|
| Defender p50 | ~118 ms | **~131 ms** |
| Peak CPU 16/32T | ~43–45 g/s | **~43 / ~44 g/s** |
| Best GPU | ~86 g/s | **~75 g/s** |

Far chaining was the only lever that approached ~30–35 g/s and it exceeded the 140 ms p50 budget. Stopped at this measured Pareto.

## Reproduce

Same runners as `v5-asymm/report.md`.
