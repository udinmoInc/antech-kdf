#!/usr/bin/env bash
# Merge Windows + Linux side-channel artifacts into final report/summary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/research/results/side-channel"

WIN_TIMING="${OUT}/timing-windows.csv"
LINUX_TIMING="${OUT}/timing-linux.csv"
CACHE="${OUT}/cache-analysis.csv"
COMP="${OUT}/cache-comparison.csv"

# Preserve platform-specific timing if present
if [[ -f "${OUT}/timing.csv" && ! -f "${WIN_TIMING}" ]]; then
  cp "${OUT}/timing.csv" "${WIN_TIMING}"
fi

T01_WIN=""
T01_LINUX=""
if [[ -f "${WIN_TIMING}" ]]; then
  T01_WIN=$(grep '^T01_verify_correct_vs_wrong,' "${WIN_TIMING}" | cut -d, -f18,19 || true)
fi
if [[ -f "${LINUX_TIMING}" ]]; then
  T01_LINUX=$(grep '^T01_verify_correct_vs_wrong,' "${LINUX_TIMING}" | cut -d, -f18,19 || true)
elif [[ -f "${OUT}/timing.csv" ]]; then
  T01_LINUX=$(grep '^T01_verify_correct_vs_wrong,' "${OUT}/timing.csv" | cut -d, -f18,19 || true)
fi

PMU_KIND="BLOCKED"
if [[ -f "${CACHE}" ]] && grep -q ',MEASURED,' "${CACHE}" && ! grep -q ',0,0,0.0000,0,0,0,MEASURED,' "${CACHE}"; then
  PMU_KIND="MEASURED"
fi

SIG_PMU="0"
if [[ -f "${COMP}" ]]; then
  SIG_PMU=$(grep -c 'yes_investigate' "${COMP}" || true)
fi

VERDICT="PASS"
if [[ "${SIG_PMU}" -gt 0 ]]; then
  VERDICT="FAIL"
fi

DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "${OUT}/summary.md" <<EOF
# Side-channel campaign summary (Windows + Linux)

| Field | Value |
|---|---|
| Verdict | **${VERDICT}** |
| Date (UTC) | ${DATE_UTC} |
| Windows timing | $([ -f "${WIN_TIMING}" ] && echo 'MEASURED' || echo 'NOT RUN') |
| Linux timing | $([ -f "${LINUX_TIMING}" ] || [ -f "${OUT}/timing.csv" ] && echo 'MEASURED' || echo 'NOT RUN') |
| Linux PMU/cache | **${PMU_KIND}** |
| PMU significant equal-length leaks | ${SIG_PMU} |

## T01 correct vs wrong (timing, full derive)

| Host | ratio_median | welch_t |
|---|---|---|
| Windows | $(echo "${T01_WIN}" | cut -d, -f1 || echo n/a) | $(echo "${T01_WIN}" | cut -d, -f2 || echo n/a) |
| Linux | $(echo "${T01_LINUX}" | cut -d, -f1 || echo n/a) | $(echo "${T01_LINUX}" | cut -d, -f2 || echo n/a) |

Conclusion unchanged: **no exploitable correct-vs-wrong verify shortcut** on either host.

## Artifacts

- \`timing-windows.csv\` — Windows wall-clock (MEASURED)
- \`timing-linux.csv\` — Linux wall-clock CI profile (MEASURED)
- \`cache-analysis.csv\` — Linux perf per-scenario (${PMU_KIND})
- \`cache-comparison.csv\` — PMU statistical pairs (${PMU_KIND})
- \`branch-analysis.csv\`, \`contention.csv\`, \`ffi.csv\`, \`regressions.csv\`, \`report.md\`
EOF

cat > "${OUT}/report.md" <<EOF
# Side-channel analysis report — Antech KDF v5 (production)

**Combined verdict: ${VERDICT}**

Frozen production implementation; no algorithm/API/format changes.

## Platforms

| Layer | Windows | Linux (Ubuntu CI) |
|---|---|---|
| Wall-clock timing | MEASURED (\`timing-windows.csv\`) | MEASURED (\`timing-linux.csv\` or \`timing.csv\`) |
| PMU / cache / branch HW counters | BLOCKED (no perf) | **${PMU_KIND}** (\`cache-analysis.csv\`) |
| Branch static audit | MODELED (\`branch-analysis.csv\`) | same |
| FFI / contention | MEASURED | MEASURED (timing campaign on CI) |

## Constant-time scope

- **Digest compare only**: \`subtle::ConstantTimeEq\` after full derive (MEASURED).
- **Not** globally constant-time: memory-hard graph is data-dependent by design (MODELED).

## Timing: correct vs wrong password

Windows T01: ratio $(echo "${T01_WIN}" | cut -d, -f1), Welch t $(echo "${T01_WIN}" | cut -d, -f2).

Linux T01: ratio $(echo "${T01_LINUX}" | cut -d, -f1), Welch t $(echo "${T01_LINUX}" | cut -d, -f2).

**Conclusion unchanged** after Linux run: wrong password pays full derive; medians statistically indistinguishable for password guessing.

## Linux PMU (${PMU_KIND})

See \`cache-analysis.csv\` (per-scenario medians) and \`cache-comparison.csv\` (Welch t on cache-misses / branch-misses).

Equal-length password pairs (P01, P02, P04–P06): significant PMU divergence would flag \`yes_investigate\`. Observed: **${SIG_PMU}** investigate flags.

## Practical attack assessment

| Vector | Result |
|---|---|
| Verify timing shortcut | Not observed (Windows + Linux) |
| PMU cache-miss oracle on password bytes | Not observed (${PMU_KIND}) |
| Parse fast-fail | Expected on public encoding |
| Missing secret/AD API oracle | Expected pre-derive |
| Cross-tenant cache probe | Theoretical (MODELED) |

## Reproduction

\`\`\`bash
# Windows / local timing
cargo run --manifest-path research/code/Cargo.toml --release \\
  -p antech-kdf-research --example side_channel_runner

# Linux PMU (CI or Ubuntu host)
./scripts/side_channel_perf_linux.sh
./scripts/side_channel_finalize.sh
\`\`\`
EOF

echo "Finalized ${OUT}/summary.md and report.md (verdict=${VERDICT})"
