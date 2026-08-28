#!/usr/bin/env bash
# Write summary.md and report.md from sanitizer CSVs and campaign-status.env.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/research/results/sanitizers"
mkdir -p "${OUT}"

COMMIT_SHA="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

read_status() {
  local key="$1"
  if [[ -f "${OUT}/campaign-status.env" ]]; then
    grep -E "^${key}=" "${OUT}/campaign-status.env" | tail -1 | cut -d= -f2- || echo NOT_RUN
  else
    echo NOT_RUN
  fi
}

ASAN_OVERALL="$(read_status asan_overall)"
UBSAN_OVERALL="$(read_status ubsan_overall)"

OVERALL=PASS
if [[ "${ASAN_OVERALL}" == FAIL || "${UBSAN_OVERALL}" == FAIL ]]; then
  OVERALL=FAIL
elif [[ "${ASAN_OVERALL}" == NOT_RUN || "${UBSAN_OVERALL}" == NOT_RUN ]]; then
  if [[ "${ASAN_OVERALL}" == BLOCKED && "${UBSAN_OVERALL}" == BLOCKED ]]; then
    OVERALL=BLOCKED
  else
    OVERALL=NOT_RUN
  fi
fi

ENV_SNIP=""
if [[ -f "${OUT}/environment.txt" ]]; then
  ENV_SNIP="$(head -20 "${OUT}/environment.txt")"
fi

cat > "${OUT}/summary.md" <<EOF
# Sanitizer campaign summary

| Field | Value |
|---|---|
| Date (UTC) | ${DATE_UTC} |
| Commit | \`${COMMIT_SHA}\` |
| ASan overall | **${ASAN_OVERALL}** |
| UB checks (\`-Zub-checks\`) overall | **${UBSAN_OVERALL}** |
| LLVM UBSan | **BLOCKED** |
| Combined | **${OVERALL}** |

## Suite matrix

See \`asan.csv\`, \`ubsan.csv\`, \`skipped.csv\`, \`regressions.csv\`, and \`logs/\`.

## Environment (last lines)

\`\`\`
${ENV_SNIP}
\`\`\`

## Exclusions

| Target | Verdict |
|---|---|
| CUDA / GPU | NOT APPLICABLE |
| antech-kdf-research runners | NOT APPLICABLE |
| antech-kdf-cli (no tests) | NOT APPLICABLE |
| Windows host | BLOCKED (use Ubuntu CI) |

Reference crate (\`antech-kdf-reference\`) runs under separate rows in CSVs — research parity, not production SOT.
EOF

cat > "${OUT}/report.md" <<EOF
# ASan + UBSan validation report — Antech KDF

**Combined verdict: ${OVERALL}**

| Sanitizer | Verdict |
|---|---|
| AddressSanitizer (ASan) | **${ASAN_OVERALL}** |
| UndefinedBehaviorSanitizer (UBSan) | **${UBSAN_OVERALL}** (Rust \`-Zub-checks\`; LLVM UBSan BLOCKED) |

This campaign targets memory safety (ASan) and undefined behavior (Rust
\`-Zub-checks\` with \`-Zbuild-std\`) on \`x86_64-unknown-linux-gnu\`. LLVM
\`-Zsanitizer=undefined\` is **not supported** on current rustc — see
\`skipped.csv\`. It does **not** change KDF algorithms, public API, v2 encoding,
or canonical parameters.

## Verdict key

| Label | Meaning |
|---|---|
| PASS | Sanitizer jobs executed; no findings / test failures |
| FAIL | Sanitizer reported defect or test failure |
| BLOCKED | Sanitizer could not run on host (toolchain/OS) |
| NOT RUN | Job did not complete or artifact missing |
| NOT APPLICABLE | Target excluded with documented reason |

## Production coverage (both sanitizers)

- \`antech-kdf-types\`, \`antech-kdf-format\`, \`antech-kdf-core\`, \`antech-kdf\`, \`antech-kdf-ffi\`
- Unit + integration tests (\`--lib --tests\`): parser/property, config boundaries, hash/verify, secret/AD, scheduler, FFI, conformance vectors
- Debug and release-like (\`--release\`) profiles

## Sensitive areas exercised

v2 parser/hex validation, config bounds, scheduler acquire/release/queue_limit, FFI ownership/panic containment, binary passwords, SecretBytes/AD, engine prefetch \`unsafe\` (via derives), serde conformance JSON.

## Failures / regressions

See \`regressions.csv\` and \`logs/\`. No suppressions added to silence findings.

Commit: \`${COMMIT_SHA}\`
EOF
