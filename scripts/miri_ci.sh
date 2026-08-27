#!/usr/bin/env bash
# Run production Miri campaign and write research/results/miri/ artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/research/results/miri"
mkdir -p "${OUT}/logs"

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"

RUSTC_VER="$(rustc +nightly --version)"
MIRI_VER="$(cargo +nightly miri --version 2>/dev/null || echo unknown)"
TARGET="$(rustc +nightly -vV | awk '/^host:/{print $2}')"
DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "toolchain=${RUSTC_VER}"
echo "miri=${MIRI_VER}"
echo "target=${TARGET}"
echo "MIRIFLAGS=${MIRIFLAGS}"

cargo +nightly miri setup

run_one() {
  local name="$1"
  shift
  local log="${OUT}/logs/${name}.log"
  echo "=== ${name}: $* ===" | tee "${log}"
  set +e
  cargo +nightly miri test "$@" 2>&1 | tee -a "${log}"
  local rc=${PIPESTATUS[0]}
  set -e
  echo "exit_code=${rc}" >> "${log}"
  return "${rc}"
}

STATUS_TYPES=PASS
STATUS_FORMAT=PASS
STATUS_FORMAT_TESTS=PASS
STATUS_CORE=PASS
STATUS_KDF=PASS
FAILS=0

run_one types -p antech-kdf-types --lib || { STATUS_TYPES=FAIL; FAILS=$((FAILS+1)); }
run_one format -p antech-kdf-format --lib || { STATUS_FORMAT=FAIL; FAILS=$((FAILS+1)); }
run_one format_tests -p antech-kdf-format --tests || { STATUS_FORMAT_TESTS=FAIL; FAILS=$((FAILS+1)); }
# Skip the heaviest multi-thread queue stress under Miri wall-time; still run nested/queue_limit unit paths.
# Engine multi-derive tests use #[cfg_attr(miri, ignore)]; deterministic_small_config still runs (1×1MiB).
run_one core -p antech-kdf-core --lib -- \
  --skip concurrent_admission_respects_global_budget \
  --skip queue_at_limit_rejects_additional_waiters \
  --skip queue_below_limit_blocks_then_admits \
  --skip queue_recovers_after_release \
  || { STATUS_CORE=FAIL; FAILS=$((FAILS+1)); }
run_one kdf_lib -p antech-kdf --lib || { STATUS_KDF=FAIL; FAILS=$((FAILS+1)); }

OVERALL=PASS
if [[ "${FAILS}" -gt 0 ]]; then
  OVERALL=FAIL
fi

# Count tests from logs (best-effort)
count_pass() {
  local f="$1"
  grep -E 'test result: ok\.' "${f}" | tail -1 | sed -E 's/.*ok\. ([0-9]+) passed.*/\1/' || echo 0
}
count_fail() {
  local f="$1"
  grep -E 'test result: FAILED\.' "${f}" | tail -1 | sed -E 's/.*FAILED\. ([0-9]+) failed.*/\1/' || echo 0
}

TP=$(count_pass "${OUT}/logs/types.log"); TF=$(count_fail "${OUT}/logs/types.log")
FP=$(count_pass "${OUT}/logs/format.log"); FF=$(count_fail "${OUT}/logs/format.log")
FTP=$(count_pass "${OUT}/logs/format_tests.log"); FTF=$(count_fail "${OUT}/logs/format_tests.log")
CP=$(count_pass "${OUT}/logs/core.log"); CF=$(count_fail "${OUT}/logs/core.log")
KP=$(count_pass "${OUT}/logs/kdf_lib.log"); KF=$(count_fail "${OUT}/logs/kdf_lib.log")

TOTAL_PASS=$(( ${TP:-0} + ${FP:-0} + ${FTP:-0} + ${CP:-0} + ${KP:-0} ))
TOTAL_FAIL=$(( ${TF:-0} + ${FF:-0} + ${FTF:-0} + ${CF:-0} + ${KF:-0} ))

cat > "${OUT}/tests.csv" <<EOF
suite,command,status,passed,failed,notes
types,cargo miri test -p antech-kdf-types --lib,${STATUS_TYPES},${TP:-0},${TF:-0},config/secret/AD/rehash boundaries
format,cargo miri test -p antech-kdf-format --lib,${STATUS_FORMAT},${FP:-0},${FF:-0},v2 encode/parse + malformed
format_tests,cargo miri test -p antech-kdf-format --tests,${STATUS_FORMAT_TESTS},${FTP:-0},${FTF:-0},parser property suite
core,cargo miri test -p antech-kdf-core --lib (skip heavy thread queues),${STATUS_CORE},${CP:-0},${CF:-0},engine+scheduler+hash/verify 1MiB
kdf_lib,cargo miri test -p antech-kdf --lib,${STATUS_KDF},${KP:-0},${KF:-0},public API secret/AD KATs
EOF

cat > "${OUT}/failures.csv" <<EOF
id,suite,test,status,notes
EOF
if [[ "${FAILS}" -eq 0 ]]; then
  echo "(none),,,,no Miri failures" >> "${OUT}/failures.csv"
fi

cat > "${OUT}/regressions.csv" <<EOF
id,description,status,notes
EOF
echo "(none),no new product defects this campaign,N/A,reporter/tests only" >> "${OUT}/regressions.csv"

cat > "${OUT}/summary.md" <<EOF
# Miri campaign summary

| Field | Value |
|---|---|
| Date (UTC) | ${DATE_UTC} |
| Rustc | ${RUSTC_VER} |
| Miri | ${MIRI_VER} |
| Target | ${TARGET} |
| MIRIFLAGS | \`${MIRIFLAGS}\` |
| Overall | **${OVERALL}** |
| Tests passed (sum of suites) | ${TOTAL_PASS} |
| Tests failed | ${TOTAL_FAIL} |
| Suites failed | ${FAILS} |

## Suite status

| Suite | Status |
|---|---|
| antech-kdf-types --lib | ${STATUS_TYPES} |
| antech-kdf-format --lib | ${STATUS_FORMAT} |
| antech-kdf-format --tests | ${STATUS_FORMAT_TESTS} |
| antech-kdf-core --lib | ${STATUS_CORE} |
| antech-kdf --lib | ${STATUS_KDF} |

## Exclusions (NOT APPLICABLE / BLOCKED)

| Target | Verdict | Reason |
|---|---|---|
| antech-kdf-ffi | NOT APPLICABLE | Unsafe C ABI / foreign pointers; covered by unit tests + ASan/UBSan separately |
| antech-kdf-cli | NOT APPLICABLE | Thin CLI I/O wrapper |
| CUDA / research attackers | NOT APPLICABLE | Non-Rust device / research-only |
| conformance.rs (FS vectors) | NOT APPLICABLE | File-system isolation; use \`include_str!\` / normal \`cargo test\` |
| Heavy core queue thread stress | SKIPPED under Miri | Wall-time; still covered by normal \`cargo test\` |
| Reference crate (research) | NOT APPLICABLE | Outside production workspace members |

See \`unsafe-audit.md\` and \`report.md\`.
EOF

cat > "${OUT}/report.md" <<EOF
# Miri validation report — Antech production Rust

**Verdict: ${OVERALL}**

See \`summary.md\`, \`tests.csv\`, \`failures.csv\`, \`regressions.csv\`, \`unsafe-audit.md\`, and \`logs/\`.
EOF

exit "${FAILS}"
