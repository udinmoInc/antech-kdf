#!/usr/bin/env bash
# Linux CI helper: run one cargo-fuzz target and append a JSONL stats line.
# Usage: ./fuzz/ci_run_and_report.sh <target> <max_total_time_secs> <out_jsonl>
set -euo pipefail

TARGET="${1:?target}"
SECS="${2:?secs}"
OUT="${3:?out jsonl}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p "$(dirname "$OUT")"
CORPUS_DIR="fuzz/corpus/${TARGET}"
# Map target names that share corpora with alternate dirs
case "$TARGET" in
  hash_parser) CORPUS_DIR="fuzz/corpus/hash_parser" ;;
  verify_input) CORPUS_DIR="fuzz/corpus/verify_input" ;;
  hash_verify) CORPUS_DIR="fuzz/corpus/hash_verify" ;;
  config_builder) CORPUS_DIR="fuzz/corpus/config_builder" ;;
  malformed_v2) CORPUS_DIR="fuzz/corpus/malformed_v2" ;;
  ffi_api) CORPUS_DIR="fuzz/corpus/ffi_api" ;;
  scheduler) CORPUS_DIR="fuzz/corpus/scheduler" ;;
esac

CORPUS_BEFORE=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
START=$(date +%s)
LOG=$(mktemp)

set +e
cargo fuzz run "$TARGET" -- -max_total_time="$SECS" -print_final_stats=1 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e
END=$(date +%s)
ELAPSED=$((END - START))

# libFuzzer prints lines like: #12345	NEW ... or DONE ... exec/s
EXECS=$(grep -Eo '([0-9]+) exec/s' "$LOG" | tail -1 | grep -Eo '^[0-9]+' || true)
# Prefer final "Done" / "stat::number_of_executed_units"
UNITS=$(grep -E 'stat::number_of_executed_units' "$LOG" | tail -1 | awk '{print $2}' || true)
if [[ -z "${UNITS}" ]]; then
  UNITS=$(grep -Eo '^#[0-9]+' "$LOG" | tail -1 | tr -d '#' || echo 0)
fi
COV=$(grep -E 'stat::coverage|cov:' "$LOG" | tail -1 || true)
CRASHES=$(find "fuzz/artifacts/${TARGET}" -type f 2>/dev/null | wc -l | tr -d ' ')
CORPUS_AFTER=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
HANGS=0
if grep -qi 'timeout\|hang' "$LOG"; then HANGS=1; fi

STATUS="PASS"
if [[ "$RC" -ne 0 ]]; then STATUS="FAIL"; fi
if [[ "$CRASHES" -gt 0 ]]; then STATUS="FAIL"; fi

python3 - <<PY >>"$OUT"
import json
print(json.dumps({
  "target": "$TARGET",
  "status": "$STATUS",
  "exit_code": $RC,
  "max_total_time_secs": $SECS,
  "elapsed_secs": $ELAPSED,
  "executions_approx": int("${UNITS}" or "0"),
  "exec_per_sec_last": int("${EXECS}" or "0"),
  "corpus_before": int("$CORPUS_BEFORE"),
  "corpus_after": int("$CORPUS_AFTER"),
  "artifact_files": int("$CRASHES"),
  "hangs_flagged": int("$HANGS"),
  "coverage_line": """${COV}""".strip(),
  "engine": "libFuzzer",
}))
PY

rm -f "$LOG"
exit "$RC"
