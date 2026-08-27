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
mkdir -p "research/results/fuzz/ci/logs"
CORPUS_DIR="fuzz/corpus/${TARGET}"
case "$TARGET" in
  hash_parser|hash_verify|config_builder|malformed_v2|ffi_api|scheduler)
    CORPUS_DIR="fuzz/corpus/${TARGET}"
    ;;
  *)
    echo "unknown target: $TARGET" >&2
    exit 2
    ;;
esac

CORPUS_BEFORE=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
START=$(date +%s)
LOG="research/results/fuzz/ci/logs/${TARGET}.log"

set +e
cargo fuzz run "$TARGET" -- \
  -max_total_time="$SECS" \
  -print_final_stats=1 \
  -rss_limit_mb=4096 \
  -timeout=25 \
  2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e
END=$(date +%s)
ELAPSED=$((END - START))

EXECS=$(grep -Eo '([0-9]+) exec/s' "$LOG" | tail -1 | grep -Eo '[0-9]+' | head -1 || true)
UNITS=$(grep -E 'stat::number_of_executed_units' "$LOG" | tail -1 | awk '{print $NF}' || true)
if [[ -z "${UNITS}" ]]; then
  UNITS=$(grep -Eo '^#[0-9]+' "$LOG" | tail -1 | tr -d '#' || echo 0)
fi
COV=$(grep -E 'stat::coverage|cov:|ft:' "$LOG" | tail -1 || true)
FEATURE=$(grep -E 'stat::feature_count|ft:' "$LOG" | tail -1 || true)
CRASH_DIR="fuzz/artifacts/${TARGET}"
CRASHES=$(find "$CRASH_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
CORPUS_AFTER=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
HANGS=0
if grep -Eiq 'ERROR: libFuzzer: timeout|ALARM:|hang detected' "$LOG"; then HANGS=1; fi
TIMEOUTS=$(find "$CRASH_DIR" -type f -name 'timeout-*' 2>/dev/null | wc -l | tr -d ' ')
if [[ "${TIMEOUTS}" -gt 0 ]]; then HANGS=1; fi

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
  "timeout_artifacts": int("$TIMEOUTS"),
  "hangs_flagged": int("$HANGS"),
  "coverage_line": """${COV}""".replace("\\","\\\\").replace('"',"'").strip(),
  "feature_line": """${FEATURE}""".replace("\\","\\\\").replace('"',"'").strip(),
  "engine": "libFuzzer",
  "log_path": "research/results/fuzz/ci/logs/${TARGET}.log",
}))
PY

exit "$RC"
