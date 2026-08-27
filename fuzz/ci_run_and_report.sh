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

# Prefer final "stat::number_of_executed_units"; fall back to last #N progress line.
UNITS=$(grep -E 'stat::number_of_executed_units' "$LOG" | tail -1 | awk '{print $NF}' || true)
if [[ -z "${UNITS}" ]]; then
  UNITS=$(grep -Eo 'Done [0-9]+ runs' "$LOG" | tail -1 | grep -Eo '[0-9]+' | head -1 || true)
fi
if [[ -z "${UNITS}" ]]; then
  UNITS=$(grep -Eo '^#[0-9]+' "$LOG" | tail -1 | tr -d '#' || echo 0)
fi
EXECS=$(grep -Eo '[0-9]+ exec/s' "$LOG" | tail -1 | grep -Eo '[0-9]+' | head -1 || true)
COV=$(grep -E 'DONE|stat::coverage|cov:' "$LOG" | tail -1 || true)
FEATURE=$(grep -E 'stat::feature_count|^#.*ft:' "$LOG" | tail -1 || true)

CRASH_DIR="fuzz/artifacts/${TARGET}"
CRASHES=$(find "$CRASH_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
TIMEOUTS=$(find "$CRASH_DIR" -type f -name 'timeout-*' 2>/dev/null | wc -l | tr -d ' ')
CORPUS_AFTER=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
HANGS=0
if grep -Eiq 'ERROR: libFuzzer: timeout|ALARM:|hang detected' "$LOG"; then HANGS=1; fi
if [[ "${TIMEOUTS:-0}" -gt 0 ]]; then HANGS=1; fi

STATUS="PASS"
if [[ "$RC" -ne 0 ]]; then STATUS="FAIL"; fi
if [[ "${CRASHES:-0}" -gt 0 ]]; then STATUS="FAIL"; fi

# Pass free-form log snippets via env so tabs/quotes cannot break the Python source.
export FUZZ_TARGET="$TARGET"
export FUZZ_STATUS="$STATUS"
export FUZZ_EXIT_CODE="$RC"
export FUZZ_SECS="$SECS"
export FUZZ_ELAPSED="$ELAPSED"
export FUZZ_UNITS="${UNITS:-0}"
export FUZZ_EXECS="${EXECS:-0}"
export FUZZ_CORPUS_BEFORE="$CORPUS_BEFORE"
export FUZZ_CORPUS_AFTER="$CORPUS_AFTER"
export FUZZ_CRASHES="${CRASHES:-0}"
export FUZZ_TIMEOUTS="${TIMEOUTS:-0}"
export FUZZ_HANGS="$HANGS"
export FUZZ_COV="$COV"
export FUZZ_FEATURE="$FEATURE"
export FUZZ_LOG="$LOG"

python3 - <<'PY' >>"$OUT"
import json, os
def i(name):
    try:
        return int(os.environ.get(name) or "0")
    except ValueError:
        return 0
print(json.dumps({
  "target": os.environ.get("FUZZ_TARGET",""),
  "status": os.environ.get("FUZZ_STATUS",""),
  "exit_code": i("FUZZ_EXIT_CODE"),
  "max_total_time_secs": i("FUZZ_SECS"),
  "elapsed_secs": i("FUZZ_ELAPSED"),
  "executions_approx": i("FUZZ_UNITS"),
  "exec_per_sec_last": i("FUZZ_EXECS"),
  "corpus_before": i("FUZZ_CORPUS_BEFORE"),
  "corpus_after": i("FUZZ_CORPUS_AFTER"),
  "artifact_files": i("FUZZ_CRASHES"),
  "timeout_artifacts": i("FUZZ_TIMEOUTS"),
  "hangs_flagged": i("FUZZ_HANGS"),
  "coverage_line": os.environ.get("FUZZ_COV","").strip(),
  "feature_line": os.environ.get("FUZZ_FEATURE","").strip(),
  "engine": "libFuzzer",
  "log_path": os.environ.get("FUZZ_LOG",""),
}))
PY

exit "$RC"
