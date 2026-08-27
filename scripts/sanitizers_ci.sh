#!/usr/bin/env bash
# Run ASan or UBSan on Linux (nightly + -Zbuild-std) and write research/results/sanitizers/.
set -euo pipefail

MODE="${1:?usage: sanitizers_ci.sh asan|ubsan}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/research/results/sanitizers"
mkdir -p "${OUT}/logs"

TARGET="${SANITIZER_TARGET:-x86_64-unknown-linux-gnu}"
TOOLCHAIN="${SANITIZER_TOOLCHAIN:-nightly}"
TOOLCHAIN_PLUS="+${TOOLCHAIN}"
COMMIT_SHA="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUSTC_VER="$(rustc "${TOOLCHAIN_PLUS}" --version)"

case "${MODE}" in
  asan)
    SAN_FLAGS="-Zsanitizer=address"
    USE_BUILD_STD=1
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1:print_summary=1}"
    ;;
  ubsan)
    # nightly 1.100+ dropped `-Zsanitizer=undefined`; pin via SANITIZER_TOOLCHAIN in CI.
    SAN_FLAGS="-Zsanitizer=undefined"
    USE_BUILD_STD=1
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"
    ;;
  *)
    echo "unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

export RUSTFLAGS="${SAN_FLAGS}"
export RUSTDOCFLAGS="${SAN_FLAGS}"

echo "mode=${MODE}"
echo "toolchain=${TOOLCHAIN}"
echo "rustc=${RUSTC_VER}"
echo "target=${TARGET}"
echo "commit=${COMMIT_SHA}"
echo "date_utc=${DATE_UTC}"
echo "RUSTFLAGS=${RUSTFLAGS}"

PROD_PKGS=(
  -p antech-kdf-types
  -p antech-kdf-format
  -p antech-kdf-core
  -p antech-kdf
  -p antech-kdf-ffi
)

run_cargo_test() {
  local name="$1"
  local profile="$2" # debug|release
  shift 2
  local log="${OUT}/logs/${MODE}-${name}.log"
  echo "=== ${MODE} ${name} (${profile}) ===" | tee "${log}"
  set +e
  if [[ "${USE_BUILD_STD}" == 1 ]]; then
    if [[ "${profile}" == "release" ]]; then
      cargo "${TOOLCHAIN_PLUS}" test -Zbuild-std --target "${TARGET}" --release "$@" 2>&1 | tee -a "${log}"
    else
      cargo "${TOOLCHAIN_PLUS}" test -Zbuild-std --target "${TARGET}" "$@" 2>&1 | tee -a "${log}"
    fi
  else
    if [[ "${profile}" == "release" ]]; then
      cargo "${TOOLCHAIN_PLUS}" test --release "$@" 2>&1 | tee -a "${log}"
    else
      cargo "${TOOLCHAIN_PLUS}" test "$@" 2>&1 | tee -a "${log}"
    fi
  fi
  local rc=${PIPESTATUS[0]}
  set -e
  echo "exit_code=${rc}" >> "${log}"
  return "${rc}"
}

count_passed() {
  local f="$1"
  grep -E 'test result: ok\.' "${f}" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="passed;") print $(i-1)}' | awk '{s+=$1} END {print s+0}'
}

count_failed() {
  local f="$1"
  grep -E 'test result: FAILED\.' "${f}" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="failed;") print $(i-1)}' | awk '{s+=$1} END {print s+0}'
}

FAILS=0
STATUS_DEBUG=PASS
STATUS_RELEASE=PASS
STATUS_REF_DEBUG=PASS
STATUS_REF_RELEASE=NOT_RUN

run_cargo_test prod_debug debug "${PROD_PKGS[@]}" --lib --tests || { STATUS_DEBUG=FAIL; FAILS=$((FAILS+1)); }
run_cargo_test prod_release release "${PROD_PKGS[@]}" --lib --tests || { STATUS_RELEASE=FAIL; FAILS=$((FAILS+1)); }

# Reference implementation (research crate; parity only — not production SOT)
if [[ -f "${ROOT}/research/code/Cargo.toml" ]]; then
  STATUS_REF_DEBUG=PASS
  STATUS_REF_RELEASE=PASS
  run_cargo_test ref_debug debug \
    --manifest-path "${ROOT}/research/code/Cargo.toml" \
    -p antech-kdf-reference --lib || { STATUS_REF_DEBUG=FAIL; FAILS=$((FAILS+1)); }
  run_cargo_test ref_release release \
    --manifest-path "${ROOT}/research/code/Cargo.toml" \
    -p antech-kdf-reference --lib || { STATUS_REF_RELEASE=FAIL; FAILS=$((FAILS+1)); }
else
  STATUS_REF_DEBUG=NOT_APPLICABLE
  STATUS_REF_RELEASE=NOT_APPLICABLE
fi

OVERALL=PASS
if [[ "${FAILS}" -gt 0 ]]; then
  OVERALL=FAIL
fi

LOG_DEBUG="${OUT}/logs/${MODE}-prod_debug.log"
LOG_RELEASE="${OUT}/logs/${MODE}-prod_release.log"
LOG_REF_D="${OUT}/logs/${MODE}-ref_debug.log"
LOG_REF_R="${OUT}/logs/${MODE}-ref_release.log"

PD=$(count_passed "${LOG_DEBUG}")
PR=$(count_passed "${LOG_RELEASE}")
FD=$(count_failed "${LOG_DEBUG}")
FR=$(count_failed "${LOG_RELEASE}")

CSV="${OUT}/${MODE}.csv"
{
  echo "suite,profile,status,passed,failed,command,notes"
  echo "production_workspace,debug,${STATUS_DEBUG},${PD},${FD},cargo test [types format core kdf ffi] --lib --tests,integration+unit+ffi"
  echo "production_workspace,release,${STATUS_RELEASE},${PR},${FR},cargo test --release [types format core kdf ffi] --lib --tests,release-like optimized+sanitizer"
  if [[ "${STATUS_REF_DEBUG}" != NOT_APPLICABLE ]]; then
    RPD=$(count_passed "${LOG_REF_D}")
    RFD=$(count_failed "${LOG_REF_D}")
    RPR=$(count_passed "${LOG_REF_R}")
    RFR=$(count_failed "${LOG_REF_R}")
    echo "reference_impl,debug,${STATUS_REF_DEBUG},${RPD},${RFD},cargo test -p antech-kdf-reference --lib,research parity crate (not production SOT)"
    echo "reference_impl,release,${STATUS_REF_RELEASE},${RPR},${RFR},cargo test -p antech-kdf-reference --lib --release,research parity crate"
  fi
} > "${CSV}"

# Merge into summary fragments (per-mode block appended by workflow or second invocation)
ENV_FILE="${OUT}/environment.txt"
{
  echo "last_run_utc=${DATE_UTC}"
  echo "commit_sha=${COMMIT_SHA}"
  echo "rustc=${RUSTC_VER}"
  echo "toolchain=${TOOLCHAIN}"
  echo "target=${TARGET}"
  echo "mode=${MODE}"
  echo "RUSTFLAGS=${RUSTFLAGS}"
  if [[ "${MODE}" == "asan" ]]; then
    echo "ASAN_OPTIONS=${ASAN_OPTIONS}"
  else
    echo "UBSAN_OPTIONS=${UBSAN_OPTIONS}"
  fi
} >> "${ENV_FILE}"

echo "${MODE}_overall=${OVERALL}" >> "${OUT}/campaign-status.env"
echo "${MODE}_debug=${STATUS_DEBUG}" >> "${OUT}/campaign-status.env"
echo "${MODE}_release=${STATUS_RELEASE}" >> "${OUT}/campaign-status.env"

exit "${FAILS}"
