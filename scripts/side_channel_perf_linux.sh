#!/usr/bin/env bash
# Linux PMU/cache analysis for side-channel validation (Ubuntu CI).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/research/results/side-channel"
mkdir -p "${OUT}"

REPEATS="${PMU_REPEATS:-20}"
ITERS="${PMU_ITERS:-12}"
CSV="${OUT}/cache-analysis.csv"
COMP="${OUT}/cache-comparison.csv"

write_blocked() {
  local reason="$1"
  cat > "${CSV}" <<EOF
test_id,scenario,instructions,cycles,ipc,cache_misses,llc_loads,branch_misses,kind,notes
pmu-all,BLOCKED: ${reason},n/a,n/a,n/a,n/a,n/a,n/a,BLOCKED,${reason}
EOF
  cat > "${COMP}" <<EOF
comparison_id,group_a,group_b,metric,n_a,n_b,median_a,median_b,ratio_median,welch_t,significant,exploitability,kind,notes
(none),n/a,n/a,n/a,0,0,n/a,n/a,n/a,n/a,n/a,n/a,BLOCKED,${reason}
EOF
  echo "PMU BLOCKED: ${reason}" >&2
}

if ! command -v perf >/dev/null 2>&1; then
  write_blocked "perf binary not found in PATH"
  exit 0
fi

# Best-effort: widen perf access on CI VMs (may require sudo).
if command -v sudo >/dev/null 2>&1; then
  sudo sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
  sudo sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1 || true
fi

PERF=(perf stat -x,)

cd "${ROOT}"
cargo build --manifest-path research/code/Cargo.toml --release \
  -p antech-kdf-research --example side_channel_pmu_runner >/dev/null 2>&1

BIN="${ROOT}/research/code/target/release/examples/side_channel_pmu_runner"
if [[ ! -x "${BIN}" ]]; then
  BIN="${ROOT}/target/release/examples/side_channel_pmu_runner"
fi
if [[ ! -x "${BIN}" ]]; then
  write_blocked "side_channel_pmu_runner binary missing after build"
  exit 0
fi

EVENTS="instructions,cycles,cache-misses,LLC-load-misses,branch-misses"

parse_perf_file() {
  local f="$1"
  local instr cycles misses llc br
  instr=$(awk -F, '$3 ~ /instructions/{gsub(/^[ \t]+/,"",$1); print $1; exit}' "${f}")
  cycles=$(awk -F, '$3 ~ /cycles/{gsub(/^[ \t]+/,"",$1); print $1; exit}' "${f}")
  misses=$(awk -F, '$3 ~ /cache-misses/{gsub(/^[ \t]+/,"",$1); print $1; exit}' "${f}")
  llc=$(awk -F, '$3 ~ /LLC-load-misses/{gsub(/^[ \t]+/,"",$1); print $1; exit}' "${f}")
  br=$(awk -F, '$3 ~ /branch-misses/{gsub(/^[ \t]+/,"",$1); print $1; exit}' "${f}")
  # Reject <not counted> or empty
  for v in "${instr}" "${cycles}"; do
    if [[ -z "${v}" || "${v}" == "<not" ]]; then
      echo "0,0,0,0,0"
      return 1
    fi
  done
  echo "${instr:-0},${cycles:-0},${misses:-0},${llc:-0},${br:-0}"
}

measure_scenario() {
  local scenario="$1"
  local tmp
  tmp="$(mktemp)"
  export PMU_ITERS="${ITERS}"
  if command -v sudo >/dev/null 2>&1; then
    sudo -E env "PMU_ITERS=${ITERS}" perf stat -x, -e "${EVENTS}" "${BIN}" "${scenario}" 2>"${tmp}" || true
  else
    perf stat -x, -e "${EVENTS}" "${BIN}" "${scenario}" 2>"${tmp}" || true
  fi
  parse_perf_file "${tmp}" || true
  rm -f "${tmp}"
}

# Probe: one run must show non-trivial instruction count.
PROBE="$(mktemp)"
if command -v sudo >/dev/null 2>&1; then
  sudo -E env "PMU_ITERS=3" perf stat -x, -e instructions,cycles "${BIN}" verify_correct_1mib 2>"${PROBE}" || true
else
  PMU_ITERS=3 perf stat -x, -e instructions,cycles "${BIN}" verify_correct_1mib 2>"${PROBE}" || true
fi
PROBE_LINE=$(parse_perf_file "${PROBE}" || echo "0,0,0,0,0")
rm -f "${PROBE}"
PROBE_INSTR=$(echo "${PROBE_LINE}" | cut -d, -f1)
if [[ -z "${PROBE_INSTR}" || "${PROBE_INSTR}" == "0" || "${PROBE_INSTR}" -lt 1000000 ]]; then
  write_blocked "perf stat returned invalid/zero instructions (probe=${PROBE_INSTR}); VM may block PMU (kernel.perf_event_paranoid)"
  cat "${ROOT}/research/results/side-channel/perf-probe.log" 2>/dev/null || true
  exit 0
fi

collect_samples() {
  local scenario="$1"
  local outf="$2"
  : > "${outf}"
  for _ in $(seq 1 "${REPEATS}"); do
    measure_scenario "${scenario}" >> "${outf}"
  done
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

SCENARIOS=(
  verify_correct_1mib
  verify_wrong_1mib
  verify_correct_16mib
  verify_wrong_16mib
  hash_password_len4
  hash_password_len256
  verify_secret_correct
  verify_secret_wrong
  verify_ad_correct
  verify_ad_wrong
  verify_correct_under_load
)

for s in "${SCENARIOS[@]}"; do
  collect_samples "${s}" "${TMPDIR}/${s}.csv"
done

python3 - "${TMPDIR}" "${CSV}" "${COMP}" "${REPEATS}" "${ITERS}" <<'PY'
import csv, math, os, sys

tmpdir, csv_path, comp_path, repeats, iters = sys.argv[1:6]
repeats = int(repeats)
iters = int(iters)

def load_col(path, col):
    vals = []
    with open(path) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) <= col:
                continue
            try:
                v = float(parts[col])
                if v > 0:
                    vals.append(v)
            except ValueError:
                pass
    return vals

def stats(vals):
    if not vals:
        return dict(n=0, median=0, mean=0, var=0, p95=0)
    s = sorted(vals)
    n = len(s)
    mean = sum(s) / n
    var = sum((x - mean) ** 2 for x in s) / (n - 1) if n > 1 else 0.0
    median = s[n // 2]
    p95 = s[int(0.95 * (n - 1))]
    return dict(n=n, median=median, mean=mean, var=var, p95=p95)

def welch(a, b):
    sa, sb = stats(a), stats(b)
    if sa["n"] < 2 or sb["n"] < 2:
        return 0.0
    se = math.sqrt(sa["var"] / sa["n"] + sb["var"] / sb["n"])
    if se <= 0:
        return 0.0
    return abs(sa["mean"] - sb["mean"]) / se

scenarios = [
    "verify_correct_1mib", "verify_wrong_1mib", "verify_correct_16mib", "verify_wrong_16mib",
    "hash_password_len4", "hash_password_len256", "verify_secret_correct", "verify_secret_wrong",
    "verify_ad_correct", "verify_ad_wrong", "verify_correct_under_load",
]

rows = []
any_valid = False
for sc in scenarios:
    path = os.path.join(tmpdir, f"{sc}.csv")
    samples = [load_col(path, i) for i in range(5)] if os.path.isfile(path) else [[]] * 5
    if not samples[0]:
        rows.append({
            "test_id": f"pmu-{sc}", "scenario": sc,
            "instructions": "n/a", "cycles": "n/a", "ipc": "n/a",
            "cache_misses": "n/a", "llc_loads": "n/a", "branch_misses": "n/a",
            "kind": "BLOCKED", "notes": "no valid perf samples",
        })
        continue
    any_valid = True
    si, scy, sm = stats(samples[0]), stats(samples[1]), stats(samples[2])
    ipc = si["mean"] / scy["mean"] if scy["mean"] else 0
    rows.append({
        "test_id": f"pmu-{sc}",
        "scenario": f"{sc} x{iters} per repeat, {repeats} perf runs",
        "instructions": f"{si['median']:.0f}",
        "cycles": f"{scy['median']:.0f}",
        "ipc": f"{ipc:.4f}",
        "cache_misses": f"{sm['median']:.0f}",
        "llc_loads": f"{stats(samples[3])['median']:.0f}",
        "branch_misses": f"{stats(samples[4])['median']:.0f}",
        "kind": "MEASURED",
        "notes": f"Linux perf stat (sudo); median of {repeats} runs",
    })

if not any_valid:
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "test_id", "scenario", "instructions", "cycles", "ipc",
            "cache_misses", "llc_loads", "branch_misses", "kind", "notes",
        ])
        w.writeheader()
        w.writerow({
            "test_id": "pmu-all", "scenario": "BLOCKED: all scenarios zero/invalid",
            "instructions": "n/a", "cycles": "n/a", "ipc": "n/a",
            "cache_misses": "n/a", "llc_loads": "n/a", "branch_misses": "n/a",
            "kind": "BLOCKED",
            "notes": "perf ran but counters unusable on runner",
        })
    with open(comp_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "comparison_id", "group_a", "group_b", "metric", "n_a", "n_b",
            "median_a", "median_b", "ratio_median", "welch_t", "significant",
            "exploitability", "kind", "notes",
        ])
        w.writeheader()
        w.writerow({
            "comparison_id": "(none)", "group_a": "n/a", "group_b": "n/a", "metric": "n/a",
            "n_a": 0, "n_b": 0, "median_a": "n/a", "median_b": "n/a",
            "ratio_median": "n/a", "welch_t": "n/a", "significant": "n/a",
            "exploitability": "n/a", "kind": "BLOCKED",
            "notes": "no valid PMU samples",
        })
    sys.exit(0)

with open(csv_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=[
        "test_id", "scenario", "instructions", "cycles", "ipc",
        "cache_misses", "llc_loads", "branch_misses", "kind", "notes",
    ])
    w.writeheader()
    w.writerows(rows)

pairs = [
    ("P01_verify_password_1mib", "verify_correct_1mib", "verify_wrong_1mib", "cache_misses", True),
    ("P02_verify_password_16mib", "verify_correct_16mib", "verify_wrong_16mib", "cache_misses", True),
    ("P03_hash_password_length", "hash_password_len4", "hash_password_len256", "cache_misses", False),
    ("P04_verify_secret", "verify_secret_correct", "verify_secret_wrong", "cache_misses", True),
    ("P05_verify_ad", "verify_ad_correct", "verify_ad_wrong", "cache_misses", True),
    ("P06_branch_miss_verify_1mib", "verify_correct_1mib", "verify_wrong_1mib", "branch_misses", True),
    ("P07_idle_vs_under_load", "verify_correct_1mib", "verify_correct_under_load", "cache_misses", False),
]

comp_rows = []
for tid, a, b, metric, equal_length in pairs:
    col = {"cache_misses": 2, "branch_misses": 4}[metric]
    va = load_col(os.path.join(tmpdir, f"{a}.csv"), col)
    vb = load_col(os.path.join(tmpdir, f"{b}.csv"), col)
    sa, sb = stats(va), stats(vb)
    ratio = sa["median"] / sb["median"] if sb["median"] else 0
    t = welch(va, vb)
    rel = abs(sa["median"] - sb["median"]) / max(sa["median"], sb["median"], 1) * 100
    sig = "no"
    exploit = "none"
    if equal_length and t > 2.0 and rel > 5.0:
        sig = "yes_investigate"
        exploit = "possible_cache_or_branch_leak"
    elif t > 2.0 and rel > 5.0:
        sig = "yes_expected_length_or_load"
        exploit = "not_password_byte_oracle"
    comp_rows.append({
        "comparison_id": tid,
        "group_a": a,
        "group_b": b,
        "metric": metric,
        "n_a": sa["n"],
        "n_b": sb["n"],
        "median_a": f"{sa['median']:.0f}",
        "median_b": f"{sb['median']:.0f}",
        "ratio_median": f"{ratio:.4f}",
        "welch_t": f"{t:.3f}",
        "significant": sig,
        "exploitability": exploit,
        "kind": "MEASURED",
        "notes": "Equal-length password pairs where noted; PMU not wall-clock.",
    })

with open(comp_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=[
        "comparison_id", "group_a", "group_b", "metric", "n_a", "n_b",
        "median_a", "median_b", "ratio_median", "welch_t", "significant",
        "exploitability", "kind", "notes",
    ])
    w.writeheader()
    w.writerows(comp_rows)
PY

echo "Wrote ${CSV} and ${COMP}"
