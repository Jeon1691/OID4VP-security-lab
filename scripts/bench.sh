#!/usr/bin/env bash
# G6 benchmark and evidence run (IMP-015/016, CI-008). Not a gate stage and never run by ci.yml:
# the numbers are evidence, not pass/fail, and no latency threshold exists. The run fails only
# if scenario-runner reports a broken protocol invariant (exit 1) or cannot run (exit 2).
#
# Usage: scripts/bench.sh [OUT_ROOT] [-- scenario-runner args...]
#   OUT_ROOT     default evidence/g6; the run is written to OUT_ROOT/<run-id>/
#   BENCH_RUN_ID run id (default <UTC yyyymmddThhmmssZ>-<12-char git sha>)
#   REDIS_URL    if set, adds the Redis store rows (the URL itself is never logged)
# Exit status: 0 every invariant held, 1 an invariant broke, 2 the run could not complete
# (build failure, bad arguments, broken run). Methodology: docs/benchmarks.md.
set -euo pipefail
export CARGO_TERM_COLOR=never

readonly EXIT_BROKEN=2
USAGE="usage: scripts/bench.sh [OUT_ROOT] [-- scenario-runner args...]"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT_ROOT="evidence/g6"
# OUT_ROOT is optional; runner arguments always follow `--`.
if [[ $# -gt 0 && "$1" != "--" ]]; then
  OUT_ROOT="$1"
  shift
fi
if [[ $# -gt 0 ]]; then
  if [[ "$1" != "--" ]]; then
    echo "$USAGE" >&2
    exit "$EXIT_BROKEN"
  fi
  shift
fi
SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo nogit)"
RUN_ID="${BENCH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-${SHA}}"
OUT="${OUT_ROOT}/${RUN_ID}"
# A run directory belongs to exactly one run: reusing one would mix old result files with the
# new manifest. The parent may exist; the run directory must not (plain `mkdir`, atomic).
mkdir -p "$OUT_ROOT"
if ! mkdir "$OUT" 2>/dev/null; then
  echo "run directory ${OUT} already exists; pick a new BENCH_RUN_ID" >&2
  exit "$EXIT_BROKEN"
fi
LOG="$OUT/bench.log"
: >"$LOG"

# Same log hygiene as ci_local.sh: no absolute checkout path or home directory in evidence.
sanitize() { sed -e "s#${ROOT}#.#g" -e "s#${HOME}#~#g"; }

echo "## bench_build: cargo build --release --locked -p scenario-runner" | tee -a "$LOG"
if cargo build --release --locked -p scenario-runner 2>&1 | sanitize >>"$LOG"; then
  echo "bench_build=pass" | tee -a "$LOG"
else
  echo "bench_build=FAIL" | tee -a "$LOG"
  scripts/evidence_manifest.sh "$OUT" >/dev/null
  exit "$EXIT_BROKEN"
fi

echo "## scenario_runner: run ${RUN_ID} ($*)" | tee -a "$LOG"
set +e
cargo run --release --locked -q -p scenario-runner -- --out "$OUT" --run-id "$RUN_ID" "$@" 2>&1 \
  | sanitize >>"$LOG"
status=${PIPESTATUS[0]}
set -e
case "$status" in
  0) echo "scenario_runner=pass" | tee -a "$LOG"; echo "invariants=pass" | tee -a "$LOG" ;;
  1) echo "scenario_runner=pass" | tee -a "$LOG"; echo "invariants=FAIL" | tee -a "$LOG" ;;
  *) echo "scenario_runner=FAIL" | tee -a "$LOG"; status="$EXIT_BROKEN" ;;
esac
scripts/evidence_manifest.sh "$OUT" >/dev/null
echo "bench exit ${status}: ${OUT}"
exit "$status"
