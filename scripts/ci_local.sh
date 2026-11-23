#!/usr/bin/env bash
# Local equivalent of the planned PR gate (Notion 04 · CI §4, CI-001/CI-002).
# Every step must run and pass; a step that is skipped or runs zero tests fails the gate.
set -euo pipefail
export CARGO_TERM_COLOR=never

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-evidence/local}"
mkdir -p "$OUT"
LOG="$OUT/ci_local.log"
: >"$LOG"

# Logs are evidence: strip the absolute checkout path and home directory before keeping them.
sanitize() { sed -e "s#${ROOT}#.#g" -e "s#${HOME}#~#g"; }

step() {
  local name="$1"
  shift
  echo "## ${name}: $*" | tee -a "$LOG"
  if "$@" 2>&1 | sanitize >>"$LOG"; then
    echo "${name}=pass" | tee -a "$LOG"
  else
    echo "${name}=FAIL" | tee -a "$LOG"
    exit 1
  fi
}

step fmt cargo fmt --all -- --check
step clippy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
step build cargo build --workspace --all-targets --locked
step test cargo test --workspace --all-features --locked
step doctest cargo test --doc --workspace --locked
step deny cargo deny --locked check advisories licenses bans sources

# cargo-audit has its own ignore list; it must stay identical to the reviewed deny.toml baseline.
# Only entries are compared (deny: `id = "..."`, audit: quoted list items), never comments.
deny_ids() { grep -Eo 'id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' deny.toml | grep -Eo 'RUSTSEC-[0-9-]+' | sort -u; }
audit_ids() { grep -Eo '^ *"RUSTSEC-[0-9]{4}-[0-9]{4}"' .cargo/audit.toml | grep -Eo 'RUSTSEC-[0-9-]+' | sort -u; }
advisory_baseline_sync() { diff <(deny_ids) <(audit_ids); }
step advisory_baseline_sync advisory_baseline_sync

# Containment: the advisory baseline is accepted only for lab-server's SpruceID tree. The core
# crates must not reach any of it, directly or transitively (cargo-deny wrappers only cover
# named crates, so check the resolved graph itself).
CORE_CRATES=(protocol-model jose-hpke session-core)
SPRUCE_TREE_RE='^(openid4vp|josekit|ssi|ssi-[a-z0-9-]+|did-[a-z0-9-]+|rsa|im|sized-chunks|bitmaps|smallstr|serde_cbor|derivative|clear_on_drop|proc-macro-error|chrono) '
core_containment() {
  local c tree hits=0
  for c in "${CORE_CRATES[@]}"; do
    # Resolve first: a failing `cargo tree` must fail the step, not read as "no match".
    tree="$(cargo tree --locked -p "$c" -e normal,build,dev --prefix none)" || return 1
    if grep -E "$SPRUCE_TREE_RE" <<<"$tree"; then
      echo "containment violated by $c"
      hits=1
    fi
  done
  return "$hits"
}
step core_containment core_containment
step audit cargo audit --deny warnings
step machete cargo machete

# Guard against "green with nothing executed": named G0 tests must have run and passed.
REQUIRED_TESTS=(
  signed_request_binding_matches_stored_session
  each_session_gets_a_distinct_response_uri
)
for t in "${REQUIRED_TESTS[@]}"; do
  if ! grep -Eq "^test ${t} \.\.\. ok$" "$LOG"; then
    echo "gate=FAIL (required test ${t} did not pass)" | tee -a "$LOG"
    exit 1
  fi
done
passed=$(grep -Eo 'test result: ok\. [0-9]+ passed' "$LOG" | awk '{s+=$4} END {print s+0}')
echo "tests_passed_total=${passed}" | tee -a "$LOG"
if [[ "$passed" -eq 0 ]]; then
  echo "gate=FAIL (0 tests executed)" | tee -a "$LOG"
  exit 1
fi
echo "gate=pass" | tee -a "$LOG"
