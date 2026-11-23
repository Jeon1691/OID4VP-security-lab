#!/usr/bin/env bash
# G0-A/B: reproduce the upstream SpruceID CI steps locally at the pinned commit.
# Mirrors spruceid/openid4vp@c57a8958 .github/workflows/ci.yml (build, test, fmt, clippy,
# machete, deny licenses) with RUSTFLAGS=-Dwarnings as upstream sets it.
set -euo pipefail
export CARGO_TERM_COLOR=never

SPRUCE_REPO="https://github.com/spruceid/openid4vp.git"
SPRUCE_SHA="c57a895884d039a741cc4b472c1698fb147ba487"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/upstream/openid4vp"
OUT="${1:-evidence/g0}"
[[ "$OUT" = /* ]] || OUT="$ROOT/$OUT"
mkdir -p "$OUT"
LOG="$OUT/upstream_ci_local.log"
: >"$LOG"

# Initialise in place rather than `git clone`: CI restores a build cache into
# $SRC/target before this runs, and clone refuses a non-empty directory.
if [[ ! -d "$SRC/.git" ]]; then
  mkdir -p "$SRC"
  git -C "$SRC" init --quiet
  git -C "$SRC" remote add origin "$SPRUCE_REPO"
fi
git -C "$SRC" fetch --quiet --depth 1 origin "$SPRUCE_SHA"
git -C "$SRC" checkout --quiet --detach "$SPRUCE_SHA"
actual="$(git -C "$SRC" rev-parse HEAD)"
[[ "$actual" == "$SPRUCE_SHA" ]] || { echo "pinned SHA mismatch: $actual" >&2; exit 1; }

sanitize() { sed -e "s#${ROOT}#.#g" -e "s#${HOME}#~#g"; }

cd "$SRC"
# Upstream pins no toolchain; build it with the lab toolchain so results are comparable.
TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")"
export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
export RUSTFLAGS="-Dwarnings"

{
  echo "spruce_sha=$actual"
  rustc -Vv
  cargo -V
} | tee -a "$LOG"

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

step build cargo build
step test cargo test --all-features
step fmt cargo fmt -- --check
step clippy cargo clippy
step machete cargo machete
step deny_licenses cargo deny check licenses

# Upstream ships no Cargo.lock; keep the one this run resolved as provenance.
cp Cargo.lock "$OUT/upstream.Cargo.lock"
grep -E 'test result:' "$LOG" | tee "$OUT/upstream_test_summary.txt"
