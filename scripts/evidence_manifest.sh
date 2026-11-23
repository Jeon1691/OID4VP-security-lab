#!/usr/bin/env bash
# Emit a run manifest (Notion 04 · CI §8): source revisions, lockfile hash, toolchain, host.
# Contains no secrets, nonces or key material.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-evidence/local}"
mkdir -p "$OUT"

SPRUCE_SHA="$(sed -n 's/^openid4vp = .*rev = "\([0-9a-f]*\)".*/\1/p' Cargo.toml)"
LAB_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="$([[ -n "$(git status --porcelain 2>/dev/null)" ]] && echo true || echo false)"
LOCK_SHA="$(shasum -a 256 Cargo.lock | awk '{print $1}')"
UPSTREAM_LOCK_SHA="$( [[ -f evidence/g0/upstream.Cargo.lock ]] && shasum -a 256 evidence/g0/upstream.Cargo.lock | awk '{print $1}' || echo none)"

python3 -I - "$OUT/manifest.json" <<EOF
import json, platform, subprocess, sys, datetime

def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()

def tool(name):
    try:
        return run(name, "--version")
    except Exception:
        return None

manifest = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "lab_git_sha": "${LAB_SHA}",
    "lab_worktree_dirty": "${DIRTY}" == "true",
    "spruce_openid4vp_sha": "${SPRUCE_SHA}",
    "cargo_lock_sha256": "${LOCK_SHA}",
    "upstream_cargo_lock_sha256": "${UPSTREAM_LOCK_SHA}",
    "rustc_vv": run("rustc", "-Vv").splitlines(),
    "cargo": run("cargo", "-V"),
    "tools": {t: tool(t) for t in ["cargo-deny", "cargo-audit", "cargo-machete", "cargo-nextest", "docker"]},
    "host": {
        "os": platform.platform(),
        "machine": platform.machine(),
        "cpu": run("sysctl", "-n", "machdep.cpu.brand_string") if platform.system() == "Darwin" else platform.processor(),
    },
}
with open(sys.argv[1], "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
print(sys.argv[1])
EOF
