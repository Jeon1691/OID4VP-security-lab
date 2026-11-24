#!/usr/bin/env bash
# Emit a run manifest (Notion 04 · CI §8): source revisions, lockfile hashes, toolchain, host
# (CPU, core count, memory, kernel), CI run identity and the per-step results found in
# OUT_DIR/*.log. For a G6 benchmark run (scripts/bench.sh) it also embeds OUT_DIR/run.json, the
# scenario parameters (run id, seed, iterations, sizes, profile).
# Contains no secrets, nonces or key material.
#
# Usage: scripts/evidence_manifest.sh [OUT_DIR]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-evidence/local}"
[[ "$OUT" = /* ]] || OUT="$ROOT/$OUT"
mkdir -p "$OUT"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }

export M_OUT="$OUT"
M_SPRUCE_SHA="$(sed -n 's/^openid4vp = .*rev = "\([0-9a-f]*\)".*/\1/p' Cargo.toml)"
M_LAB_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
# Evidence files are rewritten by the run being recorded; they do not make the source dirty.
M_DIRTY="$([[ -n "$(git status --porcelain -- . ':(exclude)evidence' 2>/dev/null)" ]] && echo true || echo false)"
M_LOCK_SHA="$(sha256 Cargo.lock)"
M_UPSTREAM_LOCK_SHA="$([[ -f "$OUT/upstream.Cargo.lock" ]] && sha256 "$OUT/upstream.Cargo.lock" || echo none)"

export M_SPRUCE_SHA M_LAB_SHA M_DIRTY M_LOCK_SHA M_UPSTREAM_LOCK_SHA

python3 -I - <<'EOF'
import datetime, glob, json, os, platform, re, subprocess

def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()

def tool(name):
    try:
        return run(name, "--version").splitlines()[0]
    except Exception:
        return None

def cpu():
    if platform.system() == "Darwin":
        return run("sysctl", "-n", "machdep.cpu.brand_string")
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None

def physical_cpus():
    if platform.system() == "Darwin":
        return int(run("sysctl", "-n", "hw.physicalcpu"))
    try:
        cores, phys = set(), None
        with open("/proc/cpuinfo") as f:
            for line in f:
                key, _, value = line.partition(":")
                if key.strip() == "physical id":
                    phys = value.strip()
                elif key.strip() == "core id":
                    cores.add((phys, value.strip()))
        return len(cores) or None
    except OSError:
        return None

def memory_bytes():
    if platform.system() == "Darwin":
        return int(run("sysctl", "-n", "hw.memsize"))
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None

out = os.environ["M_OUT"]
steps, tests_passed = {}, {}
for log in sorted(glob.glob(os.path.join(out, "*.log"))):
    name = os.path.basename(log)[: -len(".log")]
    with open(log) as f:
        text = f.read()
    steps[name] = dict(re.findall(r"^([a-z_]+)=(pass|FAIL)\b", text, re.M))
    counts = [int(n) for n in re.findall(r"^test result: ok\. (\d+) passed", text, re.M)]
    if counts:
        tests_passed[name] = sum(counts)

env = os.environ
ci = None
if env.get("GITHUB_ACTIONS") == "true":
    ci = {k.lower(): env.get(k) for k in
          ["GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_JOB", "GITHUB_RUN_ID",
           "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "RUNNER_OS"]}

manifest = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "lab_git_sha": env["M_LAB_SHA"],
    "lab_source_dirty": env["M_DIRTY"] == "true",
    "spruce_openid4vp_sha": env["M_SPRUCE_SHA"],
    "cargo_lock_sha256": env["M_LOCK_SHA"],
    "upstream_cargo_lock_sha256": env["M_UPSTREAM_LOCK_SHA"],
    "rustc_vv": run("rustc", "-Vv").splitlines(),
    "cargo": run("cargo", "-V"),
    "tools": {t: tool(t) for t in ["cargo-deny", "cargo-audit", "cargo-machete"]},
    "host": {"os": platform.platform(), "kernel": platform.release(),
             "machine": platform.machine(), "cpu": cpu(), "logical_cpus": os.cpu_count(),
             "physical_cpus": physical_cpus(), "memory_bytes": memory_bytes()},
    "ci": ci,
    "steps": steps,
    "tests_passed": tests_passed,
}
bench = os.path.join(out, "run.json")
if os.path.exists(bench):
    with open(bench) as f:
        manifest["bench"] = json.load(f)
path = os.path.join(out, "manifest.json")
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
print(path)
EOF
