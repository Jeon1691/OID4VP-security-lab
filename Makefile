.PHONY: check test gate gate-redis bench g0-upstream manifest g0 tools

EVIDENCE ?= evidence/local

## Fast inner loop
check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	cargo test --workspace --all-features --locked

## Full PR gate, same stages as CI (quality, test, supply-chain)
gate:
	scripts/ci_local.sh $(EVIDENCE)

## Opt-in redis stage (not part of `gate`): needs $REDIS_URL or Docker
gate-redis:
	scripts/ci_local.sh $(EVIDENCE) redis

## G6 benchmark (not a gate stage): evidence/g6/<run-id>/, Redis rows when $REDIS_URL is set
bench:
	scripts/bench.sh evidence/g6

## G0-A/B: reproduce upstream SpruceID CI at the pinned SHA
g0-upstream:
	scripts/g0_upstream.sh evidence/g0

manifest:
	scripts/evidence_manifest.sh $(EVIDENCE)

## Everything recorded under evidence/g0
g0:
	scripts/g0_upstream.sh evidence/g0
	scripts/ci_local.sh evidence/g0
	scripts/evidence_manifest.sh evidence/g0

## One-time developer tool install (versions recorded in the manifest)
tools:
	rustup show active-toolchain
	cargo install --locked cargo-deny@0.20.2 cargo-audit@0.23.0 cargo-machete@0.10.1
	@command -v shellcheck >/dev/null || echo 'install shellcheck 0.11.0 (e.g. brew install shellcheck)'
	@command -v actionlint >/dev/null || echo 'install actionlint 1.7.12 (e.g. brew install actionlint)'
