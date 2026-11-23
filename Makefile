.PHONY: check test gate g0-upstream manifest g0 tools

EVIDENCE ?= evidence/local

## Fast inner loop
check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	cargo test --workspace --all-features --locked

## Full local PR gate (fmt, clippy, build, test, doctest, deny, audit, machete)
gate:
	scripts/ci_local.sh $(EVIDENCE)

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
	cargo install --locked cargo-deny cargo-audit cargo-machete
