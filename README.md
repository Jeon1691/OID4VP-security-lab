# OID4VP Security Lab

Rust research harness for OpenID4VP 1.1 HPKE-0 response encryption, multi-session response
routing (OIDF OpenID4VP #792), replay, concurrency and admission control. Synthetic data and
loopback endpoints only.

Design, WBS and gate definitions live in Notion (01–06). This repository holds code and run
evidence.

## Layout

| Path | Purpose |
| --- | --- |
| `crates/protocol-model` | Versioned wire model, exact `RequestBinding` bytes (IMP-003) |
| `crates/jose-hpke` | JOSE HPKE-0 integrated encryption + Session Info (IMP-004..006) |
| `crates/session-core` | Session resolution strategies, atomic registry (IMP-007/011/012) |
| `crates/lab-server` | axum lab Verifier for HPKE-0 `direct_post.jwt` (IMP-008..010), wallet simulator (`wallet-sim` feature); G0-C API smoke test, G0-D ECDH-ES loopback e2e |
| `scripts/` | Gate stages (shared by local and CI), upstream reproduction, evidence manifest |
| `.github/workflows/` | `ci.yml` PR/main gate, `security.yml` daily advisory scan |
| `evidence/g0/` | G0 run logs, upstream lockfile, advisory baseline, manifest |
| `upstream/` | Pinned SpruceID checkout (git-ignored, recreated by `make g0-upstream`) |

The MVP is limited to these four packages (Notion 06 §6). Redis, scenario-runner and
evidence-report are split out after G0/G1.

## Pins

- Toolchain: `rust-toolchain.toml` → rustc 1.100.0
- SpruceID `openid4vp`: `c57a895884d039a741cc4b472c1698fb147ba487` (ADR-001)
- `Cargo.lock` is committed; every cargo command in the gate runs with `--locked`

## Usage

```bash
make tools        # cargo-deny, cargo-audit, cargo-machete (+ shellcheck, actionlint check)
make test
make gate         # all CI stages: quality, test, supply-chain
make g0           # upstream reproduction + lab gate + manifest into evidence/g0
```

The gate fails if zero tests ran. Logs are stripped of absolute paths before they are stored.

### Lab server

```bash
cargo run -p lab-server -- --mode hardened --bind 127.0.0.1:8080
cargo run -p lab-server -- --mode research-trial=8      # shared route, bounded trial
cargo run -p lab-server -- --mode research-kid          # shared route, unique kid
```

Every mode binds loopback only; a non-loopback deployment needs an explicit ADR first.
Release binaries come from a plain `cargo build -p lab-server --release`: builds that include
test targets unify the test-only `wallet-sim` feature (sealing) into the library.

Endpoints, modes, the per-POST pipeline and the evidence records are documented in
`crates/lab-server/src/lib.rs`. Request objects are **unsigned** for now; JAR signing is a
follow-up and must sign the stored `client_id` / `nonce` / `response_uri` unchanged (they are
the HPKE `session_info` inputs). Presentation validation is synthetic (Evidence level 2):
`nonce` and `aud` must match the session, HPKE decryption alone is never holder
authentication, and KB-JWT holder binding is out of scope for this wave.

## CI

`ci.yml` runs on every PR and on pushes to `main`. Each job runs one stage of
`scripts/ci_local.sh`, the same script `make gate` uses:

| Job | Stage |
| --- | --- |
| `rust-quality` | fmt, clippy `-D warnings`, machete, shellcheck, actionlint |
| `unit` | build, test, doctest, required G0 tests, non-zero test count |
| `supply-chain` | cargo-deny, advisory baseline sync, core containment, Verifier build without sealing, cargo-audit |
| `g0-upstream` | SpruceID CI reproduction at the pinned SHA (main / manual only) |
| `ci-gate` | Single required check: fails unless every gate job's result is `success` |

Each job uploads its logs and `manifest.json` as an `evidence-*` artifact (kept 14 days).
`security.yml` re-runs the supply-chain stage daily, because new advisories are published
without any code change. Actions are pinned to commit SHAs, the token is `contents: read`, and
`pull_request_target` is not used.

## Supply-chain baseline

The pinned SpruceID tree (`openid4vp` → `josekit`, `rsa`, `ssi`) carries 13 RustSec advisories.
Upstream CI does not see them because it only runs `cargo deny check licenses`. They are
listed with reasons in `deny.toml` (mirrored in `.cargo/audit.toml`; the gate checks that both
lists match). Unfiltered evidence is in `evidence/g0/advisories_baseline.txt`. Any new
advisory fails the gate.

The gate step `core_containment` checks the resolved graph of `jose-hpke`, `session-core` and
`protocol-model`, and fails if any crate from that tree (`openid4vp`, `josekit`, `ssi*`, `did-*`,
`rsa`, or a crate in the baseline) shows up there, directly or transitively. `deny.toml [bans]`
additionally rejects direct `openid4vp`/`ssi` dependencies outside `lab-server`. The HPKE-0 path
(`hpke` 0.15 → `p256` 0.14 → `crypto-bigint` 0.7) has no advisories.

## License

Apache-2.0. See [LICENSE](LICENSE).

`crates/lab-server/tests/fixtures/spruce_verifier.jwk` is a synthetic test key copied unchanged
from [spruceid/openid4vp](https://github.com/spruceid/openid4vp) (MIT OR Apache-2.0). It is
used here under Apache-2.0.

## Policy

No GitHub repository, fork, push, issue, comment or PR is created without prior approval.
The lab server binds to loopback only, in every mode (shared URI / bounded trial included).
