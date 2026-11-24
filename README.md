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
| `crates/session-redis` | Redis-backed `SessionStore`: Lua compare-and-set, keys kept in-process, fail closed (G5, IMP-014) |
| `crates/evidence-report` | G6 benchmark rows → JSON / CSV / Markdown summary (IMP-016) |
| `crates/scenario-runner` | G6 benchmark driver: in-process lab-server over loopback HTTP with the wallet simulator, store timings, criterion micro-benches (IMP-015) |
| `crates/lab-server` | axum lab Verifier for HPKE-0 `direct_post.jwt` (IMP-008..010) with SD-JWT VC + KB-JWT holder binding (Evidence level 3), wallet simulator and synthetic issuer (`wallet-sim` feature); G0-C API smoke test, G0-D ECDH-ES loopback e2e |
| `docs/interop/` | G7: OIDF #792 reproduction map (`issue-792-reproduction.md`), OIDF conformance-suite plan and INTEROP-02 outline (`oidf-conformance-plan.md`) |
| `scripts/` | Gate stages (shared by local and CI), upstream reproduction, evidence manifest |
| `.github/workflows/` | `ci.yml` PR/main gate, `security.yml` daily advisory scan, `bench.yml` manual G6 benchmark |
| `docs/benchmarks.md` | G6 methodology, metrics, invariants, caveats, how to reproduce |
| `evidence/g0/` | G0 run logs, upstream lockfile, advisory baseline, manifest |
| `evidence/g5/` | G5 Redis-stage run (Valkey service, 2-worker races, fail-closed) and manifest |
| `evidence/g6/` | G6 benchmark runs, one directory per run id (`results.csv/json`, `summary.md`, `manifest.json`) |
| `upstream/` | Pinned SpruceID checkout (git-ignored, recreated by `make g0-upstream`) |

The MVP was limited to four packages (Notion 06 §6); `session-redis` is split out after G0/G1,
`scenario-runner` and `evidence-report` after the MVP (G6). `scenario-runner` is not a default
workspace member: it enables lab-server's test-only `wallet-sim` as a normal dependency, so a
plain `cargo build` stays a Verifier build.

## Pins

- Toolchain: `rust-toolchain.toml` → rustc 1.100.0
- SpruceID `openid4vp`: `c57a895884d039a741cc4b472c1698fb147ba487` (ADR-001)
- `Cargo.lock` is committed; every cargo command in the gate runs with `--locked`

## Usage

```bash
make tools        # cargo-deny, cargo-audit, cargo-machete (+ shellcheck, actionlint check)
make test
make gate         # all CI stages: quality, test, supply-chain
make gate-redis   # opt-in redis stage: Redis tests against $REDIS_URL or a disposable Valkey (Docker)
make g0           # upstream reproduction + lab gate + manifest into evidence/g0
make bench        # G6 benchmark into evidence/g6/<run-id> (not a gate; Redis rows with $REDIS_URL)
```

The gate fails if zero tests ran. Logs are stripped of absolute paths before they are stored.

### Lab server

```bash
KEY=crates/lab-server/tests/fixtures/spruce_verifier.jwk   # synthetic fixture, explicit opt-in
ISSUER=crates/lab-server/tests/fixtures/lab_issuer.pub.jwk # synthetic issuer public key
cargo run -p lab-server -- --signing-key $KEY --issuer-key $ISSUER --mode hardened --bind 127.0.0.1:8080
cargo run -p lab-server -- --signing-key $KEY --issuer-key $ISSUER --mode research-trial=8  # shared route, bounded trial
cargo run -p lab-server -- --signing-key $KEY --issuer-key $ISSUER --mode research-kid      # shared route, unique kid
```

`--signing-key` (or `LAB_SIGNING_KEY`) is required: the EC P-256 private JWK that signs every
Request Object. No key is compiled into any build; the fixture above matches the default
`client_id` (`decentralized_identifier:did:key:zDnaeaDj…`). Another key needs the matching
did:key as `--client-id`. `--issuer-key` (or `LAB_ISSUER_KEY`) is required too: the EC P-256
*public* JWK (no `d`) of the only SD-JWT VC issuer the Verifier trusts.

Every mode binds loopback only; a non-loopback deployment needs an explicit ADR first.
Release binaries come from a plain `cargo build -p lab-server --release`: builds that include
test targets, or `scenario-runner` (`--workspace`), unify the test-only `wallet-sim` feature
(sealing) into the library.

Endpoints, modes, the per-POST pipeline and the evidence records are documented in
`crates/lab-server/src/lib.rs`. Request objects are signed JWTs (JAR, RFC 9101; OpenID4VP 1.1
§5): `GET request_uri` answers `application/oauth-authz-req+jwt` with an ES256 JWS (`typ`
`oauth-authz-req+jwt`, did:key `kid`, `aud` `https://self-issued.me/v2`, `iat`/`exp` = session
expiry). The server refuses to start if a did:key `client_id` is not its key's. It is signed once over
the stored `client_id` / `nonce` / `response_uri` (the HPKE `session_info` inputs), which tests
pin byte-equal on every route. The wallet simulator verifies the signature against the did:key
of the `client_id` (ssi resolver), refuses expired objects, and uses only the verified payload.

Presentation validation verifies holder binding with synthetic credentials (Evidence level
3). The Request Object's `dcql_query` asks for one `dc+sd-jwt` credential (`vct_values`
`https://credentials.lab.invalid/synthetic-identity/v1`; claims `given_name`, `family_name`,
`age_over_18`; holder binding required). The decrypted `vp_token` must be
`{"synthetic-credential": ["<SD-JWT+KB>"]}` (OpenID4VP 1.1 §8.1, B.3.6), and the Verifier
checks, without ssi or openid4vp in its build (RustCrypto `p256` / `sha2`):

- the issuer JWT: `typ` `dc+sd-jwt`, `alg` ES256 exactly, no `crit`, signature by the
  configured issuer key, `_sd_alg` `sha-256` only (RFC 9901 §4.1, §7.1 step 2);
- every Disclosure: canonical base64url, digest referenced exactly once, no duplicate or
  unreferenced Disclosures or digests, no claim-name collisions, recursive and array-element
  Disclosures (§4.2, §7.1 steps 3-5), `exp` / `nbf` (§7.1 step 6);
- the holder key from `cnf.jwk` and the KB-JWT: `typ` `kb+jwt`, ES256 by that key, `iat`
  within 300 s (60 s future skew), `nonce` and `aud` byte-equal to the session's `nonce` and
  `client_id`, `sd_hash` over the presentation up to the last `~` (§4.3, §7.3; OpenID4VP 1.1
  B.3.6, §14.2.2);
- the SD-JWT VC / DCQL profile: `vct`, claims SD-JWT VC forbids in Disclosures (`cnf`,
  `status`, ...) never disclosed and free of `_sd` / `...` digests, every requested claim
  present (draft-ietf-oauth-sd-jwt-vc-27 §2.2; OpenID4VP 1.1 §6.4.1, §8.6);
- lab data-minimisation policy (stricter than the spec, which only restricts the Wallet): no
  Disclosure at any depth, array elements included, outside the requested claims.

All JSON is parsed with duplicate members refused at any depth, and every size and count is
bounded before any crypto. The consumed session keeps only the requested claims (each at most
256 bytes), the `vct`, the holder key's RFC 7638 thumbprint and the JSON Pointers of all
disclosed claims, never the presentation; none of these go into the evidence log. Every failure answers the generic 400; the failing check is recorded
as evidence. HPKE decryption alone is never holder authentication. Out of scope: issuer trust
beyond one configured key, status/revocation, Wallet attestation, mdoc.

Pinned specifications: OpenID4VP 1.1 Editor's draft of 11 November 2026, RFC 9901 (SD-JWT,
November 2025), draft-ietf-oauth-sd-jwt-vc-27 (16 November 2026). The RFC 9901 §5.2 and
Appendix A.3 examples are verified as fixtures (`tests/fixtures/rfc9901_examples.json`, with
URL, document SHA-256 and retrieval date). SpruceID ssi 0.16's SD-JWT code (test-only) is
used as an independent implementation in both directions; note that its `KbJwtPayload`
serializes absent `exp`/`nbf` as `null`, which the lab refuses (RFC 7519 §4.1.4).

## CI

`ci.yml` runs on every PR and on pushes to `main`. Each job runs one stage of
`scripts/ci_local.sh`, the same script `make gate` uses:

| Job | Stage |
| --- | --- |
| `rust-quality` | fmt, clippy `-D warnings`, machete, shellcheck, actionlint |
| `unit` | build, test, doctest, required G0 tests, non-zero test count |
| `supply-chain` | cargo-deny, advisory baseline sync, core containment, Verifier build without sealing or session-core `store-backend`, cargo-audit |
| `redis` | session-redis against a Valkey service container (Redis-compatible, BSD-3-Clause): contract suite, two-worker race, fail closed, required Redis tests |
| `g0-upstream` | SpruceID CI reproduction at the pinned SHA (main / manual only) |
| `ci-gate` | Single required check: fails unless every gate job's result is `success` |

Each job uploads its logs and `manifest.json` as an `evidence-*` artifact (kept 14 days).
`bench.yml` (manual `workflow_dispatch` only, not part of `ci-gate`) runs `scripts/bench.sh` on
Linux with a Valkey service and uploads the run as `evidence-bench`. Benchmark numbers are
evidence: there is no latency threshold, and only broken protocol invariants (HPKE attempt
counts) fail it. See `docs/benchmarks.md`.
`security.yml` re-runs the supply-chain stage daily, because new advisories are published
without any code change. Actions are pinned to commit SHAs, the token is `contents: read`, and
`pull_request_target` is not used.

## Supply-chain baseline

The pinned SpruceID tree (`openid4vp` → `josekit`, `rsa`, `ssi`) carries 13 RustSec advisories.
Upstream CI does not see them because it only runs `cargo deny check licenses`. They are
listed with reasons in `deny.toml` (mirrored in `.cargo/audit.toml`; the gate checks that both
lists match). Unfiltered evidence is in `evidence/g0/advisories_baseline.txt`. Any new
advisory fails the gate.

The gate step `core_containment` checks the resolved graph of `jose-hpke`, `session-core`,
`session-redis`, `protocol-model` and `evidence-report`, and fails if any crate from that tree (`openid4vp`,
`josekit`, `ssi*`, `did-*`, `rsa`, or a crate in the baseline) shows up there, directly or
transitively. `deny.toml [bans]` additionally rejects direct `openid4vp`/`ssi` dependencies
outside `lab-server`. The HPKE-0 path (`hpke` 0.15 → `p256` 0.14 → `crypto-bigint` 0.7)
has no advisories.

## License

Apache-2.0. See [LICENSE](LICENSE).

`crates/lab-server/tests/fixtures/spruce_verifier.jwk` is a synthetic test key copied unchanged
from [spruceid/openid4vp](https://github.com/spruceid/openid4vp) (MIT OR Apache-2.0). It is
used here under Apache-2.0.

`crates/lab-server/tests/fixtures/lab_issuer.jwk` / `lab_issuer.pub.jwk` are a synthetic P-256
issuer key pair generated for this repository (test use only).
`crates/lab-server/tests/fixtures/rfc9901_examples.json` holds examples extracted from RFC
9901, treated as IETF Code Components (Copyright (c) 2025 IETF Trust and the persons
identified as authors of the code; Revised BSD License, full text in [NOTICE](NOTICE)). The
base64url strings are unchanged except for line breaks; restructured into a lab JSON schema.

## Policy

No GitHub repository, fork, push, issue, comment or PR is created without prior approval.
The lab server binds to loopback only, in every mode (shared URI / bounded trial included).
