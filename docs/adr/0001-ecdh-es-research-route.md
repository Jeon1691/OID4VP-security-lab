# ADR 0001: An OpenID4VP 1.0-style ECDH-ES research route

- **Status:** Accepted, 2026-11-25, by the project owner.
- **Scope:** `crates/lab-server` (feature `ecdh-es-research`), `scripts/ci_local.sh`.
- **Related:** `docs/interop/issue-792-reproduction.md` (C3, C9, §4 item 1),
  `docs/interop/oidf-conformance-plan.md` §4 item 3 and stage C2, `crates/jose-ecdh-es`.

This ADR records a lab design decision. It is not a statement of the OpenID Foundation Working
Group's position.

## Context

OIDF OpenID4VP issue #792 contrasts HPKE `session_info` with OpenID4VP 1.0's ECDH-ES. Two of
its claims could not be reproduced, because the lab had no 1.0-style Verifier:

- **C3:** under 1.0 (and under 1.1 with ECDH-ES) decryption needs only the private key, so
  the Verifier goes `kid` → key → decrypt → `state` → session.
- **C9:** `session_info` "has no ECDH-ES equivalent, so the fail-closed property §8.3.1
  describes only holds for HPKE".

The reproduction's §4 item 1 ("with ECDH-ES and a shared key, every candidate would decrypt,
so trial decryption could not select a session at all") was an inference, not a measurement.

PR #15 added `jose-ecdh-es`, a strict ECDH-ES (P-256, `A128GCM` / `A256GCM`) codec, as a
plain library that lab-server did not depend on, and pinned that in the gate until a route
was decided. The conformance plan (§4 item 3) also lists an ECDH-ES path as a precondition
for running the OIDF conformance suite, with the constraint that it must be a separate mode
and never a fallback on the HPKE route, because a fallback is the downgrade C9 describes.

## Decision

Add one research route that behaves like an OpenID4VP 1.0 Verifier with a shared key, to
observe C3 and C9 directly:

1. **A separate route, never a fallback.** `POST /lab/v1/response/ecdh-es` is one shared
   `response_uri` with ONE ECDH-ES P-256 key and `kid` for every session on it (the 1.0 shape).
   Sessions are created with `{"route": "ecdh_es_shared"}`. Their Request Object advertises
   that key (`alg` `ECDH-ES`, `use` `enc`, `kid`) and `encrypted_response_enc_values_supported`
   `["A128GCM", "A256GCM"]` (OpenID4VP 1.0 §5.1, §8.3), and still carries `state` and `nonce`.
   The HPKE-0 routes keep refusing every `alg` but `HPKE-0`; this route refuses every `alg`
   but `ECDH-ES`, `HPKE-0` included. Each session stores a key of its route's kind
   (`LabKey::Hpke` / `LabKey::EcdhEs`), and a trial never opens a candidate with a key of the
   other kind.
2. **Research mode only, opt-in per server.** The route exists only in `Mode::Research` with
   `LabConfig::ecdh_es_route` set (default `false`; only the ECDH-ES tests set it), so other
   research servers create no ECDH-ES key or registry and share no limits with it. Without it,
   and in hardened mode, the route is 404 and `ecdh_es_shared` sessions are refused (400); a
   hardened config that sets the flag is refused at start.
3. **1.0 correlation order.** Parse; resolve the live sessions on the route (this cannot select
   one: they share route token, `kid` and key); open with each one's key, i.e. the route's key
   alone; parse the plaintext once (every candidate that opens yields the same plaintext);
   `state` selects; when the research knob reuses `state`, holder binding disambiguates; then
   the existing checks for the selected session (holder binding to its `client_id` / `nonce`,
   replay guard, atomic claim). A missing `state` or one that names no live session is refused
   and consumes nothing. The generic 400 and the `EvidenceLog` reason convention are
   unchanged; new reasons are `Rejection::EcdhEsJweParse` and `ValidationError::StateUnknown`.
4. **No `state` index.** The resolved candidate list (every live session on the route) is
   scanned for the `state`. This needs no change to session-core or the session-redis store
   contract, and no second map that would have to follow the registry through claims,
   expiry, purge and the consumed retention window. The route's registry is capped at
   `MAX_ECDH_ES_SESSIONS` (= session-core `MAX_CANDIDATE_BUDGET`, 256), which also bounds the
   decryption work per POST, as on bounded trial.
5. **Feature gated.** The route and the `jose-ecdh-es` dependency sit behind the non-default
   lab-server feature `ecdh-es-research`, enabled for tests by the self dev-dependency. The
   default build, and so the `lab-server` binary, contain no ECDH-ES code. ECDH-ES sealing for
   the wallet simulator comes from `jose-ecdh-es/test-support` under `wallet-sim` only
   (`jose-ecdh-es?/test-support`, so `wallet-sim` alone does not pull jose-ecdh-es in).
6. **No binary opt-in.** `main.rs` keeps its modes (`hardened`, `research-kid`,
   `research-trial=<budget>`) and gets no flag: the route is exercised by tests only. Even a
   binary built with `--features ecdh-es-research` never sets `LabConfig::ecdh_es_route`, so it
   does not serve the route; such a build is never a release artifact anyway.

## Consequences

- **Research only, not a fallback.** No HPKE-0 response is ever retried as ECDH-ES or the other
  way round; tests pin both directions (`ecdh_es_and_hpke_routes_never_accept_each_others_jwes`).
- **No `session_info` binding.** By design: that missing binding is what the route exists to
  show. A response's ciphertext opens for every session on the route; `state`, which the
  sender chooses and which every Request Object reveals, is the only selector. Holder binding
  (KB-JWT `aud` / `nonce`) and the Verifier-wide replay guard are what refuse misdirected or
  replayed presentations; the tests show each case.
- **API.** `RouteKind`, `Rejection`, `ValidationError` and `WalletError` gain feature-gated
  variants and are `#[non_exhaustive]`, so enabling the feature never breaks a downstream
  match.
- **Containment checks.** `verifier_without_sealing` replaces PR #15's pin with real checks:
  the default lab-server build has no `jose-ecdh-es` at all and no test-only or research
  feature; the `ecdh-es-research` build reaches `jose-ecdh-es` (so the check is never vacuous)
  without `test-support`, without `wallet-sim` / `lab-instrumentation`, and without the
  SpruceID / reqwest tree. `default_members_are_verifier_builds` also fails if a default
  workspace member enables `ecdh-es-research`. `lab_server_wallet_sim_check` and
  `lab_server_ecdh_es_research_check` lint each optional feature alone (library and binary).
- **Cost.** One unauthenticated POST to the route costs, per live session (at most 256), one
  P-256 ECDH, one Concat KDF and one AES-GCM decryption of the whole ciphertext, which may be
  close to the 1 MiB body limit (a payload padded with ignored members): up to 256
  full-ciphertext decryptions per POST, the same order as bounded trial. The plaintext is
  parsed once per POST, and holder binding runs only for the session(s) its `state` names.
  Trials run behind `max_concurrent_decryptions`. Research mode, opt-in, loopback only.
- **Timing.** Response timing reveals whether a known `state` is still live (holder binding
  runs only then). `state` is public to anyone holding the `request_uri`; accepted for the lab.
- **What it does NOT enable.** It is not an OIDF conformance mode. That mode (TLS loopback
  front, x509 client id with a synthetic CA, ECDH-ES as a separate mode, kill switch) remains a
  separate, undecided C2 decision in `docs/interop/oidf-conformance-plan.md`; this route has no
  TLS, no x509 client id and no `dc_api.jwt`, and it is not reachable from the binary. It does
  not make ECDH-ES a supported production algorithm of the lab Verifier.
