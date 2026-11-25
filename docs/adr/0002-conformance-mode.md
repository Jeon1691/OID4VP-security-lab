# ADR 0002: A time-boxed OIDF conformance mode

- **Status:** Accepted, 2026-11-25, by the project owner. The owner accepted this C2 decision
  in session together with the approval to run the suite (2026-11-25), before the code was
  written.
- **Scope:** `crates/lab-server` (feature `conformance`, `Mode::Conformance`, the binary's
  `--mode conformance`), `scripts/conformance_fixtures.py`, `scripts/ci_local.sh`.
- **Amends:** the loopback-only network policy (ADR-005 as referenced in the design docs;
  `README.md` "Policy"), for this mode only and only as stated below.
- **Related:** `docs/interop/oidf-conformance-plan.md` §4 items 1-6 and stages C2-C4,
  `docs/adr/0001-ecdh-es-research-route.md`, `crates/jose-ecdh-es`.

This ADR records a lab design decision. It is not a statement of the OpenID Foundation's
position, and passing the suite's tests in this mode is not an OpenID certification.

## Context

The project owner approved running the OIDF conformance suite (prebuilt Docker images, locally,
in OrbStack on the lab Mac) against the lab: first the plain
`oid4vp-1final-verifier-test-plan` (`sd_jwt_vc`, `direct_post.jwt`, `x509_san_dns`,
`request_uri_signed`), then the HAIP plan (`x509_hash`, ECDH-ES P-256, `A128GCM` + `A256GCM`,
trust anchor PEM). That approval covers stage C2 with the plan's recommendations.

The suite acts as the Wallet. It fetches the `request_uri` and POSTs to the `response_uri`
itself, over **HTTPS only**, from its container. It has **no OpenID4VP 1.1 or HPKE plan**
(conformance plan §2.2), so the lab's primary path (HPKE-0, `session_info`, 1.1) is not what is
tested. What the 1.0 Final plans need and the lab lacked (plan §4): HTTPS endpoints the
container can reach, x509 client identifiers with an `x5c` Request Object header, ECDH-ES
response encryption, a configurable DCQL query and issuer key, and the Authorization Request
as a URL.

Facts established by the parallel suite set-up (PR #17, `tools/oidf-suite/README.md` §5, suite
`release-v5.3.5` = commit `246b2c1`, run against a stand-in Verifier):

- On OrbStack the container reaches host `127.0.0.1` through `host.docker.internal`; the
  suite accepts self-signed TLS.
- The Request Object needs `typ` `oauth-authz-req+jwt` and `x5c` = `[leaf]` (leaf not
  self-signed; the CA only in the trust-anchor PEM, strict PKIX when a trust anchor is
  configured). `client_metadata` may hold only `jwks`, `vp_formats_supported` and
  `encrypted_response_enc_values_supported`; every JWK needs a unique `kid` and `alg`. Under
  HAIP an encryption key reused across requests is a FAILURE.
- The suite encrypts with the first listed `enc`, sends `{"state","vp_token"}`, and expects the
  `response_uri` to answer exactly 200 JSON, `{}` or `{"redirect_uri": ...}`; HAIP requires the
  `redirect_uri`. Negative modules pass on a 4xx.
- The credential is `urn:eudi:pid:1`, signed by the configured issuer JWK (no `kid`), with a
  permanent `status` claim and only the requested claims disclosed; the KB-JWT `aud` is the
  full prefixed client id.

## Decision

Add **conformance mode**, a separate mode that exists only for the duration of a conformance
run:

1. **Off by default, explicitly enabled.** It exists only in builds with the non-default
   lab-server feature `conformance`; the default build and the binary built by a plain
   `cargo build -p lab-server` contain no TLS, X.509 or ECDH-ES code (gate:
   `verifier_without_sealing`). The binary enters it only on the explicit CLI flag
   `--mode conformance`; `LAB_MODE=conformance` is refused, and a binary without the feature
   refuses the flag before reading any file (gate: `binary_refuses_conformance_without_feature`).
   It refuses to start without its complete configuration (TLS chain and key, trust anchor,
   public origin, an x509 client id), and Hardened / Research servers refuse that configuration.
2. **Time-boxed.** The time box is mandatory: the server stops accepting by itself after
   `--max-runtime-secs` (default two hours, `DEFAULT_CONFORMANCE_MAX_RUNTIME`; zero and anything
   above eight hours, `MAX_CONFORMANCE_MAX_RUNTIME`, are refused at start, and the deadline is
   computed without overflow). It counts awake time: it is measured with `Instant`, which on
   macOS does not advance while the machine sleeps, so a server on a sleeping Mac stays up
   longer in wall-clock time. It is started for one plan run and stopped afterwards. Session
   lifetimes are bounded too (`MAX_SESSION_TTL`, one hour; zero refused).
3. **Loopback bind, HTTPS by the lab itself.** The bind address stays loopback (non-loopback
   binds are refused exactly as in every other mode). The lab terminates TLS itself with
   rustls (ring provider only, TLS 1.3, HTTP/1.1 via ALPN); no separate TLS front or proxy. Every
   URL it hands out uses a configured public origin (`https://host.docker.internal:<port>`),
   which the suite container reaches through OrbStack's forwarding to host loopback.
4. **Synthetic material only.** The CA, the leaf (P-256, SAN `host.docker.internal` and
   `localhost`) and its key are committed fixtures produced by
   `scripts/conformance_fixtures.py`, reproducible byte for byte; both private scalars follow
   from public labels, so the material is worthless outside the lab by construction, and the
   CA key is never written. The CA certificate (`conformance_ca.pem`) is the trust anchor for
   the HAIP plan and for test clients. Committed fixtures rather than keys generated at start,
   so that the suite configuration (trust anchor, `x509_hash` value) is set once and is
   reviewable. The credential issuer key is a synthetic JWK given to the suite as
   `credential.signing_jwk`, and its public half to the lab (`--issuer-key`).
5. **x509 client identifiers** (OpenID4VP 1.0 §5.9.3), checked at start: the leaf chains to the
   trust anchor now (`serverAuth`), is not self-signed and is not the anchor (HAIP 1.0 §5), the
   Request Object key is the leaf's key, the leaf is valid for the public host, and
   `x509_san_dns:<dns>` names the public host (so the `response_uri` FQDN matches the client
   id) and equals a dNSName SAN entry of the leaf exactly (a wildcard entry that TLS would accept
   does not count), or `x509_hash:<hash>` is the base64url SHA-256 of the leaf DER. The Request Object header
   is `alg` ES256, `typ` `oauth-authz-req+jwt`, `x5c` = the chain without the anchor; no `kid`.
6. **ECDH-ES on the unique route, a key per session.** Conformance sessions are unique-uri
   sessions with a fresh ECDH-ES P-256 key and `kid` each (HAIP 1.0 §5 "ephemeral encryption
   public keys specific to each Authorization Request"), advertised with `alg` `ECDH-ES`, `use`
   `enc`, next to `encrypted_response_enc_values_supported` `["A128GCM","A256GCM"]` and
   `vp_formats_supported` for `dc+sd-jwt` (ES256). Correlation is by the unique
   `response_uri` and the JWE `kid`; `state`, holder binding and the Verifier-wide replay
   guard run as on every route. The route refuses every `alg` but `ECDH-ES` (`HPKE-0`
   included), and the HPKE-0 routes keep refusing `ECDH-ES`. Conformance mode serves no shared
   route, no ECDH-ES research route and no research session knobs.
7. **Never a fallback, and not the primary path.** No mode switches into conformance mode, and
   conformance mode never serves HPKE-0. HPKE-0 / OpenID4VP 1.1 remains the lab's primary path;
   its conformance rests on jose-hpke draft-22 vectors, the lab's own suite and INTEROP-02
   until the suite gains a 1.1 plan (plan §5 C5).
8. **The suite-facing details are configuration, not code:** the DCQL query (`--vct`,
   `--claims`, `--credential-query-id`; for the suite `urn:eudi:pid:1` and top-level PID
   claims), the issuer key, the public origin, the client id prefix, the response
   `redirect_uri` (`--response-redirect-uri`, needed for HAIP; default `200 {}`), the session TTL
   and the authorization endpoint the session creation response builds the Authorization
   Request URL for (`authorization_request`). Both URLs must be absolute `https://` URLs with a
   host (the endpoint may also be the default `openid4vp://`), with no user info and no fragment,
   or the server refuses to start.
9. **A fresh Response Code in every redirect.** With a response `redirect_uri` configured, each
   committed response gets its own 128-bit random `response_code`, appended as a query
   parameter (OpenID4VP 1.0 §8.2: the Verifier "MUST include a fresh, cryptographically random
   value in the URL"; §13.3 step 6). It is drawn before the claim and stored with the consumed
   session; the result endpoint shows it. The lab has no frontend, so nothing redeems it the way
   §13.3 step 8 / §14.2 describe; the result token remains the capability that reads a result.

## Consequences

- The default Verifier build and binary are unchanged in content: the gate checks that they
  contain no conformance feature, no rustls / webpki / ring and no jose-ecdh-es, and that the
  `conformance` build reaches its TLS stack with ring only (no aws-lc), without sealing, test
  features, the research route or the SpruceID tree. rustls, tokio-rustls, rustls-webpki and
  ring were already in `Cargo.lock` (reqwest's TLS stack under openid4vp / ssi), so no new crate
  and no new advisory ignore entered.
- The suite tests 1.0 Final ECDH-ES behaviour of the lab's unique route with its holder
  binding. A pass says nothing about HPKE-0, `session_info` or the #792 shared-route findings,
  which the suite cannot exercise.
- The lab data-minimisation policy stays on: a disclosure outside the requested claims is
  refused. The suite discloses exactly the requested top-level claims, so the policy does not
  get in the way; nested claim paths (e.g. `place_of_birth.country`) are not configurable yet.
- Status lists are not fetched (out of lab scope); a permanent `status` claim is accepted.

### Risks

- **Loopback binding does not isolate the lab from local containers.** On OrbStack, host
  `127.0.0.1` is reachable from *every* local container; that is exactly how the suite reaches
  the lab. While conformance mode runs, any container on the Mac can reach every lab endpoint,
  including the lab-driver endpoints (`POST /lab/v1/sessions`, results by result token). This
  ADR therefore does not claim that the loopback bind confines the lab to the host process
  tree; it only keeps the lab off every non-loopback interface.
- **The suite can be made to fetch arbitrary URLs.** The suite's `/test/**` endpoints have
  permissive CORS with CSRF protection off (PR #17 security review), so while the suite stack is
  up, a web page open in a local browser can drive the suite to fetch arbitrary URLs, the lab's
  included. The lab must then be assumed reachable by untrusted web content through the suite.
- **Mitigations, all mandatory:** conformance mode is off by default and explicitly enabled
  (feature + CLI flag); it is time-boxed (maximum runtime, then it stops accepting) and is
  started only while a conformance run is in progress and stopped right after it, together
  with the suite stack; it holds synthetic material only (no real keys, credentials or
  personal data, nothing whose disclosure matters); TLS, the unique route tokens, result tokens
  and holder binding are unchanged; everything it answers on failure is the generic 400.
- The synthetic CA could be mistaken for a trustworthy one. Its subject says "never trust", its
  key is derivable from public labels, and it must never be installed in any trust store.

## Alternatives considered

- **A TLS-terminating proxy in front of the HTTP lab (plan §4 option A).** More moving parts and
  a third-party component on the path; the lab serving TLS itself keeps the request handling
  identical to the other modes.
- **Suite JVM on the host (nodocker).** Avoids container reachability but needs a host Java
  toolchain; the prebuilt images were approved.
- **Hosted OIDF demo server (plan §4 option C).** Needs a public endpoint; incompatible with the
  lab policy.
- **One ECDH-ES key per server.** HAIP fails key reuse across requests; per-session keys are also
  the safer default.
- **Keys generated at start.** The trust anchor and `x509_hash` would change every run and
  need re-pasting into the suite configuration.
