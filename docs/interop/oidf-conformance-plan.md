# OIDF conformance suite: plan for the lab Verifier

Status: G7 groundwork. Sections 1-2 and 5-7 are desk research. All sources were retrieved on
**2026-11-25**. Anything not confirmed in a source is marked **UNKNOWN**. Nothing was posted.

*Update 2026-11-25:* the suite now runs self-hosted (`tools/oidf-suite/`, release-v5.3.5 = commit
`246b2c1`, images pinned by digest, OrbStack, loopback only). It was run against a throwaway
local stand-in (`tools/oidf-suite/standin/`, which observes the suite and verifies nothing),
not against the lab and not against any external system, to resolve the UNKNOWNs in §3-§4.
`tools/oidf-suite/README.md` holds the runbook, the exact plan configuration and the source
citations. Below, **[run]** marks what was observed running and **[read]** what was read from
source only.

External contacts for that work were:
- image pulls from `registry.gitlab.com` (suite and nginx) and Docker Hub (mongo);
- public source reads (the suite repository clone, MongoDB advisory pages for CVE-2025-14847);
- one DNS lookup of `localhost.emobix.co.uk`;
- PyPI, for the stand-in's `cryptography` package.

The suite container's own egress is not restricted (README "Egress" and §2).

## 1. Sources

| Source | What was read |
| --- | --- |
| Suite source: <https://gitlab.com/openid/conformance-suite> | A read-only shallow clone of `master` at commit `246b2c14b8562012b02d0ac462d667fe49e1a937` (committed 2026-11-24). No code from it was executed. Paths below are relative to that repository. |
| `LICENSE.txt` | "This software is licensed under the MIT License" (OpenID Foundation) |
| <https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/> | VP testing instructions |
| <https://openid.net/certification/> | Hosted suite at <https://www.certification.openid.net/> |
| <https://openid.net/openid-for-verifiable-credential-self-certification-to-launch-feb-2026/> (18 Dec 2025) | Self-certification announced for "February 26th 2026" |
| <https://openid.net/?p=71965> (7 Aug 2026) | "OpenID4VP and OpenID4VCI conformance tests are complete and open for self-certification" (HAIP 1.0, wallet and verifier roles) |
| OpenID4VP 1.1 Editor's draft, 11 November 2026, §14.10 | Points to the OIDF page above as "tools that can be used to confirm that an implementation is correct and conformant" |

## 2. What the suite tests for the Verifier role

The suite acts as a **mock wallet**. The Verifier under test sends its Authorization Request to
an authorization endpoint URL that the suite provides. `AbstractVP1FinalVerifierTest.java`
(~L316) prompts:

> "Paste the openid4vp:// authorization request produced by the verifier under test; its query
> string will be delivered to this test's authorization endpoint."

The test summaries say:

> "You must configure your verifier to use the authorization endpoint url below instead of
> 'openid4vp://' and then start the flow in your verifier as normal."

The suite then fetches the Verifier's `request_uri` itself and POSTs the response to the
Verifier's `response_uri`: `AbstractVP1FinalVerifierTest.java` calls
`FetchRequestUriAndExtractRequestObject` (L488, `"JAR-5.2.3"`) and `CallDirectPostEndpoint`
(imported at L79, called at L872).

### 2.1 Test plans (verifier role)

| Plan (`testPlanName`) | Spec | Certifiable |
| --- | --- | --- |
| `oid4vp-1final-verifier-haip-test-plan` (`VP1FinalVerifierTestPlanHaip.java`; `shortName` "1.0 Final + HAIP") | OpenID4VP 1.0 Final + HAIP 1.0 | Yes. The certification profile string is `"OID4VP-1.0-FINAL+HAIP-1.0-FINAL"` (L43). |
| `oid4vp-1final-verifier-test-plan` (`VP1FinalVerifierTestPlan.java`) | 1.0 Final, plain | No. It is declared `alpha = true`, and its display name says "(alpha version - not part of certification program - use the HAIP verifier plan to certify)". |
| `oid4vp-id3-verifier-test-plan`, `oid4vp-id2-verifier-test-plan` | ID3, ID2 | No |

`plan/TestPlan.java` defines the OpenID4VP spec versions `"1.0 Final"`, `"ID2"` and `"ID3"`
(L53-55). **There is no OpenID4VP 1.1 plan.** The OIDF page says:

> "Certifications are only accepted for OpenID4VP 1.0 Final and support for HAIP 1.0 Final is
> mandatory for certification."

It also says:

> "It is recommended to run VC tests on the 'demo' server (rather than the production one) as
> this contains the latest changes."

### 2.2 Variants of the 1.0 Final verifier plans

| Variant | Values (source) | Lab |
| --- | --- | --- |
| `response_mode` | `direct_post`, `direct_post.jwt` (`VP1FinalVerifierResponseMode.java` L12-13). There is no `dc_api*` for verifiers. HAIP excludes `direct_post` ("unencrypted mode not applicable for HAIP"). | `direct_post.jwt` only ✔ |
| `client_id_prefix` | `REDIRECT_URI`, `X509_SAN_DNS`, `X509_HASH` (`VP1FinalVerifierClientIdPrefix.java` L12-14). The HAIP plan pins `x509_hash` (L31). | `decentralized_identifier:did:key:` or pre-registered. x509 is refused at start (`StartError::UnsupportedClientIdPrefix`) ✘ |
| `request_method` | `url_query`, `request_uri_signed`. `REQUEST_URI_UNSIGNED` is commented out (`VP1FinalVerifierRequestMethod.java` L12-14). The HAIP plan pins `request_uri_signed` (L32). | `request_uri` (GET), signed ✔ |
| Request Object signature | `ValidateRequestObjectSignatureAgainstX5cHeader` (L29: "Request object JWT does not contain an x5c header"), called as a FAILURE condition (`AbstractVP1FinalVerifierTest.java` L666, `"OID4VP-1FINAL-5.9.3"`) | did:key `kid`, no `x5c` ✘ |
| `credential_format` | `sd_jwt_vc`, `iso_mdl`. The happy-flow summary uses an SD-JWT VC "with a vct of urn:eudi:pid:1". The issuer key is supplied as config field `credential.signing_jwk`. | `dc+sd-jwt` ✔. The lab asks for vct `https://credentials.lab.invalid/synthetic-identity/v1` and claims `given_name`, `family_name`, `age_over_18` ✘ (needs a configurable query) |
| Query language | DCQL ("The DCQL query must request only a single credential") | DCQL, one credential ✔ |
| Response encryption | JOSE only. `JWEUtil.createEncrypter` (L250-275) builds AES, direct, RSA, ECDH (`ECDHEncrypter`) or X25519 encrypters. Under HAIP, `ValidateVpClientMetadataEncryptionForHaip.java` requires "a JWKS key with alg=ECDH-ES and P-256 curve" (L83) and `encrypted_response_enc_values_supported` "to contain both A128GCM and A256GCM" (L51). | HPKE-0 only ✘ |
| Transport | `EnsureRequestUriIsHttps` ("The scheme used in the request_uri value MUST be https", L18) and `EnsureValidResponseUriForAuthorizationEndpointRequest` ("response_uri scheme is not https.", L41). The suite's outbound HTTP client trusts all certificates (`AbstractCondition.java`: trust-all `X509TrustManager` ~L677-694, `NoopHostnameVerifier` L702). | `http://127.0.0.1` only ✘ |

**HPKE / `session_info` / 1.1.** No occurrence of `session_info` exists in `src/`. A case-sensitive search for "HPKE" has 0 hits in `src/`. A case-insensitive search has 1 hit,
only in a unit test (`src/test/java/net/openid/conformance/condition/client/ValidateIdTokenSignature_UnitTest.java`),
not in any VP code. The OpenID4VP 1.1 and HAIP 1.1 drafts are stored in the repository only
as reference text (`library/specs/…`); no test cites them.

> **Conclusion.** As of commit `246b2c1`, the suite cannot test the lab's HPKE-0 path or the
> #792 scenarios at all.

### 2.3 Verifier test modules, mapped to lab tests

| Suite module (`vp1finalverifier/`) | Lab counterpart | Notes |
| --- | --- | --- |
| `…HappyFlow` | `honest_sd_jwt_kb_presentation_commits_only_the_requested_claims` | Different vct and claims |
| `…InvalidCredentialSignature` (corrupted issuer signature) | `credential_signed_by_an_untrusted_issuer_is_rejected`; unit `sd_jwt::tests::issuer_jwt_policy_and_validity_are_enforced` | Close, not identical |
| `…InvalidKbJwtAud` / `…InvalidKbJwtNonce` | `kb_jwt_with_wrong_aud_is_rejected` / `kb_jwt_with_wrong_nonce_is_rejected` | |
| `…InvalidKbJwtSignature` | `kb_jwt_signed_by_a_non_cnf_key_is_rejected` | Wrong key, not a corrupted signature |
| `…InvalidSdHash` | `kb_jwt_with_wrong_sd_hash_is_rejected` | |
| `…KbJwtIatInFuture` / `…KbJwtIatInPast` | `kb_jwt_with_future_iat_is_rejected` / `kb_jwt_with_stale_iat_is_rejected` | The suite sets the KB-JWT `iat` 365 days in the future / past [read]; the lab allows 300 s age and 60 s future skew |
| `…MinimalCnfJwk` | none | Gap: the lab has no test for a `cnf.jwk` with only `kty`/`crv`/`x`/`y` |
| `…WrongVct` | `sd_jwt::tests::sd_jwt_vc_profile_enforces_vct_and_exactly_the_requested_claims` | Unit level only |
| `…RequestUriFetchedTwice` | `served_request_object_is_signed_once_and_never_changes` | |
| `…RequestUriMethodPost` | none | The lab serves GET only (no `request_uri_method`) |
| `…PresentRevokedCredential`, `…PresentCredentialWithoutStatus`, `…PresentCredentialOnIdentifierList` | none | Status and revocation are out of lab scope |
| `…InvalidSessionTranscript` | none | mdoc only, out of scope |

The suite has no multi-session or response-correlation tests (nothing like #792 shared-route
routing or cross-session replay). Its positive tests end in REVIEW with an uploaded screenshot
(`VP1FinalVerifierHappyFlow.java` L27; `AbstractVP1FinalVerifierTest.java` L767-773).
Its negative tests accept two outcomes (`AbstractVP1FinalVerifierNegativeTest.java` L6-12,
L17-30):

- an HTTP 4xx from `response_uri` (immediate rejection): the test finishes as PASSED
  (`EnsureHttpStatusCodeIs4xx`);
- a 2xx (verification deferred until after the redirect, which the class comment says 1.0
  Final permits, citing suite issue #1828): the 2xx must still be a well-formed §8.2 response,
  the tester uploads a screenshot showing the Verifier reporting the failure, and the test ends
  as REVIEW.

Anything else (3xx, 5xx, no status) fails.

## 3. Running the suite locally

Runbook, pins and findings: `tools/oidf-suite/README.md`. In short:

- **Prebuilt images**: `tools/oidf-suite/docker-compose.yml`, derived from upstream
  `docker-compose-prebuilt.yml` at tag `release-v5.3.5` (= `246b2c1`). The server, nginx and
  `mongo:6.0.13` images are pinned by multi-arch index digest. On 2026-11-25 `:latest` resolved
  to the same suite digests. [run]
- **No login**: the `dev` profile sets `fintechlabs.devmode=true`, which authenticates every
  request as a dummy admin, so the REST API needs no token. [run] With CSRF off and no
  authentication, any web page in a browser that has accepted the suite's certificate can
  make the suite fetch an arbitrary `request_uri` with its trust-all client. That is SSRF into
  host loopback, the LAN or the internet [read]. So runs are driven by curl or the driver
  only, with a random alias per run, and the stack is up only during a run (README §2).
- **No hosts-file edit**: `BASE_URL=https://localhost:8443`, and nginx publishes
  `127.0.0.1:8443` only. Mongo is on tmpfs, so `docker compose down` leaves nothing behind
  (export the results first). [run]
- The image runs Java 21 (Temurin 21.0.13) [run]. The Maven/Java question only matters for
  source builds, which are not used.
- **Scripted runs**: `scripts/run-test-plan.py` cannot drive a verifier plan here, because it
  cannot make the lab start a session. The REST API can, end to end, including the screenshot
  upload that REVIEW needs. README §5e lists the calls and a driver design. [run]
- **Reachability**: from inside the suite container, `host.docker.internal` and
  `host.orb.internal` both reach an HTTPS server bound to host **127.0.0.1 only**
  (`scripts/oidf_suite_probe.sh`). The suite's client accepts self-signed certificates. [run]

## 4. Lab-server changes the suite would need

None of these is in scope for G7. Each needs its own decision record.

*Status 2026-11-25:* items 1-6 are implemented by conformance mode
(`docs/adr/0002-conformance-mode.md`, feature `conformance`, `--mode conformance`): option B
with OrbStack (`host.docker.internal` reaches host loopback; established by the suite set-up,
PR #17), the lab serving HTTPS itself on its loopback bind; `x509_san_dns` / `x509_hash` with a
synthetic CA and an `x5c` header; ECDH-ES on the unique route with a key per session; a
configurable DCQL query and issuer key (`--vct`, `--claims`, `--issuer-key`); the
`authorization_request` URL in the session creation response (`--authorization-endpoint`); and
a configurable response `redirect_uri` (`--response-redirect-uri`, needed for HAIP). Item 7
stays unsupported.

1. **Network exposure (ADR required).** Lab policy is loopback only in every mode (ADR-005,
   `README.md` "Policy"). The suite needs HTTPS `request_uri` / `response_uri` endpoints that
   the suite's JVM can reach.
   - *Option A*: suite JVM on the same host (nodocker variant), with a TLS-terminating loopback
     front for the lab. The lab still binds `127.0.0.1`, but third-party code becomes a client
     and TLS is added.
   - *Option B*: suite in Docker. On OrbStack the container reaches a service bound to host
     `127.0.0.1` through `host.docker.internal` (or `host.orb.internal`), so neither a wider
     bind nor host networking is needed [run, `scripts/oidf_suite_probe.sh`]. Docker Desktop
     is still **UNKNOWN**. The same mechanism means that on OrbStack host 127.0.0.1 is
     reachable from *every* local container: a loopback bind isolates the lab from the LAN,
     not from other containers on this machine. The conformance-mode ADR therefore treats the
     mode as time-boxed and off by default.
   - *Option C*: hosted demo/production server. This needs a public endpoint and is **not**
     compatible with the lab policy.

   Recommendation (updated): Option B on OrbStack, which keeps the lab on 127.0.0.1. It still
   needs an ADR amending ADR-005 for a TLS loopback front, synthetic data only, and a
   time-boxed conformance mode. Option A remains the fallback where the Docker host alias is
   not available.
2. **Client identifier.** Add `x509_san_dns:` / `x509_hash:` with a synthetic CA, a leaf
   certificate and an `x5c` JWS header. Today they are refused by design
   (`start_refuses_client_id_prefixes_the_lab_cannot_sign_for`). HAIP also needs
   `client.request_object_trust_anchor_pem`.

   Resolved [read, run]:
   - `x5c` = `[leaf]`. The CA goes only in the trust-anchor PEM, never in `x5c`, and the leaf
     must not be self-signed.
   - The header `typ` is `oauth-authz-req+jwt`.
   - The `x509_hash:` value is the base64url SHA-256 of the DER leaf.
   - For `x509_san_dns` the suite checks only that `client_id` = `x509_san_dns:` + the config
     field `client.client_id` (which is required). It does not check the certificate SAN or the
     `response_uri` host.

   Details: README §5b.
3. **Response encryption.** Add an ECDH-ES P-256 path (`A128GCM` and `A256GCM` advertised) for
   a conformance mode. The HPKE-only Verifier build was a deliberate choice: josekit/SpruceID
   are kept out of the shipped binary, and `core_containment` / `verifier_without_sealing` hold
   that line. An ECDH-ES implementation would need RustCrypto code (no advisory tree) and an
   ADR. It must be a separate mode, never a fallback on the HPKE route, because a fallback
   would be the downgrade that #792 C9 describes.

   *Update 2026-11-25:* the RustCrypto codec exists (`crates/jose-ecdh-es`), and a research
   route uses it: `POST /lab/v1/response/ecdh-es`, one ECDH-ES P-256 key advertised with
   `alg` `ECDH-ES` and `encrypted_response_enc_values_supported` `["A128GCM","A256GCM"]`
   (`docs/adr/0001-ecdh-es-research-route.md`). It is research mode only, opt-in per server, behind the
   non-default lab-server feature `ecdh-es-research`, absent from the binary, and refuses
   HPKE-0 JWEs as the HPKE routes refuse ECDH-ES ones (`verifier_without_sealing` now checks
   the feature's build instead of pinning jose-ecdh-es out). It exists to observe #792 C3/C9;
   it is **not** the conformance mode. Whether and how a conformance mode serves ECDH-ES
   (TLS front, x509 client id, kill switch) remains the undecided C2 ADR below.

   Resolved for the conformance mode [read, run]:
   - The suite encrypts with the **first** entry of `encrypted_response_enc_values_supported`.
   - Its JWE header carries `alg`, `enc`, `epk` (`kty`/`crv`/`x`/`y`), `kid`, `cty` `json`, and
     distinct random `apu`/`apv`. The `jose-ecdh-es` header policy accepts all of these.
   - Every JWK needs a unique `kid` and an `alg`.
   - Under HAIP, a key already seen in an earlier request (within a 3 h window) is a FAILURE.
     The research route's one shared key therefore cannot be used for C4: the conformance mode
     needs a **fresh key per session**.
4. **Configurable DCQL query.** Allow vct `urn:eudi:pid:1` and the claim paths the suite's
   credential carries. Also allow a configurable trusted issuer key, set from the synthetic
   `credential.signing_jwk` given to the suite.

   Resolved [read, run]:
   - The suite discloses exactly the requested claim names, out of `given_name`,
     `family_name`, `birthdate`, `nationalities`, `place_of_birth` (`country`),
     `issuing_authority`, `issuing_country` and `picture`.
   - The issuer JWT has no `kid`. It carries `x5c` only if the JWK has one, which the code
     treats as optional.
   - There is no `_sd_alg` (so the default `sha-256` applies), and the payload has a `status`
     claim.
   - The KB-JWT `aud` is the full client id, prefix included.

   Details: README §5a.
5. **Authorization Request URL.** The lab returns `client_id` and `request_uri` as JSON
   (`POST /lab/v1/sessions`). A small driver must turn these into
   `<suite authorization endpoint>?client_id=…&request_uri=…`.
6. **Response URI answer.** The lab answers `200 {}`. The lab rejects at the `response_uri`
   with the generic 400, which takes the negative tests' 4xx path (PASSED) [run]. The lab never
   uses the deferred 2xx path, which ends in REVIEW with a screenshot (§2.3).

   Resolved [read, run]:
   - The plain plan accepts `{}` or `{"redirect_uri":"…"}`.
   - **HAIP requires `redirect_uri`**; a response without it is a FAILURE.
   - Any other member in the body is a WARNING.
   - The status must be exactly 200, with `Content-Type: application/json`.
   - Positive modules always end in REVIEW, which is completed through the image API.
   - `…PresentRevokedCredential` FAILS for any verifier that does not fetch the status list.
     The lab has no status support, so this module stays FAILED for the lab [run].
7. `request_uri_method=post` (§5.10) is not supported. That module would be skipped: it calls
   `fireTestSkipped` when the request has no `request_uri_method=post`
   (`VP1FinalVerifierRequestUriMethodPost.java` L37).

## 5. Staged plan

| Stage | Content | Network | Gate |
| --- | --- | --- | --- |
| C0 (this document) | Desk research, mapping of suite modules to lab tests | Read public pages only | none |
| C1 | Offline gap tests inside the lab: `MinimalCnfJwk`-style `cnf`, a corrupted (not foreign) issuer signature, a corrupted KB-JWT signature. Configurable DCQL query and issuer key. **Done:** `credential_with_minimal_cnf_jwk_is_accepted`, `issuer_jwt_with_corrupted_signature_is_rejected`, `kb_jwt_with_corrupted_signature_is_rejected`, `configured_credential_query_is_requested_and_enforced`. | Loopback | Default gate stages |
| C2 | ADR: conformance mode (TLS loopback front, x509 client id with a synthetic CA, ECDH-ES as a separate mode, kill switch). **Done:** ADR 0002 (accepted 2026-11-25), implemented and tested over HTTPS on loopback (`tests/conformance_mode_e2e.rs`). | none | ADR approved before any code |
| C3 | Self-hosted suite (`tools/oidf-suite/`, Option B on OrbStack), plain `oid4vp-1final-verifier-test-plan`, `sd_jwt_vc` + `direct_post.jwt` + `x509_san_dns` + `request_uri_signed`, against the ECDH-ES conformance mode. Synthetic credentials only. Results go into `evidence/` with commit SHAs. **Done (2026-11-25, lab `61dbb05`, run `evidence/oidf/20261125T044623Z-61dbb05/`):** all 14 modules as expected: 8 PASSED (negative), 4 REVIEW (positive), 1 SKIPPED (`request-uri-method-post`), 1 FAILED (`present-revoked-credential`, no status-list support); no lab bug found. | Loopback + TLS (per ADR) | Explicit approval (given 2026-11-25) |
| C4 | HAIP plan (`x509_hash`, A128GCM + A256GCM, trust anchor PEM). **Done (same run):** same 14 results as C3; the HAIP conditions (encryption metadata, no key reuse, `redirect_uri`, strict x5c chain to the trust anchor) all passed. | Same | Explicit approval (given 2026-11-25) |
| C5 | HPKE / OpenID4VP 1.1: wait for suite support. Track the suite repo for `HPKE` / `session_info` (read-only). Until then, HPKE-0 conformance rests on jose-hpke draft-22 vectors, the lab's own suite, and INTEROP-02. | none | — |

C3/C4 results in one place: `tools/oidf-suite/README.md` §7 and the run's `summary.md`. REVIEW
is not PASSED (a positive module's best result, after an uploaded image; here a rendering of the
lab's own result JSON). The suite encrypted with ECDH-ES + `A128GCM` only (the first value the
lab lists), so `A256GCM` rests on the lab test
`conformance_round_trip_with_x509_hash_a256gcm_and_redirect_uri`. This is not a certification,
nothing was submitted to the OpenID Foundation, and HPKE-0 / OpenID4VP 1.1 is not covered by the
suite (C5).

Never: run the suite against non-lab systems, use the hosted servers with lab endpoints
exposed publicly, or file issues or MRs without prior approval (`README.md` "Policy").

## 6. INTEROP-02: comparison with the Python baseline (outline; that code is not available here)

The goal is to show that, under identical spec conditions, the Rust lab Verifier and the
Python reproduction reach the same **authorization result** for the same inputs. No claim
about the Python code is made here; this is the harness shape only.

**Shared fixture format**: one JSON file per case, versioned, synthetic. A case has five parts:

1. **Provenance**: spec pins (OpenID4VP 1.1 draft date, HPKE draft-22, RFC 9901,
   sd-jwt-vc-27), generator name and version, and the RNG seed or the fixed values.
2. **Verifier state**: the list of sessions. Each session has `client_id`, `nonce`,
   `response_uri`, `kid` and the HPKE-0 private JWK (synthetic), its strategy (`unique_uri`,
   `unique_kid`, `bounded_trial` with budget), `state` (`pending` / `consumed` / `expired`),
   and the trusted issuer public JWK.
3. **Clock**: a fixed `now` (NumericDate), so `iat`, `exp` and the TTL are deterministic.
4. **Input**: the route the response is POSTed to (unique token or `shared`), the exact body
   bytes (`application/x-www-form-urlencoded`), and a step order for multi-POST cases (replay,
   cross-session).
5. **Expected result**, implementation-neutral:
   - `accepted` / `rejected`;
   - the session consumed (or none);
   - a rejection class from a shared vocabulary (`admission`, `no_candidate`, `decrypt`,
     `holder_binding:<check>`, `ambiguous`, `cross_session_replay`, `holder_proof_replay`,
     `replay`, `budget_exceeded`).

**Direction**: the fixtures are produced by each side's wallet simulator and replayed into
*both* Verifiers. Rust-sealed JWEs go into Python and Python-sealed JWEs go into Rust. The
`session_info` bytes are also compared directly (hex) against the §8.3.1 example.

**Compare**:
- the accept/reject decision and which session was consumed;
- the rejection class (mapped, because the internal error names differ);
- the decrypted plaintext bytes for accepted cases;
- the HPKE attempt count per POST for each strategy. This is a count, not a time, and it
  shows whether the #792 trial cost reproduces.

**Do not compare**: absolute or relative timings, throughput, error-message text, or any
implementation-specific evidence fields.

**Equivalence rule**: a case passes only if both Verifiers produce the same expected result.
A disagreement is triaged as one of three things:
- (a) a spec ambiguity, recorded with a quote;
- (b) a lab policy difference, for example the lab refusing a cleartext `state` beside
  `response` (lab policy, not a spec MUST);
- (c) a bug.

**Starting corpus**: the scenario table S1-S16 in `issue-792-reproduction.md` §7, plus the
holder-binding negative cases of §2.3 above.

## 7. Open questions

- Does the demo server run code newer than `246b2c1`, with any HPKE or 1.1 work? **UNKNOWN**;
  the demo host was not checked.
- Suite issue #1892 ("Clarification needed: OID4VP 1.0 spec mandates to support signed request
  for decentralized_identifier client id prefix…", open since 2026-07-15) was seen by title
  only. Whether it concerns verifier tests is **UNKNOWN**.
- Is an ECDH-ES conformance mode worth its supply-chain and downgrade cost, or should C3/C4
  wait for HPKE support in the suite?
