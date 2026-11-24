# OIDF conformance suite: plan for the lab Verifier

Status: G7 groundwork. This is desk research only. The suite has **not** been run against
anything, no external service was contacted beyond reading public pages and repositories,
and nothing was posted. All sources were retrieved on **2026-11-25**. Anything not confirmed
in a source is marked **UNKNOWN**.

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
| `…KbJwtIatInFuture` / `…KbJwtIatInPast` | `kb_jwt_with_future_iat_is_rejected` / `kb_jwt_with_stale_iat_is_rejected` | The suite's thresholds are UNKNOWN; the lab allows 300 s age and 60 s future skew |
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

## 3. Running the suite locally (as documented, not executed)

- **Prebuilt images** (from the project's Build & Run wiki):
  - `docker compose -f docker-compose-prebuilt.yml up`, then open
    `https://localhost.emobix.co.uk:8443/`. The hostname must be mapped in the hosts file.
  - The images are `registry.gitlab.com/openid/conformance-suite:${IMAGE_TAG:-latest}`, its
    nginx image, and `${MONGODB_IMAGE:-mongo:6.0.13}` (an overridable default)
    (`docker-compose-prebuilt.yml` L3, L12, L30).
  - `BASE_URL` can be overridden.
- **From source**:
  - Maven and Java. `pom.xml` sets `java.version` 21. The wiki says "17 or later". **Which one
    is authoritative is UNKNOWN.**
  - `docker-compose-dev.yml` runs mongo, nginx (8443-8445) and the server with
    `--fintechlabs.devmode=true`.
  - `docker-compose-dev-mac-nodocker.yml` runs the Java server on the host, with nginx
    reaching it through `host-gateway`.
- **Scripted runs**: `scripts/run-test-plan.py` uses `CONFORMANCE_SERVER` and a bearer
  `CONFORMANCE_TOKEN`.
- **Reachability**: the suite server must reach the Verifier's `request_uri` and
  `response_uri` over **HTTPS**. Self-signed certificates are accepted.

## 4. Lab-server changes the suite would need

None of these is in scope for G7. Each needs its own decision record.

1. **Network exposure (ADR required).** Lab policy is loopback only in every mode (ADR-005,
   `README.md` "Policy"). The suite needs HTTPS `request_uri` / `response_uri` endpoints that
   the suite's JVM can reach.
   - *Option A*: suite JVM on the same host (nodocker variant), with a TLS-terminating loopback
     front for the lab. The lab still binds `127.0.0.1`, but third-party code becomes a client
     and TLS is added.
   - *Option B*: suite in Docker. The container must reach the host, which means either a
     non-loopback bind or host networking (Linux). Whether Docker Desktop's
     `host.docker.internal` reaches a service bound to host `127.0.0.1` is **UNKNOWN**; do not
     rely on it.
   - *Option C*: hosted demo/production server. This needs a public endpoint and is **not**
     compatible with the lab policy.

   Recommendation: Option A, with an ADR amending ADR-005 for a TLS loopback front, synthetic
   data only, and a time-boxed conformance mode.
2. **Client identifier.** Add `x509_san_dns:` / `x509_hash:` with a synthetic CA, a leaf
   certificate and an `x5c` JWS header. Today they are refused by design
   (`start_refuses_client_id_prefixes_the_lab_cannot_sign_for`). HAIP also needs
   `client.request_object_trust_anchor_pem`.
3. **Response encryption.** Add an ECDH-ES P-256 path (`A128GCM` and `A256GCM` advertised) for
   a conformance mode. The HPKE-only Verifier build was a deliberate choice: josekit/SpruceID
   are kept out of the shipped binary, and `core_containment` / `verifier_without_sealing` hold
   that line. An ECDH-ES implementation would need RustCrypto code (no advisory tree) and an
   ADR. It must be a separate mode, never a fallback on the HPKE route, because a fallback
   would be the downgrade that #792 C9 describes.
4. **Configurable DCQL query.** Allow vct `urn:eudi:pid:1` and the claim paths the suite's
   credential carries. Which PID claims the suite discloses is **UNKNOWN**. Also allow a
   configurable trusted issuer key, set from the synthetic `credential.signing_jwk` given to the
   suite. Whether that key needs an `x5c` is **UNKNOWN**.
5. **Authorization Request URL.** The lab returns `client_id` and `request_uri` as JSON
   (`POST /lab/v1/sessions`). A small driver must turn these into
   `<suite authorization endpoint>?client_id=…&request_uri=…`.
6. **Response URI answer.** The lab answers `200 {}`. Whether the suite expects or tolerates a
   `redirect_uri` in that JSON is **UNKNOWN**. The lab rejects at the `response_uri` with the
   generic 400, which takes the negative tests' 4xx path (PASSED). The lab never uses the
   deferred 2xx path, which ends in REVIEW with a screenshot (§2.3).
7. `request_uri_method=post` (§5.10) is not supported. That module would be skipped: it calls
   `fireTestSkipped` when the request has no `request_uri_method=post`
   (`VP1FinalVerifierRequestUriMethodPost.java` L37).

## 5. Staged plan

| Stage | Content | Network | Gate |
| --- | --- | --- | --- |
| C0 (this document) | Desk research, mapping of suite modules to lab tests | Read public pages only | none |
| C1 | Offline gap tests inside the lab: `MinimalCnfJwk`-style `cnf`, a corrupted (not foreign) issuer signature, a corrupted KB-JWT signature. Configurable DCQL query and issuer key. | Loopback | Default gate stages |
| C2 | ADR: conformance mode (TLS loopback front, x509 client id with a synthetic CA, ECDH-ES as a separate mode, kill switch) | none | ADR approved before any code |
| C3 | Self-hosted suite (Option A), plain `oid4vp-1final-verifier-test-plan`, `sd_jwt_vc` + `direct_post.jwt` + `x509_san_dns` + `request_uri_signed`, against the ECDH-ES conformance mode. Synthetic credentials only. Results go into `evidence/` with commit SHAs. | Loopback + TLS (per ADR) | Explicit approval |
| C4 | HAIP plan (`x509_hash`, A128GCM + A256GCM, trust anchor PEM) | Same | Explicit approval |
| C5 | HPKE / OpenID4VP 1.1: wait for suite support. Track the suite repo for `HPKE` / `session_info` (read-only). Until then, HPKE-0 conformance rests on jose-hpke draft-22 vectors, the lab's own suite, and INTEROP-02. | none | — |

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
