//! Lab Verifier HTTP server for OpenID4VP 1.1 HPKE-0 `direct_post.jwt` responses (IMP-008
//! orchestration, IMP-009 HTTP, IMP-010 wallet simulator). Synthetic data, loopback only in
//! every mode (ADR-005); serving a non-loopback address needs an explicit future ADR. The
//! time-boxed OIDF conformance mode (feature `conformance`, docs/adr/0002-conformance-mode.md)
//! still binds loopback only but serves HTTPS under a public origin that local containers reach
//! through the host's loopback forwarding.
//!
//! `tests/spruce_api_smoke.rs` (G0-C) and `tests/ecdh_es_direct_post_jwt_e2e.rs` (G0-D) cover
//! the pinned SpruceID `openid4vp`; the HPKE-0 path here does not use it.
//!
//! # Endpoints (lab infrastructure, not standard OpenID4VP endpoints)
//!
//! | Method and path | Purpose |
//! | --- | --- |
//! | `POST /lab/v1/sessions` | Create a synthetic session; optional JSON `{"route": "unique"\|"shared", "nonce": "...", "state": "..."}` (`shared`, `nonce` and `state` research mode only; caller-chosen values model a Verifier that reuses them, bounded by [`MAX_RESEARCH_NONCE_LEN`] / [`MAX_RESEARCH_STATE_LEN`]). Returns `client_id` (the Authorization Request parameter), `request_uri`, `response_uri`, `result_uri` and `authorization_request` (`<LabConfig::authorization_endpoint>?client_id=...&request_uri=...`, default endpoint `openid4vp://`); the result token in `result_uri` is returned only here |
//! | `GET /lab/v1/requests/{id}` | Signed Request Object (JAR), body = compact JWS, `Content-Type: application/oauth-authz-req+jwt`. Payload: exact `client_id`, `nonce`, `state` (fresh per session, 128 random bits as base64url in the §5.2 charset, unless a research session fixed it), `response_uri`, `response_mode=direct_post.jwt`, `aud`, `dcql_query` (one `dc+sd-jwt` query, [`LabConfig::credential_request`]; default [`SYNTHETIC_CREDENTIAL_VCT`] and [`REQUESTED_CLAIMS`]), `client_metadata.jwks` with the HPKE-0 key (`alg` `HPKE-0`, `kid`); in conformance mode the ECDH-ES key, both `enc` values and `vp_formats_supported` instead, and an `x5c` header |
//! | `POST /lab/v1/response/{token}` | Unique response_uri (unique-uri strategy); HPKE-0, or in conformance mode ECDH-ES with a key per session (module `conformance`) |
//! | `POST /lab/v1/response/shared` | Shared response_uri, research mode only (404 in hardened mode) |
//! | `POST /lab/v1/response/ecdh-es` | `ecdh-es-research` feature only: the OpenID4VP 1.0-style ECDH-ES route, served only in research mode with `LabConfig::ecdh_es_route` set (404 otherwise, and `{"route": "ecdh_es_shared"}` is refused). One ECDH-ES P-256 key and `kid` for every session on it; its Request Objects advertise that key (`alg` `ECDH-ES`, `use` `enc`, `kid`) and `encrypted_response_enc_values_supported` `["A128GCM","A256GCM"]` instead of the HPKE-0 key (docs/adr/0001-ecdh-es-research-route.md) |
//! | `GET /lab/v1/results/{result_token}` | `pending` / `consumed` (with the committed `credential`: requested claims, `vct`, holder key thumbprint, disclosed claim names) / `expired`. The request id does not unlock it |
//! | `GET /health` | Liveness; exempt from the in-flight limit and request timeout |
//!
//! # Signed Request Objects (JAR)
//!
//! Request objects are signed JWTs (RFC 9101) as OpenID4VP 1.1 profiles them:
//!
//! * `request_uri` is fetched with `GET` (no `request_uri_method`, §5.1), and the answer is the
//!   Request Object itself as `application/oauth-authz-req+jwt` (§5.10.1; RFC 9101 §5.2,
//!   §5.2.3).
//! * Header: `alg` `ES256` (RFC 7518 §3.4), `typ` `oauth-authz-req+jwt` (§5: Verifiers MUST
//!   send it; RFC 9101 §10.8), and for a `decentralized_identifier:did:key:` client id `kid` =
//!   its verification method `did:key:<id>#<id>` (§5.9.3: the key comes from the DID Document
//!   and is identified by `kid`).
//! * Payload: `client_id` identical to the Authorization Request's (§5.10.1; RFC 9101 §6.3),
//!   `aud` `https://self-issued.me/v2` (§5.8, Static Discovery: the lab has no Wallet
//!   metadata), `iat` and `exp` = the session's expiry rounded up to the second (RFC 7519
//!   §4.1.6, §4.1.4), no `iss` (§5: MAY, and Wallets MUST ignore it).
//!
//! Each object is signed once, when its session is issued, over the JSON built from the
//! session's `RequestBinding`, which is then moved into the registry; `GET` serves those stored
//! bytes. So the signed `client_id` / `nonce` / `response_uri` are byte-for-byte the values the
//! registry holds and `SessionInfo::from_binding` decrypts with, the signed `state` is the one
//! the decrypted response is checked against, and no code path can change them after signing
//! (`tests/signed_request_object_e2e.rs` checks this on every route).
//!
//! The key is [`LabConfig::request_signing_key`] ([`RequestSigningKey::from_jwk`]); the lab
//! ships none. For [`DEFAULT_CLIENT_ID`] it is the synthetic SpruceID fixture
//! `tests/fixtures/spruce_verifier.jwk`, which tests load and the binary takes only as an
//! explicit `--signing-key` path, so no default or release build contains a private key. At
//! start the server derives the key's did:key and refuses a `decentralized_identifier:did:key:`
//! client id that is not it ([`StartError::ClientIdKeyMismatch`]), and refuses Client
//! Identifier Prefixes it cannot sign for: `redirect_uri` (unsigned only), other DID methods,
//! x509, attestation, federation and `origin` ([`StartError::UnsupportedClientIdPrefix`]). A
//! client id without a prefix is a pre-registered client (§5.9.2): signed, no `kid`. ES256 is computed
//! with RustCrypto `p256` 0.14 rather than SpruceID's `P256Signer` (that would put `openid4vp`,
//! reqwest and the ssi advisory tree into the Verifier build); a test pins the signature
//! byte-identical to `P256Signer`'s.
//!
//! # Modes
//!
//! * [`Mode::Hardened`] (default): unique-uri only, `RoutePolicy::UniquePerSession`, a fresh
//!   key pair and `kid` per session. No shared route.
//! * [`Mode::Research`]: additionally serves the shared route with one strategy fixed at start
//!   ([`SharedRouteStrategy`]): `BoundedTrial(budget)` with one key and `kid` shared by every
//!   session on the route (the OIDF #792 shape), or `UniqueKid` with a key and `kid` per
//!   session. Shared-route sessions live in a separate `RoutePolicy::Shared` registry, so
//!   unique-uri sessions keep the hardened guarantees. With the `ecdh-es-research` feature and
//!   `LabConfig::ecdh_es_route` it also serves the ECDH-ES route, whose sessions live in a
//!   third registry with their own shared ECDH-ES key; it is a separate route, never a
//!   fallback for the HPKE-0 ones.
//!
//! * `Mode::Conformance` (`conformance` feature; docs/adr/0002-conformance-mode.md): HTTPS
//!   (rustls) on the loopback bind under `ConformanceConfig::public_origin`, an `x509_san_dns`
//!   / `x509_hash` client id checked against the synthetic leaf at start and signed with an
//!   `x5c` header, the OpenID4VP 1.0 Final Request Object, and ECDH-ES on the unique route with
//!   a fresh key and `kid` per session. No shared or research route, no HPKE-0, never a
//!   fallback; it needs its full configuration and stops after its maximum runtime.
//!
//! Every mode refuses a non-loopback bind before binding (`IpAddr::is_loopback`: `127.0.0.0/8`
//! and `::1`; `0.0.0.0`, `::` and IPv4-mapped `::ffff:127.0.0.1` are refused).
//!
//! The strategy belongs to the route; a request can never choose it.
//!
//! # Response pipeline (per POST, in this order)
//!
//! 0. Routing: a `{token}` that is not a well-formed route token is not a route (404).
//! 1. Body limit [`MAX_RESPONSE_BODY_BYTES`] (413).
//! 2. `Content-Type: application/x-www-form-urlencoded` (415).
//! 3. Exactly one non-empty `response` parameter and nothing else; a plaintext `vp_token`
//!    (the `direct_post` downgrade found in G0-D) is refused even next to `response` (400).
//! 4. `jose_hpke::CompactJwe::parse`: structure and header policy, no key.
//! 5. `kid` required on every route (every lab key is advertised with one; OpenID4VP 1.1 §8.3).
//! 6. Ingress hint: route token from the path, `kid` from the protected header.
//! 7. `resolve` with the route's strategy.
//! 8. For each candidate: HPKE open with its key and `SessionInfo::from_binding`; then the
//!    decrypted payload's `state` against that candidate's stored `state` (OpenID4VP 1.1
//!    §14.4.2; missing → `ValidationError::StateMissing`, not a string or another value →
//!    `ValidationError::StateMismatch`), before any holder-binding work; then holder-binding
//!    validation (SD-JWT VC + KB-JWT against that candidate's `client_id` and `nonce`, see
//!    below). On the blocking pool behind [`LabConfig::max_concurrent_decryptions`]. All
//!    candidates are tried, and each is checked against its own values, so a candidate whose
//!    `state` differs simply does not validate; with bounded trial, more than one that
//!    validates is an integrity failure (reject, claim nothing, record it). Only the first
//!    validated result is kept.
//!    Then the Token Status List check of that credential (module `status_list`,
//!    docs/adr/0003-status-list-checking.md): no `status` claim, nothing to do; a
//!    `status.status_list` reference is checked by the conformance server's status policy
//!    (fetch, token verification, `idx`; only `0x00` VALID passes), and refused
//!    (`StatusError::NoPolicy`) where there is none, which includes every build without
//!    `conformance`. A refusal is `Rejection::Status` with its own `StatusError`.
//! 9. Verifier-wide replay guard: a response whose `SHA-256(compact JWE)` already validated
//!    for a *different* session is refused (`Rejection::CrossSessionReplay`), and so is one
//!    whose verified holder proof (`SHA-256` of the KB-JWT signing input, signature excluded
//!    because ECDSA signatures are malleable) did, even inside a fresh JWE
//!    (`Rejection::HolderProofReplay`); see [`MAX_REMEMBERED_DIGESTS`].
//! 10. `claim` with that digest as the response digest.
//!
//! The ECDH-ES research route (`ecdh-es-research`) runs the OpenID4VP 1.0 correlation order
//! instead (module `ecdh_es`): steps 1-3 as above; `jose_ecdh_es::CompactJwe::parse` (every
//! `alg` but `ECDH-ES`, `HPKE-0` included, is `Rejection::EcdhEsJweParse`); `kid` required;
//! resolve every live session on the route (bounded trial, at most 256: they share route token,
//! `kid` and key, so this selects nothing); open with each one's key, i.e. the route's key
//! alone, which opens for all of them or none (recorded as `hpke_attempts` / `opened`); then
//! the plaintext (the same for every candidate that opened) is parsed once and its `state`
//! selects: a session it does not name is skipped, a `state` that names no live session is
//! `ValidationError::StateUnknown` (missing: `StateMissing`), and holder binding runs for the
//! named session(s) only, which also disambiguates a `state` the research knob reused; then
//! steps 9-10. The
//! HPKE-0 routes, conversely, refuse an `ECDH-ES` JWE at step 4 (`Rejection::JweParse`).
//!
//! Around every route except `/health`: [`LabConfig::max_in_flight_requests`] (503 above it,
//! no queue) and [`LabConfig::request_timeout`] (408). Below that, the listener accepts at
//! most [`LabConfig::max_connections`] connections at once (more wait in the kernel backlog),
//! which also bounds connections that stall before sending headers. The defaults are config
//! candidates, not normative values.
//!
//! **Header read timeout:** the server runs its own accept loop over `hyper-util` (not
//! `axum::serve`, which gives hyper no timer) with a `TokioTimer` and
//! [`LabConfig::header_read_timeout`] ([`DEFAULT_HEADER_READ_TIMEOUT`]). A connection that
//! sends nothing, or dribbles its headers, is closed after that time and frees its connection
//! slot. The timeout covers each request's headers, so it also closes idle keep-alive
//! connections. It does not bound a slow body; the request timeout does.
//!
//! # Shutdown
//!
//! [`LabServer::shutdown`] is graceful: it stops accepting, lets in-flight requests finish for
//! up to [`LabConfig::shutdown_drain`], then closes commits. After it returns no request can
//! commit; one still running is refused (`Rejection::ShuttingDown`).
//! `LabServer::pause_decryptions` and `LabServer::parked_trials` are research instrumentation
//! for placing a POST at a known point (races, shutdown) deterministically; they exist only
//! with the `lab-instrumentation` feature.
//!
//! Steps 1-3 answer with distinct admission errors (they reveal nothing about sessions). Every
//! failure from step 4 on answers with the single [`GENERIC_REJECTION_BODY`] (400); the real
//! reason goes only into the [`EvidenceLog`]. A failed decryption or validation never touches
//! the session, which stays pending.
//!
//! # Threat-model notes
//!
//! * Research mode only, accepted: the HPKE attempt count of a bounded-trial POST equals the
//!   live population of the shared route, and unique-kid answers whether a `kid` is pending.
//!   Neither shows in the HTTP answer, but both show in response timing. Hardened mode has no
//!   shared route.
//! * Cross-session replay: on the shared research route, sessions can share `session_info`
//!   (shared key and route, reused nonce via the research `nonce` knob), so a consumed
//!   session's response decrypts for a new one. It also validates there only if the `state`
//!   is reused too (research `state` knob); with a fresh `state` the `state` check refuses
//!   it (`StateMismatch`, scenario S21 in `docs/interop/issue-792-reproduction.md`). The
//!   per-session state machine (pending / consumed / expired) cannot see either, so the
//!   verifier-wide replay guard refuses any response already validated for another session,
//!   and records `CrossSessionReplay` as evidence of the #792 condition.
//!   With a reused nonce and the same `client_id` the holder proof itself is valid for both
//!   sessions, so re-sealing it into a fresh JWE gets past the JWE digest; the guard therefore
//!   also binds each verified KB-JWT to its first session (`HolderProofReplay`, PR #10).
//! * `state` (§14.4.2) is inside the JWE, so it is checked only after decryption, and the
//!   sender chooses the plaintext: anyone who can fetch a Request Object reads its `state` and
//!   can echo it. Against a deliberate sender it adds nothing to the `session_info` selection
//!   and holder binding; it catches inadvertent responses (a payload meant for another
//!   request, a verbatim replay to another session, a wallet that echoes no `state`). A
//!   cleartext `state` beside `response` is refused at admission (step 3).
//! * Under bounded trial with a reused nonce (research), several candidates open, and the
//!   sender-chosen `state` (readable in every Request Object) decides which session the
//!   response is credited to. That is the same power a sender already has with fresh nonces,
//!   where the `session_info` it seals with decides; not a regression. Holder binding and the
//!   replay guard still apply to the session it picked.
//! * ECDH-ES research route (`ecdh-es-research`): no `session_info` exists, so the shared key
//!   opens a response for every session on the route, and the sender-chosen `state` (readable
//!   in every Request Object) alone decides which session it is credited to. `state` is a
//!   correlator, not authentication: A's holder proof sent with B's `state` is refused by B's
//!   KB-JWT nonce binding, and a reused nonce and `state` (research knobs) is refused by the
//!   replay guard or as `Ambiguous`, as on the shared HPKE-0 route. Every POST costs one ECDH
//!   and one AES-GCM pass over the ciphertext per live session on the route. Accepted for the
//!   lab: response timing reveals whether a known `state` is still live (holder binding runs
//!   only when it names a live session), and `state` is public to anyone holding a
//!   `request_uri`. Research mode only, opt-in per server (`LabConfig::ecdh_es_route`); the
//!   default build has no such route.
//! * Results are readable only with the result token, so the request id (visible to the
//!   wallet and anyone who sees the `request_uri`) does not reveal the outcome.
//! * Consumed records retain only the bounded [`ValidatedResponse`], never decrypted input or
//!   the presentation.
//! * Holder binding: a response is accepted only if its KB-JWT is signed by the `cnf` key of
//!   an SD-JWT VC that the configured issuer signed, over this session's exact `aud`
//!   (`client_id`) and `nonce` and over exactly the presented SD-JWT (`sd_hash`). A
//!   presentation captured from one session therefore fails on another session (`nonce`) or
//!   another Verifier (`aud`), and a Disclosure added, removed or changed after signing fails
//!   the digest or `sd_hash` check. HPKE decryption authenticates nothing about the holder.
//! * Not covered (synthetic scope): issuer trust is one configured key (no x5c / Type
//!   Metadata / trust lists), status lists only in conformance mode with a configured policy
//!   (elsewhere a referenced status is refused, never ignored), no Wallet attestation, and the
//!   KB-JWT freshness window ([`KB_JWT_MAX_AGE_SECS`]) is judged on the Verifier's clock.
//!   Within that window, nonce uniqueness per session (and the replay guard) is what stops a
//!   replay to the *same* session; a reused research nonce shares the KB-JWT between sessions
//!   by design (the #792 condition, refused as `Ambiguous` / `CrossSessionReplay`).
//! * All parsing that precedes signature checks is bounded ([`MAX_PRESENTATION_LEN`],
//!   [`MAX_DISCLOSURES`], [`MAX_DISCLOSURE_LEN`], [`MAX_SD_DEPTH`]) and strict (canonical
//!   base64url, no duplicate JSON members at any depth, no `crit`, `alg` exactly ES256).
//!
//! # Validation level
//!
//! Evidence level 3: holder binding verified with synthetic credentials. The decrypted
//! `vp_token` must answer the DCQL query with one SD-JWT+KB (OpenID4VP 1.1 §8.1, B.3.6),
//! checked by [`verify_sd_jwt_vc`] (RFC 9901 §7.1 / §7.3, draft-ietf-oauth-sd-jwt-vc-27;
//! the check-by-check table with its sources heads `src/sd_jwt.rs`) against
//! [`LabConfig::trusted_issuer`]. The failing check is recorded as a [`ValidationError`];
//! every failure answers the same generic error. Successful HPKE decryption alone is never
//! treated as holder authentication.
//!
//! Specifications pinned for this level: OpenID4VP 1.1 Editor's draft of 11 November 2026
//! (<https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-1_1-wg-draft.html>),
//! RFC 9901 (SD-JWT, November 2025), draft-ietf-oauth-sd-jwt-vc-27 (16 November 2026).
//! `tests/sd_jwt_rfc9901_vectors.rs` verifies the RFC 9901 §5.2 and Appendix A.3 examples;
//! `tests/holder_binding_e2e.rs` cross-checks against SpruceID ssi 0.16's SD-JWT code in both
//! directions.
//!
//! # Background sweep
//!
//! A task calls `expire_due` and `purge` on every registry each
//! [`LabConfig::sweep_interval`] (default [`DEFAULT_SWEEP_INTERVAL`]) and drops the request
//! objects and result tokens of purged sessions. If the sweep task panics, that surfaces only
//! in [`LabServer::shutdown`]; until then expired sessions merely linger (session-core still
//! checks TTLs lazily, so they are never accepted).
//!
//! # Features
//!
//! `wallet-sim` enables `wallet_sim` and with it `jose-hpke/test-support` (sealing), `ssi`
//! (did:key resolution and ES256 verification of Request Objects), the synthetic SD-JWT VC
//! issuer and the holder-side KB-JWT signing; `lab-instrumentation`
//! enables the decryption pause lever and `LabServer::stored_binding`; `ecdh-es-research`
//! enables the ECDH-ES research route and with it `jose-ecdh-es` (opening only; with
//! `wallet-sim` also its sealing `test-support`). The default build, including the
//! `lab-server` binary, has none of them and does not depend on `jose-ecdh-es`; the gate step
//! `verifier_without_sealing` checks it, and that the `ecdh-es-research` build reaches
//! `jose-ecdh-es` without `test-support`. `conformance` enables `Mode::Conformance` and with it
//! `jose-ecdh-es` (opening only), rustls / tokio-rustls / rustls-webpki with the ring provider,
//! Token Status List checking (hyper's HTTP/1.1 client, `miniz_oxide`), and with `wallet-sim`
//! the simulator's HTTPS client, x509 Request Object checks and `status_sim` (a synthetic
//! Status Issuer and HTTPS Status Provider for tests); the gate
//! step `conformance_without_sealing` checks that build, and `verifier_without_sealing` that the
//! default build has none of it. The binary has no flag for the ECDH-ES route; it is
//! exercised by tests (`tests/ecdh_es_research_route.rs`). Release artifacts must come from a plain
//! `cargo build -p lab-server` (`--release`): a build that also compiles test targets (e.g.
//! `cargo build --workspace --all-targets`) unifies the self dev-dependency's `wallet-sim`
//! feature into the library the binary links.

mod config;
#[cfg(feature = "conformance")]
mod conformance;
#[cfg(feature = "ecdh-es-research")]
mod ecdh_es;
mod evidence;
mod jar;
mod jose;
mod sd_jwt;
mod server;
mod status_list;
#[cfg(all(feature = "wallet-sim", feature = "conformance"))]
pub mod status_sim;
mod validate;
#[cfg(feature = "wallet-sim")]
pub mod wallet_sim;

pub use config::{
    DEFAULT_AUTHORIZATION_ENDPOINT, DEFAULT_CLIENT_ID, DEFAULT_HEADER_READ_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_DECRYPTIONS, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_IN_FLIGHT_REQUESTS,
    DEFAULT_REQUEST_TIMEOUT, DEFAULT_SESSION_TTL, DEFAULT_SHUTDOWN_DRAIN, DEFAULT_SWEEP_INTERVAL,
    LabConfig, MAX_RESPONSE_BODY_BYTES, MAX_SESSION_TTL, Mode, RouteKind, SharedRouteStrategy,
    StartError,
};
#[cfg(feature = "conformance")]
pub use conformance::{
    ConformanceConfig, DEFAULT_CONFORMANCE_MAX_RUNTIME, MAX_CHAIN_CERTIFICATES,
    MAX_CONFORMANCE_MAX_RUNTIME, PublicOrigin, X509_HASH_PREFIX, X509_SAN_DNS_PREFIX,
    X509Credentials, X509Error,
};
pub use evidence::{
    AdmissionError, CommitResult, CryptoResult, EvidenceLog, EvidenceRecord, MAX_EVIDENCE_RECORDS,
    Rejection, ValidationResult,
};
pub use jar::{
    REQUEST_OBJECT_ALG, REQUEST_OBJECT_AUD, REQUEST_OBJECT_MEDIA_TYPE, REQUEST_OBJECT_TYP,
    RequestSigningKey, SigningKeyError,
};
pub use sd_jwt::{
    CredentialQuery, IssuerKeyError, KB_JWT_MAX_AGE_SECS, KB_JWT_MAX_FUTURE_SKEW_SECS, KB_JWT_TYP,
    KeyBindingContext, MAX_COMMITTED_CLAIM_BYTES, MAX_DISCLOSURE_LEN, MAX_DISCLOSURES,
    MAX_ISSUER_JWT_LEN, MAX_KB_JWT_LEN, MAX_PRESENTATION_LEN, MAX_SD_DEPTH, ProcessedSdJwt,
    SD_JWT_VC_TYP, TrustedIssuerKey, disclosure_digest, verify_sd_jwt_kb, verify_sd_jwt_vc,
};
#[cfg(feature = "lab-instrumentation")]
pub use server::DecryptionPause;
pub use server::{GENERIC_REJECTION_BODY, LabServer, MAX_REMEMBERED_DIGESTS, RESPONSE_CODE_BYTES};
pub use status_list::{FetchFailure, MAX_STATUS_URI_LEN, StatusError, StatusResult};
#[cfg(feature = "conformance")]
pub use status_list::{
    MAX_STATUS_LIST_BYTES, MAX_STATUS_LIST_TOKEN_BYTES, STATUS_CHECK_TIMEOUT_MARGIN,
    STATUS_LIST_FETCH_TIMEOUT, STATUS_LIST_JWT_MEDIA_TYPE, STATUS_LIST_JWT_TYP,
    STATUS_LIST_MAX_FUTURE_SKEW_SECS, StatusListConfigError, StatusListPolicy, StatusListTrust,
};
pub use validate::{
    CredentialRequest, CredentialRequestError, MAX_CLAIM_NAME_LEN, MAX_CLIENT_ID_LEN,
    MAX_CREDENTIAL_QUERY_ID_LEN, MAX_RESEARCH_NONCE_LEN, MAX_RESEARCH_STATE_LEN, MAX_VCT_LEN,
    REQUESTED_CLAIMS, SYNTHETIC_CREDENTIAL_QUERY, SYNTHETIC_CREDENTIAL_QUERY_ID,
    SYNTHETIC_CREDENTIAL_VCT, ValidatedResponse, ValidationError,
};
