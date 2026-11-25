//! Lab Verifier HTTP server for OpenID4VP 1.1 HPKE-0 `direct_post.jwt` responses (IMP-008
//! orchestration, IMP-009 HTTP, IMP-010 wallet simulator). Synthetic data, loopback only in
//! every mode (ADR-005); serving a non-loopback address needs an explicit future ADR.
//!
//! `tests/spruce_api_smoke.rs` (G0-C) and `tests/ecdh_es_direct_post_jwt_e2e.rs` (G0-D) cover
//! the pinned SpruceID `openid4vp`; the HPKE-0 path here does not use it.
//!
//! # Endpoints (lab infrastructure, not standard OpenID4VP endpoints)
//!
//! | Method and path | Purpose |
//! | --- | --- |
//! | `POST /lab/v1/sessions` | Create a synthetic session; optional JSON `{"route": "unique"\|"shared", "nonce": "..."}` (`shared` and `nonce` research mode only). Returns `client_id` (the Authorization Request parameter), `request_uri`, `response_uri` and `result_uri`; the result token in `result_uri` is returned only here |
//! | `GET /lab/v1/requests/{id}` | Signed Request Object (JAR), body = compact JWS, `Content-Type: application/oauth-authz-req+jwt`. Payload: exact `client_id`, `nonce`, `response_uri`, `response_mode=direct_post.jwt`, `aud`, `dcql_query` (one `dc+sd-jwt` query for [`SYNTHETIC_CREDENTIAL_VCT`] and [`REQUESTED_CLAIMS`]), `client_metadata.jwks` with the HPKE-0 key (`alg` `HPKE-0`, `kid`) |
//! | `POST /lab/v1/response/{token}` | Unique response_uri (unique-uri strategy) |
//! | `POST /lab/v1/response/shared` | Shared response_uri, research mode only (404 in hardened mode) |
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
//! registry holds and `SessionInfo::from_binding` decrypts with, and no code path can change
//! them after signing (`tests/signed_request_object_e2e.rs` checks this on every route).
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
//!   unique-uri sessions keep the hardened guarantees.
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
//! 8. For each candidate: HPKE open with its key and `SessionInfo::from_binding`, then
//!    holder-binding validation (SD-JWT VC + KB-JWT against that candidate's `client_id` and
//!    `nonce`, see below), on the blocking pool behind
//!    [`LabConfig::max_concurrent_decryptions`]. All candidates are tried; with bounded trial,
//!    more than one that validates is an integrity failure (reject, claim nothing, record it).
//!    Only the first validated result is kept.
//! 9. Verifier-wide replay guard: a response whose `SHA-256(compact JWE)` already validated
//!    for a *different* session is refused (`Rejection::CrossSessionReplay`), and so is one
//!    whose verified holder proof (`SHA-256` of the KB-JWT signing input, signature excluded
//!    because ECDSA signatures are malleable) did, even inside a fresh JWE
//!    (`Rejection::HolderProofReplay`); see [`MAX_REMEMBERED_DIGESTS`].
//! 10. `claim` with that digest as the response digest.
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
//!   session's response would decrypt and validate for a new one. Per-session state cannot
//!   see that, so the verifier-wide replay guard refuses any response already validated for
//!   another session, and records `CrossSessionReplay` as evidence of the #792 condition.
//!   With a reused nonce and the same `client_id` the holder proof itself is valid for both
//!   sessions, so re-sealing it into a fresh JWE gets past the JWE digest; the guard therefore
//!   also binds each verified KB-JWT to its first session (`HolderProofReplay`, PR #10).
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
//!   Metadata / trust lists), no status or revocation check, no Wallet attestation, and the
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
//! enables the decryption pause lever and `LabServer::stored_binding`. The default build, including the
//! `lab-server` binary, has neither; the gate step `verifier_without_sealing` checks it. Release artifacts must come from a plain
//! `cargo build -p lab-server` (`--release`): a build that also compiles test targets (e.g.
//! `cargo build --workspace --all-targets`) unifies the self dev-dependency's `wallet-sim`
//! feature into the library the binary links.

mod config;
mod evidence;
mod jar;
mod jose;
mod sd_jwt;
mod server;
mod validate;
#[cfg(feature = "wallet-sim")]
pub mod wallet_sim;

pub use config::{
    DEFAULT_CLIENT_ID, DEFAULT_HEADER_READ_TIMEOUT, DEFAULT_MAX_CONCURRENT_DECRYPTIONS,
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_IN_FLIGHT_REQUESTS, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_SESSION_TTL, DEFAULT_SHUTDOWN_DRAIN, DEFAULT_SWEEP_INTERVAL, LabConfig,
    MAX_RESPONSE_BODY_BYTES, Mode, RouteKind, SharedRouteStrategy, StartError,
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
pub use server::{GENERIC_REJECTION_BODY, LabServer, MAX_REMEMBERED_DIGESTS};
pub use validate::{
    MAX_CLIENT_ID_LEN, MAX_RESEARCH_NONCE_LEN, MAX_RESEARCH_STATE_LEN, REQUESTED_CLAIMS,
    SYNTHETIC_CREDENTIAL_QUERY, SYNTHETIC_CREDENTIAL_QUERY_ID, SYNTHETIC_CREDENTIAL_VCT,
    ValidatedResponse, ValidationError,
};
