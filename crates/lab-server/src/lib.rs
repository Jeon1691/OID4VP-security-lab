//! Lab Verifier HTTP server for OpenID4VP 1.1 HPKE-0 `direct_post.jwt` responses (IMP-008
//! orchestration, IMP-009 HTTP, IMP-010 wallet simulator). Synthetic data, loopback only for
//! research mode (ADR-005).
//!
//! `tests/spruce_api_smoke.rs` (G0-C) and `tests/ecdh_es_direct_post_jwt_e2e.rs` (G0-D) cover
//! the pinned SpruceID `openid4vp`; the HPKE-0 path here does not use it.
//!
//! # Endpoints (lab infrastructure, not standard OpenID4VP endpoints)
//!
//! | Method and path | Purpose |
//! | --- | --- |
//! | `POST /lab/v1/sessions` | Create a synthetic session; optional JSON `{"route": "unique"\|"shared", "nonce": "..."}` (`shared` and `nonce` research mode only) |
//! | `GET /lab/v1/requests/{id}` | Request object: exact `client_id`, `nonce`, `response_uri`, `response_mode=direct_post.jwt`, `client_metadata.jwks` with the HPKE-0 key (`alg` `HPKE-0`, `kid`) |
//! | `POST /lab/v1/response/{token}` | Unique response_uri (unique-uri strategy) |
//! | `POST /lab/v1/response/shared` | Shared response_uri, research mode only (404 in hardened mode) |
//! | `GET /lab/v1/sessions/{id}/result` | `pending` / `consumed` (with the synthetic `vp_token`) / `expired` |
//! | `GET /health` | Liveness |
//!
//! The request object is **unsigned** for now. JAR signing (RFC 9101, e.g. through SpruceID's
//! request signer with the fixture key named by [`DEFAULT_CLIENT_ID`]) is a follow-up and must
//! sign exactly the stored wire values; it must not change `client_id`, `nonce` or
//! `response_uri`, because they are the HPKE `session_info` inputs.
//!
//! # Modes
//!
//! * [`Mode::Hardened`] (default): unique-uri only, `RoutePolicy::UniquePerSession`, a fresh
//!   key pair and `kid` per session. No shared route.
//! * [`Mode::Research`]: additionally serves the shared route with one strategy fixed at start
//!   ([`SharedRouteStrategy`]): `BoundedTrial(budget)` with one key and `kid` shared by every
//!   session on the route (the OIDF #792 shape), or `UniqueKid` with a key and `kid` per
//!   session. Shared-route sessions live in a separate `RoutePolicy::Shared` registry, so
//!   unique-uri sessions keep the hardened guarantees. The server refuses to start research
//!   mode on a non-loopback address.
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
//! 5. Ingress hint: route token from the path, `kid` from the protected header.
//! 6. `resolve` with the route's strategy.
//! 7. For each candidate: HPKE open with its key and `SessionInfo::from_binding`, then
//!    synthetic validation. All candidates are tried; with bounded trial, more than one that
//!    validates is an integrity failure (reject, claim nothing, record it).
//! 8. `claim` with `SHA-256(compact JWE)` as the response digest.
//!
//! Steps 1-3 answer with distinct admission errors (they reveal nothing about sessions). Every
//! failure from step 4 on answers with the single [`GENERIC_REJECTION_BODY`] (400); the real
//! reason goes only into the [`EvidenceLog`]. A failed decryption or validation never touches
//! the session, which stays pending.
//!
//! # Validation level
//!
//! Evidence level 2, synthetic: see [`validate`](crate::ValidationError). Successful HPKE
//! decryption is never treated as holder authentication; real KB-JWT / holder binding is out
//! of scope for this wave.
//!
//! # Background sweep
//!
//! A task calls `expire_due` and `purge` on every registry each
//! [`LabConfig::sweep_interval`] (default [`DEFAULT_SWEEP_INTERVAL`]) and drops the request
//! objects of purged sessions.
//!
//! # Features
//!
//! `wallet-sim` enables [`wallet_sim`] and with it `jose-hpke/test-support` (sealing). The
//! default build, including the `lab-server` binary, contains no sealing code.

mod config;
mod evidence;
mod server;
mod validate;
#[cfg(feature = "wallet-sim")]
pub mod wallet_sim;

pub use config::{
    DEFAULT_CLIENT_ID, DEFAULT_SESSION_TTL, DEFAULT_SWEEP_INTERVAL, LabConfig,
    MAX_RESPONSE_BODY_BYTES, Mode, RouteKind, SharedRouteStrategy, StartError,
};
pub use evidence::{
    AdmissionError, CommitResult, CryptoResult, EvidenceLog, EvidenceRecord, MAX_EVIDENCE_RECORDS,
    Rejection, ValidationResult,
};
pub use server::{GENERIC_REJECTION_BODY, LabServer};
pub use validate::{SYNTHETIC_CREDENTIAL_QUERY_ID, ValidatedResponse, ValidationError};
