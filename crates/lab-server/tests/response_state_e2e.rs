//! `state` per session, carried inside the JWE and checked after decryption (OpenID4VP 1.1
//! Editor's draft of 11 November 2026).
//!
//! Spec text these tests exercise:
//! - §5.2: `state` is RECOMMENDED (REQUIRED under §5.3), and "`state` values MUST only contain
//!   ASCII URL safe characters".
//! - §8.3: "The payload of the encrypted JWT response MUST include the contents of the
//!   response as defined in Section 8.1 as top-level JSON members", so under
//!   `direct_post.jwt` the echoed `state` (RFC 6749 §4.1.2) is inside the ciphertext, next to
//!   `vp_token`.
//! - §14.4.2: "The Verifier SHOULD protect its Response URI from inadvertent requests by
//!   checking that the value of the received state parameter corresponds to a recent
//!   Authorization Request."
//!
//! Invariants under test:
//! - Every session, on every route, gets its own `state`; the signed Request Object carries
//!   the value the registry stores, and an honest response that echoes it commits.
//! - The check runs per candidate, after HPKE open and before holder binding: a missing
//!   `state` is `StateMissing`, a non-string or another session's value `StateMismatch`. Both
//!   answer the generic 400, consume nothing, and a later honest response still commits.
//! - Under bounded trial, a JWE that opens for B but carries A's `state` does not validate for
//!   B, and nothing is claimed.
//!
//! Every test starts its own loopback lab server and drives it with the wallet simulator. All
//! keys, nonces, states and presentations are synthetic.

use std::collections::HashSet;

use lab_server::wallet_sim::{
    CreatedSession, PresentationTamper, RequestObject, SealOptions, StateChoice, SyntheticIssuer,
    WalletSim,
};
use lab_server::{
    CommitResult, CryptoResult, EvidenceRecord, GENERIC_REJECTION_BODY, LabConfig, LabServer, Mode,
    Rejection, RequestSigningKey, RouteKind, SYNTHETIC_CREDENTIAL_QUERY_ID, SharedRouteStrategy,
    TrustedIssuerKey, ValidationError, ValidationResult,
};
use serde_json::json;
use session_core::CandidateBudget;

/// HTTP statuses the tests pin (RFC 9110 §15).
const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
/// Two sessions are enough to show a mis-correlation.
const PAIR: usize = 2;
/// Sessions per route in the round-trip test: enough to see that values are per session.
const SESSIONS_PER_ROUTE: usize = 4;
/// Length of a lab `state`: 16 random bytes as unpadded base64url (RFC 4648 §5), the 128 bits
/// of §5.3.
const STATE_LEN: usize = 22;
/// A non-string `state` (JSON number).
const NUMERIC_STATE: u64 = 42;

/// Synthetic SpruceID fixture key that signs every request object (its did:key is the default
/// `client_id`), and the synthetic SD-JWT VC issuer (private for the wallet, public for the
/// Verifier).
const FIXTURE_JWK: &str = include_str!("fixtures/spruce_verifier.jwk");
const ISSUER_JWK: &str = include_str!("fixtures/lab_issuer.jwk");
const ISSUER_PUBLIC_JWK: &str = include_str!("fixtures/lab_issuer.pub.jwk");

struct Lab {
    server: LabServer,
    wallet: WalletSim,
}

impl Lab {
    async fn start(mode: Mode) -> Self {
        let config = LabConfig::new(
            mode,
            RequestSigningKey::from_jwk(FIXTURE_JWK).expect("fixture signing key"),
            TrustedIssuerKey::from_jwk(ISSUER_PUBLIC_JWK).expect("fixture issuer key"),
        );
        let server = LabServer::start(config).await.expect("lab server starts");
        assert!(server.local_addr().ip().is_loopback());
        let issuer = SyntheticIssuer::from_jwk(ISSUER_JWK).expect("fixture issuer");
        Self {
            server,
            wallet: WalletSim::new(&issuer).expect("wallet simulator builds"),
        }
    }

    async fn sessions(&self, route: RouteKind, n: usize) -> Vec<CreatedSession> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(
                self.wallet
                    .create_session(&self.server.base_url(), route, None)
                    .await
                    .expect("session is created"),
            );
        }
        out
    }

    async fn request(&self, session: &CreatedSession) -> RequestObject {
        self.wallet
            .fetch_request(session)
            .await
            .expect("request object is served")
    }

    async fn state(&self, session: &CreatedSession) -> String {
        self.wallet
            .session_state(&session.result_uri)
            .await
            .expect("result endpoint answers")
            .expect("session is known")
    }

    /// Seals for `request` with `opts` and POSTs to its response_uri.
    async fn post(&self, request: &RequestObject, opts: &SealOptions) -> (u16, Vec<u8>) {
        let jwe = self.wallet.seal(request, opts).expect("wallet seals");
        let reply = self
            .wallet
            .post_response(&request.response_uri, &jwe)
            .await
            .expect("response endpoint answers");
        (reply.status, reply.body)
    }

    /// The only evidence record since the last call.
    fn record(&self) -> EvidenceRecord {
        let mut records = self.server.evidence().take();
        assert_eq!(records.len(), 1, "exactly one evidence record: {records:?}");
        records.remove(0)
    }

    /// An honest response for `session` commits it.
    async fn honest_commits(&self, session: &CreatedSession) {
        let request = self.request(session).await;
        let (status, _) = self.post(&request, &SealOptions::default()).await;
        assert_eq!(status, OK);
        let record = self.record();
        assert_eq!(record.commit_result, CommitResult::Committed);
        assert_eq!(
            record.committed_session.as_ref().map(|id| id.as_str()),
            Some(session.session_id.as_str())
        );
        assert_eq!(self.state(session).await, "consumed");
    }
}

/// Research mode, shared route, one key and `kid` for every session (bounded trial).
fn shared_key(budget: usize) -> Mode {
    Mode::Research(SharedRouteStrategy::BoundedTrial(
        CandidateBudget::new(budget).expect("valid budget"),
    ))
}

fn assert_generic(status: u16, body: &[u8]) {
    assert_eq!(status, BAD_REQUEST);
    assert_eq!(body, GENERIC_REJECTION_BODY.as_bytes());
}

fn state_of(request: &RequestObject) -> String {
    request
        .state
        .clone()
        .expect("the request object carries a state")
}

/// §5.2 / §14.4.2: on the unique route and on both shared strategies every session gets a
/// fresh `state` of 128 random bits in the §5.2 charset; the signed Request Object carries
/// exactly the value the registry stores for that session; an honest wallet echoes it inside
/// the JWE and the response commits with one validated candidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn state_round_trips_inside_the_jwe_on_every_route() {
    let cases = [
        (Mode::Hardened, RouteKind::Unique),
        (shared_key(SESSIONS_PER_ROUTE), RouteKind::Shared),
        (
            Mode::Research(SharedRouteStrategy::UniqueKid),
            RouteKind::Shared,
        ),
    ];
    for (mode, route) in cases {
        let lab = Lab::start(mode).await;
        let sessions = lab.sessions(route, SESSIONS_PER_ROUTE).await;
        let mut states = HashSet::new();
        for session in &sessions {
            let request = lab.request(session).await;
            let state = state_of(&request);
            assert_eq!(state.len(), STATE_LEN, "{route:?}");
            assert!(
                state
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')),
                "§5.2 charset: {state}"
            );
            let stored = lab
                .server
                .stored_binding(&session.session_id)
                .expect("session is stored");
            assert_eq!(
                stored.state().map(|s| s.as_bytes()),
                Some(state.as_bytes()),
                "{route:?}"
            );
            states.insert(state);
        }
        assert_eq!(states.len(), SESSIONS_PER_ROUTE, "fresh per session");

        for session in &sessions {
            lab.honest_commits(session).await;
        }
        lab.server.shutdown().await;
    }
}

/// A response whose payload has no `state` (only `vp_token`, otherwise honest) is refused
/// after decryption with `StateMissing` and the generic 400, on the unique and the shared
/// route; the session stays pending and the honest response then commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_without_state_is_refused_and_the_honest_response_then_commits() {
    for (mode, route) in [
        (Mode::Hardened, RouteKind::Unique),
        (shared_key(PAIR), RouteKind::Shared),
    ] {
        let lab = Lab::start(mode).await;
        let sessions = lab.sessions(route, PAIR).await;
        let target = &sessions[0];
        let request = lab.request(target).await;
        let omit = SealOptions {
            state: StateChoice::Omit,
            ..SealOptions::default()
        };

        let (status, body) = lab.post(&request, &omit).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(
            record.crypto_result,
            CryptoResult::Opened { opened: 1 },
            "{route:?}"
        );
        assert_eq!(
            record.validation_result,
            ValidationResult::Failed(ValidationError::StateMissing),
            "{route:?}"
        );
        assert_eq!(
            record.rejection,
            Some(Rejection::Validation(ValidationError::StateMissing))
        );
        assert_eq!(record.commit_result, CommitResult::NotRun);
        assert_eq!(lab.state(target).await, "pending");

        lab.honest_commits(target).await;
        lab.server.shutdown().await;
    }
}

/// On the unique route the JWE for A carries the `state` of B, another live session, or a
/// `state` that is not a string: A's key and `session_info` open it, and the `state` check
/// refuses it (`StateMismatch`, generic 400). Neither session is consumed, and both then
/// commit their honest responses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn state_of_another_live_session_is_refused() {
    let lab = Lab::start(Mode::Hardened).await;
    let sessions = lab.sessions(RouteKind::Unique, PAIR).await;
    let (a, b) = (&sessions[0], &sessions[1]);
    let request_a = lab.request(a).await;
    let state_b = state_of(&lab.request(b).await);
    assert_ne!(state_of(&request_a), state_b);

    for wrong in [json!(state_b), json!(NUMERIC_STATE)] {
        let opts = SealOptions {
            state: StateChoice::Other(wrong.clone()),
            ..SealOptions::default()
        };
        let (status, body) = lab.post(&request_a, &opts).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(record.hpke_attempts, 1);
        assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
        assert_eq!(
            record.validation_result,
            ValidationResult::Failed(ValidationError::StateMismatch),
            "{wrong}"
        );
        assert_eq!(record.commit_result, CommitResult::NotRun);
        assert_eq!(lab.state(a).await, "pending");
        assert_eq!(lab.state(b).await, "pending");
    }

    lab.honest_commits(a).await;
    lab.honest_commits(b).await;
    lab.server.shutdown().await;
}

/// Bounded trial, shared key and route: A's whole honest payload (A's holder proof and A's
/// `state`) sealed with B's `session_info`. It opens for B only, and B's `state` check refuses
/// it per candidate (`StateMismatch`, not `KbNonceMismatch`: the `state` check runs before
/// holder binding). Nothing is claimed and both sessions stay pending; each then commits its
/// own honest response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_trial_jwe_that_opens_for_b_but_carries_a_state_is_refused_for_b() {
    let lab = Lab::start(shared_key(PAIR)).await;
    let sessions = lab.sessions(RouteKind::Shared, PAIR).await;
    let (a, b) = (&sessions[0], &sessions[1]);
    let request_a = lab.request(a).await;
    let request_b = lab.request(b).await;
    let presentation = lab
        .wallet
        .present(&request_a, &PresentationTamper::None)
        .expect("presentation for A");
    let payload_of_a = SealOptions {
        vp_token: Some(json!({ SYNTHETIC_CREDENTIAL_QUERY_ID: [presentation] })),
        state: StateChoice::Other(json!(state_of(&request_a))),
        ..SealOptions::default()
    };

    let (status, body) = lab.post(&request_b, &payload_of_a).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.candidate_count, PAIR);
    assert_eq!(record.hpke_attempts, PAIR);
    assert_eq!(
        record.crypto_result,
        CryptoResult::Opened { opened: 1 },
        "it decrypts for B, the session the sender bound it to"
    );
    assert_eq!(
        record.validation_result,
        ValidationResult::Failed(ValidationError::StateMismatch)
    );
    assert_eq!(
        record.rejection,
        Some(Rejection::Validation(ValidationError::StateMismatch))
    );
    assert_eq!(record.commit_result, CommitResult::NotRun);
    assert_eq!(record.committed_session, None);
    assert_eq!(lab.state(a).await, "pending");
    assert_eq!(lab.state(b).await, "pending");

    lab.honest_commits(b).await;
    lab.honest_commits(a).await;
    lab.server.shutdown().await;
}
