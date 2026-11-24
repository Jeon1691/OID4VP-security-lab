//! Wave-2 HTTP path (IMP-008/009/010, gates G2/G3/G4): OpenID4VP 1.1 HPKE-0 `direct_post.jwt`
//! responses over real loopback HTTP, routed to sessions by the session-core strategies.
//!
//! Every test starts its own lab server on `127.0.0.1:0` and drives it with the wallet
//! simulator (`wallet-sim` feature, enabled for tests through the self dev-dependency). All
//! keys, nonces and presentations are synthetic.
//!
//! Plan IDs: HTTP-01..05 (routing strategies, admission), CRYPTO-03 (session binding),
//! STATE-01/02/06 (replay, concurrency, failed attempts), plus the mode and error-uniformity
//! checks of the G2-G4 gates. A multi-thread runtime is fine here: session-core's
//! `MemoryRegistry` waits on its lock instead of failing like the upstream `try_lock` store.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use jose_hpke::Error as JweError;
use lab_server::wallet_sim::{CreatedSession, KidChoice, SealOptions, WalletSim};
use lab_server::{
    AdmissionError, CommitResult, CryptoResult, EvidenceRecord, GENERIC_REJECTION_BODY, LabConfig,
    LabServer, MAX_RESPONSE_BODY_BYTES, Mode, Rejection, RouteKind, SharedRouteStrategy,
    StartError, ValidationError, ValidationResult,
};
use session_core::{CandidateBudget, ClaimError, ResolutionStrategy, ResolveError};

/// Media type of a `direct_post.jwt` POST body (OpenID4VP 1.1 §8.2).
const FORM: &str = "application/x-www-form-urlencoded";
/// A media type the response endpoint must refuse even for a valid form body.
const JSON: &str = "application/json";
/// HTTP statuses the tests pin (RFC 9110 §15).
const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
const NOT_FOUND: u16 = 404;
const PAYLOAD_TOO_LARGE: u16 = 413;
const UNSUPPORTED_MEDIA_TYPE: u16 = 415;
/// Session counts for the shared-route scenarios (plan HTTP-04 / session-core resolution).
const TRIAL_SIZES: [usize; 3] = [2, 8, 32];
/// Concurrent duplicate POSTs (plan STATE-02).
const CONCURRENCY_LEVELS: [usize; 3] = [2, 16, 128];
/// Sessions sharing a route or key in the multi-session unique-URI / unique-kid scenarios.
const MANY_SESSIONS: usize = 8;
/// A `client_id` no lab session was issued with.
const FOREIGN_CLIENT_ID: &str = "decentralized_identifier:did:key:zDnaeForeignSyntheticVerifier";
/// Short TTL and sweep interval for the expiry test; the wait covers several sweeps.
const SHORT_TTL: Duration = Duration::from_millis(50);
const FAST_SWEEP: Duration = Duration::from_millis(20);
const EXPIRY_WAIT: Duration = Duration::from_millis(400);

struct Lab {
    server: LabServer,
    wallet: WalletSim,
}

impl Lab {
    async fn start(mode: Mode) -> Self {
        Self::start_with(LabConfig::new(mode)).await
    }

    async fn start_with(config: LabConfig) -> Self {
        let server = LabServer::start(config).await.expect("lab server starts");
        assert!(server.local_addr().ip().is_loopback());
        Self {
            server,
            wallet: WalletSim::new().expect("wallet simulator builds"),
        }
    }

    fn base(&self) -> String {
        self.server.base_url()
    }

    async fn session(&self, route: RouteKind) -> CreatedSession {
        self.wallet
            .create_session(&self.base(), route, None)
            .await
            .expect("session is created")
    }

    async fn sessions(&self, route: RouteKind, n: usize) -> Vec<CreatedSession> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.session(route).await);
        }
        out
    }

    async fn state(&self, session: &CreatedSession) -> Option<String> {
        self.wallet
            .session_state(&self.base(), &session.session_id)
            .await
            .expect("result endpoint answers")
    }

    async fn assert_pending(&self, session: &CreatedSession) {
        assert_eq!(self.state(session).await.as_deref(), Some("pending"));
    }

    /// Fetches the session's request object, seals with `opts` and POSTs to its response_uri.
    async fn respond(
        &self,
        session: &CreatedSession,
        opts: &SealOptions,
    ) -> (String, u16, Vec<u8>) {
        let request = self
            .wallet
            .fetch_request(&session.request_uri)
            .await
            .expect("request object is served");
        let jwe = self.wallet.seal(&request, opts).expect("wallet seals");
        let reply = self
            .wallet
            .post_response(&request.response_uri, &jwe)
            .await
            .expect("response endpoint answers");
        (jwe, reply.status, reply.body)
    }

    /// The only evidence record since the last call.
    fn record(&self) -> EvidenceRecord {
        let mut records = self.server.evidence().take();
        assert_eq!(records.len(), 1, "exactly one evidence record: {records:?}");
        records.remove(0)
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

fn research(strategy: SharedRouteStrategy) -> Mode {
    Mode::Research(strategy)
}

fn trial(budget: usize) -> Mode {
    research(SharedRouteStrategy::BoundedTrial(
        CandidateBudget::new(budget).expect("valid budget"),
    ))
}

fn assert_success(status: u16) {
    assert_eq!(status, OK, "valid response must be accepted");
}

fn assert_generic(status: u16, body: &[u8]) {
    assert_eq!(status, BAD_REQUEST);
    assert_eq!(
        body,
        GENERIC_REJECTION_BODY.as_bytes(),
        "generic error body"
    );
}

fn assert_committed(record: &EvidenceRecord, session: &CreatedSession) {
    assert_eq!(record.commit_result, CommitResult::Committed);
    assert_eq!(record.rejection, None);
    assert_eq!(
        record.committed_session.as_ref().map(|id| id.as_str()),
        Some(session.session_id.as_str())
    );
}

/// HTTP-01: one session on its unique response_uri, real form POST, exactly one HPKE attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unique_uri_form_post_succeeds_with_one_hpke_attempt() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;

    let (_, status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_success(status);

    let record = lab.record();
    assert_eq!(record.route, RouteKind::Unique);
    assert_eq!(record.strategy, ResolutionStrategy::UniqueUri);
    assert_eq!(record.candidate_count, 1);
    assert_eq!(record.hpke_attempts, 1);
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 1 }
    );
    assert_committed(&record, &session);
    assert_eq!(lab.state(&session).await.as_deref(), Some("consumed"));
    lab.shutdown().await;
}

/// HTTP-02: among many pending sessions, the unique URI selects exactly one; one attempt, and
/// only the addressed session is consumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unique_uri_among_many_sessions_consumes_only_the_addressed_one() {
    let lab = Lab::start(Mode::Hardened).await;
    let sessions = lab.sessions(RouteKind::Unique, MANY_SESSIONS).await;
    let target = &sessions[MANY_SESSIONS / 2];

    let (_, status, _) = lab.respond(target, &SealOptions::default()).await;
    assert_success(status);
    let record = lab.record();
    assert_eq!(record.candidate_count, 1);
    assert_eq!(record.hpke_attempts, 1);
    assert_committed(&record, target);

    for s in &sessions {
        let want = if s.session_id == target.session_id {
            "consumed"
        } else {
            "pending"
        };
        assert_eq!(lab.state(s).await.as_deref(), Some(want));
    }
    lab.shutdown().await;
}

/// The request object carries the exact wire values the session was stored with, and a
/// response_uri of the decided shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_object_carries_exact_wire_values() {
    let lab = Lab::start(Mode::Hardened).await;
    let a = lab.session(RouteKind::Unique).await;
    let b = lab.session(RouteKind::Unique).await;
    let ra = lab
        .wallet
        .fetch_request(&a.request_uri)
        .await
        .expect("request a");
    let rb = lab
        .wallet
        .fetch_request(&b.request_uri)
        .await
        .expect("request b");

    let prefix = format!("{}/lab/v1/response/", lab.base());
    assert!(ra.response_uri.starts_with(&prefix), "{}", ra.response_uri);
    assert!(ra.response_uri.starts_with("http://127.0.0.1:"));
    assert_eq!(ra.response_uri, a.response_uri);
    assert_ne!(ra.response_uri, rb.response_uri);
    assert_ne!(ra.nonce, rb.nonce);
    assert_ne!(ra.kid, rb.kid);
    assert_eq!(ra.response_mode, "direct_post.jwt");
    assert_eq!(ra.jwk_alg, "HPKE-0");
    assert!(ra.kid.is_some());
    assert!(
        ra.nonce
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')),
        "nonce in the OpenID4VP §5.2 charset"
    );
    lab.shutdown().await;
}

/// HTTP-03: shared route, per-session key and kid: the kid selects one candidate, one attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unique_kid_on_shared_route_yields_one_candidate_and_one_attempt() {
    let lab = Lab::start(research(SharedRouteStrategy::UniqueKid)).await;
    let sessions = lab.sessions(RouteKind::Shared, MANY_SESSIONS).await;
    let uris: HashSet<_> = sessions.iter().map(|s| s.response_uri.as_str()).collect();
    assert_eq!(uris.len(), 1, "all sessions share one response_uri");
    assert!(
        sessions[0]
            .response_uri
            .ends_with("/lab/v1/response/shared")
    );
    let target = &sessions[MANY_SESSIONS - 1];

    let (_, status, _) = lab.respond(target, &SealOptions::default()).await;
    assert_success(status);
    let record = lab.record();
    assert_eq!(record.route, RouteKind::Shared);
    assert_eq!(record.strategy, ResolutionStrategy::UniqueKid);
    assert_eq!(record.candidate_count, 1);
    assert_eq!(record.hpke_attempts, 1);
    assert_committed(&record, target);

    // Without a kid the unique-kid route cannot select a session: no decryption at all.
    let other = &sessions[0];
    let opts = SealOptions {
        kid: KidChoice::Omit,
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(other, &opts).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::Resolve(ResolveError::MissingKid))
    );
    assert_eq!(record.hpke_attempts, 0);
    lab.assert_pending(other).await;
    lab.shutdown().await;
}

/// HTTP-04: shared route and shared key (the #792 shape). Every live session is a candidate up
/// to the budget, and all of them are tried, even after one has matched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_trial_succeeds_with_right_session_last_within_budget() {
    for n in TRIAL_SIZES {
        let lab = Lab::start(trial(n)).await;
        let sessions = lab.sessions(RouteKind::Shared, n).await;

        let last = &sessions[n - 1];
        let (_, status, _) = lab.respond(last, &SealOptions::default()).await;
        assert_success(status);
        let record = lab.record();
        assert_eq!(
            record.strategy,
            ResolutionStrategy::BoundedTrial(CandidateBudget::new(n).expect("budget"))
        );
        assert_eq!(record.candidate_count, n);
        assert!(record.hpke_attempts <= n);
        assert_eq!(
            record.hpke_attempts, n,
            "bounded trial tries every candidate"
        );
        assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
        assert_committed(&record, last);

        // The right session first: still no stop-at-first, every remaining candidate is tried.
        let first = &sessions[0];
        let (_, status, _) = lab.respond(first, &SealOptions::default()).await;
        assert_success(status);
        let record = lab.record();
        assert_eq!(record.candidate_count, n - 1);
        assert_eq!(record.hpke_attempts, n - 1);
        assert_committed(&record, first);
        lab.shutdown().await;
    }
}

/// HTTP-04: more live sessions than the budget is refused as a whole, before any decryption.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_trial_over_budget_is_rejected_without_decryption() {
    for n in TRIAL_SIZES {
        let lab = Lab::start(trial(n)).await;
        let sessions = lab.sessions(RouteKind::Shared, n + 1).await;

        let (_, status, body) = lab.respond(&sessions[n], &SealOptions::default()).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(
            record.rejection,
            Some(Rejection::Resolve(ResolveError::CandidateBudgetExceeded {
                found: n + 1,
                budget: n
            }))
        );
        assert_eq!(record.hpke_attempts, 0);
        assert_eq!(record.crypto_result, CryptoResult::NotAttempted);
        lab.assert_pending(&sessions[n]).await;
        lab.shutdown().await;
    }
}

/// Bounded trial: two sessions that both decrypt and validate (a verifier that reused a nonce
/// under a shared key) are an integrity failure. Nothing is claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_trial_with_two_validating_sessions_is_an_integrity_failure() {
    const REUSED_NONCE: &str = "lab-reused-nonce";
    let lab = Lab::start(trial(TRIAL_SIZES[0])).await;
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let s = lab
            .wallet
            .create_session(&lab.base(), RouteKind::Shared, Some(REUSED_NONCE))
            .await
            .expect("research mode accepts a fixed nonce");
        sessions.push(s);
    }

    let (_, status, body) = lab.respond(&sessions[0], &SealOptions::default()).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.hpke_attempts, 2);
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 2 });
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 2 }
    );
    assert_eq!(record.commit_result, CommitResult::RefusedAmbiguous);
    assert_eq!(
        record.rejection,
        Some(Rejection::Ambiguous { validated: 2 })
    );
    for s in &sessions {
        lab.assert_pending(s).await;
    }
    lab.shutdown().await;
}

/// HTTP-05: admission failures are rejected before any JWE work (0 HPKE attempts) and leave
/// the session pending. Oversize body, wrong media type, duplicated `response`, and plaintext
/// `vp_token` (the downgrade found in G0-D) alone or next to `response`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_failures_are_rejected_before_decryption() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let request = lab
        .wallet
        .fetch_request(&session.request_uri)
        .await
        .expect("request");
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");
    let form = |pairs: &[(&str, &str)]| {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
            .into_bytes()
    };
    let plaintext_vp = r#"{"synthetic-credential":[{"nonce":"x","aud":"y"}]}"#;

    let mut oversize = form(&[("response", &jwe)]);
    oversize.resize(MAX_RESPONSE_BODY_BYTES + 1, b'A');
    let cases: Vec<(&str, &str, Vec<u8>, u16, AdmissionError)> = vec![
        (
            "oversize",
            FORM,
            oversize,
            PAYLOAD_TOO_LARGE,
            AdmissionError::BodyTooLarge,
        ),
        (
            "wrong mime",
            JSON,
            form(&[("response", &jwe)]),
            UNSUPPORTED_MEDIA_TYPE,
            AdmissionError::UnsupportedMediaType,
        ),
        (
            "duplicated response",
            FORM,
            form(&[("response", &jwe), ("response", &jwe)]),
            BAD_REQUEST,
            AdmissionError::DuplicateResponse,
        ),
        (
            "plaintext vp_token",
            FORM,
            form(&[("vp_token", plaintext_vp)]),
            BAD_REQUEST,
            AdmissionError::PlaintextVpToken,
        ),
        (
            "plaintext vp_token next to response",
            FORM,
            form(&[("response", &jwe), ("vp_token", plaintext_vp)]),
            BAD_REQUEST,
            AdmissionError::PlaintextVpToken,
        ),
        (
            "missing response",
            FORM,
            form(&[("state", "x")]),
            BAD_REQUEST,
            AdmissionError::UnexpectedParameter,
        ),
    ];
    for (name, content_type, body, want_status, want) in cases {
        let reply = lab
            .wallet
            .post_raw(&request.response_uri, content_type, body)
            .await
            .expect("endpoint answers");
        assert_eq!(reply.status, want_status, "{name}");
        let record = lab.record();
        assert_eq!(record.rejection, Some(Rejection::Admission(want)), "{name}");
        assert_eq!(record.hpke_attempts, 0, "{name}");
        assert_eq!(record.candidate_count, 0, "{name}");
        lab.assert_pending(&session).await;
    }

    // The JWE used in every case is valid: the session was untouched and still accepts it.
    let reply = lab
        .wallet
        .post_response(&request.response_uri, &jwe)
        .await
        .expect("post");
    assert_success(reply.status);
    lab.shutdown().await;
}

/// CRYPTO-03: a JWE sealed to session A's key but bound (session_info) to another session's
/// nonce, client_id or response_uri does not decrypt, and A stays pending. A kid of another
/// session on A's unique URI selects nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jwe_bound_to_another_sessions_values_fails() {
    let lab = Lab::start(Mode::Hardened).await;
    let a = lab.session(RouteKind::Unique).await;
    let b = lab.session(RouteKind::Unique).await;
    let rb = lab
        .wallet
        .fetch_request(&b.request_uri)
        .await
        .expect("request b");

    let cases = [
        (
            "nonce",
            SealOptions {
                session_info_nonce: Some(rb.nonce.clone()),
                ..SealOptions::default()
            },
        ),
        (
            "client_id",
            SealOptions {
                session_info_client_id: Some(FOREIGN_CLIENT_ID.to_owned()),
                ..SealOptions::default()
            },
        ),
        (
            "response_uri",
            SealOptions {
                session_info_response_uri: Some(rb.response_uri.clone()),
                ..SealOptions::default()
            },
        ),
    ];
    for (name, opts) in cases {
        let (_, status, body) = lab.respond(&a, &opts).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(record.hpke_attempts, 1, "{name}");
        assert_eq!(record.crypto_result, CryptoResult::NoneOpened, "{name}");
        assert_eq!(record.rejection, Some(Rejection::Decrypt), "{name}");
        lab.assert_pending(&a).await;
    }

    let opts = SealOptions {
        kid: KidChoice::Other(rb.kid.clone().expect("b has a kid")),
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(&a, &opts).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::Resolve(ResolveError::NoCandidate))
    );
    assert_eq!(record.hpke_attempts, 0);
    lab.assert_pending(&a).await;
    lab.assert_pending(&b).await;
    lab.shutdown().await;
}

/// STATE-01: a valid response replayed after it was consumed is rejected without decryption.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequential_replay_is_rejected() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let (jwe, status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_success(status);
    assert_committed(&lab.record(), &session);

    let reply = lab
        .wallet
        .post_response(&session.response_uri, &jwe)
        .await
        .expect("post");
    assert_generic(reply.status, &reply.body);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::Resolve(ResolveError::Replay))
    );
    assert_eq!(record.hpke_attempts, 0);
    assert_eq!(lab.state(&session).await.as_deref(), Some("consumed"));
    lab.shutdown().await;
}

/// STATE-02: the same valid JWE POSTed concurrently is committed exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_identical_posts_consume_exactly_once() {
    for k in CONCURRENCY_LEVELS {
        let lab = Lab::start(Mode::Hardened).await;
        let session = lab.session(RouteKind::Unique).await;
        let request = lab
            .wallet
            .fetch_request(&session.request_uri)
            .await
            .expect("request");
        let jwe = lab
            .wallet
            .seal(&request, &SealOptions::default())
            .expect("seal");

        let mut tasks = Vec::with_capacity(k);
        for _ in 0..k {
            let wallet = lab.wallet.clone();
            let uri = request.response_uri.clone();
            let jwe = jwe.clone();
            tasks.push(tokio::spawn(async move {
                wallet.post_response(&uri, &jwe).await.expect("post")
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            let reply = task.await.expect("task");
            if reply.status == OK {
                accepted += 1;
            } else {
                assert_generic(reply.status, &reply.body);
            }
        }
        assert_eq!(accepted, 1, "k = {k}");

        let records = lab.server.evidence().take();
        assert_eq!(records.len(), k);
        let committed = records
            .iter()
            .filter(|r| r.commit_result == CommitResult::Committed)
            .count();
        assert_eq!(committed, 1, "k = {k}");
        for r in records
            .iter()
            .filter(|r| r.commit_result != CommitResult::Committed)
        {
            assert!(
                matches!(
                    r.rejection,
                    Some(Rejection::Resolve(ResolveError::Replay))
                        | Some(Rejection::Claim(ClaimError::Replay {
                            same_response: true
                        }))
                ),
                "loser rejected as replay: {r:?}"
            );
        }
        assert_eq!(lab.state(&session).await.as_deref(), Some("consumed"));
        lab.shutdown().await;
    }
}

/// STATE-06: failed decryption and failed validation do not consume the session; a later valid
/// response still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_jwe_does_not_consume_the_session() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;

    let tampered = SealOptions {
        tamper_ciphertext: true,
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(&session, &tampered).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.rejection, Some(Rejection::Decrypt));
    assert_eq!(record.commit_result, CommitResult::NotRun);
    lab.assert_pending(&session).await;

    // Decrypts (right session_info) but the presentation carries another nonce: HPKE alone is
    // never accepted as holder authentication.
    let wrong_presentation = SealOptions {
        presentation_nonce: Some("another-nonce".to_owned()),
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(&session, &wrong_presentation).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_eq!(
        record.validation_result,
        ValidationResult::Failed(ValidationError::NonceMismatch)
    );
    assert_eq!(
        record.rejection,
        Some(Rejection::Validation(ValidationError::NonceMismatch))
    );
    lab.assert_pending(&session).await;

    let wrong_aud = SealOptions {
        presentation_aud: Some(FOREIGN_CLIENT_ID.to_owned()),
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(&session, &wrong_aud).await;
    assert_generic(status, &body);
    assert_eq!(
        lab.record().rejection,
        Some(Rejection::Validation(ValidationError::AudienceMismatch))
    );
    lab.assert_pending(&session).await;

    let (_, status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_success(status);
    assert_committed(&lab.record(), &session);
    lab.shutdown().await;
}

/// Resolve, parse, decrypt, validate and replay failures all answer with the same bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generic_rejection_bodies_are_byte_identical() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let request = lab
        .wallet
        .fetch_request(&session.request_uri)
        .await
        .expect("request");
    let mut bodies = Vec::new();

    // Resolve: a well-formed route token no session was issued with.
    let unknown = session_core::RouteToken::generate().expect("token");
    let unknown_uri = format!(
        "{}/lab/v1/response/{}",
        lab.base(),
        unknown.to_url_segment()
    );
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");
    let reply = lab
        .wallet
        .post_response(&unknown_uri, &jwe)
        .await
        .expect("post");
    assert_eq!(
        lab.record().rejection,
        Some(Rejection::Resolve(ResolveError::NoCandidate))
    );
    bodies.push((reply.status, reply.body));

    // Parse: not a compact JWE at all.
    let reply = lab
        .wallet
        .post_response(&request.response_uri, "not.a.jwe")
        .await
        .expect("post");
    assert_eq!(
        lab.record().rejection,
        Some(Rejection::JweParse(JweError::SegmentCount { found: 3 }))
    );
    bodies.push((reply.status, reply.body));

    // Decrypt.
    let opts = SealOptions {
        tamper_ciphertext: true,
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(&session, &opts).await;
    assert_eq!(lab.record().rejection, Some(Rejection::Decrypt));
    bodies.push((status, body));

    // Validate.
    let opts = SealOptions {
        presentation_nonce: Some("another-nonce".to_owned()),
        ..SealOptions::default()
    };
    let (_, status, body) = lab.respond(&session, &opts).await;
    assert!(matches!(
        lab.record().rejection,
        Some(Rejection::Validation(_))
    ));
    bodies.push((status, body));

    // Replay.
    let reply = lab
        .wallet
        .post_response(&request.response_uri, &jwe)
        .await
        .expect("post");
    assert_success(reply.status);
    lab.record();
    let reply = lab
        .wallet
        .post_response(&request.response_uri, &jwe)
        .await
        .expect("post");
    assert_eq!(
        lab.record().rejection,
        Some(Rejection::Resolve(ResolveError::Replay))
    );
    bodies.push((reply.status, reply.body));

    for (status, body) in &bodies {
        assert_generic(*status, body);
    }
    lab.shutdown().await;
}

/// Hardened mode serves no shared route and refuses to create shared-route sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hardened_mode_has_no_shared_route() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let request = lab
        .wallet
        .fetch_request(&session.request_uri)
        .await
        .expect("request");
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");

    let shared = format!("{}/lab/v1/response/shared", lab.base());
    let reply = lab.wallet.post_response(&shared, &jwe).await.expect("post");
    assert_eq!(reply.status, NOT_FOUND);
    assert!(lab.server.evidence().take().is_empty(), "no pipeline ran");
    assert!(
        lab.wallet
            .create_session(&lab.base(), RouteKind::Shared, None)
            .await
            .is_err(),
        "hardened mode creates no shared-route session"
    );
    assert!(
        lab.wallet
            .create_session(&lab.base(), RouteKind::Unique, Some("fixed-nonce"))
            .await
            .is_err(),
        "hardened mode never takes a caller-chosen nonce"
    );
    lab.assert_pending(&session).await;
    lab.shutdown().await;
}

/// Research mode (shared URI / bounded trial) binds to loopback only, checked before binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn research_mode_refuses_non_loopback_bind() {
    let unspecified: SocketAddr = "0.0.0.0:0".parse().expect("addr");
    let test_net: SocketAddr = "192.0.2.1:0".parse().expect("addr");
    for strategy in [
        SharedRouteStrategy::UniqueKid,
        SharedRouteStrategy::BoundedTrial(CandidateBudget::new(2).expect("budget")),
    ] {
        for bind in [unspecified, test_net] {
            let mut config = LabConfig::new(research(strategy));
            config.bind = bind;
            match LabServer::start(config).await {
                Err(StartError::ResearchRequiresLoopback) => {}
                Err(other) => panic!("unexpected error for {bind}: {other:?}"),
                Ok(server) => {
                    server.shutdown().await;
                    panic!("research mode bound {bind}");
                }
            }
        }
    }
    let mut config = LabConfig::new(Mode::Research(SharedRouteStrategy::UniqueKid));
    config.bind = "[::1]:0".parse().expect("addr");
    if let Ok(server) = LabServer::start(config).await {
        server.shutdown().await;
    }
}

/// The background sweep expires and purges sessions whose TTL passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sweep_expires_and_purges_stale_sessions() {
    let mut config = LabConfig::new(Mode::Hardened);
    config.session_ttl = SHORT_TTL;
    config.sweep_interval = FAST_SWEEP;
    let lab = Lab::start_with(config).await;
    let session = lab.session(RouteKind::Unique).await;
    let request = lab
        .wallet
        .fetch_request(&session.request_uri)
        .await
        .expect("request");
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");

    tokio::time::sleep(EXPIRY_WAIT).await;
    assert_eq!(lab.state(&session).await, None, "purged after expiry");
    let reply = lab.wallet.get(&session.request_uri).await.expect("get");
    assert_eq!(reply.status, NOT_FOUND);
    let reply = lab
        .wallet
        .post_response(&request.response_uri, &jwe)
        .await
        .expect("post");
    assert_generic(reply.status, &reply.body);
    assert!(matches!(
        lab.record().rejection,
        Some(Rejection::Resolve(_))
    ));
    lab.shutdown().await;
}
