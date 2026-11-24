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
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
const SERVICE_UNAVAILABLE: u16 = 503;
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
/// Load-limit test: one request in flight, a short timeout, and a deadline for observing the
/// saturated state.
const SINGLE_IN_FLIGHT: usize = 1;
const SHORT_REQUEST_TIMEOUT: Duration = Duration::from_millis(500);
const SATURATION_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Request Timeout (RFC 9110 §15.5.9), answered for a body that never arrives.
const REQUEST_TIMEOUT_STATUS: &str = "HTTP/1.1 408";
/// Presentation member the lab never defines, and a value that pushes the vp_token past
/// `MAX_COMMITTED_VP_TOKEN_BYTES`.
const EXTRA_MEMBER: &str = "extra";
const OVERSIZE_FILLER: usize = lab_server::MAX_COMMITTED_VP_TOKEN_BYTES + 1;

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
            .session_state(&session.result_uri)
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
    assert_eq!(record.rejection, Some(Rejection::MissingKid));
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

        // Release every POST at once, so they race through resolve and claim together.
        let barrier = Arc::new(tokio::sync::Barrier::new(k));
        let mut tasks = Vec::with_capacity(k);
        for _ in 0..k {
            let wallet = lab.wallet.clone();
            let uri = request.response_uri.clone();
            let jwe = jwe.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
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
        let claim_replays = records
            .iter()
            .filter(|r| {
                r.rejection
                    == Some(Rejection::Claim(ClaimError::Replay {
                        same_response: true,
                    }))
            })
            .count();
        println!("k = {k}: {claim_replays} losers rejected at claim, the rest at resolve");
        if k == CONCURRENCY_LEVELS[CONCURRENCY_LEVELS.len() - 1] {
            // Losers that resolved before the commit reach the atomic claim and lose there; with
            // 128 simultaneous POSTs and HPKE between resolve and claim, some always do.
            assert!(
                claim_replays >= 1,
                "no loser reached the claim: {records:?}"
            );
        }
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

/// Every mode binds loopback only (lab policy until an ADR allows more), checked before
/// binding, with `IpAddr::is_loopback` semantics: `127.0.0.0/8` and `::1` pass; the
/// IPv4-mapped `::ffff:127.0.0.1` is not loopback under that definition and is refused, like
/// the unspecified addresses and a LAN address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_mode_binds_loopback_only() {
    let modes = [
        Mode::Hardened,
        research(SharedRouteStrategy::UniqueKid),
        trial(TRIAL_SIZES[0]),
    ];
    let refused = [
        "0.0.0.0:0",
        "[::]:0",
        "192.168.1.10:0",
        "[::ffff:127.0.0.1]:0",
    ];
    // `None` = the host has no IPv6 loopback, so binding `::1` must fail at bind, not policy.
    let ipv6_available = std::net::TcpListener::bind("[::1]:0").is_ok();
    for mode in modes {
        for bind in refused {
            let mut config = LabConfig::new(mode);
            config.bind = bind.parse().expect("addr");
            match LabServer::start(config).await {
                Err(StartError::LoopbackOnly) => {}
                Err(other) => panic!("{mode:?} {bind}: unexpected error {other:?}"),
                Ok(server) => {
                    server.shutdown().await;
                    panic!("{mode:?} bound non-loopback {bind}");
                }
            }
        }
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let want: SocketAddr = bind.parse().expect("addr");
            let mut config = LabConfig::new(mode);
            config.bind = want;
            match LabServer::start(config).await {
                Ok(server) => {
                    assert_eq!(server.local_addr().ip(), want.ip(), "{mode:?}");
                    server.shutdown().await;
                }
                Err(StartError::Bind(_)) if want.is_ipv6() && !ipv6_available => {}
                Err(other) => panic!("{mode:?} {bind}: loopback refused: {other:?}"),
            }
        }
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

/// M1: the synthetic presentation carries only `nonce` and `aud`, and the committed vp_token is
/// size-capped; neither an extra member nor an oversized one is committed or consumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presentation_with_extra_or_oversized_members_is_rejected_and_does_not_consume() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let cases = [
        (
            "x".to_owned(),
            ValidationError::UnexpectedPresentationMember,
        ),
        (
            "x".repeat(OVERSIZE_FILLER),
            ValidationError::VpTokenTooLarge,
        ),
    ];
    for (value, want) in cases {
        let opts = SealOptions {
            presentation_extra: vec![(EXTRA_MEMBER.to_owned(), value)],
            ..SealOptions::default()
        };
        let (_, status, body) = lab.respond(&session, &opts).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
        assert_eq!(record.rejection, Some(Rejection::Validation(want)));
        lab.assert_pending(&session).await;
    }
    let (_, status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_success(status);
    assert_committed(&lab.record(), &session);
    lab.shutdown().await;
}

/// M2: results are served only under the result token returned at session creation; the
/// session id that appears in the request_uri unlocks nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn results_are_served_only_by_result_token() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    assert!(
        !session.result_uri.contains(&session.session_id),
        "result token is not derived from the session id"
    );
    assert!(
        session
            .result_uri
            .starts_with(&format!("{}/lab/v1/results/", lab.base()))
    );
    lab.assert_pending(&session).await;
    for guess in [
        format!("{}/lab/v1/results/{}", lab.base(), session.session_id),
        format!(
            "{}/lab/v1/sessions/{}/result",
            lab.base(),
            session.session_id
        ),
    ] {
        let reply = lab.wallet.get(&guess).await.expect("get");
        assert_eq!(reply.status, NOT_FOUND, "{guess}");
    }
    lab.shutdown().await;
}

/// L5: every route requires a `kid` (the lab always advertises one, OpenID4VP 1.1 §8.3);
/// without it the response is refused before any HPKE attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jwe_without_kid_is_rejected_on_every_route() {
    let opts = SealOptions {
        kid: KidChoice::Omit,
        ..SealOptions::default()
    };
    for (mode, route) in [
        (Mode::Hardened, RouteKind::Unique),
        (research(SharedRouteStrategy::UniqueKid), RouteKind::Shared),
        (trial(TRIAL_SIZES[0]), RouteKind::Shared),
    ] {
        let lab = Lab::start(mode).await;
        let session = lab.session(route).await;
        let (_, status, body) = lab.respond(&session, &opts).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(record.rejection, Some(Rejection::MissingKid), "{mode:?}");
        assert_eq!(record.hpke_attempts, 0, "{mode:?}");
        assert_eq!(record.candidate_count, 0, "{mode:?}");
        lab.assert_pending(&session).await;
        lab.shutdown().await;
    }
}

/// L3: the in-flight limit sheds load with 503 (except `/health`, which stays responsive), and
/// a request whose body never arrives is answered 408 at the request timeout, freeing its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_limit_sheds_load_and_times_out_stalled_bodies() {
    let mut config = LabConfig::new(Mode::Hardened);
    config.max_in_flight_requests = SINGLE_IN_FLIGHT;
    config.request_timeout = SHORT_REQUEST_TIMEOUT;
    let lab = Lab::start_with(config).await;

    // Headers announce a body that is never sent: the request holds the only slot.
    let mut stalled = std::net::TcpStream::connect(lab.server.local_addr()).expect("connect");
    stalled
        .write_all(
            b"POST /lab/v1/sessions HTTP/1.1\r\nHost: lab\r\n\
              Content-Type: application/json\r\nContent-Length: 64\r\n\r\n",
        )
        .expect("write headers");

    let deadline = Instant::now() + SATURATION_DEADLINE;
    loop {
        match lab
            .wallet
            .create_session(&lab.base(), RouteKind::Unique, None)
            .await
        {
            Err(lab_server::wallet_sim::WalletError::Status(SERVICE_UNAVAILABLE)) => break,
            Ok(_) => {}
            Err(other) => panic!("unexpected: {other:?}"),
        }
        assert!(Instant::now() < deadline, "limit never engaged");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let health = format!("{}/health", lab.base());
    assert_eq!(lab.wallet.get(&health).await.expect("health").status, OK);

    let answer = tokio::task::spawn_blocking(move || {
        stalled
            .set_read_timeout(Some(SATURATION_DEADLINE))
            .expect("read timeout");
        let mut buf = [0u8; 64];
        let n = stalled.read(&mut buf).expect("stalled request is answered");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    })
    .await
    .expect("reader");
    assert!(answer.starts_with(REQUEST_TIMEOUT_STATUS), "{answer}");

    // The slot is free again.
    lab.wallet
        .create_session(&lab.base(), RouteKind::Unique, None)
        .await
        .expect("accepted after the stalled request timed out");
    lab.shutdown().await;
}

/// Drain deadline for the shutdown tests: long enough to release a parked POST inside it.
const SHORT_DRAIN: Duration = Duration::from_millis(400);
/// Time to let the drain start before releasing the parked POST (well inside `SHORT_DRAIN`).
const DRAIN_HEAD_START: Duration = Duration::from_millis(50);
/// How long a request must stay unserved to show the connection cap holds it back.
const CAPPED_WAIT: Duration = Duration::from_millis(300);

/// Waits until `n` POSTs are parked on the decryption semaphore.
async fn wait_parked(server: &LabServer, n: usize) {
    let deadline = Instant::now() + SATURATION_DEADLINE;
    while server.parked_trials() < n {
        assert!(Instant::now() < deadline, "POST never parked");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Review H1: in research mode a session created with a reused nonce on the shared route has
/// the same session_info as an already consumed one, so a previously accepted JWE decrypts and
/// validates for it. The verifier-wide replay guard refuses it (evidence CrossSessionReplay)
/// and the new session stays pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_session_replay_on_shared_route_is_rejected() {
    const REUSED_NONCE: &str = "lab-reused-nonce";
    let lab = Lab::start(trial(TRIAL_SIZES[0])).await;
    let base = lab.base();
    let create = || {
        lab.wallet
            .create_session(&base, RouteKind::Shared, Some(REUSED_NONCE))
    };
    let a = create().await.expect("session a");
    let (jwe, status, _) = lab.respond(&a, &SealOptions::default()).await;
    assert_success(status);
    assert_committed(&lab.record(), &a);

    let b = create().await.expect("session b with the same nonce");
    let reply = lab
        .wallet
        .post_response(&b.response_uri, &jwe)
        .await
        .expect("post");
    assert_generic(reply.status, &reply.body);
    let record = lab.record();
    assert_eq!(record.hpke_attempts, 1, "only b is live");
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 1 }
    );
    assert_eq!(record.rejection, Some(Rejection::CrossSessionReplay));
    assert_eq!(record.commit_result, CommitResult::NotRun);
    lab.assert_pending(&b).await;
    lab.shutdown().await;
}

/// Review M2: a caller-chosen research nonce is capped so that, with the longest allowed
/// client_id (all characters needing JSON escapes), a matching presentation still fits under
/// MAX_COMMITTED_VP_TOKEN_BYTES and commits; longer nonces and client ids are refused up front.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn research_nonce_length_is_capped_so_the_presentation_always_fits() {
    let mut config = LabConfig::new(trial(TRIAL_SIZES[0]));
    config.client_id =
        protocol_model::ClientIdWire::new("\"".repeat(lab_server::MAX_CLIENT_ID_LEN))
            .expect("client_id");
    let lab = Lab::start_with(config).await;
    let longest = "n".repeat(lab_server::MAX_RESEARCH_NONCE_LEN);
    let session = lab
        .wallet
        .create_session(&lab.base(), RouteKind::Shared, Some(&longest))
        .await
        .expect("nonce at the cap is accepted");
    let (_, status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_success(status);
    assert_committed(&lab.record(), &session);

    let too_long = "n".repeat(lab_server::MAX_RESEARCH_NONCE_LEN + 1);
    match lab
        .wallet
        .create_session(&lab.base(), RouteKind::Shared, Some(&too_long))
        .await
    {
        Err(lab_server::wallet_sim::WalletError::Status(BAD_REQUEST)) => {}
        other => panic!("over-long nonce accepted: {other:?}"),
    }
    lab.shutdown().await;

    let mut config = LabConfig::new(Mode::Hardened);
    config.client_id =
        protocol_model::ClientIdWire::new("c".repeat(lab_server::MAX_CLIENT_ID_LEN + 1))
            .expect("client_id");
    assert!(matches!(
        LabServer::start(config).await,
        Err(StartError::ClientIdTooLong)
    ));
}

/// Review M3: shutdown drains gracefully. A POST parked on the decryption semaphore and
/// released during the drain commits before shutdown returns; one still parked at the drain
/// deadline can never commit afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_drains_in_flight_requests_and_commits_nothing_afterwards() {
    for release_during_drain in [true, false] {
        let mut config = LabConfig::new(Mode::Hardened);
        config.shutdown_drain = SHORT_DRAIN;
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

        let pause = lab.server.pause_decryptions().await;
        let wallet = lab.wallet.clone();
        let uri = request.response_uri.clone();
        let post = tokio::spawn(async move { wallet.post_response(&uri, &jwe).await });
        wait_parked(&lab.server, 1).await;

        let evidence = lab.server.evidence().clone();
        let Lab { server, .. } = lab;
        let shutdown = tokio::spawn(server.shutdown());
        if release_during_drain {
            tokio::time::sleep(DRAIN_HEAD_START).await;
            drop(pause);
            shutdown.await.expect("shutdown");
            let records = evidence.take();
            assert_eq!(records.len(), 1, "committed before shutdown returned");
            assert_eq!(records[0].commit_result, CommitResult::Committed);
            let reply = post
                .await
                .expect("task")
                .expect("answered during the drain");
            assert_success(reply.status);
        } else {
            shutdown.await.expect("shutdown");
            drop(pause);
            // The connection task still finishes the request, but can never commit it.
            let reply = post.await.expect("task").expect("answered after shutdown");
            assert_generic(reply.status, &reply.body);
            let records = evidence.take();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].rejection, Some(Rejection::ShuttingDown));
            assert_eq!(records[0].commit_result, CommitResult::NotRun);
        }
    }
}

/// Review L4: a connection that never sends headers holds a connection slot, so the cap on
/// accepted connections (not only the in-flight request limit) bounds such stalls; the slot
/// frees when that connection closes. `/health` is used because it bypasses the request limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_cap_holds_connections_stalled_before_headers() {
    let mut config = LabConfig::new(Mode::Hardened);
    config.max_connections = SINGLE_IN_FLIGHT;
    let lab = Lab::start_with(config).await;
    let health = format!("{}/health", lab.base());

    let stalled = std::net::TcpStream::connect(lab.server.local_addr()).expect("connect");
    let waited = tokio::time::timeout(CAPPED_WAIT, lab.wallet.get(&health)).await;
    assert!(
        waited.is_err(),
        "served while the only slot was held: {waited:?}"
    );

    drop(stalled);
    let reply = lab
        .wallet
        .get(&health)
        .await
        .expect("served after the slot freed");
    assert_eq!(reply.status, OK);
    lab.shutdown().await;
}

/// Connection cap of the stalled-header test: one slot, so a second connection is served only
/// after the stalled one is closed.
const STALL_TEST_MAX_CONNECTIONS: usize = 1;
/// The server must not close before this fraction of the header timeout has elapsed.
const HEADER_TIMEOUT_LOWER_BOUND_DIVISOR: u32 = 2;
/// Header read timeout used by the stalled-header test.
const SHORT_HEADER_TIMEOUT: Duration = Duration::from_millis(500);
/// Slack for scheduling jitter on the upper side of the header-timeout assertions.
const HEADER_TIMEOUT_SLACK: Duration = Duration::from_secs(3);
/// Bound on how long the test waits for the server to close a stalled connection.
const STALL_CLOSE_DEADLINE: Duration = Duration::from_secs(10);

/// A client that sends a partial request and stalls is disconnected at about the header read
/// timeout, and its connection slot frees: with `max_connections = 1` a following request is
/// served. Not early (the timeout is not a hair trigger), not much later (no indefinite hold).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_header_connection_is_closed_at_the_header_timeout_and_frees_its_slot() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut config = LabConfig::new(Mode::Hardened);
    config.max_connections = STALL_TEST_MAX_CONNECTIONS;
    config.header_read_timeout = SHORT_HEADER_TIMEOUT;
    let lab = Lab::start_with(config).await;

    let mut stalled = tokio::net::TcpStream::connect(lab.server.local_addr())
        .await
        .expect("connect");
    stalled
        .write_all(b"GET /health HTTP/1.1\r\nHost: lab\r\nX-Partial: ")
        .await
        .expect("send partial headers");

    let started = Instant::now();
    let mut buf = Vec::new();
    let closed = tokio::time::timeout(STALL_CLOSE_DEADLINE, stalled.read_to_end(&mut buf)).await;
    let elapsed = started.elapsed();
    assert!(closed.is_ok(), "server never closed the stalled connection");
    assert!(
        elapsed >= SHORT_HEADER_TIMEOUT / HEADER_TIMEOUT_LOWER_BOUND_DIVISOR
            && elapsed <= SHORT_HEADER_TIMEOUT + HEADER_TIMEOUT_SLACK,
        "closed after {elapsed:?}, expected about {SHORT_HEADER_TIMEOUT:?}"
    );

    let reply = lab
        .wallet
        .get(&format!("{}/health", lab.base()))
        .await
        .expect("served after the stalled connection's slot freed");
    assert_eq!(reply.status, OK);
    lab.shutdown().await;
}

/// HTTP status of a request cut off by the request timeout (RFC 9110 §15.5.9).
const HTTP_REQUEST_TIMEOUT: u16 = 408;

/// PR review: a POST that times out while parked on the decryption semaphore is dropped by the
/// timeout middleware before it reaches the slot; the parked-trial counter must not keep
/// counting it, or later research steps that wait on `parked_trials()` proceed too early.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_parked_post_is_no_longer_counted_as_parked() {
    let mut config = LabConfig::new(Mode::Hardened);
    config.request_timeout = SHORT_REQUEST_TIMEOUT;
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

    let pause = lab.server.pause_decryptions().await;
    let reply = {
        let post = lab.wallet.post_response(&request.response_uri, &jwe);
        let parked = wait_parked(&lab.server, 1);
        let (reply, ()) = tokio::join!(post, parked);
        reply.expect("answered")
    };
    assert_eq!(reply.status, HTTP_REQUEST_TIMEOUT);
    assert_eq!(
        lab.server.parked_trials(),
        0,
        "timed-out POST still counted"
    );
    drop(pause);
    lab.shutdown().await;
}
