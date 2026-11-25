//! G7 interop groundwork: the scenarios of OIDF OpenID4VP issue #792 ("HPKE `session_info`
//! requires the session that only decryption can reveal",
//! <https://github.com/openid/OpenID4VP/issues/792>, read 2026-11-25) as named lab tests.
//!
//! Only what the existing suite does not already show lives here. The mapping of every claim
//! of the issue to these and to the existing tests (`http_e2e.rs`, `holder_binding_e2e.rs`,
//! jose-hpke `session_info.rs`, session-core `resolution.rs`) is in
//! `docs/interop/issue-792-reproduction.md`.
//!
//! Spec text these tests exercise: OpenID4VP 1.1 Editor's draft of 11 November 2026, §8.3
//! (`kid` identifies the *public key*), §8.3.1 (`session_info` = client_id ‖ nonce ‖
//! response_uri is the HPKE `info`), §8.3.2 (`direct_post.jwt` body carries `response`).
//!
//! Every test starts its own loopback lab server and drives it with the wallet simulator. All
//! keys, nonces and presentations are synthetic.

use std::collections::HashSet;

use jose_hpke::CompactJwe;
use lab_server::wallet_sim::{
    CreatedSession, KidChoice, PresentationTamper, RequestObject, SealOptions, SyntheticIssuer,
    WalletSim,
};
use lab_server::{
    AdmissionError, CommitResult, CryptoResult, EvidenceRecord, GENERIC_REJECTION_BODY, LabConfig,
    LabServer, Mode, Rejection, RequestSigningKey, RouteKind, SharedRouteStrategy,
    TrustedIssuerKey, ValidationError, ValidationResult,
};
use serde_json::json;
use session_core::{CandidateBudget, ResolutionStrategy};

/// Media type of a `direct_post.jwt` POST body (OpenID4VP 1.1 §8.3.2).
const FORM: &str = "application/x-www-form-urlencoded";
/// HTTP statuses the tests pin (RFC 9110 §15).
const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
/// Live sessions per scenario: the same sizes as the `http_e2e.rs` shared-route scenarios.
const POPULATIONS: [usize; 3] = [2, 8, 32];
/// Two sessions are enough to show a mis-correlation.
const PAIR: usize = 2;
/// A synthetic `state` value, as a 1.0-style Verifier would read it from a `direct_post` body.
const CLEARTEXT_STATE: &str = "3b9404401ea74da7";

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

    /// Seals for `session`'s request object with `opts` and POSTs to its response_uri.
    async fn respond(&self, session: &CreatedSession, opts: &SealOptions) -> (u16, Vec<u8>) {
        let request = self.request(session).await;
        let jwe = self.wallet.seal(&request, opts).expect("wallet seals");
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
}

/// Research mode, shared route, one key and `kid` for every session: the #792 shape.
fn shared_key(budget: usize) -> Mode {
    Mode::Research(SharedRouteStrategy::BoundedTrial(
        CandidateBudget::new(budget).expect("valid budget"),
    ))
}

fn assert_generic(status: u16, body: &[u8]) {
    assert_eq!(status, BAD_REQUEST);
    assert_eq!(body, GENERIC_REJECTION_BODY.as_bytes());
}

fn distinct<T: std::hash::Hash + Eq>(values: impl IntoIterator<Item = T>) -> usize {
    values.into_iter().collect::<HashSet<_>>().len()
}

/// #792 "The Verifier is not missing the *values* — it issued all three itself in (1). It
/// cannot tell **which (1) this (2) is answering**", and "`kid` identifies a *key*, not a
/// session". With a shared response_uri and a shared key, the sessions' `session_info` inputs
/// differ only in `nonce` (their `state`s differ too, inside the ciphertext), and what reaches
/// the Verifier before decryption (POST target and JWE
/// protected header) is byte-identical across sessions. The Verifier can only make every live
/// session a candidate; the nonce inside `session_info` is what lets exactly one of them open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue_792_shared_uri_and_kid_leave_nothing_outside_the_ciphertext_to_correlate_on() {
    let n = POPULATIONS[1];
    let lab = Lab::start(shared_key(n)).await;
    let sessions = lab.sessions(RouteKind::Shared, n).await;
    let mut requests = Vec::with_capacity(n);
    for s in &sessions {
        requests.push(lab.request(s).await);
    }

    // The three session_info inputs and the encryption key: only the nonce varies.
    assert_eq!(distinct(requests.iter().map(|r| r.client_id.as_str())), 1);
    assert_eq!(
        distinct(requests.iter().map(|r| r.response_uri.as_str())),
        1
    );
    assert!(
        requests[0].kid.is_some(),
        "the shared key is advertised with a kid"
    );
    assert_eq!(distinct(requests.iter().map(|r| r.kid.as_deref())), 1);
    assert_eq!(
        distinct(requests.iter().map(|r| r.public_key.to_bytes())),
        1
    );
    assert_eq!(distinct(requests.iter().map(|r| r.nonce.as_str())), n);
    // `state` differs per session too, but it is not a session_info input and travels only
    // inside the ciphertext (§8.3), so it is no pre-decryption correlator either.
    assert_eq!(distinct(requests.iter().map(|r| r.state.as_deref())), n);

    // Pre-decryption view of each session's honest response: same path, same protected header
    // bytes (so the same `kid`), and a body that carries `response` only.
    let jwes: Vec<String> = requests
        .iter()
        .map(|r| lab.wallet.seal(r, &SealOptions::default()).expect("seal"))
        .collect();
    let protected = |jwe: &str| jwe.split('.').next().expect("segment").to_owned();
    assert_eq!(distinct(jwes.iter().map(|j| protected(j))), 1);
    for jwe in &jwes {
        let parsed = CompactJwe::parse(jwe).expect("lab policy accepts the header");
        assert_eq!(
            parsed.header().kid().map(|k| k.as_str()),
            requests[0].kid.as_deref()
        );
    }

    let target = n / 2;
    let reply = lab
        .wallet
        .post_response(&requests[target].response_uri, &jwes[target])
        .await
        .expect("post");
    assert_eq!(reply.status, OK);
    let record = lab.record();
    assert_eq!(
        record.candidate_count, n,
        "every live session is a candidate"
    );
    assert_eq!(record.hpke_attempts, n);
    assert_eq!(
        record.crypto_result,
        CryptoResult::Opened { opened: 1 },
        "the per-session nonce in session_info is the only discriminator"
    );
    assert_eq!(
        record.committed_session.as_ref().map(|id| id.as_str()),
        Some(sessions[target].session_id.as_str())
    );
    lab.server.shutdown().await;
}

/// #792 / #708: under 1.0 `direct_post` the Verifier matches on the cleartext `state`; under
/// `direct_post.jwt` it is inside the JWE (§8.3: "The payload of the encrypted JWT response
/// MUST include the contents of the response as defined in Section 8.1"). Lab policy, not a
/// spec MUST: an unauthenticated cleartext `state` next to `response` is not accepted as a
/// correlation shortcut; it is refused at admission, before any HPKE work, and the session
/// stays pending and still accepts the same JWE alone.
///
/// Overlap: `http_e2e.rs` `admission_failures_are_rejected_before_decryption` already refuses
/// a `state` *alone* and a plaintext `vp_token` beside `response`, on a unique URI. This test
/// adds `state` *next to a valid `response`*, on the shared bounded-trial route, where a
/// cleartext correlator would be the only pre-decryption way to pick a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue_792_cleartext_state_beside_the_jwe_is_refused_before_decryption() {
    let lab = Lab::start(shared_key(PAIR)).await;
    let sessions = lab.sessions(RouteKind::Shared, PAIR).await;
    let target = &sessions[0];
    let request = lab.request(target).await;
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("response", &jwe)
        .append_pair("state", CLEARTEXT_STATE)
        .finish()
        .into_bytes();

    let reply = lab
        .wallet
        .post_raw(&request.response_uri, FORM, body)
        .await
        .expect("endpoint answers");
    assert_eq!(reply.status, BAD_REQUEST);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::Admission(AdmissionError::UnexpectedParameter))
    );
    assert_eq!(record.candidate_count, 0);
    assert_eq!(record.hpke_attempts, 0);
    assert_eq!(lab.state(target).await, "pending");

    let reply = lab
        .wallet
        .post_response(&request.response_uri, &jwe)
        .await
        .expect("post");
    assert_eq!(reply.status, OK);
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    lab.server.shutdown().await;
}

/// #792 "Workarounds, none of them written down": (1) a distinct response_uri per
/// transaction, (2) a distinct encryption key per session identified by `kid`, (3) trial
/// decryption against every pending session, "O(n) HPKE operations per response". Same live
/// population N for all three; the evidence records the cost the issue predicts (1 / 1 / N
/// HPKE attempts), exactly one candidate opens, and only the addressed session is consumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue_792_workarounds_compared_on_one_population() {
    for n in POPULATIONS {
        // (name, mode, route, strategy, distinct response_uris, distinct kids, HPKE attempts)
        let cases = [
            (
                "unique response_uri",
                Mode::Hardened,
                RouteKind::Unique,
                ResolutionStrategy::UniqueUri,
                n,
                n,
                1,
            ),
            (
                "unique kid",
                Mode::Research(SharedRouteStrategy::UniqueKid),
                RouteKind::Shared,
                ResolutionStrategy::UniqueKid,
                1,
                n,
                1,
            ),
            (
                "trial decryption",
                shared_key(n),
                RouteKind::Shared,
                ResolutionStrategy::BoundedTrial(CandidateBudget::new(n).expect("budget")),
                1,
                1,
                n,
            ),
        ];
        for (name, mode, route, want_strategy, want_uris, want_kids, want_attempts) in cases {
            let lab = Lab::start(mode).await;
            let sessions = lab.sessions(route, n).await;
            let mut requests = Vec::with_capacity(n);
            for s in &sessions {
                requests.push(lab.request(s).await);
            }
            let uris = distinct(requests.iter().map(|r| r.response_uri.as_str()));
            let kids = distinct(requests.iter().map(|r| r.kid.as_deref()));
            assert_eq!((uris, kids), (want_uris, want_kids), "{name}, N={n}");

            let target = &sessions[n - 1];
            let (status, _) = lab.respond(target, &SealOptions::default()).await;
            assert_eq!(status, OK, "{name}, N={n}");
            let record = lab.record();
            assert_eq!(record.strategy, want_strategy, "{name}, N={n}");
            assert_eq!(record.candidate_count, want_attempts, "{name}, N={n}");
            assert_eq!(record.hpke_attempts, want_attempts, "{name}, N={n}");
            assert_eq!(
                record.crypto_result,
                CryptoResult::Opened { opened: 1 },
                "{name}, N={n}"
            );
            assert_eq!(
                record.commit_result,
                CommitResult::Committed,
                "{name}, N={n}"
            );
            for s in &sessions {
                let want = if s.session_id == target.session_id {
                    "consumed"
                } else {
                    "pending"
                };
                assert_eq!(lab.state(s).await, want, "{name}, N={n}");
            }
            lab.server.shutdown().await;
        }
    }
}

/// #792 workaround (2) "Stretches `kid` beyond the role §8.3 gives it": the `kid` is read from
/// the unauthenticated JWE header, so it is a hint, not a session identifier. A JWE sealed to
/// session A (A's key and session_info) but labelled with B's `kid` selects B as the only
/// candidate, fails to open under B's key, and consumes nothing; A still accepts its own
/// honest response afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue_792_kid_of_another_session_on_the_unique_kid_route_fails_closed() {
    let lab = Lab::start(Mode::Research(SharedRouteStrategy::UniqueKid)).await;
    let sessions = lab.sessions(RouteKind::Shared, PAIR).await;
    let (a, b) = (&sessions[0], &sessions[1]);
    let kid_b = lab
        .request(b)
        .await
        .kid
        .expect("b is advertised with a kid");

    let misdirected = SealOptions {
        kid: KidChoice::Other(kid_b),
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(a, &misdirected).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.strategy, ResolutionStrategy::UniqueKid);
    assert_eq!(record.candidate_count, 1, "the kid selected B");
    assert_eq!(record.hpke_attempts, 1);
    assert_eq!(record.crypto_result, CryptoResult::NoneOpened);
    assert_eq!(record.rejection, Some(Rejection::Decrypt));
    assert_eq!(lab.state(a).await, "pending");
    assert_eq!(lab.state(b).await, "pending");

    let (status, _) = lab.respond(a, &SealOptions::default()).await;
    assert_eq!(status, OK);
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    lab.server.shutdown().await;
}

/// Lab finding beyond #792: trial decryption opens the session whose `session_info` the
/// *sender* chose. All three inputs (client_id, nonce, response_uri) are in the Request
/// Object, which anyone holding the `request_uri` can fetch, and HPKE encrypts to a public
/// key, so a successful open is not evidence that the response belongs to that session. Here
/// a valid holder proof for A is sealed with B's session_info on the shared-key route: it opens
/// for B only, and B's holder-binding check (KB-JWT `nonce`, OpenID4VP 1.1 §14.2.2) is what
/// refuses it. Both sessions stay pending; the same proof sealed for A commits A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue_792_trial_opens_the_session_the_sender_bound_and_holder_binding_decides() {
    let lab = Lab::start(shared_key(PAIR)).await;
    let sessions = lab.sessions(RouteKind::Shared, PAIR).await;
    let (a, b) = (&sessions[0], &sessions[1]);
    let presentation = lab
        .wallet
        .present(&lab.request(a).await, &PresentationTamper::None)
        .expect("presentation for A");
    let proof_of_a = SealOptions {
        vp_token: Some(json!({ lab_server::SYNTHETIC_CREDENTIAL_QUERY_ID: [presentation] })),
        ..SealOptions::default()
    };

    let (status, body) = lab.respond(b, &proof_of_a).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.candidate_count, PAIR);
    assert_eq!(record.hpke_attempts, PAIR);
    assert_eq!(
        record.crypto_result,
        CryptoResult::Opened { opened: 1 },
        "it decrypts, for the session the sender bound it to"
    );
    assert_eq!(
        record.validation_result,
        ValidationResult::Failed(ValidationError::KbNonceMismatch)
    );
    assert_eq!(lab.state(a).await, "pending");
    assert_eq!(lab.state(b).await, "pending");

    let (status, _) = lab.respond(a, &proof_of_a).await;
    assert_eq!(status, OK);
    let record = lab.record();
    assert_eq!(
        record.committed_session.as_ref().map(|id| id.as_str()),
        Some(a.session_id.as_str())
    );
    lab.server.shutdown().await;
}
