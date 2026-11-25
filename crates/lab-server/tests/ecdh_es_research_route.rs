//! The OpenID4VP 1.0-style ECDH-ES research route (`ecdh-es-research`;
//! docs/adr/0001-ecdh-es-research-route.md): experiments E1-E7 of
//! `docs/interop/issue-792-reproduction.md` §7 (S23-S38), over real loopback HTTP with the
//! wallet simulator.
//!
//! Spec text these tests exercise:
//! - OpenID4VP 1.0 Final §5.1: `encrypted_response_enc_values_supported` ("MUST be present for
//!   anything other than the default single value of `A128GCM`").
//! - OpenID4VP 1.0 Final §8.3: "The JWE `alg` algorithm used MUST be equal to the `alg` value
//!   of the chosen `jwk`", the JWE carries its `kid`, and the payload carries the §8.1 response
//!   parameters as top-level JSON members (here `vp_token` and the echoed `state`).
//! - RFC 7518 §4.6: ECDH-ES Direct Key Agreement derives the CEK from the recipient key alone;
//!   nothing session-specific enters the key schedule.
//!
//! Invariants under test:
//! - E1: with N sessions on the shared key, an honest response opens under the key of every
//!   live session (attempts = opened = live sessions), so decryption cannot select one; the
//!   decrypted `state` is the only selector. The HPKE-0 shared route, same population and one
//!   shared key, opens for exactly one (`session_info`).
//! - E2: an honest response commits exactly the session its `state` names, for `A128GCM` and
//!   `A256GCM`; the Request Object advertises the shared ECDH-ES key and both `enc` values.
//! - E3: `state` is a correlator, not authentication: A's valid holder proof carrying B's
//!   `state` is routed to B and refused by B's KB-JWT nonce binding; A then commits.
//! - E4: a missing, unknown, non-string or another route's `state` is refused and consumes
//!   nothing; so is a JWE whose `kid` is not the route's.
//! - E5: the same JWE twice commits once; a reused nonce and `state` (research knobs) let the
//!   same holder proof validate for a second session, which the replay guard refuses (verbatim:
//!   `CrossSessionReplay`; re-sealed: `HolderProofReplay`); two live sessions sharing both are
//!   `Ambiguous`.
//! - E6: no downgrade or cross-route acceptance: HPKE-0 to the ECDH-ES route and ECDH-ES to the
//!   HPKE-0 unique and shared routes are refused at parse; a plaintext `vp_token` is refused at
//!   admission on the ECDH-ES route too.
//! - E7: hardened mode serves no ECDH-ES route (404) and creates no ECDH-ES session, and a
//!   research server serves it only when configured to (`LabConfig::ecdh_es_route`).
//! - The route's pending sessions are capped at `MAX_CANDIDATE_BUDGET`; a `state` the research
//!   knob gives two sessions is disambiguated by holder binding; expired sessions are never
//!   candidates.
//!
//! Every test starts its own loopback lab server. All keys, nonces, states and presentations
//! are synthetic.

use std::collections::HashSet;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_ecdh_es::ContentEncryption;
use lab_server::wallet_sim::{
    CreatedSession, KidChoice, PresentationTamper, RequestObject, SealOptions, StateChoice,
    SyntheticIssuer, WalletError, WalletSim,
};
use lab_server::{
    AdmissionError, CommitResult, CryptoResult, EvidenceRecord, GENERIC_REJECTION_BODY, LabConfig,
    LabServer, Mode, Rejection, RequestSigningKey, RouteKind, SYNTHETIC_CREDENTIAL_QUERY_ID,
    SharedRouteStrategy, StartError, TrustedIssuerKey, ValidationError, ValidationResult,
};
use serde_json::{Value, json};
use session_core::{CandidateBudget, MAX_CANDIDATE_BUDGET, ResolveError};

/// HTTP statuses the tests pin (RFC 9110 §15).
const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
const NOT_FOUND: u16 = 404;
const SERVICE_UNAVAILABLE: u16 = 503;
/// Session lifetime of the expiry test: the shortest whole-second TTL (Request Object `exp` is
/// a whole-second NumericDate), and how far past it the test waits so the session is surely due.
const SHORT_TTL: Duration = Duration::from_secs(1);
const EXPIRY_MARGIN: Duration = Duration::from_millis(250);
/// E1 population: eight live sessions on one shared key (the middle `http_e2e.rs` size).
const POPULATION: usize = 8;
/// Two sessions are enough to show a mis-correlation.
const PAIR: usize = 2;
/// Media types of the lab endpoints (OpenID4VP 1.1 §8.2; lab session creation).
const FORM: &str = "application/x-www-form-urlencoded";
const JSON: &str = "application/json";
/// Lab paths (lab infrastructure, not OpenID4VP endpoints).
const SESSIONS_PATH: &str = "/lab/v1/sessions";
const ECDH_ES_RESPONSE_PATH: &str = "/lab/v1/response/ecdh-es";
/// `route` value that creates an ECDH-ES session.
const ECDH_ES_ROUTE: &str = "ecdh_es_shared";
/// OpenID4VP 1.0 §5.1 `client_metadata` member, and the values the route advertises.
const ENC_VALUES_MEMBER: &str = "encrypted_response_enc_values_supported";
const ADVERTISED_ENC: [&str; 2] = ["A128GCM", "A256GCM"];
/// `alg` values (RFC 7518 §4.6; draft-ietf-jose-hpke-encrypt).
const ALG_ECDH_ES: &str = "ECDH-ES";
/// A `state` no session was issued, a non-string one, and a `kid` no key has.
const UNKNOWN_STATE: &str = "lab-unknown-state";
const NUMERIC_STATE: u64 = 42;
const OTHER_KID: &str = "lab-other-kid";
/// Research-knob values two sessions share (E5).
const REUSED_NONCE: &str = "lab-reused-nonce";
const REUSED_STATE: &str = "lab-reused-state";
/// JWS compact segments: header, payload, signature (RFC 7515 §7.1).
const JWS_PAYLOAD_SEGMENT: usize = 1;

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

/// `mode` with the fixture keys; the ECDH-ES route is off (`LabConfig::new`'s default).
fn config(mode: Mode) -> LabConfig {
    LabConfig::new(
        mode,
        RequestSigningKey::from_jwk(FIXTURE_JWK).expect("fixture signing key"),
        TrustedIssuerKey::from_jwk(ISSUER_PUBLIC_JWK).expect("fixture issuer key"),
    )
}

/// Research mode with the shared HPKE-0 route (one shared key, budget `budget`).
fn bounded_trial(budget: usize) -> Mode {
    Mode::Research(SharedRouteStrategy::BoundedTrial(
        CandidateBudget::new(budget).expect("valid budget"),
    ))
}

/// The research configuration of these tests: [`bounded_trial`] plus the opt-in ECDH-ES route.
fn ecdh_es_config(budget: usize) -> LabConfig {
    let mut config = config(bounded_trial(budget));
    config.ecdh_es_route = true;
    config
}

impl Lab {
    async fn start(mode: Mode) -> Self {
        Self::with_config(config(mode)).await
    }

    async fn with_config(config: LabConfig) -> Self {
        let server = LabServer::start(config).await.expect("lab server starts");
        assert!(server.local_addr().ip().is_loopback());
        let issuer = SyntheticIssuer::from_jwk(ISSUER_JWK).expect("fixture issuer");
        Self {
            server,
            wallet: WalletSim::new(&issuer).expect("wallet simulator builds"),
        }
    }

    /// Research mode (shared HPKE-0 route with one shared key, budget `budget`) plus the
    /// ECDH-ES route.
    async fn research(budget: usize) -> Self {
        Self::with_config(ecdh_es_config(budget)).await
    }

    async fn sessions(&self, route: RouteKind, n: usize) -> Vec<CreatedSession> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.session(route, None, None).await);
        }
        out
    }

    async fn session(
        &self,
        route: RouteKind,
        nonce: Option<&str>,
        state: Option<&str>,
    ) -> CreatedSession {
        self.wallet
            .create_research_session(&self.server.base_url(), route, nonce, state)
            .await
            .expect("session is created")
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

    async fn assert_pending(&self, sessions: &[&CreatedSession]) {
        for session in sessions {
            assert_eq!(
                self.state(session).await,
                "pending",
                "{}",
                session.session_id
            );
        }
    }

    /// Seals `request` as ECDH-ES with `enc` and `opts`.
    fn seal(&self, request: &RequestObject, enc: ContentEncryption, opts: &SealOptions) -> String {
        self.wallet
            .seal_ecdh_es(request, enc, opts)
            .expect("wallet seals ECDH-ES")
    }

    async fn post(&self, uri: &str, jwe: &str) -> (u16, Vec<u8>) {
        let reply = self
            .wallet
            .post_response(uri, jwe)
            .await
            .expect("response endpoint answers");
        (reply.status, reply.body)
    }

    /// Seals `request` as ECDH-ES `A128GCM` with `opts` and POSTs it to its response_uri.
    async fn respond(&self, request: &RequestObject, opts: &SealOptions) -> (u16, Vec<u8>) {
        let jwe = self.seal(request, ContentEncryption::A128Gcm, opts);
        self.post(&request.response_uri, &jwe).await
    }

    /// The only evidence record since the last call.
    fn record(&self) -> EvidenceRecord {
        let mut records = self.server.evidence().take();
        assert_eq!(records.len(), 1, "exactly one evidence record: {records:?}");
        records.remove(0)
    }

    /// The decoded payload of `session`'s signed Request Object.
    async fn request_payload(&self, session: &CreatedSession) -> Value {
        let reply = self
            .wallet
            .get(&session.request_uri)
            .await
            .expect("request_uri answers");
        assert_eq!(reply.status, OK);
        let jwt = String::from_utf8(reply.body).expect("compact JWS is ASCII");
        let payload = jwt
            .split('.')
            .nth(JWS_PAYLOAD_SEGMENT)
            .expect("payload segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("payload is JSON")
    }
}

fn assert_generic(status: u16, body: &[u8]) {
    assert_eq!(status, BAD_REQUEST);
    assert_eq!(body, GENERIC_REJECTION_BODY.as_bytes());
}

fn assert_committed(record: &EvidenceRecord, session: &CreatedSession) {
    assert_eq!(record.rejection, None, "{record:?}");
    assert_eq!(record.commit_result, CommitResult::Committed);
    assert_eq!(
        record.committed_session.as_ref().map(|id| id.as_str()),
        Some(session.session_id.as_str())
    );
}

fn state_of(request: &RequestObject) -> String {
    request.state.clone().expect("request carries a state")
}

/// An honest `vp_token` for `request`, to re-seal verbatim.
fn vp_token(lab: &Lab, request: &RequestObject) -> Value {
    let presentation = lab
        .wallet
        .present(request, &PresentationTamper::None)
        .expect("presentation");
    json!({ SYNTHETIC_CREDENTIAL_QUERY_ID: [presentation] })
}

/// E1 (#792 §4 item 1, measured). Eight live sessions share the route's one ECDH-ES key. Each
/// honest response, posted for one session after another, opens under the key of *every* live
/// session (attempts = opened = live sessions), so trial decryption cannot select a session;
/// the decrypted `state` selects exactly one (validated = 1), and it is the right one. On the
/// HPKE-0 shared route with the same population and one shared key, the same honest response
/// opens for exactly one candidate: `session_info` selects there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_shared_key_opens_for_every_live_session_and_only_state_selects() {
    let lab = Lab::research(POPULATION).await;

    let hpke = lab.sessions(RouteKind::Shared, POPULATION).await;
    let last = hpke.last().expect("population is not empty");
    let request = lab.request(last).await;
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");
    let (status, _) = lab.post(&request.response_uri, &jwe).await;
    assert_eq!(status, OK);
    let record = lab.record();
    assert_eq!(record.hpke_attempts, POPULATION);
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_committed(&record, last);

    let sessions = lab.sessions(RouteKind::EcdhEs, POPULATION).await;
    let mut requests = Vec::with_capacity(POPULATION);
    for session in &sessions {
        requests.push(lab.request(session).await);
    }
    let kids: HashSet<_> = requests.iter().map(|r| r.kid.clone()).collect();
    assert_eq!(kids.len(), 1, "one kid for every session on the route");
    let states: HashSet<_> = requests.iter().map(state_of).collect();
    assert_eq!(states.len(), POPULATION, "one state per session");

    for (done, (session, request)) in sessions.iter().zip(&requests).enumerate() {
        let live = POPULATION - done;
        let (status, _) = lab.respond(request, &SealOptions::default()).await;
        assert_eq!(status, OK);
        let record = lab.record();
        assert_eq!(record.route, RouteKind::EcdhEs);
        assert_eq!(record.candidate_count, live);
        assert_eq!(
            record.hpke_attempts, live,
            "one ECDH-ES open per live session"
        );
        assert_eq!(
            record.crypto_result,
            CryptoResult::Opened { opened: live },
            "the shared key opens the response for every live session"
        );
        assert_eq!(
            record.validation_result,
            ValidationResult::Passed { validated: 1 },
            "state selects exactly one"
        );
        assert_committed(&record, session);
        assert_eq!(lab.state(session).await, "consumed");
    }
    lab.server.shutdown().await;
}

/// E2. The Request Object of an ECDH-ES session advertises the route's shared key (`alg`
/// `ECDH-ES`, `use` `enc`, `kid`, OpenID4VP 1.0 §8.3) and `encrypted_response_enc_values_supported`
/// `["A128GCM", "A256GCM"]` (§5.1), with `state`, `nonce` and `response_mode` `direct_post.jwt`;
/// `response_uri` is the shared ECDH-ES route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_request_object_advertises_the_shared_key_and_both_enc_values() {
    let lab = Lab::research(PAIR).await;
    let sessions = lab.sessions(RouteKind::EcdhEs, PAIR).await;
    let mut jwks = HashSet::new();
    for session in &sessions {
        let payload = lab.request_payload(session).await;
        let metadata = &payload["client_metadata"];
        let keys = metadata["jwks"]["keys"].as_array().expect("jwks.keys");
        let [jwk] = keys.as_slice() else {
            panic!("exactly one key: {keys:?}");
        };
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], ALG_ECDH_ES);
        assert_eq!(jwk["use"], "enc");
        assert!(jwk["kid"].is_string());
        assert!(jwk.get("d").is_none(), "public key only");
        assert_eq!(metadata[ENC_VALUES_MEMBER], json!(ADVERTISED_ENC));
        assert!(payload["state"].is_string());
        assert!(payload["nonce"].is_string());
        assert_eq!(payload["response_mode"], "direct_post.jwt");
        let uri = format!("{}{ECDH_ES_RESPONSE_PATH}", lab.server.base_url());
        assert_eq!(payload["response_uri"], uri.as_str());
        assert_eq!(session.response_uri, uri);
        jwks.insert(jwk.to_string());
    }
    assert_eq!(
        jwks.len(),
        1,
        "every session advertises the same key and kid"
    );
    lab.server.shutdown().await;
}

/// E2. For `A128GCM` and `A256GCM`, an honest response commits exactly the session named by
/// its `state`; the other session stays pending, and the committed result is the requested
/// credential bound to the wallet's holder key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_honest_round_trip_commits_the_session_named_by_state() {
    for enc in [ContentEncryption::A128Gcm, ContentEncryption::A256Gcm] {
        let lab = Lab::research(PAIR).await;
        let sessions = lab.sessions(RouteKind::EcdhEs, PAIR).await;
        let (other, target) = (&sessions[0], &sessions[1]);
        let request = lab.request(target).await;
        assert_eq!(request.jwk_alg, ALG_ECDH_ES);
        let jwe = lab.seal(&request, enc, &SealOptions::default());
        let (status, _) = lab.post(&request.response_uri, &jwe).await;
        assert_eq!(status, OK, "{enc:?}");
        let record = lab.record();
        assert_eq!(record.crypto_result, CryptoResult::Opened { opened: PAIR });
        assert_committed(&record, target);
        lab.assert_pending(&[other]).await;
        let result = lab.wallet.get(&target.result_uri).await.expect("result");
        let result: Value = serde_json::from_slice(&result.body).expect("json");
        assert_eq!(result["state"], "consumed");
        assert_eq!(
            result["credential"]["holder_key_thumbprint"],
            lab.wallet.holder_key_thumbprint().as_str()
        );
        lab.server.shutdown().await;
    }
}

/// E3. `state` is a correlator, not authentication. The wallet seals A's valid holder proof
/// (KB-JWT over A's nonce) but writes B's `state`: the response opens for both, the `state`
/// routes it to B, and B's KB-JWT nonce binding refuses it (`KbNonceMismatch`). Nothing is
/// consumed; A's honest response then commits A, and B stays pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_state_swap_routes_to_the_named_session_and_fails_its_nonce() {
    let lab = Lab::research(PAIR).await;
    let sessions = lab.sessions(RouteKind::EcdhEs, PAIR).await;
    let (a, b) = (&sessions[0], &sessions[1]);
    let request_a = lab.request(a).await;
    let request_b = lab.request(b).await;
    let swapped = SealOptions {
        state: StateChoice::Other(state_of(&request_b).into()),
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(&request_a, &swapped).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: PAIR });
    assert_eq!(
        record.validation_result,
        ValidationResult::Failed(ValidationError::KbNonceMismatch)
    );
    assert_eq!(
        record.rejection,
        Some(Rejection::Validation(ValidationError::KbNonceMismatch))
    );
    assert_eq!(record.commit_result, CommitResult::NotRun);
    lab.assert_pending(&[a, b]).await;

    let (status, _) = lab.respond(&request_a, &SealOptions::default()).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), a);
    lab.assert_pending(&[b]).await;
    lab.server.shutdown().await;
}

/// E4. With no session selected by decryption, a response whose `state` is missing
/// (`StateMissing`), unknown, not a string, or the `state` of a session on another route
/// (`StateUnknown`) is refused after opening, and one whose `kid` is not the route's (no live
/// session matches it) or that has no `kid` is refused before. Every refusal answers the
/// generic 400 and consumes nothing; the honest response then commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_missing_unknown_or_foreign_state_is_refused_and_consumes_nothing() {
    let lab = Lab::research(PAIR).await;
    let ecdh_es = lab.session(RouteKind::EcdhEs, None, None).await;
    let unique = lab.session(RouteKind::Unique, None, None).await;
    let shared = lab.session(RouteKind::Shared, None, None).await;
    let request = lab.request(&ecdh_es).await;
    let unique_state = state_of(&lab.request(&unique).await);
    let shared_state = state_of(&lab.request(&shared).await);
    let cases = [
        (StateChoice::Omit, ValidationError::StateMissing),
        (
            StateChoice::Other(UNKNOWN_STATE.into()),
            ValidationError::StateUnknown,
        ),
        (
            StateChoice::Other(NUMERIC_STATE.into()),
            ValidationError::StateUnknown,
        ),
        (
            StateChoice::Other(unique_state.into()),
            ValidationError::StateUnknown,
        ),
        (
            StateChoice::Other(shared_state.into()),
            ValidationError::StateUnknown,
        ),
    ];
    for (state, expected) in cases {
        let opts = SealOptions {
            state: state.clone(),
            ..SealOptions::default()
        };
        let (status, body) = lab.respond(&request, &opts).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
        assert_eq!(
            record.rejection,
            Some(Rejection::Validation(expected)),
            "{state:?}"
        );
        assert_eq!(record.commit_result, CommitResult::NotRun);
    }
    let kids = [
        (
            KidChoice::Other(OTHER_KID.to_owned()),
            Rejection::Resolve(ResolveError::NoCandidate),
        ),
        (KidChoice::Omit, Rejection::MissingKid),
    ];
    for (kid, expected) in kids {
        let opts = SealOptions {
            kid,
            ..SealOptions::default()
        };
        let (status, body) = lab.respond(&request, &opts).await;
        assert_generic(status, &body);
        let record = lab.record();
        assert_eq!(record.rejection, Some(expected));
        assert_eq!(record.hpke_attempts, 0, "refused before any decryption");
    }
    lab.assert_pending(&[&ecdh_es, &unique, &shared]).await;

    let (status, _) = lab.respond(&request, &SealOptions::default()).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), &ecdh_es);
    lab.server.shutdown().await;
}

/// E5. The same JWE posted twice commits once: the second POST opens only for the sessions
/// still live, none of which has its `state` (`StateUnknown`); with no session left on the
/// route, resolve already reports the replay. A Verifier that reuses nonce and `state`
/// (research knobs) lets A's holder proof validate for a later session B too; the
/// Verifier-wide replay guard refuses it, verbatim (`CrossSessionReplay`) and re-sealed into a
/// fresh ECDH-ES JWE (`HolderProofReplay`), exactly as on the HPKE-0 routes. B stays pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_replays_commit_once_and_reused_values_hit_the_replay_guard() {
    let lab = Lab::research(PAIR).await;
    let sessions = lab.sessions(RouteKind::EcdhEs, PAIR).await;
    let (first, bystander) = (&sessions[0], &sessions[1]);
    let request = lab.request(first).await;
    let jwe = lab.seal(
        &request,
        ContentEncryption::A128Gcm,
        &SealOptions::default(),
    );
    let (status, _) = lab.post(&request.response_uri, &jwe).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), first);
    let (status, body) = lab.post(&request.response_uri, &jwe).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_eq!(
        record.rejection,
        Some(Rejection::Validation(ValidationError::StateUnknown))
    );
    lab.assert_pending(&[bystander]).await;
    let bystander_request = lab.request(bystander).await;
    let (status, _) = lab
        .respond(&bystander_request, &SealOptions::default())
        .await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), bystander);
    let (status, body) = lab.post(&request.response_uri, &jwe).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::Resolve(ResolveError::Replay))
    );
    assert_eq!(record.hpke_attempts, 0);

    let a = lab
        .session(RouteKind::EcdhEs, Some(REUSED_NONCE), Some(REUSED_STATE))
        .await;
    let request_a = lab.request(&a).await;
    let reseal = SealOptions {
        vp_token: Some(vp_token(&lab, &request_a)),
        ..SealOptions::default()
    };
    let jwe_a = lab.seal(&request_a, ContentEncryption::A128Gcm, &reseal);
    let (status, _) = lab.post(&request_a.response_uri, &jwe_a).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), &a);

    let b = lab
        .session(RouteKind::EcdhEs, Some(REUSED_NONCE), Some(REUSED_STATE))
        .await;
    let request_b = lab.request(&b).await;
    let (status, body) = lab.post(&request_b.response_uri, &jwe_a).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 1 },
        "with reused nonce and state, a's response is valid for b"
    );
    assert_eq!(record.rejection, Some(Rejection::CrossSessionReplay));

    let jwe_b = lab.seal(&request_b, ContentEncryption::A256Gcm, &reseal);
    assert_ne!(jwe_a, jwe_b, "a fresh JWE, so a fresh ciphertext digest");
    let (status, body) = lab.post(&request_b.response_uri, &jwe_b).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 1 }
    );
    assert_eq!(record.rejection, Some(Rejection::HolderProofReplay));
    assert_eq!(record.commit_result, CommitResult::NotRun);
    lab.assert_pending(&[&b]).await;
    lab.server.shutdown().await;
}

/// E5. Two live sessions with the same nonce and `state` (research knobs): the shared key
/// opens the response for both and the `state` names both, so both validate. The route cannot
/// pick one; it refuses as an integrity failure (`Ambiguous`) and claims nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_two_live_sessions_sharing_nonce_and_state_are_ambiguous() {
    let lab = Lab::research(PAIR).await;
    let a = lab
        .session(RouteKind::EcdhEs, Some(REUSED_NONCE), Some(REUSED_STATE))
        .await;
    let b = lab
        .session(RouteKind::EcdhEs, Some(REUSED_NONCE), Some(REUSED_STATE))
        .await;
    let request = lab.request(&a).await;
    let (status, body) = lab.respond(&request, &SealOptions::default()).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: PAIR });
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: PAIR }
    );
    assert_eq!(
        record.rejection,
        Some(Rejection::Ambiguous { validated: PAIR })
    );
    assert_eq!(record.commit_result, CommitResult::RefusedAmbiguous);
    lab.assert_pending(&[&a, &b]).await;
    lab.server.shutdown().await;
}

/// E6. No downgrade and no cross-route acceptance. An HPKE-0 JWE (sealed to the ECDH-ES key,
/// with its `kid`) posted to the ECDH-ES route is refused at parse (`EcdhEsJweParse`,
/// `UnsupportedAlg`); ECDH-ES JWEs posted to the HPKE-0 unique and shared routes, whether
/// sealed to that session's key or to the ECDH-ES route's, are refused at parse
/// (`JweParse`, `UnsupportedAlg`). Nothing is decrypted or consumed, and every session then
/// commits with its own route's honest response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_and_hpke_routes_never_accept_each_others_jwes() {
    let lab = Lab::research(PAIR).await;
    let ecdh_es = lab.session(RouteKind::EcdhEs, None, None).await;
    let unique = lab.session(RouteKind::Unique, None, None).await;
    let shared = lab.session(RouteKind::Shared, None, None).await;
    let request_e = lab.request(&ecdh_es).await;
    let request_u = lab.request(&unique).await;
    let request_s = lab.request(&shared).await;

    let hpke_to_ecdh_es = lab
        .wallet
        .seal(&request_e, &SealOptions::default())
        .expect("HPKE-0 seal to the ECDH-ES key");
    let (status, body) = lab.post(&request_e.response_uri, &hpke_to_ecdh_es).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::EcdhEsJweParse(
            jose_ecdh_es::Error::UnsupportedAlg
        ))
    );
    assert_eq!(record.hpke_attempts, 0);

    for (target, own) in [(&request_u, &request_u), (&request_s, &request_s)] {
        for key_of in [own, &request_e] {
            for enc in [ContentEncryption::A128Gcm, ContentEncryption::A256Gcm] {
                let opts = SealOptions {
                    state: StateChoice::Other(state_of(target).into()),
                    ..SealOptions::default()
                };
                let jwe = lab.seal(key_of, enc, &opts);
                let (status, body) = lab.post(&target.response_uri, &jwe).await;
                assert_generic(status, &body);
                let record = lab.record();
                assert_eq!(
                    record.rejection,
                    Some(Rejection::JweParse(jose_hpke::Error::UnsupportedAlg)),
                    "{} {enc:?}",
                    target.response_uri
                );
                assert_eq!(record.hpke_attempts, 0);
            }
        }
    }
    lab.assert_pending(&[&ecdh_es, &unique, &shared]).await;

    let (status, _) = lab.respond(&request_e, &SealOptions::default()).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), &ecdh_es);
    for (session, request) in [(&unique, &request_u), (&shared, &request_s)] {
        let jwe = lab
            .wallet
            .seal(request, &SealOptions::default())
            .expect("seal");
        let (status, _) = lab.post(&request.response_uri, &jwe).await;
        assert_eq!(status, OK);
        assert_committed(&lab.record(), session);
    }
    lab.server.shutdown().await;
}

/// E6. The `direct_post` downgrade found in G0-D: a plaintext `vp_token` is refused at
/// admission on the ECDH-ES route as on the HPKE-0 routes, alone or next to a valid
/// `response`, before any parsing; the session stays pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_route_refuses_plaintext_vp_token_at_admission() {
    let lab = Lab::research(PAIR).await;
    let session = lab.session(RouteKind::EcdhEs, None, None).await;
    let request = lab.request(&session).await;
    let jwe = lab.seal(
        &request,
        ContentEncryption::A128Gcm,
        &SealOptions::default(),
    );
    let vp_token = vp_token(&lab, &request).to_string();
    let alone = form_urlencoded::Serializer::new(String::new())
        .append_pair("vp_token", &vp_token)
        .finish();
    let beside = form_urlencoded::Serializer::new(String::new())
        .append_pair("response", &jwe)
        .append_pair("vp_token", &vp_token)
        .finish();
    for body in [alone, beside] {
        let reply = lab
            .wallet
            .post_raw(&request.response_uri, FORM, body.into_bytes())
            .await
            .expect("response endpoint answers");
        assert_eq!(reply.status, BAD_REQUEST);
        let record = lab.record();
        assert_eq!(
            record.rejection,
            Some(Rejection::Admission(AdmissionError::PlaintextVpToken))
        );
        assert_eq!(record.hpke_attempts, 0);
    }
    lab.assert_pending(&[&session]).await;
    lab.server.shutdown().await;
}

/// E7. Hardened mode has no ECDH-ES route and creates no ECDH-ES session; asking a hardened
/// server for the route (`LabConfig::ecdh_es_route`) is refused at start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hardened_mode_has_no_ecdh_es_route_and_refuses_ecdh_es_sessions() {
    let lab = Lab::start(Mode::Hardened).await;
    assert_no_ecdh_es_route(&lab).await;
    lab.server.shutdown().await;

    let mut asked = config(Mode::Hardened);
    asked.ecdh_es_route = true;
    assert!(matches!(
        LabServer::start(asked).await,
        Err(StartError::EcdhEsRouteNeedsResearchMode)
    ));
}

/// The route is opt-in per server: a research-mode server without `LabConfig::ecdh_es_route`
/// (both shared strategies) has no ECDH-ES key, route or sessions, exactly as in hardened mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn research_mode_without_the_opt_in_has_no_ecdh_es_route() {
    for mode in [
        bounded_trial(PAIR),
        Mode::Research(SharedRouteStrategy::UniqueKid),
    ] {
        let lab = Lab::start(mode).await;
        assert_no_ecdh_es_route(&lab).await;
        lab.server.shutdown().await;
    }
}

/// The route caps its pending sessions at session-core's `MAX_CANDIDATE_BUDGET`: the session
/// after the cap is refused (503) while other routes still issue sessions, and an honest
/// response for the last session commits after exactly that many ECDH-ES opens, all of which
/// open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_route_caps_pending_sessions_at_the_candidate_budget() {
    let lab = Lab::research(PAIR).await;
    let sessions = lab.sessions(RouteKind::EcdhEs, MAX_CANDIDATE_BUDGET).await;
    let refused = lab
        .wallet
        .create_session(&lab.server.base_url(), RouteKind::EcdhEs, None)
        .await;
    assert!(
        matches!(refused, Err(WalletError::Status(SERVICE_UNAVAILABLE))),
        "{refused:?}"
    );
    lab.session(RouteKind::Unique, None, None).await;

    let last = sessions.last().expect("sessions were created");
    let request = lab.request(last).await;
    let (status, _) = lab.respond(&request, &SealOptions::default()).await;
    assert_eq!(status, OK);
    let record = lab.record();
    assert_eq!(record.candidate_count, MAX_CANDIDATE_BUDGET);
    assert_eq!(record.hpke_attempts, MAX_CANDIDATE_BUDGET);
    assert_eq!(
        record.crypto_result,
        CryptoResult::Opened {
            opened: MAX_CANDIDATE_BUDGET
        }
    );
    assert_committed(&record, last);
    lab.server.shutdown().await;
}

/// The research `state` knob gives two sessions the same `state` but each its own nonce: the
/// `state` names both, and holder binding disambiguates. A's honest response validates for A
/// only and commits it; posted again, it is named for B alone and refused by B's KB-JWT nonce
/// binding (`KbNonceMismatch`). B then commits with its own response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_duplicate_state_with_distinct_nonces_is_disambiguated_by_holder_binding() {
    let lab = Lab::research(PAIR).await;
    let a = lab
        .session(RouteKind::EcdhEs, None, Some(REUSED_STATE))
        .await;
    let b = lab
        .session(RouteKind::EcdhEs, None, Some(REUSED_STATE))
        .await;
    let request_a = lab.request(&a).await;
    let request_b = lab.request(&b).await;
    assert_eq!(state_of(&request_a), state_of(&request_b));
    assert_ne!(request_a.nonce, request_b.nonce);

    let jwe = lab.seal(
        &request_a,
        ContentEncryption::A128Gcm,
        &SealOptions::default(),
    );
    let (status, _) = lab.post(&request_a.response_uri, &jwe).await;
    assert_eq!(status, OK);
    let record = lab.record();
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: PAIR });
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 1 }
    );
    assert_committed(&record, &a);

    let (status, body) = lab.post(&request_a.response_uri, &jwe).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_eq!(
        record.rejection,
        Some(Rejection::Validation(ValidationError::KbNonceMismatch))
    );
    lab.assert_pending(&[&b]).await;
    let (status, _) = lab.respond(&request_b, &SealOptions::default()).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), &b);
    lab.server.shutdown().await;
}

/// Expiry: expired sessions are never candidates. A response for expired A while B is live
/// opens for B only and names no live session (`StateUnknown`); once B has expired too, the
/// route has no live session and resolve reports the expiry (`Resolve(SessionExpired)`)
/// before any decryption. Nothing is consumed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ecdh_es_response_for_an_expired_session_is_refused() {
    let mut config = ecdh_es_config(PAIR);
    config.session_ttl = SHORT_TTL;
    let lab = Lab::with_config(config).await;
    let a = lab.session(RouteKind::EcdhEs, None, None).await;
    let request_a = lab.request(&a).await;
    let jwe = lab.seal(
        &request_a,
        ContentEncryption::A128Gcm,
        &SealOptions::default(),
    );
    tokio::time::sleep(SHORT_TTL + EXPIRY_MARGIN).await;

    let b = lab.session(RouteKind::EcdhEs, None, None).await;
    let (status, body) = lab.post(&request_a.response_uri, &jwe).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(record.candidate_count, 1, "only b is live");
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_eq!(
        record.rejection,
        Some(Rejection::Validation(ValidationError::StateUnknown))
    );
    lab.assert_pending(&[&b]).await;

    tokio::time::sleep(SHORT_TTL + EXPIRY_MARGIN).await;
    let (status, body) = lab.post(&request_a.response_uri, &jwe).await;
    assert_generic(status, &body);
    let record = lab.record();
    assert_eq!(
        record.rejection,
        Some(Rejection::Resolve(ResolveError::SessionExpired))
    );
    assert_eq!(record.hpke_attempts, 0);
    // The result endpoint shows the stored state, which the sweep (not yet run here) moves to
    // `expired`; what matters is that neither session was consumed.
    for session in [&a, &b] {
        assert_ne!(lab.state(session).await, "consumed");
    }
    lab.server.shutdown().await;
}

/// The ECDH-ES route is absent from `lab`: a POST to it is 404 and never reaches the pipeline
/// (no evidence record), a session for it is refused at creation (400), and an honest HPKE-0
/// unique-route flow still works.
async fn assert_no_ecdh_es_route(lab: &Lab) {
    let base = lab.server.base_url();
    let reply = lab
        .wallet
        .post_raw(
            &format!("{base}{ECDH_ES_RESPONSE_PATH}"),
            FORM,
            b"response=x".to_vec(),
        )
        .await
        .expect("server answers");
    assert_eq!(reply.status, NOT_FOUND);
    assert!(lab.server.evidence().take().is_empty());

    let created = lab
        .wallet
        .create_session(&base, RouteKind::EcdhEs, None)
        .await;
    assert!(
        matches!(created, Err(WalletError::Status(BAD_REQUEST))),
        "{created:?}"
    );
    let raw = lab
        .wallet
        .post_raw(
            &format!("{base}{SESSIONS_PATH}"),
            JSON,
            json!({ "route": ECDH_ES_ROUTE }).to_string().into_bytes(),
        )
        .await
        .expect("server answers");
    assert_eq!(raw.status, BAD_REQUEST);

    let unique = lab.session(RouteKind::Unique, None, None).await;
    let request = lab.request(&unique).await;
    assert_ne!(request.jwk_alg, ALG_ECDH_ES);
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");
    let (status, _) = lab.post(&request.response_uri, &jwe).await;
    assert_eq!(status, OK);
    assert_committed(&lab.record(), &unique);
}
