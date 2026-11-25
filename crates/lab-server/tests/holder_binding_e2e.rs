//! Holder binding over real loopback HTTP (Evidence level 3, synthetic credentials): the
//! `vp_token` carries an SD-JWT VC + Key Binding JWT (OpenID4VP 1.1 B.3; RFC 9901;
//! draft-ietf-oauth-sd-jwt-vc-27), sealed with HPKE-0 and posted as `direct_post.jwt`.
//!
//! Each tamper case answers the generic 400, leaves the session pending, and records the
//! specific `ValidationError`; the honest presentation then still commits. Replays of a valid
//! KB-JWT to another session or another Verifier fail on the `nonce` / `aud` binding. Two
//! cross-implementation checks use SpruceID `ssi` 0.16's SD-JWT code (dev-dependency only): an
//! SD-JWT+KB built and signed by ssi is accepted by the lab Verifier over HTTP, and the lab
//! wallet's presentation verifies with ssi.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lab_server::wallet_sim::{
    CreatedSession, PresentationTamper, RequestObject, SealOptions, SyntheticIssuer, WalletSim,
};
use lab_server::{
    CommitResult, CredentialRequest, CredentialRequestError, CryptoResult, EvidenceRecord,
    GENERIC_REJECTION_BODY, LabConfig, LabServer, Mode, REQUESTED_CLAIMS, Rejection,
    RequestSigningKey, RouteKind, SYNTHETIC_CREDENTIAL_QUERY_ID, SYNTHETIC_CREDENTIAL_VCT,
    SharedRouteStrategy, TrustedIssuerKey, ValidationError, ValidationResult,
};
use protocol_model::ClientIdWire;
use serde_json::{Value, json};
use session_core::CandidateBudget;
use ssi::JWK;
use ssi::claims::JwsPayload;
use ssi::claims::VerificationParameters;
use ssi::claims::sd_jwt::{
    DisclosureDescription, JsonPointerBuf, KbJwtPayload, SdAlg, SdHash, SdJwt, SdJwtPayload,
};

/// HTTP statuses the tests pin (RFC 9110 §15).
const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
/// Synthetic Request Object signing key (its did:key is the default `client_id`).
const FIXTURE_JWK: &str = include_str!("fixtures/spruce_verifier.jwk");
/// Synthetic lab SD-JWT VC issuer: private for the wallet, public for the Verifier.
const ISSUER_JWK: &str = include_str!("fixtures/lab_issuer.jwk");
const ISSUER_PUBLIC_JWK: &str = include_str!("fixtures/lab_issuer.pub.jwk");
/// A `client_id` no lab session was issued with.
const FOREIGN_CLIENT_ID: &str = "decentralized_identifier:did:key:zDnaeForeignSyntheticVerifier";
/// A nonce no lab session was issued with.
const FOREIGN_NONCE: &str = "another-nonce";
/// A second, pre-registered Verifier (OpenID4VP 1.1 §5.9.2) for the cross-Verifier replay.
const OTHER_VERIFIER_CLIENT_ID: &str = "lab-other-verifier";
/// One research nonce shared by sessions on two Verifiers, so only `aud` differs.
const SHARED_NONCE: &str = "cross-verifier-replay-nonce";
/// Bounded-trial budget of the research servers (any value works; the unique route is used).
const TRIAL_BUDGET: usize = 2;
/// Validity of the ssi-issued credential, in seconds.
const SSI_CREDENTIAL_LIFETIME_SECS: u64 = 3600;
/// Compact JWS payload segment (RFC 7515 §7.1).
const JWS_PAYLOAD: usize = 1;

fn issuer() -> SyntheticIssuer {
    SyntheticIssuer::from_jwk(ISSUER_JWK).expect("fixture issuer")
}

fn config(mode: Mode) -> LabConfig {
    LabConfig::new(
        mode,
        RequestSigningKey::from_jwk(FIXTURE_JWK).expect("fixture signing key"),
        TrustedIssuerKey::from_jwk(ISSUER_PUBLIC_JWK).expect("fixture issuer key"),
    )
}

fn research() -> Mode {
    Mode::Research(SharedRouteStrategy::BoundedTrial(
        CandidateBudget::new(TRIAL_BUDGET).expect("valid budget"),
    ))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

struct Lab {
    server: LabServer,
    wallet: WalletSim,
}

impl Lab {
    async fn start(mode: Mode) -> Self {
        Self::start_with(config(mode), &issuer()).await
    }

    async fn start_with(config: LabConfig, issuer: &SyntheticIssuer) -> Self {
        let server = LabServer::start(config).await.expect("lab server starts");
        Self {
            server,
            wallet: WalletSim::new(issuer).expect("wallet builds"),
        }
    }

    async fn session(&self) -> CreatedSession {
        self.session_with_nonce(None).await
    }

    async fn session_with_nonce(&self, nonce: Option<&str>) -> CreatedSession {
        self.wallet
            .create_session(&self.server.base_url(), RouteKind::Unique, nonce)
            .await
            .expect("session is created")
    }

    async fn request(&self, session: &CreatedSession) -> RequestObject {
        self.wallet
            .fetch_request(session)
            .await
            .expect("request object verifies")
    }

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

    fn record(&self) -> EvidenceRecord {
        let mut records = self.server.evidence().take();
        assert_eq!(records.len(), 1, "exactly one evidence record: {records:?}");
        records.remove(0)
    }

    async fn result(&self, session: &CreatedSession) -> Value {
        let reply = self
            .wallet
            .get(&session.result_uri)
            .await
            .expect("result endpoint answers");
        assert_eq!(reply.status, OK);
        serde_json::from_slice(&reply.body).expect("result JSON")
    }

    async fn assert_pending(&self, session: &CreatedSession) {
        assert_eq!(self.result(session).await["state"], "pending");
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

fn vp_token(presentation: &str) -> Value {
    json!({ SYNTHETIC_CREDENTIAL_QUERY_ID: [presentation] })
}

fn assert_generic(status: u16, body: &[u8]) {
    assert_eq!(status, BAD_REQUEST);
    assert_eq!(body, GENERIC_REJECTION_BODY.as_bytes());
}

/// The rejection of one validation failure: decrypted, not validated, nothing claimed.
fn assert_validation_failed(record: &EvidenceRecord, want: ValidationError) {
    assert_eq!(record.crypto_result, CryptoResult::Opened { opened: 1 });
    assert_eq!(record.validation_result, ValidationResult::Failed(want));
    assert_eq!(record.rejection, Some(Rejection::Validation(want)));
    assert_eq!(record.commit_result, CommitResult::NotRun);
    assert_eq!(record.committed_session, None);
}

/// OpenID4VP 1.1 §6.1 / B.3.5 / §7: the signed Request Object asks for exactly the lab
/// SD-JWT VC (`dc+sd-jwt`, `vct_values`) and its claims, with holder binding required. The
/// wallet reads the same values from the verified payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_object_dcql_query_requests_the_sd_jwt_vc_and_its_claims() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let reply = lab.wallet.get(&session.request_uri).await.expect("request");
    let jwt = String::from_utf8(reply.body).expect("compact JWS");
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(JWS_PAYLOAD).expect("payload"))
            .expect("base64url"),
    )
    .expect("JSON payload");
    assert_eq!(
        payload["dcql_query"],
        json!({
            "credentials": [{
                "id": SYNTHETIC_CREDENTIAL_QUERY_ID,
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [SYNTHETIC_CREDENTIAL_VCT] },
                "require_cryptographic_holder_binding": true,
                "claims": [
                    { "path": ["given_name"] },
                    { "path": ["family_name"] },
                    { "path": ["age_over_18"] },
                ],
            }]
        })
    );
    let request = lab.request(&session).await;
    assert_eq!(request.credential_query_id, SYNTHETIC_CREDENTIAL_QUERY_ID);
    assert_eq!(request.vct_values, [SYNTHETIC_CREDENTIAL_VCT]);
    assert_eq!(request.requested_claims, REQUESTED_CLAIMS);
    lab.shutdown().await;
}

/// Happy path: an honest SD-JWT+KB commits; the result holds only the requested claims plus
/// evidence (vct, holder key thumbprint, disclosed claim names), never the presentation or the
/// unrequested `birthdate`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_sd_jwt_kb_presentation_commits_only_the_requested_claims() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let (status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_eq!(status, OK);
    let record = lab.record();
    assert_eq!(
        record.validation_result,
        ValidationResult::Passed { validated: 1 }
    );
    assert_eq!(record.commit_result, CommitResult::Committed);
    assert_eq!(
        record.committed_session.as_ref().map(|id| id.as_str()),
        Some(session.session_id.as_str())
    );

    let result = lab.result(&session).await;
    assert_eq!(result["state"], "consumed");
    assert_eq!(
        result["credential"],
        json!({
            "vct": SYNTHETIC_CREDENTIAL_VCT,
            "holder_key_thumbprint": lab.wallet.holder_key_thumbprint(),
            "claims": { "given_name": "Alex", "family_name": "Sample", "age_over_18": true },
            "disclosed_claim_names": ["/age_over_18", "/family_name", "/given_name"],
        })
    );
    let text = result.to_string();
    assert!(!text.contains('~') && !text.contains("birthdate"), "{text}");
    lab.shutdown().await;
}

/// One tampered presentation: generic 400, session pending, the specific error in evidence;
/// the session is then still consumed by the honest presentation.
async fn assert_tamper_rejected(tamper: PresentationTamper, want: ValidationError) {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let opts = SealOptions {
        presentation: tamper,
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(&session, &opts).await;
    assert_generic(status, &body);
    assert_validation_failed(&lab.record(), want);
    lab.assert_pending(&session).await;

    let (status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_eq!(status, OK, "honest presentation after {want:?}");
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    lab.shutdown().await;
}

macro_rules! tamper_is_rejected {
    ($($(#[$doc:meta])* $name:ident: $tamper:expr => $error:ident;)*) => {$(
        $(#[$doc])*
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            assert_tamper_rejected($tamper, ValidationError::$error).await;
        }
    )*};
}

tamper_is_rejected! {
    /// OpenID4VP 1.1 B.3.6 / §14.2.2: `aud` must be the session's Client Identifier.
    kb_jwt_with_wrong_aud_is_rejected:
        PresentationTamper::KbAudience(FOREIGN_CLIENT_ID.to_owned()) => KbAudienceMismatch;
    /// B.3.6 / §14.2.2: `nonce` must be the Authorization Request's nonce.
    kb_jwt_with_wrong_nonce_is_rejected:
        PresentationTamper::KbNonce(FOREIGN_NONCE.to_owned()) => KbNonceMismatch;
    /// RFC 9901 §7.3 step 5e: `iat` older than `KB_JWT_MAX_AGE_SECS`.
    kb_jwt_with_stale_iat_is_rejected: PresentationTamper::StaleIat => KbIatOutOfWindow;
    /// RFC 9901 §7.3 step 5e: `iat` beyond `KB_JWT_MAX_FUTURE_SKEW_SECS`.
    kb_jwt_with_future_iat_is_rejected: PresentationTamper::FutureIat => KbIatOutOfWindow;
    /// RFC 9901 §4.3.1 / §7.3 step 5g: `sd_hash` over another SD-JWT.
    kb_jwt_with_wrong_sd_hash_is_rejected: PresentationTamper::WrongSdHash => KbSdHashMismatch;
    /// RFC 9901 §4.3.2 / §7.3 step 5c: only the `cnf` key may sign the KB-JWT.
    kb_jwt_signed_by_a_non_cnf_key_is_rejected:
        PresentationTamper::KbSignedByOtherKey => KbSignature;
    /// RFC 9901 §4.3 / §7.3 step 5b: `alg` MUST NOT be `none`.
    kb_jwt_with_alg_none_is_rejected: PresentationTamper::KbAlgNone => KbAlg;
    /// RFC 9901 §7.3 step 2; OpenID4VP 1.1 B.3: holder binding is required.
    presentation_without_kb_jwt_is_rejected: PresentationTamper::MissingKb => KeyBindingMissing;
    /// RFC 9901 §7.1 step 5: the altered Disclosure's digest is in no `_sd` array (checked
    /// before `sd_hash`, so the in-transit change is caught by the digest).
    disclosure_altered_in_transit_is_rejected:
        PresentationTamper::AlteredDisclosure => UnreferencedDisclosure;
    /// RFC 9901 §7.1 step 5: a fabricated Disclosure, even one the holder signed over.
    unreferenced_disclosure_is_rejected:
        PresentationTamper::UnreferencedDisclosure => UnreferencedDisclosure;
    /// RFC 9901 §4: a Disclosure MUST NOT be sent more than once.
    duplicate_disclosure_is_rejected: PresentationTamper::DuplicateDisclosure => DuplicateDisclosure;
    /// OpenID4VP 1.1 §6.4.1 / §8.6: every requested claim must be presented.
    withheld_requested_claim_is_rejected:
        PresentationTamper::WithholdRequestedClaim => RequestedClaimMissing;
    /// OpenID4VP 1.1 §6.4.1 (lab policy: nothing beyond the request is accepted).
    unrequested_disclosed_claim_is_rejected:
        PresentationTamper::DiscloseUnrequestedClaim => UnrequestedClaimDisclosed;
    /// RFC 9901 §7.1 step 2c: the issuer signature must verify with the trusted key.
    credential_signed_by_an_untrusted_issuer_is_rejected:
        PresentationTamper::UntrustedIssuer => IssuerSignature;
    /// RFC 9901 §4.1 / §7.1 step 2a: the issuer JWT MUST NOT use `none`.
    issuer_jwt_with_alg_none_is_rejected: PresentationTamper::IssuerAlgNone => IssuerAlg;
    /// RFC 9901 §7.1 step 2b-c, OIDF `InvalidCredentialSignature` (C1): the trusted issuer's
    /// own signature with one character changed in transit, not a foreign key.
    issuer_jwt_with_corrupted_signature_is_rejected:
        PresentationTamper::CorruptIssuerSignature => IssuerSignature;
    /// RFC 9901 §7.3 step 5c, OIDF `InvalidKbJwtSignature` (C1): the holder's own KB-JWT
    /// signature with one character changed, not a signature by another key.
    kb_jwt_with_corrupted_signature_is_rejected:
        PresentationTamper::CorruptKbSignature => KbSignature;
}

/// OIDF `MinimalCnfJwk` (C1): the credential's `cnf.jwk` carries only the RFC 7518 §6.2.1
/// members `kty`, `crv`, `x`, `y` (no `kid`, `use`, `alg`), and the presentation commits with
/// that key's thumbprint (RFC 7800 §3.2; RFC 9901 §4.1.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_with_minimal_cnf_jwk_is_accepted() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let request = lab.request(&session).await;
    let presentation = lab
        .wallet
        .present(&request, &PresentationTamper::None)
        .expect("presentation");
    let issuer_jwt = presentation.split('~').next().expect("issuer JWT");
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(issuer_jwt.split('.').nth(JWS_PAYLOAD).expect("payload"))
            .expect("base64url"),
    )
    .expect("JSON payload");
    let cnf_jwk = payload["cnf"]["jwk"].as_object().expect("cnf.jwk object");
    let mut members: Vec<&str> = cnf_jwk.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(members, ["crv", "kty", "x", "y"]);

    let opts = SealOptions {
        vp_token: Some(vp_token(&presentation)),
        ..SealOptions::default()
    };
    let (status, _) = lab.respond(&session, &opts).await;
    assert_eq!(status, OK);
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    assert_eq!(
        lab.result(&session).await["credential"]["holder_key_thumbprint"],
        lab.wallet.holder_key_thumbprint()
    );
    lab.shutdown().await;
}

/// Plan §4 item 4 (C1): a configured Credential Query (`LabConfig::credential_request`, here
/// the OIDF suite's `urn:eudi:pid:1` shape) is what the signed Request Object asks for
/// (OpenID4VP §6.1, B.3.5) and what the Verifier enforces: a credential of that `vct` with
/// those claims commits them; the default synthetic `vct` is `VctMismatch`; a `vp_token` keyed
/// by the default query id is `QueryMismatch`. Invalid queries are refused at construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_credential_query_is_requested_and_enforced() {
    const PID_VCT: &str = "urn:eudi:pid:1";
    const PID_QUERY_ID: &str = "pid";
    let pid_claims = ["given_name", "birthdate"];
    let mut cfg = config(Mode::Hardened);
    cfg.credential_request =
        CredentialRequest::new(PID_QUERY_ID, PID_VCT, pid_claims).expect("valid query");
    let lab = Lab::start_with(cfg, &issuer().with_vct(PID_VCT)).await;
    let session = lab.session().await;
    let request = lab.request(&session).await;
    assert_eq!(request.credential_query_id, PID_QUERY_ID);
    assert_eq!(request.vct_values, [PID_VCT]);
    assert_eq!(request.requested_claims, pid_claims);

    // The default synthetic credential type is not the requested one.
    let other_type = WalletSim::new(&issuer()).expect("wallet");
    let mut claimed = request.clone();
    claimed.vct_values = vec![SYNTHETIC_CREDENTIAL_VCT.to_owned()];
    let presentation = other_type
        .present(&claimed, &PresentationTamper::None)
        .expect("presentation of the synthetic type");
    let opts = SealOptions {
        vp_token: Some(json!({ PID_QUERY_ID: [presentation] })),
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(&session, &opts).await;
    assert_generic(status, &body);
    assert_validation_failed(&lab.record(), ValidationError::VctMismatch);

    // The right credential under the default query id answers no query of this request.
    let presentation = lab
        .wallet
        .present(&request, &PresentationTamper::None)
        .expect("presentation");
    let opts = SealOptions {
        vp_token: Some(vp_token(&presentation)),
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(&session, &opts).await;
    assert_generic(status, &body);
    assert_validation_failed(&lab.record(), ValidationError::QueryMismatch);
    lab.assert_pending(&session).await;

    let (status, _) = lab.respond(&session, &SealOptions::default()).await;
    assert_eq!(status, OK);
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    let result = lab.result(&session).await;
    assert_eq!(
        result["credential"]["claims"],
        json!({ "given_name": "Alex", "birthdate": "2000-01-01" })
    );
    assert_eq!(result["credential"]["vct"], PID_VCT);
    lab.shutdown().await;

    let refused = [
        CredentialRequest::new("", PID_VCT, pid_claims),
        CredentialRequest::new("pid query", PID_VCT, pid_claims),
        CredentialRequest::new(PID_QUERY_ID, "", pid_claims),
        CredentialRequest::new(PID_QUERY_ID, "urn:with space", pid_claims),
        CredentialRequest::new(PID_QUERY_ID, PID_VCT, Vec::<String>::new()),
        CredentialRequest::new(PID_QUERY_ID, PID_VCT, ["given_name", "given_name"]),
        CredentialRequest::new(PID_QUERY_ID, PID_VCT, ["_sd"]),
        CredentialRequest::new(PID_QUERY_ID, PID_VCT, [""]),
    ];
    let errors: Vec<_> = refused
        .into_iter()
        .map(|r| r.expect_err("refused"))
        .collect();
    assert_eq!(
        errors,
        [
            CredentialRequestError::Id,
            CredentialRequestError::Id,
            CredentialRequestError::Vct,
            CredentialRequestError::Vct,
            CredentialRequestError::Claims,
            CredentialRequestError::Claims,
            CredentialRequestError::Claims,
            CredentialRequestError::Claims,
        ]
    );
}

/// OpenID4VP 1.1 §14.2.2: a valid SD-JWT+KB for session A, sealed for session B on the same
/// Verifier, fails B's nonce binding and leaves B pending; the same presentation still commits
/// A, so it was valid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valid_kb_jwt_replayed_to_another_session_fails_the_nonce_binding() {
    let lab = Lab::start(Mode::Hardened).await;
    let a = lab.session().await;
    let b = lab.session().await;
    let presentation = lab
        .wallet
        .present(&lab.request(&a).await, &PresentationTamper::None)
        .expect("presentation for A");
    let replay = SealOptions {
        vp_token: Some(vp_token(&presentation)),
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(&b, &replay).await;
    assert_generic(status, &body);
    assert_validation_failed(&lab.record(), ValidationError::KbNonceMismatch);
    lab.assert_pending(&b).await;

    let (status, _) = lab.respond(&a, &replay).await;
    assert_eq!(status, OK);
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    lab.shutdown().await;
}

/// OpenID4VP 1.1 §14.2.2: "The client_id is used to detect the replay of Verifiable
/// Presentations to a party other than the one intended." Two Verifiers, sessions with the
/// same (research) nonce: A's presentation sealed for the other Verifier fails on `aud`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valid_kb_jwt_replayed_to_another_verifier_fails_the_audience_binding() {
    let lab = Lab::start(research()).await;
    let mut other_config = config(research());
    other_config.client_id = ClientIdWire::new(OTHER_VERIFIER_CLIENT_ID).expect("client_id");
    let other = LabServer::start(other_config)
        .await
        .expect("second Verifier starts");
    // A pre-registered client id is not a DID: the wallet pins the Verifier key (§5.9.2).
    let mut public: Value = serde_json::from_str(FIXTURE_JWK).expect("fixture JSON");
    public.as_object_mut().expect("JWK").remove("d");
    let other_wallet =
        WalletSim::with_pinned_verifier_key(&public.to_string(), &issuer()).expect("pinned wallet");

    let a = lab.session_with_nonce(Some(SHARED_NONCE)).await;
    let presentation = lab
        .wallet
        .present(&lab.request(&a).await, &PresentationTamper::None)
        .expect("presentation for A");
    let b = other_wallet
        .create_session(&other.base_url(), RouteKind::Unique, Some(SHARED_NONCE))
        .await
        .expect("session on the other Verifier");
    let request_b = other_wallet.fetch_request(&b).await.expect("request B");
    assert_eq!(request_b.nonce, SHARED_NONCE);
    let jwe = other_wallet
        .seal(
            &request_b,
            &SealOptions {
                vp_token: Some(vp_token(&presentation)),
                ..SealOptions::default()
            },
        )
        .expect("seal");
    let reply = other_wallet
        .post_response(&request_b.response_uri, &jwe)
        .await
        .expect("post");
    assert_generic(reply.status, &reply.body);
    let records = other.evidence().take();
    assert_eq!(records.len(), 1);
    assert_validation_failed(&records[0], ValidationError::KbAudienceMismatch);
    assert_eq!(
        other_wallet
            .session_state(&b.result_uri)
            .await
            .expect("state")
            .as_deref(),
        Some("pending")
    );
    other.shutdown().await;
    lab.shutdown().await;
}

/// The lab SD-JWT VC `typ` for an ssi-signed issuer JWT (ssi's own `SdJwtPayload` sets none).
struct SdJwtVcPayload(SdJwtPayload);

impl JwsPayload for SdJwtVcPayload {
    fn typ(&self) -> Option<&str> {
        Some(lab_server::SD_JWT_VC_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        self.0.payload_bytes()
    }
}

/// A KB-JWT payload with exactly the RFC 9901 §4.3 claims, `sd_hash` computed by ssi.
struct KbPayload(Value);

impl JwsPayload for KbPayload {
    fn typ(&self) -> Option<&str> {
        Some(lab_server::KB_JWT_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_string().into_bytes())
    }
}

/// An SD-JWT VC for the lab's issuer and query, concealed and signed by ssi; returns the
/// SD-JWT (ending in `~`) with the requested Disclosures and the ssi holder key.
async fn ssi_sd_jwt(request: &RequestObject) -> (String, JWK) {
    let issuer: JWK = serde_json::from_str(ISSUER_JWK).expect("issuer JWK");
    let holder = JWK::generate_p256();
    let now = now_secs();
    let claims = json!({
        "iss": "https://ssi-issuer.lab.invalid",
        "iat": now,
        "exp": now + SSI_CREDENTIAL_LIFETIME_SECS,
        "vct": SYNTHETIC_CREDENTIAL_VCT,
        "cnf": { "jwk": holder.to_public() },
        "given_name": "Robin",
        "family_name": "Roe",
        "age_over_18": true,
        "birthdate": "1999-12-31",
    });
    let pointers: Vec<JsonPointerBuf> =
        ["/given_name", "/family_name", "/age_over_18", "/birthdate"]
            .iter()
            .map(|p| p.parse().expect("JSON pointer"))
            .collect();
    let (payload, disclosures) =
        SdJwtPayload::conceal(&claims, SdAlg::Sha256, &pointers).expect("ssi conceals");
    let jwt = SdJwtVcPayload(payload)
        .sign(&issuer)
        .await
        .expect("ssi signs");
    let mut sd_jwt = format!("{}~", jwt.as_str());
    for disclosure in &disclosures {
        let DisclosureDescription::ObjectEntry { key, .. } = &disclosure.desc else {
            panic!("only object entries were concealed");
        };
        if request.requested_claims.contains(key) {
            sd_jwt.push_str(disclosure.encoded.as_str());
            sd_jwt.push('~');
        }
    }
    (sd_jwt, holder)
}

/// Cross-implementation (ssi → lab): issuer JWT, Disclosures, digests, `sd_hash` and both
/// ES256 signatures produced by SpruceID ssi 0.16 (`ssi-sd-jwt` 0.6), sealed by the lab wallet
/// and posted over HTTP, are accepted by the lab Verifier and commit ssi's claim values.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sd_jwt_kb_built_with_ssi_is_accepted_by_the_lab_verifier() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let request = lab.request(&session).await;
    let (sd_jwt, holder) = ssi_sd_jwt(&request).await;
    let sd = SdJwt::new(&sd_jwt).expect("ssi parses the SD-JWT");
    let kb = KbPayload(json!({
        "iat": now_secs(),
        "aud": request.client_id,
        "nonce": request.nonce,
        "sd_hash": SdHash::new(SdAlg::Sha256, sd).0,
    }))
    .sign(&holder)
    .await
    .expect("ssi signs the KB-JWT");
    let presentation = format!("{sd_jwt}{}", kb.as_str());
    let opts = SealOptions {
        vp_token: Some(vp_token(&presentation)),
        ..SealOptions::default()
    };
    let (status, _) = lab.respond(&session, &opts).await;
    assert_eq!(
        status,
        OK,
        "evidence: {:?}",
        lab.server.evidence().records()
    );
    assert_eq!(lab.record().commit_result, CommitResult::Committed);
    let result = lab.result(&session).await;
    assert_eq!(
        result["credential"]["claims"],
        json!({ "given_name": "Robin", "family_name": "Roe", "age_over_18": true })
    );
    lab.shutdown().await;
}

/// Characterization (ssi → lab): ssi 0.16's own `KbJwtPayload` serializes absent `exp` / `nbf`
/// as `null`, which is not a NumericDate (RFC 7519 §4.1.4-§4.1.5), so the strict lab Verifier
/// refuses it as malformed. ssi itself accepts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssi_kb_jwt_payload_with_null_exp_is_rejected_as_malformed() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let request = lab.request(&session).await;
    let (sd_jwt, holder) = ssi_sd_jwt(&request).await;
    let sd = SdJwt::new(&sd_jwt).expect("ssi parses the SD-JWT");
    let kb = KbJwtPayload::new(
        request.client_id.clone(),
        request.nonce.clone(),
        SdAlg::Sha256,
        sd,
    )
    .sign(&holder)
    .await
    .expect("ssi signs the KB-JWT");
    let kb_payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(kb.as_str().split('.').nth(JWS_PAYLOAD).expect("payload"))
            .expect("base64url"),
    )
    .expect("KB-JWT JSON");
    assert_eq!(kb_payload["exp"], Value::Null, "{kb_payload}");
    let presentation = format!("{sd_jwt}{}", kb.as_str());
    let opts = SealOptions {
        vp_token: Some(vp_token(&presentation)),
        ..SealOptions::default()
    };
    let (status, body) = lab.respond(&session, &opts).await;
    assert_generic(status, &body);
    assert_validation_failed(&lab.record(), ValidationError::KbJwtMalformed);
    lab.assert_pending(&session).await;
    lab.shutdown().await;
}

/// Cross-implementation (lab → ssi): the lab wallet's SD-JWT+KB verifies with ssi: issuer
/// signature against the trusted issuer key, revealed claims, KB-JWT `aud` / `nonce`,
/// `sd_hash` and the KB-JWT signature with the revealed `cnf.jwk`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lab_wallet_presentation_verifies_with_ssi() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session().await;
    let request = lab.request(&session).await;
    let presentation = lab
        .wallet
        .present(&request, &PresentationTamper::None)
        .expect("presentation");
    let sd = SdJwt::new(&presentation).expect("ssi parses the SD-JWT+KB");
    let issuer: JWK = serde_json::from_str(ISSUER_PUBLIC_JWK).expect("issuer JWK");
    let (revealed, verification) = sd
        .decode_reveal_verify_any(&VerificationParameters::from_resolver(&issuer))
        .await
        .expect("ssi decodes and reveals");
    verification.expect("ssi verifies the issuer signature");
    let claims = serde_json::to_value(revealed.claims()).expect("claims JSON");
    assert_eq!(claims["given_name"], "Alex");
    assert_eq!(claims["family_name"], "Sample");
    assert_eq!(claims["age_over_18"], true);
    assert_eq!(claims["vct"], SYNTHETIC_CREDENTIAL_VCT);
    assert!(claims.get("birthdate").is_none());
    assert_eq!(claims["cnf"]["jwk"], lab.wallet.holder_public_jwk());

    let kb = sd
        .decode_kb()
        .expect("KB-JWT decodes")
        .expect("KB-JWT present");
    let kb_claims = &kb.signing_bytes.payload;
    assert_eq!(kb_claims.aud, request.client_id);
    assert_eq!(kb_claims.nonce.0, request.nonce);
    assert!(
        kb_claims.sd_hash.verify(revealed.sd_alg, sd),
        "ssi recomputes sd_hash"
    );
    let holder: JWK = serde_json::from_value(claims["cnf"]["jwk"].clone()).expect("holder JWK");
    kb.verify(&VerificationParameters::from_resolver(holder))
        .await
        .expect("KB-JWT verification runs")
        .expect("ssi verifies the KB-JWT signature with cnf.jwk");
    lab.shutdown().await;
}

/// The trusted issuer key comes from configuration as an EC P-256 public JWK; a private JWK,
/// another curve, duplicate members or non-JSON are refused.
#[test]
fn trusted_issuer_key_config_accepts_only_p256_public_jwks() {
    use lab_server::IssuerKeyError;
    let key = TrustedIssuerKey::from_jwk(ISSUER_PUBLIC_JWK).expect("public JWK");
    assert_eq!(key.thumbprint(), issuer().trusted_key().thumbprint());
    assert_eq!(
        TrustedIssuerKey::from_jwk(ISSUER_JWK),
        Err(IssuerKeyError::Unsupported),
        "private JWK"
    );
    let mut other_curve: Value = serde_json::from_str(ISSUER_PUBLIC_JWK).expect("JSON");
    other_curve["crv"] = "P-384".into();
    assert_eq!(
        TrustedIssuerKey::from_jwk(&other_curve.to_string()),
        Err(IssuerKeyError::Unsupported)
    );
    let duplicated = ISSUER_PUBLIC_JWK.replacen('{', r#"{"kty":"EC","#, 1);
    assert_eq!(
        TrustedIssuerKey::from_jwk(&duplicated),
        Err(IssuerKeyError::Malformed)
    );
    assert_eq!(
        TrustedIssuerKey::from_jwk("not json"),
        Err(IssuerKeyError::Malformed)
    );
}
