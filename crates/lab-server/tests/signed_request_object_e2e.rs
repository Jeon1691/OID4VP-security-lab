//! Signed Request Objects (JAR, RFC 9101) served at the lab's `request_uri`, and the wallet
//! simulator's verification of them (OpenID4VP 1.1 §5, §5.8, §5.9.3, §5.10.1).
//!
//! Invariants under test:
//! - `GET request_uri` answers `application/oauth-authz-req+jwt` with a compact ES256 JWS whose
//!   header is `typ: oauth-authz-req+jwt` and `kid` = the did:key verification method of the
//!   `client_id`, and whose payload carries `aud: https://self-issued.me/v2`.
//! - The signed `client_id` / `nonce` / `response_uri` bytes equal the stored `RequestBinding`
//!   bytes, which equal the `SessionInfo::from_binding` inputs the Verifier decrypts with, on
//!   the unique, shared bounded-trial and shared unique-kid routes.
//! - The JWS is made once at issue time and served unchanged; any later change to the payload
//!   is detected by the wallet.
//! - The wallet takes binding values only from a payload it verified, and refuses a tampered
//!   payload, a wrong key, a wrong `typ`, `alg: none`, a foreign `client_id`, a wrong `aud`, an
//!   expired object, a wrong media type, `crit`, a bad `kid` and an attacker's own did:key.
//! - The server refuses to start with a did:key `client_id` that is not its signing key's, or a
//!   Client Identifier Prefix it cannot sign for.
//!
//! The signing key is the synthetic SpruceID fixture (`fixtures/spruce_verifier.jwk`), loaded
//! here through the lab's config; it is never compiled into the library or binary.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_hpke::SessionInfo;
use lab_server::wallet_sim::{
    CreatedSession, RequestRejection, SealOptions, WalletError, WalletSim,
};
use lab_server::{
    DEFAULT_CLIENT_ID, DEFAULT_SESSION_TTL, LabConfig, LabServer, Mode, RequestSigningKey,
    RouteKind, SharedRouteStrategy, StartError,
};
use openid4vp::verifier::request_signer::{P256Signer, RequestSigner as _};
use protocol_model::{ClientIdWire, NonceWire, RequestBinding, ResponseUriWire};
use serde_json::{Value, json};
use session_core::CandidateBudget;

/// Synthetic SpruceID fixture key (spruceid/openid4vp@c57a8958 `tests/examples/verifier.jwk`);
/// its did:key is `DEFAULT_CLIENT_ID`.
const FIXTURE_JWK: &str = include_str!("fixtures/spruce_verifier.jwk");
/// did:key verification method of the fixture key (did:key Method v0.7 §3.1: the fragment is
/// the multibase key itself).
const VERIFIER_DID_VM: &str = "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn#zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn";
/// Media type of a Request URI response (OpenID4VP 1.1 §5.10.1, RFC 9101 §5.2.3 / §9.4.1).
const JAR_MEDIA_TYPE: &str = "application/oauth-authz-req+jwt";
/// Request Object `typ` (OpenID4VP 1.1 §5, RFC 9101 §10.8).
const JAR_TYP: &str = "oauth-authz-req+jwt";
/// `aud` under Static Discovery (OpenID4VP 1.1 §5.8).
const STATIC_DISCOVERY_AUD: &str = "https://self-issued.me/v2";
/// Request Object signing algorithm of a P-256 key (RFC 7518 §3.4).
const ES256: &str = "ES256";
/// Compact JWS segments (RFC 7515 §7.1).
const JWS_HEADER: usize = 0;
const JWS_PAYLOAD: usize = 1;
const JWS_SIGNATURE: usize = 2;
const JWS_SEGMENTS: usize = 3;
/// Scalar byte of a second synthetic P-256 key (any value in `[1, n)` works; 0x07.. is).
const WRONG_KEY_BYTE: u8 = 0x07;
const P256_SCALAR_BYTES: usize = 32;
/// Shared-route bounded-trial budget for the route matrix.
const TRIAL_BUDGET: usize = 2;
/// A `decentralized_identifier` client_id the lab did not issue (never resolved: the checks
/// that refuse it run on the fixture-signed payload).
const FOREIGN_CLIENT_ID: &str =
    "decentralized_identifier:did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
/// An `aud` that is neither Static Discovery nor this wallet's issuer.
const FOREIGN_AUD: &str = "https://wallet.example";
/// A `typ` that is a plain JWT, not a Request Object (RFC 7519 §5.1).
const PLAIN_JWT_TYP: &str = "JWT";
/// Unsecured JWS algorithm (RFC 7518 §3.6).
const ALG_NONE: &str = "none";
/// A media type that is a JWT but not a Request Object (RFC 7519 §10.3.1).
const PLAIN_JWT_MEDIA_TYPE: &str = "application/jwt";
/// Client ids whose prefix needs trust material the lab cannot produce (OpenID4VP 1.1 §5.9.3):
/// `redirect_uri` requests cannot be signed, other DID methods need a `kid` the lab cannot
/// derive, and the x509 / attestation / federation prefixes need certificates or statements.
const UNSIGNABLE_CLIENT_IDS: [&str; 7] = [
    "redirect_uri:http://127.0.0.1/cb",
    "decentralized_identifier:did:web:verifier.example",
    "x509_san_dns:verifier.example",
    "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk",
    "verifier_attestation:verifier.example",
    "openid_federation:https://verifier.example",
    "origin:https://verifier.example",
];
/// A pre-registered client id (no Client Identifier Prefix, OpenID4VP 1.1 §5.9.2).
const PRE_REGISTERED_CLIENT_ID: &str = "lab-pre-registered-verifier";
/// A did:key client id whose method-specific id is not a multibase P-256 key.
const MALFORMED_DID_KEY_CLIENT_ID: &str = "decentralized_identifier:did:key:zNotAKey";
/// A did:key DID URL whose method-specific id does not decode to a key.
const UNRESOLVABLE_KID: &str = "did:key:zNotAKey#zNotAKey";
/// A JOSE header extension no wallet understands (RFC 7515 §4.1.11).
const UNKNOWN_CRIT: &str = "urn:lab:unknown";
/// Seconds subtracted from now for an already-expired `exp`.
const EXPIRED_BY_SECS: u64 = 1;

fn fixture_key() -> RequestSigningKey {
    RequestSigningKey::from_jwk(FIXTURE_JWK).expect("fixture JWK is a P-256 private key")
}

fn wrong_key_jwk() -> String {
    p256_spruce::SecretKey::from_slice(&[WRONG_KEY_BYTE; P256_SCALAR_BYTES])
        .expect("valid scalar")
        .to_jwk_string()
        .to_string()
}

/// The fixture's public JWK (no `d`), as a wallet would pin it.
fn fixture_public_jwk() -> String {
    let mut jwk: Value = serde_json::from_str(FIXTURE_JWK).expect("fixture JSON");
    jwk.as_object_mut().expect("JWK object").remove("d");
    jwk.to_string()
}

fn trial() -> Mode {
    Mode::Research(SharedRouteStrategy::BoundedTrial(
        CandidateBudget::new(TRIAL_BUDGET).expect("valid budget"),
    ))
}

struct Lab {
    server: LabServer,
    wallet: WalletSim,
}

impl Lab {
    async fn start(mode: Mode) -> Self {
        Self::start_with(LabConfig::new(mode, fixture_key())).await
    }

    async fn start_with(config: LabConfig) -> Self {
        Self {
            server: LabServer::start(config).await.expect("lab server starts"),
            wallet: WalletSim::new().expect("wallet simulator builds"),
        }
    }

    async fn session(&self, route: RouteKind) -> CreatedSession {
        self.wallet
            .create_session(&self.server.base_url(), route, None)
            .await
            .expect("session is created")
    }

    /// The raw `request_uri` answer: status 200 and the JAR media type, body = compact JWS.
    async fn raw_request(&self, session: &CreatedSession) -> String {
        let reply = self
            .wallet
            .get(&session.request_uri)
            .await
            .expect("request_uri answers");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.content_type.as_deref(), Some(JAR_MEDIA_TYPE));
        String::from_utf8(reply.body).expect("compact JWS is ASCII")
    }
}

fn segments(jwt: &str) -> Vec<&str> {
    let segments: Vec<&str> = jwt.split('.').collect();
    assert_eq!(segments.len(), JWS_SEGMENTS, "compact JWS: {jwt}");
    segments
}

fn decode_json(segment: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64url segment");
    serde_json::from_slice(&bytes).expect("JSON segment")
}

fn encode_json(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn spruce_signer() -> P256Signer {
    spruce_signer_for(FIXTURE_JWK)
}

fn spruce_signer_for(jwk: &str) -> P256Signer {
    let secret = p256_spruce::SecretKey::from_jwk_str(jwk).expect("JWK parses");
    P256Signer::new(secret.into()).expect("P-256 signer")
}

/// A compact JWS over `header` and `payload`, signed by SpruceID's `P256Signer` with the
/// fixture key: a validly signed object the lab never issued.
async fn spruce_signed(header: &Value, payload: &Value) -> String {
    spruce_signed_with(&spruce_signer(), header, payload).await
}

async fn spruce_signed_with(signer: &P256Signer, header: &Value, payload: &Value) -> String {
    let input = format!("{}.{}", encode_json(header), encode_json(payload));
    let signature = signer.sign(input.as_bytes()).await;
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// did:key DID URL of `jwk`'s public key, computed by ssi (independent of the lab).
fn ssi_did_key_url(jwk: &str) -> String {
    let jwk: ssi::JWK = serde_json::from_str(jwk).expect("ssi parses the JWK");
    ssi::dids::DIDKey::generate_url(&jwk.to_public())
        .expect("did:key of a P-256 key")
        .to_string()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn jar_header() -> Value {
    json!({ "alg": ES256, "typ": JAR_TYP, "kid": VERIFIER_DID_VM })
}

fn binding_parts(binding: &RequestBinding) -> (&ClientIdWire, &NonceWire, &ResponseUriWire) {
    match binding {
        RequestBinding::DirectPostJwt {
            client_id,
            nonce,
            response_uri,
        } => (client_id, nonce, response_uri),
        RequestBinding::DcApiJwt { .. } => panic!("lab issues direct_post.jwt only"),
    }
}

fn assert_rejected(result: Result<impl std::fmt::Debug, WalletError>, want: RequestRejection) {
    match result {
        Err(WalletError::Rejected(got)) => assert_eq!(got, want),
        other => panic!("expected Rejected({want:?}), got {other:?}"),
    }
}

/// OpenID4VP 1.1 §5.10.1 / §5 / §5.8 / §5.9.3: the request_uri answer is a signed Request
/// Object with the JAR media type, `typ`, ES256, the did:key `kid`, static-discovery `aud`, the
/// same `client_id` as the authorization request, and no `iss` (MAY, and ignored by wallets).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_uri_serves_signed_jar_with_spec_header_and_claims() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    assert_eq!(session.client_id, DEFAULT_CLIENT_ID);

    let jwt = lab.raw_request(&session).await;
    let parts = segments(&jwt);
    let header = decode_json(parts[JWS_HEADER]);
    assert_eq!(header["alg"], ES256);
    assert_eq!(header["typ"], JAR_TYP);
    assert_eq!(header["kid"], VERIFIER_DID_VM);
    assert!(header.get("crit").is_none());

    let payload = decode_json(parts[JWS_PAYLOAD]);
    assert_eq!(payload["aud"], STATIC_DISCOVERY_AUD);
    assert_eq!(payload["client_id"], DEFAULT_CLIENT_ID);
    assert_eq!(payload["response_mode"], "direct_post.jwt");
    assert_eq!(payload["response_type"], "vp_token");
    assert_eq!(
        payload["client_metadata"]["jwks"]["keys"][0]["alg"],
        "HPKE-0"
    );
    assert!(payload.get("iss").is_none());

    let request = lab
        .wallet
        .fetch_request(&session)
        .await
        .expect("wallet verifies the signed request");
    assert_eq!(request.client_id, DEFAULT_CLIENT_ID);
    lab.server.shutdown().await;
}

/// ADR-001 reuse: the lab's ES256 signature is byte-identical to SpruceID's `P256Signer` over
/// the same signing input with the same key (both RFC 6979 deterministic ECDSA), so the lab
/// signer computes exactly what the verified upstream signer computes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lab_request_signature_is_byte_identical_to_spruce_p256_signer() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let parts = segments(&jwt);
    let input = format!("{}.{}", parts[JWS_HEADER], parts[JWS_PAYLOAD]);
    let spruce = spruce_signer().sign(input.as_bytes()).await;
    let lab_signature = URL_SAFE_NO_PAD
        .decode(parts[JWS_SIGNATURE])
        .expect("signature segment");
    assert_eq!(lab_signature, spruce);
    lab.server.shutdown().await;
}

/// The invariant JAR signing must keep: on every route, the signed `client_id` / `nonce` /
/// `response_uri` bytes == the stored `RequestBinding` bytes == the `SessionInfo::from_binding`
/// inputs; the wallet's verified values are those bytes, and a response sealed from them is
/// accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_request_object_binding_bytes_match_stored_session_and_session_info() {
    let cases = [
        (Mode::Hardened, RouteKind::Unique),
        (trial(), RouteKind::Shared),
        (
            Mode::Research(SharedRouteStrategy::UniqueKid),
            RouteKind::Shared,
        ),
    ];
    for (mode, route) in cases {
        let lab = Lab::start(mode).await;
        let session = lab.session(route).await;
        let jwt = lab.raw_request(&session).await;
        let payload = decode_json(segments(&jwt)[JWS_PAYLOAD]);
        let signed = |name: &str| {
            payload[name]
                .as_str()
                .unwrap_or_else(|| panic!("{name} in payload"))
                .as_bytes()
                .to_vec()
        };

        let binding = lab
            .server
            .stored_binding(&session.session_id)
            .expect("session is stored");
        let (client_id, nonce, response_uri) = binding_parts(&binding);
        assert_eq!(signed("client_id"), client_id.as_bytes(), "{route:?}");
        assert_eq!(signed("nonce"), nonce.as_bytes(), "{route:?}");
        assert_eq!(signed("response_uri"), response_uri.as_bytes(), "{route:?}");
        assert_eq!(session.response_uri.as_bytes(), response_uri.as_bytes());

        let from_signed = SessionInfo::direct_post_jwt(
            &ClientIdWire::new(String::from_utf8(signed("client_id")).expect("utf-8"))
                .expect("wire client_id"),
            &NonceWire::new(String::from_utf8(signed("nonce")).expect("utf-8"))
                .expect("wire nonce"),
            &ResponseUriWire::new(String::from_utf8(signed("response_uri")).expect("utf-8"))
                .expect("wire response_uri"),
        );
        assert_eq!(
            from_signed.as_bytes(),
            SessionInfo::from_binding(&binding).as_bytes(),
            "{route:?}"
        );

        let request = lab
            .wallet
            .fetch_request(&session)
            .await
            .expect("wallet verifies");
        assert_eq!(request.client_id.as_bytes(), client_id.as_bytes());
        assert_eq!(request.nonce.as_bytes(), nonce.as_bytes());
        assert_eq!(request.response_uri.as_bytes(), response_uri.as_bytes());

        let jwe = lab
            .wallet
            .seal(&request, &SealOptions::default())
            .expect("wallet seals");
        let reply = lab
            .wallet
            .post_response(&request.response_uri, &jwe)
            .await
            .expect("response endpoint answers");
        assert_eq!(reply.status, 200, "{route:?}");
        assert_eq!(
            lab.wallet
                .session_state(&session.result_uri)
                .await
                .expect("result")
                .as_deref(),
            Some("consumed")
        );
        lab.server.shutdown().await;
    }
}

/// The JWS is made once, at issue time, from the binding that is then moved into the
/// registry; `request_uri` serves those stored bytes. Before and after the session is
/// consumed the answer is byte-identical and still matches the stored binding, so the
/// Verifier has no path that changes a signed value after signing (and a changed payload
/// would not verify; see `wallet_refuses_tampered_request_payload`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn served_request_object_is_signed_once_and_never_changes() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let first = lab.raw_request(&session).await;
    assert_eq!(lab.raw_request(&session).await, first);

    let request = lab.wallet.fetch_request(&session).await.expect("verifies");
    let jwe = lab
        .wallet
        .seal(&request, &SealOptions::default())
        .expect("seal");
    let reply = lab
        .wallet
        .post_response(&request.response_uri, &jwe)
        .await
        .expect("answers");
    assert_eq!(reply.status, 200);

    assert_eq!(lab.raw_request(&session).await, first);
    let binding = lab
        .server
        .stored_binding(&session.session_id)
        .expect("consumed session is still stored");
    let (_, nonce, _) = binding_parts(&binding);
    assert_eq!(
        decode_json(segments(&first)[JWS_PAYLOAD])["nonce"].as_str(),
        Some(nonce.as_str())
    );
    lab.server.shutdown().await;
}

/// A payload changed after signing (here: the nonce) is refused on the signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_tampered_request_payload() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let parts = segments(&jwt);
    let mut payload = decode_json(parts[JWS_PAYLOAD]);
    payload["nonce"] = "attacker-chosen-nonce".into();
    let tampered = format!(
        "{}.{}.{}",
        parts[JWS_HEADER],
        encode_json(&payload),
        parts[JWS_SIGNATURE]
    );
    assert_rejected(
        lab.wallet
            .verify_request(&tampered, &session.client_id)
            .await,
        RequestRejection::Signature,
    );
    // The untouched object still verifies.
    lab.wallet
        .verify_request(&jwt, &session.client_id)
        .await
        .expect("original verifies");
    lab.server.shutdown().await;
}

/// An object naming the fixture's did:key `kid` but signed with another key, and a wallet
/// pinning another key than the signer's, both fail on the signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_request_signed_with_wrong_key() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let payload = decode_json(segments(&jwt)[JWS_PAYLOAD]);
    let forged = spruce_signed_with(
        &spruce_signer_for(&wrong_key_jwk()),
        &jar_header(),
        &payload,
    )
    .await;
    assert_rejected(
        lab.wallet.verify_request(&forged, &session.client_id).await,
        RequestRejection::Signature,
    );

    let mut wrong_public: Value = serde_json::from_str(&wrong_key_jwk()).expect("JWK");
    wrong_public.as_object_mut().expect("object").remove("d");
    let pinned = WalletSim::with_pinned_verifier_key(&wrong_public.to_string())
        .expect("pinned wallet builds");
    assert_rejected(
        pinned.fetch_request(&session).await,
        RequestRejection::Signature,
    );
    let pinned_right =
        WalletSim::with_pinned_verifier_key(&fixture_public_jwk()).expect("pinned wallet builds");
    pinned_right
        .fetch_request(&session)
        .await
        .expect("right pinned key verifies");
    lab.server.shutdown().await;
}

/// OpenID4VP 1.1 §5: a Request Object whose `typ` is missing or not `oauth-authz-req+jwt` is
/// not processed, even when validly signed by the right key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_request_with_wrong_typ() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let payload = decode_json(segments(&jwt)[JWS_PAYLOAD]);

    let mut header = jar_header();
    header["typ"] = PLAIN_JWT_TYP.into();
    let wrong_typ = spruce_signed(&header, &payload).await;
    assert_rejected(
        lab.wallet
            .verify_request(&wrong_typ, &session.client_id)
            .await,
        RequestRejection::Typ,
    );

    header.as_object_mut().expect("object").remove("typ");
    let no_typ = spruce_signed(&header, &payload).await;
    assert_rejected(
        lab.wallet.verify_request(&no_typ, &session.client_id).await,
        RequestRejection::Typ,
    );

    // Control: the same payload with the right header verifies.
    let right = spruce_signed(&jar_header(), &payload).await;
    lab.wallet
        .verify_request(&right, &session.client_id)
        .await
        .expect("SpruceID-signed JAR with the lab header verifies");
    lab.server.shutdown().await;
}

/// An unsecured (`alg: none`) Request Object, with or without a signature segment, and any
/// algorithm other than ES256 are refused (`decentralized_identifier` requires a signature,
/// OpenID4VP 1.1 §5.9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_unsigned_alg_none_request() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let parts = segments(&jwt);

    let mut header = jar_header();
    header["alg"] = ALG_NONE.into();
    let unsecured = format!("{}.{}.", encode_json(&header), parts[JWS_PAYLOAD]);
    assert_rejected(
        lab.wallet
            .verify_request(&unsecured, &session.client_id)
            .await,
        RequestRejection::Alg,
    );
    let none_with_signature = format!(
        "{}.{}.{}",
        encode_json(&header),
        parts[JWS_PAYLOAD],
        parts[JWS_SIGNATURE]
    );
    assert_rejected(
        lab.wallet
            .verify_request(&none_with_signature, &session.client_id)
            .await,
        RequestRejection::Alg,
    );
    header["alg"] = "HS256".into();
    let hmac = format!(
        "{}.{}.{}",
        encode_json(&header),
        parts[JWS_PAYLOAD],
        parts[JWS_SIGNATURE]
    );
    assert_rejected(
        lab.wallet.verify_request(&hmac, &session.client_id).await,
        RequestRejection::Alg,
    );
    lab.server.shutdown().await;
}

/// OpenID4VP 1.1 §5.10.1: the Request Object `client_id` must equal the authorization
/// request's; §5.9.3: the signing key belongs to that DID; §5.8: `aud` is the static-discovery
/// value. Each is checked on validly signed objects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_request_with_foreign_client_id_or_aud() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let payload = decode_json(segments(&jwt)[JWS_PAYLOAD]);

    // The authorization request named another client.
    assert_rejected(
        lab.wallet.verify_request(&jwt, FOREIGN_CLIENT_ID).await,
        RequestRejection::ClientId,
    );

    // Signed by the fixture DID's key, but claiming another DID as client_id.
    let mut foreign = payload.clone();
    foreign["client_id"] = FOREIGN_CLIENT_ID.into();
    let foreign = spruce_signed(&jar_header(), &foreign).await;
    assert_rejected(
        lab.wallet.verify_request(&foreign, FOREIGN_CLIENT_ID).await,
        RequestRejection::ClientId,
    );

    let mut wrong_aud = payload.clone();
    wrong_aud["aud"] = FOREIGN_AUD.into();
    let wrong_aud = spruce_signed(&jar_header(), &wrong_aud).await;
    assert_rejected(
        lab.wallet
            .verify_request(&wrong_aud, &session.client_id)
            .await,
        RequestRejection::Audience,
    );
    lab.server.shutdown().await;
}

/// The signing key comes from config; a malformed or public-only JWK, or one whose public
/// half does not match `d`, is refused, and `Debug` never shows the private key.
#[test]
fn request_signing_key_is_loaded_from_config_and_never_printed() {
    let key = fixture_key();
    let d = serde_json::from_str::<Value>(FIXTURE_JWK).expect("JSON")["d"]
        .as_str()
        .expect("d")
        .to_owned();
    assert!(!format!("{key:?}").contains(&d));

    assert!(RequestSigningKey::from_jwk(&fixture_public_jwk()).is_err());
    assert!(RequestSigningKey::from_jwk("not json").is_err());
    let mut mismatched: Value = serde_json::from_str(FIXTURE_JWK).expect("JSON");
    let wrong: Value = serde_json::from_str(&wrong_key_jwk()).expect("JSON");
    mismatched["d"] = wrong["d"].clone();
    assert!(RequestSigningKey::from_jwk(&mismatched.to_string()).is_err());
    let mut other_curve: Value = serde_json::from_str(FIXTURE_JWK).expect("JSON");
    other_curve["crv"] = "P-384".into();
    assert!(RequestSigningKey::from_jwk(&other_curve.to_string()).is_err());
}

/// L1: a `decentralized_identifier:did:key:` client id must be the did:key of the signing key;
/// the server derives it from the key and refuses to start on a mismatch (another key's DID, or
/// a malformed one).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_did_key_client_id_that_is_not_the_signing_keys() {
    let wrong = RequestSigningKey::from_jwk(&wrong_key_jwk()).expect("second synthetic key");
    assert!(matches!(
        LabServer::start(LabConfig::new(Mode::Hardened, wrong)).await,
        Err(StartError::ClientIdKeyMismatch)
    ));
    let mut config = LabConfig::new(Mode::Hardened, fixture_key());
    config.client_id = ClientIdWire::new(MALFORMED_DID_KEY_CLIENT_ID).expect("wire client_id");
    assert!(matches!(
        LabServer::start(config).await,
        Err(StartError::ClientIdKeyMismatch)
    ));
}

/// L1: any P-256 key works with its own did:key (derived by the lab, cross-checked against
/// ssi's did:key generation); the header `kid` is that DID's verification method and the
/// did:key wallet verifies the request end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_accepts_the_did_key_of_any_signing_key() {
    let jwk = wrong_key_jwk();
    let kid = ssi_did_key_url(&jwk);
    let (did, _) = kid.split_once('#').expect("DID URL");
    let mut config = LabConfig::new(
        Mode::Hardened,
        RequestSigningKey::from_jwk(&jwk).expect("second synthetic key"),
    );
    config.client_id =
        ClientIdWire::new(format!("decentralized_identifier:{did}")).expect("wire client_id");
    let lab = Lab::start_with(config).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    assert_eq!(decode_json(segments(&jwt)[JWS_HEADER])["kid"], kid.as_str());
    lab.wallet
        .fetch_request(&session)
        .await
        .expect("did:key wallet verifies the second key's request");
    lab.server.shutdown().await;
}

/// L1: Client Identifier Prefixes the lab cannot sign for correctly are refused at start;
/// a pre-registered client id (no prefix) is allowed and gets no `kid`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_client_id_prefixes_the_lab_cannot_sign_for() {
    for client_id in UNSIGNABLE_CLIENT_IDS {
        let mut config = LabConfig::new(Mode::Hardened, fixture_key());
        config.client_id = ClientIdWire::new(client_id).expect("wire client_id");
        assert!(
            matches!(
                LabServer::start(config).await,
                Err(StartError::UnsupportedClientIdPrefix)
            ),
            "{client_id}"
        );
    }
    let mut config = LabConfig::new(Mode::Hardened, fixture_key());
    config.client_id = ClientIdWire::new(PRE_REGISTERED_CLIENT_ID).expect("wire client_id");
    let lab = Lab::start_with(config).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    assert!(decode_json(segments(&jwt)[JWS_HEADER]).get("kid").is_none());
    let pinned = WalletSim::with_pinned_verifier_key(&fixture_public_jwk()).expect("pinned");
    pinned
        .fetch_request(&session)
        .await
        .expect("pinned wallet verifies a pre-registered client's request");
    lab.server.shutdown().await;
}

/// L2: the Request Object carries `iat` and `exp` (RFC 7519 §4.1.6 / §4.1.4) with `exp` the
/// session's expiry, rounded up to the second so it never ends before the session does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_object_carries_iat_and_exp_of_the_session_ttl() {
    let lab = Lab::start(Mode::Hardened).await;
    let before = now_secs();
    let session = lab.session(RouteKind::Unique).await;
    let after = now_secs();
    let payload = decode_json(segments(&lab.raw_request(&session).await)[JWS_PAYLOAD]);
    let iat = payload["iat"].as_u64().expect("iat is a NumericDate");
    let exp = payload["exp"].as_u64().expect("exp is a NumericDate");
    assert!(
        (before..=after).contains(&iat),
        "iat {iat} in [{before}, {after}]"
    );
    let ttl = DEFAULT_SESSION_TTL.as_secs();
    assert!(
        (ttl..=ttl + 1).contains(&(exp - iat)),
        "exp - iat = {}",
        exp - iat
    );
    lab.server.shutdown().await;
}

/// L2: an expired Request Object (`exp` not after now, RFC 7519 §4.1.4), or one without a
/// numeric `exp`, is refused even when validly signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_expired_or_exp_less_request() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let payload = decode_json(segments(&lab.raw_request(&session).await)[JWS_PAYLOAD]);

    let mut expired = payload.clone();
    expired["exp"] = (now_secs() - EXPIRED_BY_SECS).into();
    let expired = spruce_signed(&jar_header(), &expired).await;
    assert_rejected(
        lab.wallet
            .verify_request(&expired, &session.client_id)
            .await,
        RequestRejection::Expired,
    );
    let mut missing = payload.clone();
    missing.as_object_mut().expect("object").remove("exp");
    let missing = spruce_signed(&jar_header(), &missing).await;
    assert_rejected(
        lab.wallet
            .verify_request(&missing, &session.client_id)
            .await,
        RequestRejection::Expired,
    );
    let mut textual = payload.clone();
    textual["exp"] = "tomorrow".into();
    let textual = spruce_signed(&jar_header(), &textual).await;
    assert_rejected(
        lab.wallet
            .verify_request(&textual, &session.client_id)
            .await,
        RequestRejection::Expired,
    );
    let fresh = spruce_signed(&jar_header(), &payload).await;
    lab.wallet
        .verify_request(&fresh, &session.client_id)
        .await
        .expect("unexpired control verifies");
    lab.server.shutdown().await;
}

/// L4: a correctly signed Request Object served as `application/jwt` (not
/// `application/oauth-authz-req+jwt`, OpenID4VP 1.1 §5.10.1) is refused before parsing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_request_served_with_wrong_content_type() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;

    let stub = axum::Router::new().route(
        "/request",
        axum::routing::get(move || async move {
            (
                [(axum::http::header::CONTENT_TYPE, PLAIN_JWT_MEDIA_TYPE)],
                jwt,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind");
    let addr = listener.local_addr().expect("stub address");
    let serve = tokio::spawn(async move { axum::serve(listener, stub).await });
    let relabelled = CreatedSession {
        request_uri: format!("http://{addr}/request"),
        ..session.clone()
    };
    assert_rejected(
        lab.wallet.fetch_request(&relabelled).await,
        RequestRejection::ContentType,
    );
    serve.abort();
    lab.wallet
        .fetch_request(&session)
        .await
        .expect("the lab's own answer verifies");
    lab.server.shutdown().await;
}

/// L4: a `crit` header (RFC 7515 §4.1.11, no extension is understood) and a compact
/// serialization with an extra segment are malformed, even when validly signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_request_with_crit_header_or_extra_segment() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let jwt = lab.raw_request(&session).await;
    let payload = decode_json(segments(&jwt)[JWS_PAYLOAD]);

    let mut header = jar_header();
    header["crit"] = json!([UNKNOWN_CRIT]);
    header[UNKNOWN_CRIT] = true.into();
    let crit = spruce_signed(&header, &payload).await;
    assert_rejected(
        lab.wallet.verify_request(&crit, &session.client_id).await,
        RequestRejection::Malformed,
    );
    let four_segments = format!("{jwt}.{}", segments(&jwt)[JWS_SIGNATURE]);
    assert_rejected(
        lab.wallet
            .verify_request(&four_segments, &session.client_id)
            .await,
        RequestRejection::Malformed,
    );
    lab.server.shutdown().await;
}

/// L4: with did:key trust the `kid` must be present, a DID URL, and resolve to a key
/// (OpenID4VP 1.1 §5.9.3); each failure is refused before any signature check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_request_with_missing_or_unresolvable_kid() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let payload = decode_json(segments(&lab.raw_request(&session).await)[JWS_PAYLOAD]);
    let (did, _) = VERIFIER_DID_VM.split_once('#').expect("DID URL");

    let mut header = jar_header();
    header.as_object_mut().expect("object").remove("kid");
    let headers = [
        header.clone(),
        json!({ "alg": ES256, "typ": JAR_TYP, "kid": did }),
        json!({ "alg": ES256, "typ": JAR_TYP, "kid": UNRESOLVABLE_KID }),
    ];
    for header in headers {
        let jwt = spruce_signed(&header, &payload).await;
        assert_rejected(
            lab.wallet.verify_request(&jwt, &session.client_id).await,
            RequestRejection::Kid,
        );
    }
    lab.server.shutdown().await;
}

/// L4: an attacker signs with their own key and names their own did:key as `kid`, so the
/// signature verifies, but claims the lab's `client_id`: refused, because the signing DID is
/// not the client_id's (OpenID4VP 1.1 §5.9.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_refuses_attacker_did_key_claiming_the_lab_client_id() {
    let lab = Lab::start(Mode::Hardened).await;
    let session = lab.session(RouteKind::Unique).await;
    let payload = decode_json(segments(&lab.raw_request(&session).await)[JWS_PAYLOAD]);
    assert_eq!(payload["client_id"], DEFAULT_CLIENT_ID);

    let attacker = wrong_key_jwk();
    let header = json!({ "alg": ES256, "typ": JAR_TYP, "kid": ssi_did_key_url(&attacker) });
    let forged = spruce_signed_with(&spruce_signer_for(&attacker), &header, &payload).await;
    assert_rejected(
        lab.wallet.verify_request(&forged, &session.client_id).await,
        RequestRejection::ClientId,
    );
    lab.server.shutdown().await;
}
