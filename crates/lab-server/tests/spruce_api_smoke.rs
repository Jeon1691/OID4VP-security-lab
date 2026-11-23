//! G0-C: the pinned SpruceID `openid4vp` public API compiles and is usable from this workspace.
//!
//! Checks the facts the HPKE Session Info design depends on (Notion 02 · Architecture §4, §7.2):
//! - `RequestBuilder` forces `<submission_endpoint>/<session uuid>` as `response_uri` (the
//!   Unique-URI baseline, and the reason Shared-URI experiments need a separate RequestFactory).
//! - The `response_uri`, `nonce` and `client_id` inside the *signed* Request Object are
//!   byte-identical to what the SessionStore keeps, so Session Info can be rebuilt from storage.
//!
//! All key material is the synthetic upstream test fixture; no real credentials are involved.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openid4vp::{
    core::{
        authorization_request::parameters::{ClientMetadata, Nonce, ResponseMode, ResponseType},
        credential_format::ClaimFormatDesignation,
        dcql_query::{DcqlCredentialQuery, DcqlQuery},
        metadata::WalletMetadata,
        object::UntypedObject,
    },
    utils::NonEmptyVec,
    verifier::{
        Verifier,
        client::DIDClient,
        request_signer::P256Signer,
        session::{MemoryStore, SessionStore, Status},
    },
};
use serde_json::{Value, json};
use ssi::{
    dids::{DIDKey, VerificationMethodDIDResolver},
    verification_methods::AnyJwkMethod,
};

/// did:key verification method of `fixtures/spruce_verifier.jwk`
/// (copied from spruceid/openid4vp@c57a8958 `tests/examples/verifier.jwk`).
const VERIFIER_DID_VM: &str = "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn#zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn";
/// Loopback-only lab submission endpoint (Research/Hardened modes never bind publicly).
const SUBMISSION_ENDPOINT: &str = "http://127.0.0.1:8080/lab/v1/response";
/// Synthetic nonce with characters that URL/percent encoding or normalisation would rewrite
/// (`+`, `/`, `=`, `%`, space), to catch any non-byte-exact handling.
const TEST_NONCE: &str = "g0 Nonce+/=%2F~Synthetic";
/// Segment indices of a compact JWS (`header.payload.signature`).
const JWS_HEADER_SEGMENT: usize = 0;
const JWS_PAYLOAD_SEGMENT: usize = 1;
/// Number of segments in a compact JWS.
const JWS_SEGMENT_COUNT: usize = 3;
/// Request Object signing algorithm of the P-256 fixture signer (RFC 7518 §3.4).
const EXPECTED_JWS_ALG: &str = "ES256";

async fn verifier_with_store() -> (Verifier, MemoryStore) {
    let secret = p256_spruce::SecretKey::from_jwk_str(include_str!("fixtures/spruce_verifier.jwk"))
        .expect("fixture JWK parses");
    let signer = Arc::new(P256Signer::new(secret.into()).expect("P-256 signer"));
    let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
        VerificationMethodDIDResolver::new(DIDKey);
    let client = DIDClient::new(VERIFIER_DID_VM.to_owned(), signer, &resolver)
        .await
        .expect("DID client resolves fixture key");

    let store = MemoryStore::default();
    let verifier = Verifier::builder()
        .with_client(Arc::new(client))
        .with_submission_endpoint(SUBMISSION_ENDPOINT.parse().expect("valid URL"))
        .with_session_store(Arc::new(store.clone()))
        .build()
        .await
        .expect("verifier builds");
    (verifier, store)
}

fn wallet_metadata() -> WalletMetadata {
    serde_json::from_value(json!({
        "authorization_endpoint": "openid4vp:",
        "client_id_prefixes_supported": ["decentralized_identifier"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "response_types_supported": ["vp_token"],
        "vp_formats_supported": { "jwt_vc_json": { "alg_values_supported": ["ES256"] } }
    }))
    .expect("wallet metadata parses")
}

fn dcql_query() -> DcqlQuery {
    DcqlQuery::new(NonEmptyVec::new(DcqlCredentialQuery::new(
        "synthetic-credential".into(),
        ClaimFormatDesignation::JwtVcJson,
    )))
}

/// Decodes one segment of a compact JWS. The signature itself is verified by the Wallet in
/// upstream tests; here we only assert the signed bytes are a well-formed ES256 JWS.
fn jws_segment(jwt: &str, index: usize) -> Value {
    let segments: Vec<&str> = jwt.split('.').collect();
    assert_eq!(segments.len(), JWS_SEGMENT_COUNT, "compact JWS");
    assert!(
        !segments[JWS_SEGMENT_COUNT - 1].is_empty(),
        "JWS has a signature"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(segments[index])
        .expect("base64url segment");
    serde_json::from_slice(&bytes).expect("JSON segment")
}

async fn build_direct_post_jwt_request(verifier: &Verifier) -> uuid::Uuid {
    let (id, _url) = verifier
        .build_authorization_request()
        .with_dcql_query(dcql_query())
        .with_request_parameter(ResponseMode::DirectPostJwt)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(Nonce::from(TEST_NONCE))
        .with_request_parameter(ClientMetadata(UntypedObject::default()))
        .build(wallet_metadata())
        .await
        .expect("direct_post.jwt request builds");
    id
}

#[tokio::test]
async fn signed_request_binding_matches_stored_session() {
    let (verifier, store) = verifier_with_store().await;
    let id = build_direct_post_jwt_request(&verifier).await;

    let session = store.get_session(id).await.expect("session stored");
    assert_eq!(session.status, Status::SentRequest);

    let object = &session.authorization_request_object;
    assert_eq!(object.response_mode(), &ResponseMode::DirectPostJwt);

    // RequestBuilder appends the session UUID: Unique-URI baseline (ADR-003).
    let expected_uri = format!("{SUBMISSION_ENDPOINT}/{id}");
    assert_eq!(object.return_uri().as_str(), expected_uri);

    // The signed Request Object carries exactly the bytes the store returns.
    let jwt = &session.authorization_request_jwt;
    let header = jws_segment(jwt, JWS_HEADER_SEGMENT);
    assert_eq!(header["alg"].as_str(), Some(EXPECTED_JWS_ALG));
    let payload = jws_segment(jwt, JWS_PAYLOAD_SEGMENT);
    assert_eq!(payload["response_mode"], "direct_post.jwt");
    assert_eq!(
        payload["response_uri"].as_str(),
        Some(expected_uri.as_str())
    );
    assert_eq!(payload["nonce"].as_str(), Some(TEST_NONCE));
    assert_eq!(object.nonce().as_str(), TEST_NONCE);
    let client_id = object.client_id().expect("client_id present");
    assert_eq!(payload["client_id"].as_str(), Some(client_id.0.as_str()));
    assert!(client_id.0.starts_with("decentralized_identifier:did:key:"));
}

#[tokio::test]
async fn each_session_gets_a_distinct_response_uri() {
    let (verifier, store) = verifier_with_store().await;
    let first = build_direct_post_jwt_request(&verifier).await;
    let second = build_direct_post_jwt_request(&verifier).await;

    let uri = |s: openid4vp::verifier::session::Session| {
        s.authorization_request_object.return_uri().to_string()
    };
    let first_uri = uri(store.get_session(first).await.expect("first session"));
    let second_uri = uri(store.get_session(second).await.expect("second session"));
    assert_ne!(
        first_uri, second_uri,
        "Shared URI is not expressible via RequestBuilder"
    );
}
