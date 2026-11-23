//! G0-D: the pinned SpruceID `openid4vp` runs the OpenID4VP 1.0 ECDH-ES `direct_post.jwt` flow
//! end to end over real loopback HTTP.
//!
//! Flow under test (OpenID4VP 1.0 §8.2, §8.3):
//! 1. The Verifier issues a signed Request Object whose `client_metadata.jwks` advertises a
//!    freshly generated, synthetic P-256 `ECDH-ES` encryption key.
//! 2. The wallet validates the request and encrypts its Authorization Response with SpruceID's
//!    own `build_encrypted_response` (`JweBuilder`, josekit ECDH-ES + A128GCM).
//! 3. `Wallet::submit_response` POSTs `response=<jwe>` as `application/x-www-form-urlencoded`
//!    over a real TCP connection to the request's `response_uri` on `127.0.0.1`.
//! 4. The axum handler decrypts the JWE inside `Verifier::verify_response`, which records the
//!    outcome in the session store.
//!
//! The handler is test scaffolding only; production routing lands in a later sprint. All keys
//! and presentations are synthetic, and the HTTP client refuses anything but loopback.
//!
//! Every test pins `flavor = "current_thread"`: upstream `MemoryStore` takes its lock with
//! `try_lock()` and errors instead of waiting, so a multi-threaded runtime could let the test's
//! `poll_status` and the server's `update_status` collide and fail spuriously. On one thread the
//! server task only runs while the test awaits, and no store lock is held across an await.

use std::{
    cell::RefCell,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, Request, Response, StatusCode, header::CONTENT_TYPE},
    routing::post,
};
use josekit::{
    JoseHeader as _,
    jwe::{ECDH_ES, JweDecrypter, JweHeader, alg::ecdh_es::EcdhEsJweDecrypter},
    jwk::{Jwk, KeyPair as _},
    jwt::JwtPayload,
};
use openid4vp::{
    core::{
        authorization_request::{
            AuthorizationRequestObject,
            parameters::{ClientMetadata, Nonce, ResponseMode, ResponseType},
            verification::{RequestVerifier, did},
        },
        credential_format::ClaimFormatDesignation,
        dcql_query::{DcqlCredentialQuery, DcqlQuery},
        jwe::build_encrypted_response,
        metadata::{WalletMetadata, parameters::verifier::JWKs},
        object::UntypedObject,
        response::{
            AuthorizationResponse, JwtAuthorizationResponse, UnencodedAuthorizationResponse,
            parameters::{VpToken, VpTokenItem},
        },
        util::AsyncHttpClient,
    },
    utils::NonEmptyVec,
    verifier::{
        Verifier,
        client::DIDClient,
        request_signer::P256Signer,
        session::{MemoryStore, Outcome, Session, Status},
    },
    wallet::Wallet,
};
use p256_spruce::NistP256;
use serde_json::{Map, Value, json};
use ssi::{
    dids::{DIDKey, VerificationMethodDIDResolver},
    verification_methods::AnyJwkMethod,
};
use tokio::{net::TcpListener, task::JoinHandle};
use uuid::Uuid;

/// did:key of `fixtures/spruce_verifier.jwk`
/// (copied from spruceid/openid4vp@c57a8958 `tests/examples/verifier.jwk`).
const VERIFIER_DID: &str = "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn";
/// Verification method of [`VERIFIER_DID`] that signs the Request Object.
const VERIFIER_DID_VM: &str = "did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn#zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn";
/// Loopback only; port 0 lets the OS pick a free port so parallel tests never collide.
const LOOPBACK_BIND: &str = "127.0.0.1:0";
/// Submission endpoint path; `RequestBuilder` appends `/<session uuid>` (see G0-C).
const RESPONSE_PATH: &str = "/lab/v1/response";
/// Media type of a `direct_post(.jwt)` POST body (OpenID4VP 1.0 §8.2).
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
/// Form parameter carrying the encrypted response in `direct_post.jwt` (OpenID4VP 1.0 §8.3.1).
const RESPONSE_PARAM: &str = "response";
/// A media type the endpoint must refuse even though the body itself is a valid form.
const WRONG_CONTENT_TYPE: &str = "application/json";
/// DCQL credential query id requested by the Verifier and answered by the wallet.
const CREDENTIAL_QUERY_ID: &str = "synthetic-credential";
/// Opaque synthetic presentation. G0-D tests transport encryption, not VP verification, so the
/// validator only checks that this exact value survives the encrypt/POST/decrypt round trip.
const SYNTHETIC_PRESENTATION: &str = "g0d-synthetic-presentation";
/// Synthetic Request Object nonce. The ECDH-ES flow only needs it to be present in the signed
/// request (byte-exact nonce handling is covered by G0-C), so a plain ASCII value suffices.
const TEST_NONCE: &str = "g0d-synthetic-nonce";
/// `kid` of the generated encryption key; OpenID4VP 1.0 §8.3 requires the JWE to echo it.
const ENCRYPTION_KID: &str = "g0d-ecdh-es-1";
/// A `kid` the Verifier never advertised.
const UNKNOWN_KID: &str = "g0d-unknown-kid";
/// JWK `use` value for encryption keys (RFC 7517 §4.2).
const KEY_USE_ENC: &str = "enc";
/// A valid AES-GCM `enc` (RFC 7518 §5.1) that the Verifier did not advertise.
const UNADVERTISED_JWE_ENC: &str = "A256GCM";
/// DEFLATE, the only registered JWE `zip` value (RFC 7516 §4.1.3).
const JWE_ZIP_DEFLATE: &str = "DEF";
/// Typ of the JWE SpruceID's `JweBuilder` emits (an encrypted JWT).
const JWE_TYP_JWT: &str = "JWT";
/// Upper bound for one loopback request; a wedged server fails the test instead of hanging it.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// `Outcome::Failure` reason prefixes, so tests can tell which validator step refused a JWE.
const REASON_HEADER_REJECTED: &str = "JWE protected header rejected";
const REASON_DECRYPT_FAILED: &str = "JWE decryption failed";
/// Key in `Outcome::Success.info` holding the validator run that produced the outcome.
const INFO_DECRYPT_ATTEMPT: &str = "decrypt_attempt";
/// Key agreement algorithm advertised in `jwks` (the only one SpruceID's `JweBuilder` supports).
const EXPECTED_JWE_ALG: &str = "ECDH-ES";
/// Content encryption used when `encrypted_response_enc_values_supported` is absent
/// (OpenID4VP 1.0 §8.3 default; `openid4vp::core::jwe::DEFAULT_ENC`).
const EXPECTED_JWE_ENC: &str = "A128GCM";
/// Compact JWE: header.encrypted_key.iv.ciphertext.tag (RFC 7516 §7.1).
const JWE_COMPACT_SEGMENTS: usize = 5;
/// Index of the ciphertext segment in a compact JWE (RFC 7516 §7.1).
const JWE_CIPHERTEXT_SEGMENT: usize = 3;

/// What the verifier-side validator saw for one successfully decrypted JWE.
#[derive(Debug)]
struct DecryptedJwe {
    /// The compact JWE exactly as received in the `response` form parameter.
    jwe: String,
    alg: Option<String>,
    enc: Option<String>,
    kid: Option<String>,
    payload: Value,
}

#[derive(Debug, Default)]
struct Observations {
    /// Times the validator reached the decryption step.
    decrypt_attempts: usize,
    decrypted: Vec<DecryptedJwe>,
}

#[derive(Clone)]
struct ServerState {
    verifier: Arc<Verifier>,
    decrypter: Arc<EcdhEsJweDecrypter<NistP256>>,
    observations: Arc<Mutex<Observations>>,
}

struct Lab {
    verifier: Arc<Verifier>,
    observations: Arc<Mutex<Observations>>,
    wallet: LoopbackWallet,
    /// Public half of the encryption key, as published in `client_metadata.jwks`.
    encryption_jwk: Map<String, Value>,
    /// The `axum::serve` task. Checked in [`Lab::shutdown`] so a serve loop that exited or
    /// panicked mid-test fails the test. (A panicking handler only kills its connection task;
    /// the client then sees a connection error and the test's `expect` fails.)
    server: JoinHandle<()>,
}

impl Lab {
    fn observations(&self) -> MutexGuard<'_, Observations> {
        lock(&self.observations)
    }

    async fn status(&self, id: Uuid) -> Status {
        self.verifier.poll_status(id).await.expect("session exists")
    }

    /// Stops the server, surfacing a panic or early exit of the serve task.
    async fn shutdown(self) {
        self.server.abort();
        match self.server.await {
            Err(e) if e.is_cancelled() => {}
            Err(e) => std::panic::resume_unwind(e.into_panic()),
            Ok(()) => panic!("lab server exited during the test"),
        }
    }
}

fn lock(observations: &Mutex<Observations>) -> MutexGuard<'_, Observations> {
    observations.lock().expect("observations lock not poisoned")
}

/// HTTP client for the wallet. Adapted from spruceid/openid4vp@c57a8958
/// `src/core/util/mod.rs` (`ReqwestClient`, MIT OR Apache-2.0): same request/response
/// conversion, but proxies and redirects are disabled and non-loopback targets are refused, so
/// no test traffic can leave 127.0.0.1.
struct LoopbackHttpClient(reqwest::Client);

impl LoopbackHttpClient {
    fn new() -> Self {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("reqwest client builds");
        Self(client)
    }
}

#[async_trait]
impl AsyncHttpClient for LoopbackHttpClient {
    async fn execute(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        let host = request.uri().host().context("request has a host")?;
        // Fails closed: only a literal IP that is loopback passes. Host names (`localhost`) and
        // IPv6 loopback are refused on purpose: `Uri::host()` keeps the brackets of `[::1]`, so
        // it never parses as an `IpAddr`. The lab only binds 127.0.0.1, so nothing else is needed.
        ensure!(
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            "refusing non-loopback request to {host}"
        );
        let response = self
            .0
            .execute(request.try_into().context("unable to convert request")?)
            .await
            .context("http request failed")?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .context("failed to read response body")?;
        Response::builder()
            .status(status)
            .body(body.to_vec())
            .context("unable to construct response")
    }
}

/// Wallet side, following spruceid/openid4vp@c57a8958 `tests/jwt_vc.rs` (`JwtVcWallet`), with
/// a real HTTP client instead of the in-process mock.
struct LoopbackWallet {
    metadata: WalletMetadata,
    http_client: LoopbackHttpClient,
    trusted_dids: Vec<String>,
}

#[async_trait]
impl Wallet for LoopbackWallet {
    type HttpClient = LoopbackHttpClient;

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    fn http_client(&self) -> &Self::HttpClient {
        &self.http_client
    }
}

#[async_trait]
impl RequestVerifier for LoopbackWallet {
    async fn decentralized_identifier(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: Option<String>,
    ) -> Result<()> {
        let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
            VerificationMethodDIDResolver::new(DIDKey);
        let request_jwt = request_jwt.context("signed Request Object is required")?;
        did::verify_with_resolver(
            &self.metadata,
            decoded_request,
            request_jwt,
            Some(self.trusted_dids.as_slice()),
            &resolver,
        )
        .await
    }
}

fn wallet_metadata() -> WalletMetadata {
    serde_json::from_value(json!({
        "authorization_endpoint": "openid4vp:",
        "client_id_prefixes_supported": ["decentralized_identifier"],
        "request_object_signing_alg_values_supported": ["ES256"],
        "response_types_supported": ["vp_token"],
        "vp_formats_supported": { "jwt_vc_json": { "alg_values_supported": ["ES256"] } },
        // Makes upstream `validate_request_against_metadata` check the advertised key/enc.
        "authorization_encryption_alg_values_supported": [EXPECTED_JWE_ALG],
        "authorization_encryption_enc_values_supported": [EXPECTED_JWE_ENC]
    }))
    .expect("wallet metadata parses")
}

/// Synthetic verifier encryption key pair, generated per test run with josekit (the same
/// implementation openid4vp encrypts with). Returns the decrypter and the public JWK.
fn encryption_key_pair() -> (EcdhEsJweDecrypter<NistP256>, Map<String, Value>) {
    let key_pair = ECDH_ES
        .generate_ec_key_pair::<NistP256>()
        .expect("P-256 key pair generates");

    let mut private = key_pair.to_jwk_key_pair();
    private.set_key_use(KEY_USE_ENC);
    private.set_key_id(ENCRYPTION_KID);
    let decrypter = ECDH_ES
        .decrypter_from_jwk::<NistP256>(&private)
        .expect("ECDH-ES decrypter from private JWK");

    let mut public = key_pair.to_jwk_public_key();
    public.set_key_use(KEY_USE_ENC);
    public.set_algorithm(EXPECTED_JWE_ALG);
    public.set_key_id(ENCRYPTION_KID);
    (decrypter, public.into())
}

async fn build_verifier(submission_endpoint: &str) -> Verifier {
    let secret = p256_spruce::SecretKey::from_jwk_str(include_str!("fixtures/spruce_verifier.jwk"))
        .expect("fixture JWK parses");
    let signer = Arc::new(P256Signer::new(secret.into()).expect("P-256 signer"));
    let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
        VerificationMethodDIDResolver::new(DIDKey);
    let client = DIDClient::new(VERIFIER_DID_VM.to_owned(), signer, &resolver)
        .await
        .expect("DID client resolves fixture key");

    Verifier::builder()
        .with_client(Arc::new(client))
        .with_submission_endpoint(submission_endpoint.parse().expect("valid URL"))
        .with_session_store(Arc::new(MemoryStore::default()))
        .build()
        .await
        .expect("verifier builds")
}

/// Binds the loopback listener first, so the Verifier's `response_uri` names the real port,
/// then serves the response endpoint in the background.
async fn start_lab() -> Lab {
    let listener = TcpListener::bind(LOOPBACK_BIND)
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener address");
    assert!(addr.ip().is_loopback(), "lab must only listen on loopback");

    let verifier = Arc::new(build_verifier(&format!("http://{addr}{RESPONSE_PATH}")).await);
    let (decrypter, encryption_jwk) = encryption_key_pair();
    let observations = Arc::new(Mutex::new(Observations::default()));

    let app = Router::new()
        .route(
            &format!("{RESPONSE_PATH}/{{session}}"),
            post(receive_response),
        )
        .with_state(ServerState {
            verifier: verifier.clone(),
            decrypter: Arc::new(decrypter),
            observations: observations.clone(),
        });
    let server =
        tokio::spawn(async move { axum::serve(listener, app).await.expect("lab server runs") });

    Lab {
        verifier,
        observations,
        wallet: LoopbackWallet {
            metadata: wallet_metadata(),
            http_client: LoopbackHttpClient::new(),
            trusted_dids: vec![VERIFIER_DID.to_owned()],
        },
        encryption_jwk,
        server,
    }
}

/// `response_uri` handler. Transport checks run before anything reaches the decrypter; the
/// decryption and payload check run inside upstream `Verifier::verify_response`.
async fn receive_response(
    State(state): State<ServerState>,
    Path(session): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Ok(reference) = session.parse::<Uuid>() else {
        return StatusCode::NOT_FOUND;
    };
    if !is_form_urlencoded(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }
    let response_params = form_urlencoded::parse(&body)
        .filter(|(name, _)| name == RESPONSE_PARAM)
        .count();
    if response_params != 1 {
        return StatusCode::BAD_REQUEST;
    }
    let Ok(response @ AuthorizationResponse::Jwt(_)) =
        AuthorizationResponse::from_x_www_form_urlencoded(&body)
    else {
        return StatusCode::BAD_REQUEST;
    };

    let decrypter = state.decrypter.clone();
    let observations = state.observations.clone();
    let verified = state
        .verifier
        .verify_response(reference, response, move |session, response| {
            Box::pin(
                async move { decrypt_and_validate(&decrypter, &observations, &session, &response) },
            )
        })
        .await;
    if verified.is_err() {
        return StatusCode::NOT_FOUND;
    }

    // OpenID4VP 1.0 §8.2: a response that fails verification gets an error status.
    match state.verifier.poll_status(reference).await {
        Ok(Status::Complete(Outcome::Success { .. })) => StatusCode::OK,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn is_form_urlencoded(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(FORM_CONTENT_TYPE))
}

/// Protected-header policy: only exactly what the Verifier advertised is accepted (fail closed).
/// Upstream `verify_response` and josekit alone would accept any registered `enc` and `zip`.
fn check_protected_header(header: &JweHeader) -> Result<(), String> {
    let expect = |name: &str, got: Option<&str>, want: &str| {
        if got == Some(want) {
            Ok(())
        } else {
            Err(format!("{name} {got:?} is not {want:?}"))
        }
    };
    expect("alg", header.algorithm(), EXPECTED_JWE_ALG)?;
    expect("enc", header.content_encryption(), EXPECTED_JWE_ENC)?;
    expect("kid", header.key_id(), ENCRYPTION_KID)?;
    if let Some(zip) = header.claim("zip") {
        return Err(format!("zip {zip} is not allowed"));
    }
    Ok(())
}

/// Verifier-side decryption, following spruceid/openid4vp@c57a8958
/// `examples/verifier-conformance-adapter/crypto/jwe.rs` (`decrypt_jwe`). The header policy runs
/// in josekit's decrypter selector, i.e. before key agreement or content decryption.
fn decrypt_and_validate(
    decrypter: &EcdhEsJweDecrypter<NistP256>,
    observations: &Mutex<Observations>,
    session: &Session,
    response: &AuthorizationResponse,
) -> Outcome {
    let AuthorizationResponse::Jwt(JwtAuthorizationResponse { response: jwe }) = response else {
        return Outcome::Failure {
            reason: "direct_post.jwt requires an encrypted response".into(),
        };
    };
    let attempt = {
        let mut observations = lock(observations);
        observations.decrypt_attempts += 1;
        observations.decrypt_attempts
    };

    let header_rejection = RefCell::new(None);
    let decrypted =
        josekit::jwe::deserialize_compact_with_selector(
            jwe,
            |header| match check_protected_header(header) {
                Ok(()) => Ok(Some(decrypter as &dyn JweDecrypter)),
                Err(reason) => {
                    *header_rejection.borrow_mut() = Some(reason);
                    Ok(None)
                }
            },
        );
    let (plaintext, header) = match decrypted {
        Ok(decrypted) => decrypted,
        Err(e) => {
            let reason = match header_rejection.into_inner() {
                Some(rejection) => format!("{REASON_HEADER_REJECTED}: {rejection}"),
                None => format!("{REASON_DECRYPT_FAILED}: {e}"),
            };
            return Outcome::Failure { reason };
        }
    };
    let Ok(payload) = serde_json::from_slice::<Value>(&plaintext) else {
        return Outcome::Failure {
            reason: "decrypted payload is not JSON".into(),
        };
    };

    let answers_every_query = session
        .dcql_query
        .credentials()
        .iter()
        .all(|query| payload["vp_token"][query.id()] == json!([SYNTHETIC_PRESENTATION]));

    lock(observations).decrypted.push(DecryptedJwe {
        jwe: jwe.clone(),
        alg: header.algorithm().map(str::to_owned),
        enc: header.content_encryption().map(str::to_owned),
        kid: header.key_id().map(str::to_owned),
        payload,
    });

    if answers_every_query {
        Outcome::Success {
            info: json!({ INFO_DECRYPT_ATTEMPT: attempt }),
        }
    } else {
        Outcome::Failure {
            reason: "vp_token does not answer the DCQL query".into(),
        }
    }
}

fn dcql_query() -> DcqlQuery {
    DcqlQuery::new(NonEmptyVec::new(DcqlCredentialQuery::new(
        CREDENTIAL_QUERY_ID.into(),
        ClaimFormatDesignation::JwtVcJson,
    )))
}

/// Verifier issues a signed `direct_post.jwt` request advertising the encryption key; the
/// wallet validates it (signature, client_id prefix, jwks/alg/enc against its metadata).
async fn issue_request(lab: &Lab) -> (Uuid, AuthorizationRequestObject) {
    let mut client_metadata = UntypedObject::default();
    client_metadata.insert(JWKs {
        keys: vec![lab.encryption_jwk.clone()],
    });

    let (id, url) = lab
        .verifier
        .build_authorization_request()
        .with_dcql_query(dcql_query())
        .with_request_parameter(ResponseMode::DirectPostJwt)
        .with_request_parameter(ResponseType::VpToken)
        .with_request_parameter(Nonce::from(TEST_NONCE))
        .with_request_parameter(ClientMetadata(client_metadata))
        .build(lab.wallet.metadata().clone())
        .await
        .expect("direct_post.jwt request builds");
    let request = lab
        .wallet
        .validate_request(url)
        .await
        .expect("wallet accepts the signed request");
    (id, request)
}

fn vp_token() -> VpToken {
    VpToken::with_credential(
        CREDENTIAL_QUERY_ID,
        vec![VpTokenItem::String(SYNTHETIC_PRESENTATION.into())],
    )
}

/// Encrypts the response with SpruceID's own `build_encrypted_response`; returns the JWE.
fn encrypt_response(request: &AuthorizationRequestObject) -> String {
    match build_encrypted_response(request, &vp_token(), None)
        .expect("SpruceID builds the ECDH-ES JWE")
    {
        AuthorizationResponse::Jwt(jwt) => jwt.response,
        AuthorizationResponse::Unencoded(_) => panic!("direct_post.jwt response is encrypted"),
    }
}

fn jwe_form_body(jwe: &str) -> String {
    JwtAuthorizationResponse {
        response: jwe.to_owned(),
    }
    .into_x_www_form_urlencoded()
    .expect("form-encodes the JWE")
}

/// Flips the first ciphertext character so the AES-GCM tag no longer verifies.
fn tamper_ciphertext(jwe: &str) -> String {
    let mut segments: Vec<String> = jwe.split('.').map(str::to_owned).collect();
    assert_eq!(segments.len(), JWE_COMPACT_SEGMENTS, "compact JWE");
    let ciphertext = &mut segments[JWE_CIPHERTEXT_SEGMENT];
    let first = ciphertext.remove(0);
    ciphertext.insert(0, if first == 'A' { 'B' } else { 'A' });
    segments.join(".")
}

/// POSTs an arbitrary body to the request's `response_uri` over the same loopback client.
async fn post_raw(
    lab: &Lab,
    request: &AuthorizationRequestObject,
    content_type: &str,
    body: String,
) -> StatusCode {
    let http_request = Request::builder()
        .method(Method::POST)
        .uri(request.return_uri().as_str())
        .header(CONTENT_TYPE, content_type)
        .body(body.into_bytes())
        .expect("valid HTTP request");
    lab.wallet
        .http_client()
        .execute(http_request)
        .await
        .expect("loopback POST completes")
        .status()
}

/// Encrypts the synthetic response with josekit directly (not SpruceID's `JweBuilder`) to the
/// advertised public key, so the protected header can deviate from what the Verifier advertised.
fn encrypt_with_header(lab: &Lab, enc: &str, kid: &str, zip: Option<&str>) -> String {
    let jwk = Jwk::from_map(lab.encryption_jwk.clone()).expect("advertised JWK parses");
    let encrypter = ECDH_ES
        .encrypter_from_jwk::<NistP256>(&jwk)
        .expect("ECDH-ES encrypter from advertised JWK");

    let mut header = JweHeader::new();
    header.set_token_type(JWE_TYP_JWT);
    header.set_algorithm(EXPECTED_JWE_ALG);
    header.set_content_encryption(enc);
    header.set_key_id(kid);
    if let Some(zip) = zip {
        header.set_compression(zip);
    }

    let vp_token = serde_json::to_value(vp_token()).expect("vp_token serializes");
    let payload = JwtPayload::from_map(
        json!({ "vp_token": vp_token })
            .as_object()
            .cloned()
            .expect("object"),
    )
    .expect("JWT payload");
    josekit::jwt::encode_with_encrypter(&payload, &header, &encrypter).expect("josekit encrypts")
}

async fn assert_rejected_before_decryption(lab: &Lab, id: Uuid, got: StatusCode, want: StatusCode) {
    assert_eq!(got, want);
    assert_eq!(
        lab.status(id).await,
        Status::SentRequest,
        "session untouched"
    );
    assert_eq!(
        lab.observations().decrypt_attempts,
        0,
        "decrypter never ran"
    );
}

/// The `reason` of a `Complete(Failure)` session; panics on any other status.
async fn failure_reason(lab: &Lab, id: Uuid) -> String {
    match lab.status(id).await {
        Status::Complete(Outcome::Failure { reason }) => reason,
        other => panic!("expected Complete(Failure), got {other:?}"),
    }
}

/// The validator run recorded in a `Complete(Success)` session; panics on any other status.
async fn success_attempt(lab: &Lab, id: Uuid) -> u64 {
    match lab.status(id).await {
        Status::Complete(Outcome::Success { info }) => info[INFO_DECRYPT_ATTEMPT]
            .as_u64()
            .expect("success info records the attempt"),
        other => panic!("expected Complete(Success), got {other:?}"),
    }
}

/// Posts a JWE whose protected header deviates from the advertised key and checks that the
/// header policy refused it before any decryption.
async fn assert_header_rejected(
    lab: &Lab,
    id: Uuid,
    request: &AuthorizationRequestObject,
    jwe: String,
) {
    let got = post_raw(lab, request, FORM_CONTENT_TYPE, jwe_form_body(&jwe)).await;
    assert_eq!(got, StatusCode::BAD_REQUEST);

    let reason = failure_reason(lab, id).await;
    assert!(reason.starts_with(REASON_HEADER_REJECTED), "{reason}");
    let observations = lab.observations();
    assert_eq!(observations.decrypt_attempts, 1, "validator ran once");
    assert!(observations.decrypted.is_empty(), "nothing decrypted");
}

#[tokio::test(flavor = "current_thread")]
async fn ecdh_es_direct_post_jwt_round_trip_completes_with_success() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    assert_eq!(request.response_mode(), &ResponseMode::DirectPostJwt);
    assert!(
        request
            .return_uri()
            .as_str()
            .ends_with(&format!("{RESPONSE_PATH}/{id}"))
    );
    assert_eq!(lab.status(id).await, Status::SentRequest);

    let jwe = encrypt_response(&request);
    let response = AuthorizationResponse::Jwt(JwtAuthorizationResponse {
        response: jwe.clone(),
    });
    let redirect = lab
        .wallet
        .submit_response(request, response)
        .await
        .expect("verifier accepts the encrypted response");
    assert_eq!(redirect, None);
    assert_eq!(success_attempt(&lab, id).await, 1);

    {
        let observations = lab.observations();
        assert_eq!(observations.decrypt_attempts, 1);
        let [decrypted] = observations.decrypted.as_slice() else {
            panic!("exactly one decrypted JWE: {observations:?}");
        };
        assert_eq!(
            decrypted.jwe, jwe,
            "server decrypted the bytes sent over HTTP"
        );
        assert_eq!(decrypted.jwe.split('.').count(), JWE_COMPACT_SEGMENTS);
        assert_eq!(decrypted.alg.as_deref(), Some(EXPECTED_JWE_ALG));
        assert_eq!(decrypted.enc.as_deref(), Some(EXPECTED_JWE_ENC));
        assert_eq!(decrypted.kid.as_deref(), Some(ENCRYPTION_KID));
        assert_eq!(
            decrypted.payload["vp_token"],
            json!({ CREDENTIAL_QUERY_ID: [SYNTHETIC_PRESENTATION] })
        );
    }
    lab.shutdown().await;
}

/// Observed upstream behaviour: the failed decryption still ends the session as
/// `Complete(Failure)`, because `verify_response` stores whatever the validator returns.
#[tokio::test(flavor = "current_thread")]
async fn tampered_jwe_ciphertext_is_not_accepted() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let tampered = tamper_ciphertext(&encrypt_response(&request));

    let got = post_raw(&lab, &request, FORM_CONTENT_TYPE, jwe_form_body(&tampered)).await;
    assert_eq!(got, StatusCode::BAD_REQUEST);

    // The header passed the policy; AES-GCM tag verification is what refused it.
    let reason = failure_reason(&lab, id).await;
    assert!(reason.starts_with(REASON_DECRYPT_FAILED), "{reason}");
    assert_eq!(
        lab.observations().decrypt_attempts,
        1,
        "decryption was attempted"
    );
    assert!(lab.observations().decrypted.is_empty(), "nothing decrypted");
    lab.shutdown().await;
}

/// A well-formed JWE to the advertised key, but with `enc` = A256GCM, which the Verifier did not
/// advertise (josekit would decrypt it; the header policy must not).
#[tokio::test(flavor = "current_thread")]
async fn jwe_with_unadvertised_enc_is_rejected() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let jwe = encrypt_with_header(&lab, UNADVERTISED_JWE_ENC, ENCRYPTION_KID, None);

    assert_header_rejected(&lab, id, &request, jwe).await;
    lab.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn jwe_with_wrong_kid_is_rejected() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let jwe = encrypt_with_header(&lab, EXPECTED_JWE_ENC, UNKNOWN_KID, None);

    assert_header_rejected(&lab, id, &request, jwe).await;
    lab.shutdown().await;
}

/// Compression before encryption is a length side channel and was not negotiated.
#[tokio::test(flavor = "current_thread")]
async fn jwe_with_zip_header_is_rejected() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let jwe = encrypt_with_header(
        &lab,
        EXPECTED_JWE_ENC,
        ENCRYPTION_KID,
        Some(JWE_ZIP_DEFLATE),
    );

    assert_header_rejected(&lab, id, &request, jwe).await;
    lab.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn non_form_content_type_is_rejected_before_decryption() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let body = jwe_form_body(&encrypt_response(&request));

    let got = post_raw(&lab, &request, WRONG_CONTENT_TYPE, body).await;
    assert_rejected_before_decryption(&lab, id, got, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
    lab.shutdown().await;
}

/// The body is a plaintext `direct_post` response (`vp_token=...`) sent to a `direct_post.jwt`
/// session. Upstream's `AuthorizationResponse::from_x_www_form_urlencoded` happily parses it as
/// `Unencoded`, and `verify_response` would pass it to the validator: upstream does not bind the
/// response format to the request's `response_mode`, so the endpoint must.
#[tokio::test(flavor = "current_thread")]
async fn missing_response_parameter_is_rejected_before_decryption() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let body = UnencodedAuthorizationResponse::new(vp_token())
        .into_x_www_form_urlencoded()
        .expect("form-encodes the plaintext response");
    assert!(matches!(
        AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes()),
        Ok(AuthorizationResponse::Unencoded(_))
    ));

    let got = post_raw(&lab, &request, FORM_CONTENT_TYPE, body).await;
    assert_rejected_before_decryption(&lab, id, got, StatusCode::BAD_REQUEST).await;
    lab.shutdown().await;
}

/// Upstream's parser also refuses this body (serde `duplicate field`), so either way nothing
/// reaches the decrypter; the endpoint's explicit count keeps that independent of upstream.
#[tokio::test(flavor = "current_thread")]
async fn duplicated_response_parameter_is_rejected_before_decryption() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let single = jwe_form_body(&encrypt_response(&request));
    let body = format!("{single}&{single}");
    assert!(AuthorizationResponse::from_x_www_form_urlencoded(body.as_bytes()).is_err());

    let got = post_raw(&lab, &request, FORM_CONTENT_TYPE, body).await;
    assert_rejected_before_decryption(&lab, id, got, StatusCode::BAD_REQUEST).await;
    lab.shutdown().await;
}

/// Characterizes upstream behaviour (openid4vp@c57a8958); it does not assert what a hardened
/// verifier should do, and nothing here "fixes" upstream (ADR-004 replay research).
///
/// Observed: replaying the byte-identical `response=<jwe>` POST after a successful submission
/// is processed again. `Verifier::verify_response` is get_session -> validator -> update_status
/// with no check of the current status and no atomic claim, so the second POST returns 200,
/// the validator decrypts the same JWE a second time, and the stored outcome is overwritten:
/// `Complete(Success)` now carries the replay's attempt number (2) instead of the original (1).
/// Replay protection is left entirely to the integrator.
#[tokio::test(flavor = "current_thread")]
async fn characterize_upstream_verify_response_reprocesses_replayed_jwe() {
    let lab = start_lab().await;
    let (id, request) = issue_request(&lab).await;
    let jwe = encrypt_response(&request);

    lab.wallet
        .submit_response(
            request.clone(),
            AuthorizationResponse::Jwt(JwtAuthorizationResponse {
                response: jwe.clone(),
            }),
        )
        .await
        .expect("first submission accepted");
    assert_eq!(
        success_attempt(&lab, id).await,
        1,
        "original outcome stored"
    );

    // Same bytes the wallet sent, replayed by anyone who captured the POST.
    let replay = post_raw(&lab, &request, FORM_CONTENT_TYPE, jwe_form_body(&jwe)).await;

    assert_eq!(replay, StatusCode::OK, "upstream accepts the replay");
    assert_eq!(
        success_attempt(&lab, id).await,
        2,
        "session outcome overwritten by the replay"
    );
    {
        let observations = lab.observations();
        assert_eq!(observations.decrypt_attempts, 2, "validator ran again");
        assert_eq!(observations.decrypted.len(), 2);
        assert!(observations.decrypted.iter().all(|d| d.jwe == jwe));
    }
    lab.shutdown().await;
}
