//! A synthetic Status Issuer and Status Provider for tests (`wallet-sim` + `conformance`; never
//! in a Verifier build): [`StatusListSigner`] signs Token Status Lists in JWT format
//! (draft-ietf-oauth-status-list-14 §5.1), [`encode_lst`] packs and compresses them (§4.1), and
//! [`StatusProvider`] serves them over HTTPS on loopback (§8.1, §8.2) and records every request
//! it receives, so tests can show that the Verifier actually fetched the list and how.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::jar::RequestSigningKey;
use crate::jose::{ALG_ES256, BASE64URL, HEADER_ALG, HEADER_TYP};
use crate::status_list::{STATUS_LIST_JWT_MEDIA_TYPE, STATUS_LIST_JWT_TYP};
use crate::wallet_sim::{WalletError, random_signing_key};

/// ZLIB compression level of [`encode_lst`]: the highest, as TSL §4.1 step 4 recommends.
const ZLIB_BEST_COMPRESSION: u8 = 9;
/// Bits per byte (TSL §4.1 packs statuses into bytes).
const BITS_PER_BYTE: usize = 8;
/// Host name of every [`StatusProvider`] URI: resolved by the Verifier to loopback.
const PROVIDER_HOST: &str = "localhost";
/// Path prefix of the lists a [`StatusProvider`] serves (the OIDF suite's shape).
const PROVIDER_PATH_PREFIX: &str = "/statuslists/";
/// Application protocol (RFC 7301 ALPN identifier for HTTP/1.1).
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// `lst` of a Status List (TSL §4.1, §4.2): `statuses[i]` is the status of index `i`, packed
/// at `bits` bits per entry from the least significant bit of each byte, ZLIB-compressed and
/// base64url-encoded. Values wider than `bits` are truncated to it.
#[must_use]
pub fn encode_lst(statuses: &[u8], bits: u8) -> String {
    let bits = usize::from(bits);
    let mut packed = vec![0u8; (statuses.len() * bits).div_ceil(BITS_PER_BYTE)];
    // `bits` divides 8, so an entry never straddles a byte.
    let mask = u8::MAX >> (BITS_PER_BYTE - bits);
    for (idx, status) in statuses.iter().enumerate() {
        let first_bit = idx * bits;
        packed[first_bit / BITS_PER_BYTE] |= (status & mask) << (first_bit % BITS_PER_BYTE);
    }
    BASE64URL.encode(miniz_oxide::deflate::compress_to_vec_zlib(
        &packed,
        ZLIB_BEST_COMPRESSION,
    ))
}

/// Claims of a Status List Token (TSL §5.1): `sub`, `iat`, optional `exp`, and the list.
#[must_use]
pub fn status_list_claims(sub: &str, iat: u64, exp: Option<u64>, bits: u8, lst: &str) -> Value {
    let mut claims = json!({
        "sub": sub,
        "iat": iat,
        "status_list": { "bits": bits, "lst": lst },
    });
    if let Some(exp) = exp {
        claims["exp"] = json!(exp);
    }
    claims
}

/// A synthetic Status Issuer: ES256 with one P-256 key, optionally an `x5c` header.
pub struct StatusListSigner {
    key: SigningKey,
    x5c: Option<Vec<String>>,
}

impl std::fmt::Debug for StatusListSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusListSigner").finish_non_exhaustive()
    }
}

impl StatusListSigner {
    /// A signer with an EC P-256 private JWK (e.g. `tests/fixtures/lab_issuer.jwk`, the key the
    /// OIDF suite signs its lists with, or `tests/fixtures/status_signer.jwk`).
    ///
    /// # Errors
    /// [`WalletError::Malformed`].
    pub fn from_jwk(private_jwk: &str) -> Result<Self, WalletError> {
        let key = RequestSigningKey::from_jwk(private_jwk)
            .map_err(|_| WalletError::Malformed("status signer jwk"))?;
        Ok(Self {
            key: key.into_signing_key(),
            x5c: None,
        })
    }

    /// A signer with a fresh random key (one no Verifier trusts).
    ///
    /// # Errors
    /// [`WalletError::Rng`].
    pub fn generate() -> Result<Self, WalletError> {
        Ok(Self {
            key: random_signing_key()?,
            x5c: None,
        })
    }

    /// The same signer, sending `chain_pem` (one or more PEM certificates, leaf first) as the
    /// `x5c` header (RFC 7515 §4.1.6: standard base64 DER).
    ///
    /// # Errors
    /// [`WalletError::Malformed`].
    pub fn with_x5c_pem(mut self, chain_pem: &[u8]) -> Result<Self, WalletError> {
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .map(|cert| cert.map(|der| STANDARD.encode(der)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WalletError::Malformed("x5c pem"))?;
        self.x5c = Some(chain);
        Ok(self)
    }

    /// A compact JWS over `claims`, header `{"alg":"ES256","typ":"statuslist+jwt"}` plus `x5c`
    /// when set, then every member of `header` (which may override those).
    #[must_use]
    pub fn sign(&self, header: &Map<String, Value>, claims: &Value) -> String {
        let mut full = Map::new();
        full.insert(HEADER_ALG.into(), ALG_ES256.into());
        full.insert(HEADER_TYP.into(), STATUS_LIST_JWT_TYP.into());
        if let Some(x5c) = &self.x5c {
            full.insert("x5c".into(), json!(x5c));
        }
        full.extend(header.clone());
        let input = format!(
            "{}.{}",
            BASE64URL.encode(Value::Object(full).to_string()),
            BASE64URL.encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", BASE64URL.encode(signature.to_bytes()))
    }

    /// The signer's public key as an EC P-256 JWK (for a header `jwk` the Verifier must ignore).
    #[must_use]
    pub fn public_jwk(&self) -> Value {
        Value::Object(crate::jose::p256_jwk_value(self.key.verifying_key()))
    }

    /// [`StatusListSigner::sign`] with the default header.
    #[must_use]
    pub fn token(&self, claims: &Value) -> String {
        self.sign(&Map::new(), claims)
    }
}

/// What a [`StatusProvider`] answers every request with.
#[derive(Debug, Clone)]
pub struct StatusReply {
    /// HTTP status.
    pub status: u16,
    /// Extra headers, `Content-Type` included.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// Send the status line and headers, then never the body (a Status Provider that stalls
    /// mid-response); `body` is ignored.
    pub stall_body: bool,
}

impl StatusReply {
    /// `200`, `Content-Type: application/statuslist+jwt`, the token as body (TSL §8.2).
    #[must_use]
    pub fn token(token: &str) -> Self {
        Self {
            status: StatusCode::OK.as_u16(),
            headers: vec![(
                CONTENT_TYPE.as_str().into(),
                STATUS_LIST_JWT_MEDIA_TYPE.into(),
            )],
            body: token.as_bytes().to_vec(),
            stall_body: false,
        }
    }
}

/// One request a [`StatusProvider`] received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRequest {
    /// HTTP method.
    pub method: String,
    /// Path, without query.
    pub path: String,
    /// Query string, if any.
    pub query: Option<String>,
    /// `Accept` header, if any.
    pub accept: Option<String>,
}

/// A loopback HTTPS Status Provider (TLS 1.3, ring) serving one configurable reply for every
/// request and recording each request. Stops when dropped.
pub struct StatusProvider {
    addr: SocketAddr,
    reply: Arc<Mutex<StatusReply>>,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct ProviderState {
    reply: Arc<Mutex<StatusReply>>,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
}

impl StatusProvider {
    /// Binds `127.0.0.1:0` and serves `chain_pem` / `key_pem` (e.g. the conformance leaf
    /// fixtures), answering `404` until [`StatusProvider::set_reply`].
    ///
    /// # Errors
    /// [`WalletError::Malformed`] for unusable TLS material or a failed bind.
    pub async fn start(chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, WalletError> {
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WalletError::Malformed("provider chain"))?;
        let key =
            PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| WalletError::Malformed("key"))?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| WalletError::Malformed("provider tls"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| WalletError::Malformed("provider tls"))?;
        tls.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| WalletError::Malformed("provider bind"))?;
        let addr = listener
            .local_addr()
            .map_err(|_| WalletError::Malformed("provider bind"))?;
        let state = ProviderState {
            reply: Arc::new(Mutex::new(StatusReply {
                status: StatusCode::NOT_FOUND.as_u16(),
                headers: Vec::new(),
                body: Vec::new(),
                stall_body: false,
            })),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new().fallback(answer).with_state(state.clone());
        let task = tokio::spawn(async move {
            // Connection tasks live in this set: aborting the accept task (on drop) drops it,
            // which aborts every connection, stalled handshakes included.
            let mut connections = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                while connections.try_join_next().is_some() {}
                let (acceptor, service) = (acceptor.clone(), TowerToHyperService::new(app.clone()));
                connections.spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                });
            }
        });
        Ok(Self {
            addr,
            reply: state.reply,
            requests: state.requests,
            task,
        })
    }

    /// `https://localhost:<port>/statuslists/`: the URI prefix a Verifier policy allows.
    #[must_use]
    pub fn prefix(&self) -> String {
        format!(
            "https://{PROVIDER_HOST}:{}{PROVIDER_PATH_PREFIX}",
            self.addr.port()
        )
    }

    /// `<prefix><id>`: the `uri` of list `id`.
    #[must_use]
    pub fn uri(&self, id: &str) -> String {
        format!("{}{id}", self.prefix())
    }

    /// The bound loopback address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Answers every following request with `reply`.
    pub fn set_reply(&self, reply: StatusReply) {
        *self.reply.lock().unwrap_or_else(PoisonError::into_inner) = reply;
    }

    /// Every request received so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<ObservedRequest> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for StatusProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn answer(State(state): State<ProviderState>, request: Request) -> Response {
    let observed = ObservedRequest {
        method: request.method().as_str().to_owned(),
        path: request.uri().path().to_owned(),
        query: request.uri().query().map(str::to_owned),
        accept: request
            .headers()
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    };
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(observed);
    let reply = state
        .reply
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let body = if reply.stall_body {
        Body::new(StalledBody)
    } else {
        Body::from(reply.body)
    };
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::OK);
    for (name, value) in reply.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

/// A response body that never yields a frame.
struct StalledBody;

impl hyper::body::Body for StalledBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Pending
    }
}
