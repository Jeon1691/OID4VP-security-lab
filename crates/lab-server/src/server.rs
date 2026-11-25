//! axum application: session issuing, request objects, the response pipeline and the sweep.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
#[cfg(feature = "lab-instrumentation")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::{ALG_HPKE_0, CompactJwe, RecipientPrivateKey, SessionInfo};
use protocol_model::{
    ClientIdWire, EncryptedResponseMode, KeyId, NonceWire, RequestBinding, ResponseUriWire,
    SessionId, StateWire,
};
use serde_json::{Map, Value, json};
use session_core::{
    Candidate, Clock as _, DEFAULT_CONSUMED_RETENTION, IngressHint, InsertError, MemoryRegistry,
    NewSession, RegistryConfig, ResolutionStrategy, ResponseDigest, RoutePolicy, RouteToken,
    SessionState, SessionStore, SystemClock, Timestamp,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::config::SharedRouteStrategy;
use crate::config::{self, LabConfig, MAX_RESPONSE_BODY_BYTES, Mode, RouteKind, StartError};
use crate::evidence::{
    AdmissionError, CommitResult, CryptoResult, EvidenceLog, EvidenceRecord, Rejection,
    ValidationResult,
};
use crate::jar::{REQUEST_OBJECT_AUD, REQUEST_OBJECT_MEDIA_TYPE, RequestSigner};
use crate::validate::{
    self, Acceptance, MAX_RESEARCH_NONCE_LEN, MAX_RESEARCH_STATE_LEN, REQUEST_NONCE,
    RESPONSE_STATE, ValidatedResponse, ValidationError,
};

/// Most digests the replay guard remembers at once, per kind (response and holder proof): four
/// times session-core's default pending cap. An entry exists only for a response that
/// decrypted and validated for a live session, and lives as long as that session's consumed
/// record would (TTL plus `DEFAULT_CONSUMED_RETENTION`). About 100 bytes each, so at most a
/// few MiB for both kinds. When either is full, new responses are refused (fail closed) until
/// the sweep frees entries.
pub const MAX_REMEMBERED_DIGESTS: usize = 4 * session_core::DEFAULT_MAX_PENDING_SESSIONS;

/// Verifier-wide replay guard: digests of responses that validated, and of the holder proofs
/// they carried, each with the session it validated for.
///
/// The per-session state machine (pending / consumed / expired) alone does not stop
/// cross-session replay on the shared research route: bounded trial never offers a consumed
/// session as a candidate, so a new session with the same `session_info` (shared key and
/// route, reused nonce) and the same `state` (research knob) would accept an old response.
/// With a fresh `state` the `state` check already refuses it; the guard does not rely on that.
/// Two keys are guarded, because the JWE digest alone only catches the *same ciphertext*:
///
/// * the response digest (`SHA-256` of the compact JWE): the same JWE posted again;
/// * the holder-proof digest (`validate::holder_proof_digest`, `SHA-256` of the verified
///   KB-JWT's signing input): the same holder proof re-sealed into a fresh JWE, which a
///   reused nonce and the same `client_id` would let another session accept (PR #10).
///
/// Both are checked and recorded together before the claim, under one lock, so two concurrent
/// POSTs carrying one JWE or one proof for two sessions cannot both pass; recorded digests are
/// kept even if their claim then fails (fail closed: that JWE or proof stays bound to the first
/// session it validated for). The same session's own retries pass through to the claim, which
/// reports them as replays.
#[derive(Default)]
struct ReplayGuard {
    /// Response digest, owning session, and when the entry may be forgotten.
    responses: HashMap<ResponseDigest, (SessionId, Timestamp)>,
    /// Holder-proof digest, owning session, and when the entry may be forgotten.
    proofs: HashMap<ResponseDigest, (SessionId, Timestamp)>,
}

impl ReplayGuard {
    fn admit(
        &mut self,
        response: ResponseDigest,
        proof: ResponseDigest,
        session: &SessionId,
        retain_until: Timestamp,
    ) -> Result<(), Rejection> {
        let owned_elsewhere = |map: &HashMap<ResponseDigest, (SessionId, Timestamp)>, digest| {
            map.get(digest).is_some_and(|(owner, _)| owner != session)
        };
        if owned_elsewhere(&self.responses, &response) {
            return Err(Rejection::CrossSessionReplay);
        }
        if owned_elsewhere(&self.proofs, &proof) {
            return Err(Rejection::HolderProofReplay);
        }
        let full = |map: &HashMap<ResponseDigest, _>, digest| {
            !map.contains_key(digest) && map.len() >= MAX_REMEMBERED_DIGESTS
        };
        if full(&self.responses, &response) || full(&self.proofs, &proof) {
            return Err(Rejection::ReplayGuardFull);
        }
        self.responses
            .entry(response)
            .or_insert_with(|| (session.clone(), retain_until));
        self.proofs
            .entry(proof)
            .or_insert_with(|| (session.clone(), retain_until));
        Ok(())
    }

    fn forget_before(&mut self, now: Timestamp) {
        self.responses.retain(|_, (_, until)| *until > now);
        self.proofs.retain(|_, (_, until)| *until > now);
    }
}

/// Result of one decryption trial over a resolve's candidates (HPKE, or ECDH-ES on that
/// research route).
#[derive(Default)]
pub(crate) struct Trial {
    pub(crate) attempts: usize,
    pub(crate) opened: usize,
    /// Candidates that validated (all are tried; only the first result is kept).
    pub(crate) validated: usize,
    /// Index and result of the first validating candidate.
    pub(crate) first: Option<(usize, validate::Validated)>,
    /// First validation error among opened candidates.
    pub(crate) first_error: Option<ValidationError>,
}

/// The one body answered for every resolve, parse, decrypt, validate and claim failure, so the
/// response does not reveal whether a session exists, was consumed, expired or is shared
/// (session-core `ResolveError` / `ClaimError` docs). Status 400.
pub const GENERIC_REJECTION_BODY: &str = r#"{"error":"invalid_request"}"#;

/// Path prefixes and routes (lab infrastructure, not standard OpenID4VP endpoints).
const SESSIONS_PATH: &str = "/lab/v1/sessions";
const REQUESTS_PATH: &str = "/lab/v1/requests";
pub(crate) const RESPONSE_PATH: &str = "/lab/v1/response";
const RESULTS_PATH: &str = "/lab/v1/results";
/// Last path segment of the shared research route. Never a valid route token (wrong length),
/// so it cannot collide with a unique route.
const SHARED_SEGMENT: &str = "shared";

/// Media type of a `direct_post(.jwt)` body (OpenID4VP 1.1 §8.2).
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";
/// Form parameter carrying the encrypted response (OpenID4VP 1.1 §8.3.2).
const RESPONSE_PARAM: &str = "response";

/// Random bytes in a nonce: 128 bits, so it is fresh and unpredictable per request
/// (OpenID4VP 1.1 §14.1); base64url output stays inside the §5.2 nonce charset.
const NONCE_BYTES: usize = 16;
/// Random bytes in a `state`: 128 bits. Lab policy, adopted from OpenID4VP 1.1 §5.3 ("at
/// least 128 bits of entropy"), which requires it only when a Presentation without Holder
/// Binding is requested (outside the DC API); the lab always requires holder binding, so §5.3
/// does not apply and §5.2 sets no size. Unpadded base64url (22 characters) stays inside the
/// §5.2 `state` charset.
const STATE_BYTES: usize = 16;
/// Random bytes in a session id and in a per-session `kid`: 128 bits, so ids never collide
/// and unique-kid resolution is never ambiguous by accident.
const SESSION_ID_BYTES: usize = 16;
pub(crate) const KID_BYTES: usize = 16;
/// Random bytes in a Response Code: 128 bits, OpenID4VP 1.0 §8.2 "RECOMMENDED to use a
/// cryptographic random value of 128 bits or more".
pub const RESPONSE_CODE_BYTES: usize = 16;
/// Query parameter carrying the Response Code in the response `redirect_uri` (OpenID4VP 1.0
/// §8.2 example, §13.3).
const RESPONSE_CODE_PARAM: &str = "response_code";

/// JWK members for the advertised HPKE-0 key (RFC 7517 / RFC 7518 §6.2, draft-22 §5.1).
pub(crate) const JWK_KTY_EC: &str = "EC";
pub(crate) const JWK_CRV_P256: &str = "P-256";
pub(crate) const JWK_USE_ENC: &str = "enc";
/// SEC1 uncompressed point: `0x04 || x || y` with 32-byte P-256 coordinates (SEC1 §2.3.3).
pub(crate) const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
pub(crate) const P256_COORDINATE_BYTES: usize = 32;
/// JWT NumericDates are whole seconds (RFC 7519 §2); session-core timestamps are milliseconds.
pub(crate) const MILLIS_PER_SECOND: u64 = 1000;
/// OpenID4VP `response_type` of every lab request (§5.2).
const RESPONSE_TYPE_VP_TOKEN: &str = "vp_token";

/// A session's decryption key. Each route stores one kind; a candidate whose key is not of the
/// kind its route decrypts with never opens (fail closed), so no route can fall back to the
/// other algorithm.
pub(crate) enum LabKey {
    /// HPKE-0 (`alg` `HPKE-0`): the unique and shared routes.
    Hpke(RecipientPrivateKey),
    /// ECDH-ES (`alg` `ECDH-ES`): the research route of `ecdh-es-research`, and the unique
    /// route of `Mode::Conformance` (`conformance`).
    #[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
    EcdhEs(jose_ecdh_es::RecipientPrivateKey),
}

impl LabKey {
    /// The HPKE-0 key, if this is one.
    const fn hpke(&self) -> Option<&RecipientPrivateKey> {
        match self {
            Self::Hpke(key) => Some(key),
            #[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
            Self::EcdhEs(_) => None,
        }
    }

    /// The ECDH-ES key, if this is one.
    #[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
    pub(crate) const fn ecdh_es(&self) -> Option<&jose_ecdh_es::RecipientPrivateKey> {
        match self {
            Self::EcdhEs(key) => Some(key),
            Self::Hpke(_) => None,
        }
    }
}

/// `client_metadata` member listing the content encryption algorithms (OpenID4VP 1.0 §5.1 and
/// §8.3: "MUST be present for anything other than the default single value of `A128GCM`").
#[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
const ENC_VALUES_SUPPORTED: &str = "encrypted_response_enc_values_supported";

/// A fresh ECDH-ES P-256 key pair from the OS CSPRNG. `UnwrapErr` panics if the OS RNG fails,
/// which fails closed (no key is ever made from bad randomness).
#[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
pub(crate) fn ecdh_es_key() -> SessionKey {
    Arc::new(LabKey::EcdhEs(jose_ecdh_es::RecipientPrivateKey::generate(
        &mut jose_ecdh_es::rand_core::UnwrapErr(getrandom::SysRng),
    )))
}

/// `client_metadata` of an ECDH-ES session (OpenID4VP 1.0 §5.1, §8.3): `jwks` with the
/// session's public key (`alg` `ECDH-ES`, `use` `enc`, `kid`; the 1.0 §8.3 example's members)
/// and `encrypted_response_enc_values_supported` = `A128GCM`, `A256GCM`, the two `enc` values
/// jose-ecdh-es implements (HAIP 1.0 §5 requires both).
#[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
pub(crate) fn ecdh_es_client_metadata(
    key: &jose_ecdh_es::RecipientPrivateKey,
    kid: &KeyId,
) -> Value {
    let mut jwk = key.public_key().to_jwk();
    if let Some(members) = jwk.as_object_mut() {
        members.insert("use".into(), JWK_USE_ENC.into());
        members.insert("alg".into(), jose_ecdh_es::ALG_ECDH_ES.into());
        members.insert("kid".into(), kid.as_str().into());
    }
    json!({
        "jwks": { "keys": [jwk] },
        ENC_VALUES_SUPPORTED: [jose_ecdh_es::ENC_A128GCM, jose_ecdh_es::ENC_A256GCM],
    })
}

/// Private-key handle stored per session; shared across sessions in bounded-trial mode and on
/// the ECDH-ES research route.
pub(crate) type SessionKey = Arc<LabKey>;
pub(crate) type Registry = MemoryRegistry<SessionKey, ValidatedResponse>;

/// The shared research route.
struct SharedRoute {
    token: RouteToken,
    strategy: SharedRouteStrategy,
    registry: Registry,
    /// Bounded trial only: one key and `kid` for every session on the route (#792 shape).
    shared_key: Option<(SessionKey, KeyId)>,
}

/// What `GET /lab/v1/requests/{id}` serves, which registry holds the session, and the result
/// token that reads its outcome.
struct IssuedRequest {
    route: RouteKind,
    request_object: String,
    result_token: RouteToken,
}

/// Lookup tables of held sessions.
///
/// The request id appears in the `request_uri` the wallet sees; the result token is a separate
/// 128-bit capability returned only in the session-creation response, so knowing the request
/// id never unlocks the result. It reuses session-core's [`RouteToken`] for the same properties
/// (OS CSPRNG, canonical parse, redacted `Debug`, comparison without early exit).
#[derive(Default)]
struct Issued {
    requests: HashMap<SessionId, IssuedRequest>,
    results: HashMap<RouteToken, SessionId>,
}

/// Global request limits (see the `config` defaults); `/health` is exempt.
struct Limits {
    in_flight: Arc<Semaphore>,
    timeout: Duration,
}

pub(crate) struct AppState {
    mode: Mode,
    /// Conformance mode only, optional: the `redirect_uri` the `200` answer to a committed
    /// response carries, with that response's fresh `response_code` (OpenID4VP 1.0 §8.2);
    /// `None` answers `{}`.
    response_redirect_uri: Option<String>,
    /// Prefix of the `authorization_request` URL in the session creation response.
    authorization_endpoint: String,
    client_id: ClientIdWire,
    /// Signs each request object once, at issue time.
    signer: RequestSigner,
    /// Verifies the issuer signature of every presented SD-JWT VC.
    pub(crate) acceptance: Arc<Acceptance>,
    session_ttl: Duration,
    base_url: String,
    /// Unique-uri sessions; `RoutePolicy::UniquePerSession`, in every mode.
    pub(crate) unique: Registry,
    /// Research mode only; `RoutePolicy::Shared`.
    shared: Option<SharedRoute>,
    /// Research mode only: the ECDH-ES route (`RoutePolicy::Shared`, one key and `kid`).
    #[cfg(feature = "ecdh-es-research")]
    pub(crate) ecdh_es: Option<crate::ecdh_es::EcdhEsRoute>,
    /// Request objects and result tokens of held sessions. Entries are added only after the
    /// registry accepted the session (so its capacity bounds the maps) and pruned by the sweep
    /// after a purge.
    issued: Mutex<Issued>,
    /// Slots for HPKE trials on the blocking pool.
    decryptions: Arc<Semaphore>,
    /// Size of `decryptions`, for `LabServer::pause_decryptions`.
    #[cfg(feature = "lab-instrumentation")]
    decryption_slots: u32,
    /// POSTs waiting for a decryption slot (instrumentation).
    #[cfg(feature = "lab-instrumentation")]
    parked_trials: AtomicUsize,
    replay_guard: Mutex<ReplayGuard>,
    /// `true` while commits are allowed. Every claim runs under a read guard; shutdown takes
    /// the write guard after the drain and sets `false`, so once it returns no request can
    /// commit, even on a connection task that outlived the serve loop.
    commits_open: RwLock<bool>,
    evidence: EvidenceLog,
}

impl AppState {
    /// Whether this is a `Mode::Conformance` server.
    #[cfg(feature = "conformance")]
    fn conformance(&self) -> bool {
        self.mode == Mode::Conformance
    }

    fn registry(&self, route: RouteKind) -> Option<&Registry> {
        match route {
            RouteKind::Unique => Some(&self.unique),
            RouteKind::Shared => self.shared.as_ref().map(|s| &s.registry),
            #[cfg(feature = "ecdh-es-research")]
            RouteKind::EcdhEs => self.ecdh_es.as_ref().map(|e| &e.registry),
        }
    }

    fn issued(&self) -> std::sync::MutexGuard<'_, Issued> {
        // Plain maps of immutable entries, each insert/remove pair done under one guard; a
        // panic elsewhere cannot leave them inconsistent.
        self.issued.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Expires and purges every registry, then drops request objects of purged sessions.
    /// A store failure just skips the round; the next tick retries.
    fn sweep(&self) {
        for registry in [
            Some(&self.unique),
            self.shared.as_ref().map(|s| &s.registry),
            #[cfg(feature = "ecdh-es-research")]
            self.ecdh_es.as_ref().map(|e| &e.registry),
        ]
        .into_iter()
        .flatten()
        {
            let _ = registry.expire_due();
            let _ = registry.purge();
        }
        self.replay_guard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .forget_before(SystemClock.now());
        let mut issued = self.issued();
        let Issued { requests, results } = &mut *issued;
        requests.retain(|id, request| {
            let held = self
                .registry(request.route)
                .is_some_and(|r| r.snapshot(id).ok().flatten().is_some());
            if !held {
                results.remove(&request.result_token);
            }
            held
        });
    }
}

/// A running lab server.
pub struct LabServer {
    addr: SocketAddr,
    base_url: String,
    /// When the server stops accepting by itself (conformance mode's maximum runtime).
    deadline: Option<Instant>,
    evidence: EvidenceLog,
    state: Arc<AppState>,
    shutdown_drain: Duration,
    stop: oneshot::Sender<()>,
    serve: JoinHandle<()>,
    sweep: JoinHandle<()>,
}

/// Holds every decryption slot until dropped; see [`LabServer::pause_decryptions`].
#[cfg(feature = "lab-instrumentation")]
#[derive(Debug)]
pub struct DecryptionPause {
    _slots: OwnedSemaphorePermit,
}

/// Accepts connections while holding one slot per live connection, so at most `slots` exist
/// at once. Each accepted stream keeps its permit until hyper drops it, so connections that
/// never send headers count too.
struct CappedListener {
    inner: TcpListener,
    slots: Arc<Semaphore>,
}

impl CappedListener {
    /// Waits for a free slot, then for a connection. Connection-level errors (aborted, reset
    /// or refused before accept) concern one peer and are retried at once; any other error
    /// (typically descriptor exhaustion) is retried after [`ACCEPT_ERROR_BACKOFF`], as
    /// `axum::serve` does.
    async fn accept(&self) -> CappedStream {
        // The semaphore is never closed, so acquiring only waits.
        let Ok(permit) = Arc::clone(&self.slots).acquire_owned().await else {
            return std::future::pending().await;
        };
        loop {
            match self.inner.accept().await {
                Ok((stream, _)) => {
                    return CappedStream {
                        stream,
                        _permit: permit,
                    };
                }
                Err(e) if is_connection_error(&e) => {}
                Err(_) => tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await,
            }
        }
    }
}

/// Whether an `accept` error only concerns the one connection that failed.
fn is_connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
    )
}

/// Pause after a non-connection `accept` error so a persistent error (descriptor exhaustion) does not spin.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// An accepted connection and its slot.
struct CappedStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for CappedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CappedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl LabServer {
    /// Checks the configuration, binds the listener and starts serving and sweeping.
    ///
    /// # Errors
    /// [`StartError`]; a non-loopback address is refused before binding.
    pub async fn start(config: LabConfig) -> Result<Self, StartError> {
        let key_hint = config::check(&config)?;
        let listener = TcpListener::bind(config.bind).await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{addr}");
        let response_redirect_uri: Option<String> = None;
        // `config::check` admits a conformance configuration in conformance mode only.
        #[cfg(feature = "conformance")]
        let (base_url, response_redirect_uri, tls, max_runtime) = match &config.conformance {
            Some(conformance) => (
                conformance.public_origin.base_url(addr.port()),
                conformance.response_redirect_uri.clone(),
                Some(crate::conformance::tls_acceptor(&conformance.credentials)?),
                Some(conformance.max_runtime),
            ),
            None => (base_url, response_redirect_uri, None, None),
        };
        // Only conformance mode has a time box.
        #[cfg(not(feature = "conformance"))]
        let deadline: Option<Instant> = None;
        // `config::check` bounds the runtime; `checked_add` keeps an overflow from panicking.
        #[cfg(feature = "conformance")]
        let deadline = match max_runtime {
            Some(runtime) => Some(
                Instant::now()
                    .checked_add(runtime)
                    .ok_or(StartError::MaxRuntimeTooLong)?,
            ),
            None => None,
        };

        let shared = match config.mode {
            Mode::Hardened => None,
            #[cfg(feature = "conformance")]
            Mode::Conformance => None,
            Mode::Research(strategy) => {
                let shared_key = match strategy {
                    SharedRouteStrategy::BoundedTrial(_) => {
                        let kid = KeyId::new(random_b64(KID_BYTES).ok_or(StartError::Rng)?)
                            .map_err(|_| StartError::Rng)?;
                        Some((hpke_key(), kid))
                    }
                    SharedRouteStrategy::UniqueKid => None,
                };
                Some(SharedRoute {
                    token: RouteToken::generate().map_err(|_| StartError::Rng)?,
                    strategy,
                    registry: registry(RoutePolicy::Shared),
                    shared_key,
                })
            }
        };
        let evidence = EvidenceLog::default();
        let signer = RequestSigner::new(config.request_signing_key, key_hint);
        let state = Arc::new(AppState {
            mode: config.mode,
            response_redirect_uri,
            authorization_endpoint: config.authorization_endpoint,
            client_id: config.client_id,
            signer,
            acceptance: Arc::new(Acceptance {
                issuer: config.trusted_issuer,
                request: config.credential_request,
            }),
            session_ttl: config.session_ttl,
            base_url: base_url.clone(),
            unique: registry(RoutePolicy::UniquePerSession),
            shared,
            #[cfg(feature = "ecdh-es-research")]
            // Opt-in per server (`config::check` refuses it in hardened mode), so other
            // research servers create no ECDH-ES key, registry or route.
            ecdh_es: if config.ecdh_es_route {
                Some(crate::ecdh_es::EcdhEsRoute::new()?)
            } else {
                None
            },
            issued: Mutex::new(Issued::default()),
            decryptions: Arc::new(Semaphore::new(config.max_concurrent_decryptions)),
            #[cfg(feature = "lab-instrumentation")]
            decryption_slots: u32::try_from(config.max_concurrent_decryptions)
                .map_err(|_| StartError::ZeroLimit)?,
            #[cfg(feature = "lab-instrumentation")]
            parked_trials: AtomicUsize::new(0),
            replay_guard: Mutex::new(ReplayGuard::default()),
            commits_open: RwLock::new(true),
            evidence: evidence.clone(),
        });
        let limits = Arc::new(Limits {
            in_flight: Arc::new(Semaphore::new(config.max_in_flight_requests)),
            timeout: config.request_timeout,
        });

        let sweep_state = Arc::clone(&state);
        let interval = config.sweep_interval;
        let sweep = tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                sweep_state.sweep();
            }
        });
        let app = router(Arc::clone(&state), limits);
        let listener = CappedListener {
            inner: listener,
            slots: Arc::new(Semaphore::new(config.max_connections)),
        };
        let (stop, stopped) = oneshot::channel::<()>();
        let connections = Connections {
            header_read_timeout: config.header_read_timeout,
            #[cfg(feature = "conformance")]
            tls,
        };
        let serve = tokio::spawn(serve(listener, app, connections, deadline, stopped));
        Ok(Self {
            addr,
            base_url,
            deadline,
            evidence,
            state,
            shutdown_drain: config.shutdown_drain,
            stop,
            serve,
            sweep,
        })
    }

    /// The bound address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The prefix of every lab URL: `http://<addr>`, or in conformance mode the public origin
    /// (`https://<host>:<port>`), which resolves to the loopback bind only through the host's
    /// forwarding (or a client's resolver override).
    #[must_use]
    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    /// The evidence handle.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceLog {
        &self.evidence
    }

    /// Runs until the serve loop ends.
    ///
    /// # Errors
    /// A panic of the serve loop, as `std::io::Error`.
    pub async fn wait(self) -> std::io::Result<()> {
        self.serve.await.map_err(std::io::Error::other)?;
        self.sweep.abort();
        Ok(())
    }

    /// Research instrumentation (`lab-instrumentation` feature only): takes every decryption
    /// slot until the returned guard is dropped, so POSTs park before HPKE. Lets scenarios and
    /// tests place a request at a known point (races, shutdown) without timing assumptions.
    ///
    /// # Panics
    /// Never: the semaphore is never closed.
    #[cfg(feature = "lab-instrumentation")]
    pub async fn pause_decryptions(&self) -> DecryptionPause {
        let permit = Arc::clone(&self.state.decryptions)
            .acquire_many_owned(self.state.decryption_slots)
            .await
            .expect("decryption semaphore is never closed");
        DecryptionPause { _slots: permit }
    }

    /// Research instrumentation (`lab-instrumentation` feature only): the `RequestBinding` the
    /// registry holds for `session_id` (pending or consumed), i.e. the values
    /// `SessionInfo::from_binding` decrypts with. Lets tests compare them with the signed
    /// request object byte for byte.
    #[cfg(feature = "lab-instrumentation")]
    #[must_use]
    pub fn stored_binding(&self, session_id: &str) -> Option<RequestBinding> {
        let id = SessionId::new(session_id).ok()?;
        let route = self.state.issued().requests.get(&id)?.route;
        let snapshot = self.state.registry(route)?.snapshot(&id).ok()??;
        Some(snapshot.binding().clone())
    }

    /// Research instrumentation (`lab-instrumentation` feature only): the stored session's
    /// expiry in Unix milliseconds, so tests can check the signed `exp` never precedes it.
    #[cfg(feature = "lab-instrumentation")]
    #[must_use]
    pub fn stored_session_expiry_millis(&self, session_id: &str) -> Option<u64> {
        let id = SessionId::new(session_id).ok()?;
        let route = self.state.issued().requests.get(&id)?.route;
        let snapshot = self.state.registry(route)?.snapshot(&id).ok()??;
        Some(snapshot.expires_at().as_unix_millis())
    }

    /// Research instrumentation (`lab-instrumentation` feature only): POSTs currently waiting
    /// for a decryption slot.
    #[cfg(feature = "lab-instrumentation")]
    #[must_use]
    pub fn parked_trials(&self) -> usize {
        self.state.parked_trials.load(Ordering::SeqCst)
    }

    /// Graceful shutdown: stops accepting, lets in-flight requests finish for up to
    /// [`LabConfig::shutdown_drain`], then closes commits and stops sweeping. Once it returns,
    /// no request can commit: one still running past the deadline (on a connection task that
    /// outlives the serve loop) is refused with `Rejection::ShuttingDown`.
    ///
    /// A serve or sweep task that panicked re-raises its panic, and one that exited before
    /// shutdown panics, so a broken server fails the caller (tests). A sweep panic surfaces
    /// only here: while running, a dead sweep only means expired sessions linger (session-core
    /// still checks TTLs lazily).
    pub async fn shutdown(self) {
        let Self {
            state,
            shutdown_drain,
            stop,
            mut serve,
            sweep,
            deadline,
            ..
        } = self;
        // Stopping at the maximum runtime is the kill switch working, not an early exit.
        let exited_early =
            serve.is_finished() && deadline.is_none_or(|deadline| Instant::now() < deadline);
        let _ = stop.send(());
        let drained = tokio::time::timeout(shutdown_drain, &mut serve).await;
        *state.commits_open.write().await = false;
        sweep.abort();
        match drained {
            Ok(Ok(())) if exited_early => panic!("lab server exited early"),
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Ok(Err(_)) => {}
            Err(_) => serve.abort(),
        }
        match sweep.await {
            Err(e) if e.is_cancelled() => {}
            Err(e) => std::panic::resume_unwind(e.into_panic()),
            Ok(()) => panic!("sweep task exited early"),
        }
    }
}

/// How accepted connections are served.
struct Connections {
    header_read_timeout: Duration,
    /// Conformance mode: every connection is TLS (rustls) before HTTP.
    #[cfg(feature = "conformance")]
    tls: Option<tokio_rustls::TlsAcceptor>,
}

/// Accept loop: one hyper HTTP/1 connection task per accepted stream, with a header read
/// timeout (`axum::serve` gives hyper no timer, so it could never fire). In conformance mode
/// each task first completes the TLS handshake, bounded by the same timeout. When `stopped`
/// resolves, or `deadline` passes, it stops accepting and waits for every connection to finish
/// (idle ones are closed at once); [`LabServer::shutdown`] bounds that wait.
async fn serve(
    listener: CappedListener,
    app: Router,
    connections: Connections,
    deadline: Option<Instant>,
    stopped: oneshot::Receiver<()>,
) {
    let graceful = GracefulShutdown::new();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(connections.header_read_timeout);
    let mut stopped = std::pin::pin!(stopped);
    let expired = async move {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
            None => std::future::pending().await,
        }
    };
    let mut expired = std::pin::pin!(expired);
    loop {
        let stream = tokio::select! {
            stream = listener.accept() => stream,
            _ = &mut stopped => break,
            () = &mut expired => break,
        };
        let service = TowerToHyperService::new(app.clone());
        #[cfg(feature = "conformance")]
        if let Some(tls) = &connections.tls {
            let (tls, http, watcher) = (tls.clone(), http.clone(), graceful.watcher());
            let handshake_timeout = connections.header_read_timeout;
            tokio::spawn(async move {
                // A failed or stalled handshake ends only that connection.
                let Ok(Ok(stream)) =
                    tokio::time::timeout(handshake_timeout, tls.accept(stream)).await
                else {
                    return;
                };
                let connection = http.serve_connection(TokioIo::new(stream), service);
                let _ = watcher.watch(connection).await;
            });
            continue;
        }
        let connection = http.serve_connection(TokioIo::new(stream), service);
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            // A connection error (client reset, header timeout) ends only that connection.
            let _ = connection.await;
        });
    }
    // Close the listening socket before draining: accepted streams own their sockets and
    // connection permits, so in-flight requests finish, while new clients are refused at
    // connect time instead of being queued by the kernel with nobody left to serve them.
    drop(listener);
    graceful.shutdown().await;
}

fn registry(route_policy: RoutePolicy) -> Registry {
    MemoryRegistry::with_config(
        Arc::new(SystemClock),
        RegistryConfig {
            route_policy,
            ..RegistryConfig::default()
        },
    )
}

/// A fresh HPKE-0 key pair from the OS CSPRNG. `UnwrapErr` panics if the OS RNG fails, which
/// fails closed (no key is ever made from bad randomness).
fn hpke_key() -> SessionKey {
    Arc::new(LabKey::Hpke(RecipientPrivateKey::generate(&mut UnwrapErr(
        getrandom::SysRng,
    ))))
}

/// `bytes` random bytes from the OS CSPRNG as unpadded base64url; `None` if the RNG fails.
pub(crate) fn random_b64(bytes: usize) -> Option<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).ok()?;
    Some(URL_SAFE_NO_PAD.encode(buf))
}

fn router(state: Arc<AppState>, limits: Arc<Limits>) -> Router {
    let mut app = Router::new()
        .route(SESSIONS_PATH, post(create_session))
        .route(&format!("{REQUESTS_PATH}/{{id}}"), get(get_request))
        .route(&format!("{RESULTS_PATH}/{{token}}"), get(get_result))
        .route(&format!("{RESPONSE_PATH}/{{token}}"), post(post_unique));
    if state.shared.is_some() {
        // A static segment takes precedence over `{token}` in the router.
        app = app.route(
            &format!("{RESPONSE_PATH}/{SHARED_SEGMENT}"),
            post(post_shared),
        );
    }
    #[cfg(feature = "ecdh-es-research")]
    if state.ecdh_es.is_some() {
        app = app.route(
            &format!("{RESPONSE_PATH}/{}", crate::ecdh_es::ECDH_ES_SEGMENT),
            post(crate::ecdh_es::post_ecdh_es),
        );
    }
    let limited = app
        .layer(DefaultBodyLimit::max(MAX_RESPONSE_BODY_BYTES))
        .layer(middleware::from_fn_with_state(limits, limit));
    Router::new()
        .route("/health", get(health))
        .merge(limited)
        .with_state(state)
}

/// In-flight limit and request timeout. Over the limit the request is refused with 503 at once
/// (no queue, so overload shows in results). A request still running at the timeout, e.g. one
/// whose body never arrives, is dropped and answered 408; dropping is safe because the claim
/// is atomic and session-core futures are lazy. A trial already on the blocking pool runs to
/// completion but its result is discarded, and that request leaves no evidence record.
async fn limit(State(limits): State<Arc<Limits>>, request: Request, next: Next) -> Response {
    let Ok(_slot) = Arc::clone(&limits.in_flight).try_acquire_owned() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "server busy");
    };
    match tokio::time::timeout(limits.timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error_response(StatusCode::REQUEST_TIMEOUT, "request timed out"),
    }
}

fn json_response(status: StatusCode, body: String) -> Response {
    (status, [(CONTENT_TYPE, JSON_CONTENT_TYPE)], body).into_response()
}

fn error_response(status: StatusCode, description: &str) -> Response {
    json_response(
        status,
        json!({ "error": "invalid_request", "error_description": description }).to_string(),
    )
}

async fn health() -> Response {
    json_response(StatusCode::OK, json!({ "status": "ok" }).to_string())
}

/// `POST /lab/v1/sessions` with an optional JSON body `{"route": "unique"|"shared",
/// "nonce": "...", "state": "..."}`. `route` defaults to `unique`; `shared`, `nonce` and
/// `state` (caller-chosen values, to model a Verifier that reuses them) are research-mode only,
/// and so is `"route": "ecdh_es_shared"` (the ECDH-ES route, `ecdh-es-research` builds only).
async fn create_session(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let (route, fixed) = match parse_create(&state, &body) {
        Ok(v) => v,
        Err(description) => return error_response(StatusCode::BAD_REQUEST, description),
    };
    match issue(&state, route, fixed).await {
        Ok(created) => json_response(StatusCode::CREATED, created.to_string()),
        Err(InsertError::Capacity { .. }) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "session capacity reached")
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "session not created"),
    }
}

/// Research-mode overrides of the values `issue` otherwise draws fresh.
#[derive(Default)]
struct FixedValues {
    nonce: Option<NonceWire>,
    state: Option<StateWire>,
}

fn parse_create(state: &AppState, body: &[u8]) -> Result<(RouteKind, FixedValues), &'static str> {
    let mut fixed = FixedValues::default();
    if body.is_empty() {
        return Ok((RouteKind::Unique, fixed));
    }
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(body) else {
        return Err("body must be a JSON object");
    };
    let research = matches!(state.mode, Mode::Research(_));
    let mut route = RouteKind::Unique;
    for (name, value) in &request {
        match (name.as_str(), value.as_str()) {
            ("route", Some("unique")) => route = RouteKind::Unique,
            ("route", Some("shared")) if research => route = RouteKind::Shared,
            #[cfg(feature = "ecdh-es-research")]
            ("route", Some(crate::ecdh_es::ECDH_ES_ROUTE_NAME)) if state.ecdh_es.is_some() => {
                route = RouteKind::EcdhEs;
            }
            ("route", _) => return Err("unsupported route"),
            (REQUEST_NONCE, n) if research => {
                let n = n.ok_or("invalid nonce")?;
                // Bounded so an honest KB-JWT always fits `MAX_KB_JWT_LEN` (checked at
                // compile time in `validate`).
                if n.len() > MAX_RESEARCH_NONCE_LEN {
                    return Err("nonce too long");
                }
                fixed.nonce = Some(NonceWire::new(n).map_err(|_| "invalid nonce")?);
            }
            (RESPONSE_STATE, s) if research => {
                let s = s.ok_or("invalid state")?;
                if s.len() > MAX_RESEARCH_STATE_LEN {
                    return Err("state too long");
                }
                fixed.state = Some(StateWire::new(s).map_err(|_| "invalid state")?);
            }
            _ => return Err("unsupported member"),
        }
    }
    Ok((route, fixed))
}

/// Creates and registers a session; returns the creation response.
async fn issue(
    state: &AppState,
    route: RouteKind,
    fixed: FixedValues,
) -> Result<Value, InsertError> {
    let fail = || InsertError::Unavailable(session_core::StoreUnavailable);
    let random = |n| random_b64(n).ok_or_else(fail);
    let id = SessionId::new(random(SESSION_ID_BYTES)?).map_err(|_| fail())?;
    let nonce = match fixed.nonce {
        Some(n) => n,
        None => NonceWire::new(random(NONCE_BYTES)?).map_err(|_| fail())?,
    };
    // Fresh per session, on every route and in every mode (OpenID4VP 1.1 §5.2, §14.4.2),
    // unless a research session fixed it.
    let response_state = match fixed.state {
        Some(s) => s,
        None => StateWire::new(random(STATE_BYTES)?).map_err(|_| fail())?,
    };
    let (registry, route_token, response_uri, key, kid) = match (route, &state.shared) {
        (RouteKind::Shared, Some(shared)) => {
            let (key, kid) = match &shared.shared_key {
                Some((key, kid)) => (Arc::clone(key), kid.clone()),
                None => (
                    hpke_key(),
                    KeyId::new(random(KID_BYTES)?).map_err(|_| fail())?,
                ),
            };
            let uri = format!("{}{RESPONSE_PATH}/{SHARED_SEGMENT}", state.base_url);
            (&shared.registry, shared.token.clone(), uri, key, kid)
        }
        #[cfg(feature = "ecdh-es-research")]
        (RouteKind::EcdhEs, _) => {
            // `parse_create` admits this route in research mode only, where it always exists.
            let ecdh_es = state.ecdh_es.as_ref().ok_or_else(fail)?;
            let uri = format!(
                "{}{RESPONSE_PATH}/{}",
                state.base_url,
                crate::ecdh_es::ECDH_ES_SEGMENT
            );
            (
                &ecdh_es.registry,
                ecdh_es.token.clone(),
                uri,
                Arc::clone(&ecdh_es.key),
                ecdh_es.kid.clone(),
            )
        }
        _ => {
            let token = RouteToken::generate().map_err(|_| fail())?;
            let uri = format!(
                "{}{RESPONSE_PATH}/{}",
                state.base_url,
                token.to_url_segment()
            );
            let kid = KeyId::new(random(KID_BYTES)?).map_err(|_| fail())?;
            // Conformance mode: a fresh ECDH-ES key per session (HAIP 1.0 §5); every other
            // mode: HPKE-0. Each unique session holds exactly one kind.
            #[cfg(feature = "conformance")]
            let key = if state.conformance() {
                ecdh_es_key()
            } else {
                hpke_key()
            };
            #[cfg(not(feature = "conformance"))]
            let key = hpke_key();
            (&state.unique, token, uri, key, kid)
        }
    };
    let response_uri = ResponseUriWire::new(response_uri).map_err(|_| fail())?;
    let binding = RequestBinding::DirectPostJwt {
        client_id: state.client_id.clone(),
        nonce,
        response_uri,
        state: response_state,
    };
    let response_uri = match &binding {
        RequestBinding::DirectPostJwt { response_uri, .. } => response_uri.as_str().to_owned(),
        RequestBinding::DcApiJwt { .. } => return Err(fail()),
    };
    let issued_at = SystemClock.now();
    let stored = SessionStore::insert(
        registry,
        NewSession {
            id: id.clone(),
            binding,
            route_token,
            kid: Some(kid.clone()),
            key: Arc::clone(&key),
            ttl: state.session_ttl,
        },
    )
    .await?;
    // Signed once, after insertion, over the binding and expiry the registry actually stored:
    // `exp` then derives from the session's own deadline (a clock read before insertion could
    // straddle a second boundary and expire the request before its session). The request is
    // published below only once signed; `request_uri` serves these bytes unchanged.
    let lifetime = Lifetime::for_session(issued_at, stored.expires_at());
    let metadata = match &*key {
        #[cfg(feature = "conformance")]
        LabKey::EcdhEs(key) if state.conformance() => {
            crate::conformance::client_metadata(key, &kid)
        }
        _ => client_metadata(&key, &kid),
    };
    let request_object = state.signer.sign(
        request_object(
            stored.binding(),
            metadata,
            state.acceptance.request.dcql_query(),
            lifetime,
        )
        .to_string()
        .as_bytes(),
    );
    let request_uri = format!("{}{REQUESTS_PATH}/{id}", state.base_url);
    let result_token = RouteToken::generate().map_err(|_| fail())?;
    let result_uri = format!(
        "{}{RESULTS_PATH}/{}",
        state.base_url,
        result_token.to_url_segment()
    );
    let route_name = match route {
        RouteKind::Unique => "unique",
        RouteKind::Shared => "shared",
        #[cfg(feature = "ecdh-es-research")]
        RouteKind::EcdhEs => crate::ecdh_es::ECDH_ES_ROUTE_NAME,
    };
    // `client_id` is what the Authorization Request carries next to `request_uri`; the Request
    // Object's `client_id` must equal it (OpenID4VP 1.1 §5.10.1). `authorization_request` is
    // that Authorization Request by reference (RFC 9101 §5.2: `client_id` and `request_uri`)
    // on the configured endpoint, e.g. the OIDF suite's per-test authorization endpoint.
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", state.client_id.as_str())
        .append_pair("request_uri", &request_uri)
        .finish();
    let separator = if state.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let authorization_request = format!("{}{separator}{query}", state.authorization_endpoint);
    let created = json!({
        "session_id": id.as_str(),
        "client_id": state.client_id.as_str(),
        "request_uri": request_uri,
        "authorization_request": authorization_request,
        "response_uri": response_uri,
        "result_uri": result_uri,
        "route": route_name,
    });
    let mut issued = state.issued();
    issued.results.insert(result_token.clone(), id.clone());
    issued.requests.insert(
        id,
        IssuedRequest {
            route,
            request_object,
            result_token,
        },
    );
    Ok(created)
}

/// `iat` / `exp` of a Request Object, as JWT NumericDates (RFC 7519 §2, §4.1.6, §4.1.4).
#[derive(Clone, Copy)]
struct Lifetime {
    issued_at: u64,
    expires_at: u64,
}

impl Lifetime {
    /// `iat` = issuance time, rounded down; `exp` = the stored session's expiry, rounded up, so
    /// the request object never expires before its session does.
    const fn for_session(issued_at: Timestamp, session_expires_at: Timestamp) -> Self {
        Self {
            issued_at: issued_at.as_unix_millis() / MILLIS_PER_SECOND,
            expires_at: session_expires_at
                .as_unix_millis()
                .div_ceil(MILLIS_PER_SECOND),
        }
    }
}

/// The `client_metadata` advertising the session's encryption key: the HPKE-0 public key in
/// `jwks` (`alg` `HPKE-0`, `use` `enc`, `kid`), or on the ECDH-ES research route its key and
/// `encrypted_response_enc_values_supported` (`ecdh_es::client_metadata`).
fn client_metadata(key: &LabKey, kid: &KeyId) -> Value {
    match key {
        LabKey::Hpke(key) => json!({ "jwks": { "keys": [hpke_jwk(key, kid)] } }),
        #[cfg(any(feature = "ecdh-es-research", feature = "conformance"))]
        LabKey::EcdhEs(key) => ecdh_es_client_metadata(key, kid),
    }
}

/// The request object payload for `binding`: exactly the stored wire values (`state` included,
/// OpenID4VP 1.1 §5.2), `client_metadata` with the encryption key ([`client_metadata`]), the
/// configured `dcql_query` (`CredentialRequest::dcql_query`), `aud` (OpenID4VP 1.1 §5.8, Static
/// Discovery), `iat` and `exp` ([`Lifetime`]). No `iss`: it MAY be present and Wallets MUST
/// ignore it (§5). Signed by `RequestSigner::sign`.
fn request_object(
    binding: &RequestBinding,
    client_metadata: Value,
    dcql_query: Value,
    lifetime: Lifetime,
) -> Value {
    let RequestBinding::DirectPostJwt {
        client_id,
        nonce,
        response_uri,
        state,
    } = binding
    else {
        return Value::Null;
    };
    json!({
        "aud": REQUEST_OBJECT_AUD,
        "iat": lifetime.issued_at,
        "exp": lifetime.expires_at,
        "client_id": client_id.as_str(),
        "response_type": RESPONSE_TYPE_VP_TOKEN,
        "response_mode": EncryptedResponseMode::DirectPostJwt.as_str(),
        "response_uri": response_uri.as_str(),
        REQUEST_NONCE: nonce.as_str(),
        RESPONSE_STATE: state.as_str(),
        "dcql_query": dcql_query,
        "client_metadata": client_metadata,
    })
}

/// The advertised HPKE-0 public JWK (RFC 7518 §6.2.1; draft-22 §5.1).
fn hpke_jwk(key: &RecipientPrivateKey, kid: &KeyId) -> Value {
    let point = key.public_key().to_bytes();
    let (x, y) = point
        .strip_prefix(&[SEC1_UNCOMPRESSED_TAG])
        .map(|xy| xy.split_at(P256_COORDINATE_BYTES))
        .unwrap_or_default();
    let mut jwk = Map::new();
    jwk.insert("kty".into(), JWK_KTY_EC.into());
    jwk.insert("crv".into(), JWK_CRV_P256.into());
    jwk.insert("x".into(), URL_SAFE_NO_PAD.encode(x).into());
    jwk.insert("y".into(), URL_SAFE_NO_PAD.encode(y).into());
    jwk.insert("use".into(), JWK_USE_ENC.into());
    jwk.insert("alg".into(), ALG_HPKE_0.into());
    jwk.insert("kid".into(), kid.as_str().into());
    Value::Object(jwk)
}

async fn get_request(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Ok(id) = SessionId::new(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let object = state
        .issued()
        .requests
        .get(&id)
        .map(|r| r.request_object.clone());
    match object {
        // OpenID4VP 1.1 §5.10.1: the body is the Request Object itself, as
        // `application/oauth-authz-req+jwt` (RFC 9101 §5.2.3).
        Some(object) => (
            StatusCode::OK,
            [(CONTENT_TYPE, REQUEST_OBJECT_MEDIA_TYPE)],
            object,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET /lab/v1/results/{result_token}`: `{"state": "pending"|"consumed"|"expired"}`, with
/// the committed `credential` ([`ValidatedResponse::to_json`]) once consumed. Only the result token from the
/// session-creation response finds a session; the request id does not.
async fn get_result(State(state): State<Arc<AppState>>, Path(token): Path<String>) -> Response {
    let Ok(token) = RouteToken::parse(&token) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let found = {
        let issued = state.issued();
        issued.results.get(&token).and_then(|id| {
            let route = issued.requests.get(id)?.route;
            Some((id.clone(), route))
        })
    };
    let Some((id, route)) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(registry) = state.registry(route) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let snapshot = match SessionStore::snapshot(registry, &id).await {
        Ok(Some(s)) => s,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let body = match snapshot.state() {
        SessionState::Pending => json!({ "state": "pending" }),
        SessionState::Consumed { result, .. } => match &result.response_code {
            // The lab has no frontend: the result endpoint (result token only) stands in for
            // the Verifier frontend of OpenID4VP 1.0 §13.3 and shows the Response Code, so a
            // run can match it to the redirect the Wallet was given. It does not gate the
            // read on it; the result token is already the capability.
            Some(code) => json!({
                "state": "consumed",
                "credential": result.to_json(),
                RESPONSE_CODE_PARAM: code,
            }),
            None => json!({ "state": "consumed", "credential": result.to_json() }),
        },
        SessionState::Expired => json!({ "state": "expired" }),
    };
    json_response(StatusCode::OK, body.to_string())
}

/// `POST /lab/v1/response/{token}`. A path segment that is not a well-formed route token is
/// not a route (404), decided before the pipeline; it reveals nothing about any session.
async fn post_unique(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Ok(token) = RouteToken::parse(&token) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    #[cfg(feature = "conformance")]
    if state.conformance() {
        return crate::conformance::post_unique(&state, token, &headers, body).await;
    }
    let route = Route {
        kind: RouteKind::Unique,
        token,
        strategy: ResolutionStrategy::UniqueUri,
        registry: &state.unique,
    };
    respond(&state, route, &headers, body).await
}

/// `POST /lab/v1/response/shared` (research mode only; not routed otherwise).
async fn post_shared(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(shared) = &state.shared else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let route = Route {
        kind: RouteKind::Shared,
        token: shared.token.clone(),
        strategy: shared.strategy.resolution(),
        registry: &shared.registry,
    };
    respond(&state, route, &headers, body).await
}

/// A response route: its fixed strategy and registry.
struct Route<'a> {
    kind: RouteKind,
    token: RouteToken,
    strategy: ResolutionStrategy,
    registry: &'a Registry,
}

/// Runs the pipeline, records its evidence and maps the outcome to the HTTP answer.
async fn respond(
    state: &AppState,
    route: Route<'_>,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let mut record = EvidenceRecord::new(route.kind, route.strategy);
    record.rejection = pipeline(&mut record, state, route, headers, body)
        .await
        .err();
    answer(state, record)
}

/// Pushes `record` and maps its outcome to the HTTP answer: 200 `{}` on success, the
/// admission errors' own answers, and [`GENERIC_REJECTION_BODY`] for everything else.
pub(crate) fn answer(state: &AppState, record: EvidenceRecord) -> Response {
    let response = match &record.rejection {
        None => json_response(StatusCode::OK, success_body(state, &record)),
        Some(Rejection::Admission(a)) => admission_response(*a),
        Some(_) => json_response(StatusCode::BAD_REQUEST, GENERIC_REJECTION_BODY.to_owned()),
    };
    state.evidence.push(record);
    response
}

/// The `200` body for a committed response: `{}`, or with a configured response `redirect_uri`
/// `{"redirect_uri": "<uri>?response_code=<code>"}` with the fresh code `commit` stored with the
/// consumed session (OpenID4VP 1.0 §8.2: "MUST include a fresh, cryptographically random value
/// in the URL"). Read back from the registry, so the answer carries exactly the stored code.
fn success_body(state: &AppState, record: &EvidenceRecord) -> String {
    let code = state.response_redirect_uri.as_ref().and_then(|uri| {
        let id = record.committed_session.as_ref()?;
        let snapshot = state.registry(record.route)?.snapshot(id).ok()??;
        match snapshot.state() {
            SessionState::Consumed { result, .. } => Some((uri, result.response_code.clone()?)),
            _ => None,
        }
    });
    match code {
        Some((uri, code)) => {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair(RESPONSE_CODE_PARAM, &code)
                .finish();
            let separator = if uri.contains('?') { '&' } else { '?' };
            json!({ "redirect_uri": format!("{uri}{separator}{query}") }).to_string()
        }
        None => json!({}).to_string(),
    }
}

fn admission_response(error: AdmissionError) -> Response {
    match error {
        AdmissionError::BodyTooLarge => {
            error_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large")
        }
        AdmissionError::UnsupportedMediaType => error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type must be application/x-www-form-urlencoded",
        ),
        AdmissionError::BodyUnreadable
        | AdmissionError::PlaintextVpToken
        | AdmissionError::DuplicateResponse
        | AdmissionError::UnexpectedParameter
        | AdmissionError::MissingResponse => error_response(
            StatusCode::BAD_REQUEST,
            "body must carry exactly one response parameter",
        ),
    }
}

/// The per-POST pipeline, in order: body limit, media type, form, JWE parse (no key), `kid`
/// required, ingress hint, resolve, open + validate every candidate (blocking pool, bounded
/// by `decryptions`), claim.
async fn pipeline(
    record: &mut EvidenceRecord,
    state: &AppState,
    route: Route<'_>,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(), Rejection> {
    let response = admit(headers, body)?;
    let jwe = CompactJwe::parse(&response).map_err(Rejection::JweParse)?;
    // Every lab key is advertised with a kid, and OpenID4VP 1.1 §8.3 ties the JWE kid to the
    // chosen JWK: a JWE without one matches nothing, on any route.
    let kid = jwe.header().kid().cloned().ok_or(Rejection::MissingKid)?;
    let hint = IngressHint::new(route.token, Some(kid));
    let candidates = SessionStore::resolve(route.registry, &hint, route.strategy)
        .await
        .map_err(Rejection::Resolve)?;
    record.candidate_count = candidates.len();

    // HPKE is CPU-bound: run it on the blocking pool, at most `decryptions` trials at once.
    let slot = decryption_slot(state).await?;
    let acceptance = Arc::clone(&state.acceptance);
    // KB-JWT freshness is judged on this clock, in NumericDate seconds (RFC 7519 §2).
    let now = SystemClock.now().as_unix_millis() / MILLIS_PER_SECOND;
    let (trial, trial_time, candidates) = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let started = Instant::now();
        let trial = trial(&jwe, &candidates, &acceptance, now);
        (trial, started.elapsed(), candidates)
    })
    .await
    .map_err(|_| Rejection::TrialAborted)?;
    record.trial_time = trial_time;
    let (index, validated) = select(record, trial)?;
    let candidate = candidates.get(index).ok_or(Rejection::TrialAborted)?;
    commit(
        record,
        state,
        route.registry,
        candidate,
        &response,
        validated,
    )
    .await
}

/// Steps 1-3: body limit, media type, exactly one non-empty `response` and nothing else.
/// Returns the `response` value.
pub(crate) fn admit(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<String, Rejection> {
    let body = body.map_err(|e| {
        Rejection::Admission(if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            AdmissionError::BodyTooLarge
        } else {
            AdmissionError::BodyUnreadable
        })
    })?;
    if !is_form_urlencoded(headers) {
        return Err(Rejection::Admission(AdmissionError::UnsupportedMediaType));
    }
    single_response_param(&body).map_err(Rejection::Admission)
}

/// One of the `decryptions` slots for a trial on the blocking pool; counted as parked while
/// it waits (instrumentation).
pub(crate) async fn decryption_slot(state: &AppState) -> Result<OwnedSemaphorePermit, Rejection> {
    #[cfg(feature = "lab-instrumentation")]
    let parked = ParkedTrial::enter(&state.parked_trials);
    let slot = Arc::clone(&state.decryptions).acquire_owned().await;
    #[cfg(feature = "lab-instrumentation")]
    drop(parked);
    slot.map_err(|_| Rejection::TrialAborted)
}

/// Records the trial's evidence and picks its result: exactly one validated candidate is
/// kept, more than one is an integrity failure (`Ambiguous`), none is the first validation
/// error (or `Decrypt` when nothing opened).
pub(crate) fn select(
    record: &mut EvidenceRecord,
    trial: Trial,
) -> Result<(usize, validate::Validated), Rejection> {
    record.hpke_attempts = trial.attempts;
    if trial.attempts > 0 {
        record.crypto_result = if trial.opened == 0 {
            CryptoResult::NoneOpened
        } else {
            CryptoResult::Opened {
                opened: trial.opened,
            }
        };
    }
    if trial.opened > 0 {
        record.validation_result = match (trial.validated, trial.first_error) {
            (0, Some(e)) => ValidationResult::Failed(e),
            (validated, _) => ValidationResult::Passed { validated },
        };
    }
    match (trial.first, trial.validated) {
        (Some(first), 1) => Ok(first),
        (Some(_), validated) => {
            record.commit_result = CommitResult::RefusedAmbiguous;
            Err(Rejection::Ambiguous { validated })
        }
        (None, _) => Err(trial
            .first_error
            .map_or(Rejection::Decrypt, Rejection::Validation)),
    }
}

/// Steps 9-10: the Verifier-wide replay guard, then the atomic claim of `candidate` with the
/// digest of the compact JWE `response`.
pub(crate) async fn commit(
    record: &mut EvidenceRecord,
    state: &AppState,
    registry: &Registry,
    candidate: &Candidate<SessionKey>,
    response: &str,
    validated: validate::Validated,
) -> Result<(), Rejection> {
    let validate::Validated {
        response: mut result,
        holder_proof,
    } = validated;
    // A fresh Response Code per committed response when the answer carries a `redirect_uri`
    // (OpenID4VP 1.0 §8.2, §13.3 step 6: created by the Response URI and bound to the stored
    // response). Drawn before the claim, so it is stored with the consumed session atomically.
    if state.response_redirect_uri.is_some() {
        result.response_code =
            Some(random_b64(RESPONSE_CODE_BYTES).ok_or(Rejection::ResponseCodeUnavailable)?);
    }
    let digest = ResponseDigest::new(Sha256::digest(response.as_bytes()).into());
    let commits_open = state.commits_open.read().await;
    if !*commits_open {
        return Err(Rejection::ShuttingDown);
    }
    state
        .replay_guard
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(
            digest,
            ResponseDigest::new(holder_proof),
            candidate.id(),
            candidate
                .expires_at()
                .saturating_add(DEFAULT_CONSUMED_RETENTION),
        )?;
    match SessionStore::claim(registry, candidate, digest, result).await {
        Ok(snapshot) => {
            record.commit_result = CommitResult::Committed;
            record.committed_session = Some(snapshot.id().clone());
            Ok(())
        }
        Err(e) => {
            record.commit_result = CommitResult::Rejected(e);
            Err(Rejection::Claim(e))
        }
    }
}

/// Opens the JWE with every candidate's key and `session_info` and validates every plaintext
/// against that candidate: its `state` first, then holder binding to its `client_id` and
/// `nonce`.
/// Never stops at the first match: for bounded trial, a second validating candidate must be
/// seen to be refused. Only the first validated result is kept; later ones are counted and
/// dropped, so the work per candidate (and the timing) is the same either way. Unique
/// strategies return at most one candidate.
pub(crate) fn trial(
    jwe: &CompactJwe,
    candidates: &[Candidate<SessionKey>],
    acceptance: &Acceptance,
    now: u64,
) -> Trial {
    open_and_validate(candidates, acceptance, now, |candidate| {
        let info = SessionInfo::from_binding(candidate.binding());
        jwe.open(candidate.key().hpke()?, info.as_bytes()).ok()
    })
}

/// [`trial`] with the decryption as a parameter: `open` returns a candidate's plaintext, or
/// `None` when its key is of another kind or does not open the JWE. Every candidate is tried,
/// every opened plaintext validated against its own candidate.
pub(crate) fn open_and_validate(
    candidates: &[Candidate<SessionKey>],
    acceptance: &Acceptance,
    now: u64,
    open: impl Fn(&Candidate<SessionKey>) -> Option<Vec<u8>>,
) -> Trial {
    let mut out = Trial::default();
    for (index, candidate) in candidates.iter().enumerate() {
        out.attempts += 1;
        let Some(plaintext) = open(candidate) else {
            continue;
        };
        out.opened += 1;
        match validate::validate(&plaintext, candidate.binding(), acceptance, now) {
            Ok(result) => {
                out.validated += 1;
                if out.first.is_none() {
                    out.first = Some((index, result));
                }
            }
            Err(e) => {
                out.first_error.get_or_insert(e);
            }
        }
    }
    out
}

/// Content-Type essence is `application/x-www-form-urlencoded` (parameters such as `charset`
/// are ignored).
fn is_form_urlencoded(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(FORM_CONTENT_TYPE))
}

/// The value of the single `response` parameter. Parses lazily and stops at the first
/// plaintext `vp_token`, second `response` or any other parameter; an empty or missing
/// `response` is refused too.
fn single_response_param(body: &[u8]) -> Result<String, AdmissionError> {
    let mut response = None;
    for (name, value) in form_urlencoded::parse(body) {
        if name == validate::VP_TOKEN {
            return Err(AdmissionError::PlaintextVpToken);
        }
        if name != RESPONSE_PARAM {
            return Err(AdmissionError::UnexpectedParameter);
        }
        if response.replace(value).is_some() {
            return Err(AdmissionError::DuplicateResponse);
        }
    }
    match response {
        Some(value) if !value.is_empty() => Ok(value.into_owned()),
        _ => Err(AdmissionError::MissingResponse),
    }
}

/// Counts a POST as parked on the decryption semaphore for exactly as long as it waits there.
///
/// An RAII guard rather than paired `fetch_add`/`fetch_sub`: the request-timeout middleware
/// drops the handler future while it is parked, and only `Drop` runs on that path.
#[cfg(feature = "lab-instrumentation")]
struct ParkedTrial<'a>(&'a AtomicUsize);

#[cfg(feature = "lab-instrumentation")]
impl<'a> ParkedTrial<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

#[cfg(feature = "lab-instrumentation")]
impl Drop for ParkedTrial<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
