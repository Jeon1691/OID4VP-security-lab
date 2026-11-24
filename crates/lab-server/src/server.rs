//! axum application: session issuing, request objects, the response pipeline and the sweep.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
#[cfg(feature = "lab-instrumentation")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

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
    SessionId,
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
    self, MAX_RESEARCH_NONCE_LEN, SYNTHETIC_CREDENTIAL_QUERY_ID, ValidatedResponse, ValidationError,
};

/// Most response digests the replay guard remembers at once: four times session-core's
/// default pending cap. An entry exists only for a response that decrypted and validated for
/// a live session, and lives as long as that session's consumed record would (TTL plus
/// `DEFAULT_CONSUMED_RETENTION`). About 100 bytes each, so at most a few MiB. When full, new
/// responses are refused (fail closed) until the sweep frees entries.
pub const MAX_REMEMBERED_DIGESTS: usize = 4 * session_core::DEFAULT_MAX_PENDING_SESSIONS;

/// Verifier-wide replay guard: digests of responses that validated, with the session they
/// validated for.
///
/// Per-session state alone does not stop cross-session replay on the shared research route:
/// bounded trial never offers a consumed session as a candidate, so a new session with the
/// same `session_info` (shared key and route, reused nonce) would accept an old response. A
/// digest is recorded before the claim, under one lock, so two concurrent POSTs of one JWE for
/// two sessions cannot both pass; a recorded digest is kept even if its claim then fails
/// (fail closed: that JWE stays bound to the first session it validated for). The same
/// session's own retries pass through to the claim, which reports them as replays.
#[derive(Default)]
struct ReplayGuard {
    /// Digest, owning session, and when the entry may be forgotten.
    seen: HashMap<ResponseDigest, (SessionId, Timestamp)>,
}

impl ReplayGuard {
    fn admit(
        &mut self,
        digest: ResponseDigest,
        session: &SessionId,
        retain_until: Timestamp,
    ) -> Result<(), Rejection> {
        match self.seen.get(&digest) {
            Some((owner, _)) if owner == session => Ok(()),
            Some(_) => Err(Rejection::CrossSessionReplay),
            None if self.seen.len() >= MAX_REMEMBERED_DIGESTS => Err(Rejection::ReplayGuardFull),
            None => {
                self.seen.insert(digest, (session.clone(), retain_until));
                Ok(())
            }
        }
    }

    fn forget_before(&mut self, now: Timestamp) {
        self.seen.retain(|_, (_, until)| *until > now);
    }
}

/// Result of one HPKE trial over a resolve's candidates.
struct Trial {
    attempts: usize,
    opened: usize,
    /// Candidates that validated (all are tried; only the first result is kept).
    validated: usize,
    /// Index and result of the first validating candidate.
    first: Option<(usize, ValidatedResponse)>,
    /// First validation error among opened candidates.
    first_error: Option<ValidationError>,
}

/// The one body answered for every resolve, parse, decrypt, validate and claim failure, so the
/// response does not reveal whether a session exists, was consumed, expired or is shared
/// (session-core `ResolveError` / `ClaimError` docs). Status 400.
pub const GENERIC_REJECTION_BODY: &str = r#"{"error":"invalid_request"}"#;

/// Path prefixes and routes (lab infrastructure, not standard OpenID4VP endpoints).
const SESSIONS_PATH: &str = "/lab/v1/sessions";
const REQUESTS_PATH: &str = "/lab/v1/requests";
const RESPONSE_PATH: &str = "/lab/v1/response";
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
/// Random bytes in a session id and in a per-session `kid`: 128 bits, so ids never collide
/// and unique-kid resolution is never ambiguous by accident.
const SESSION_ID_BYTES: usize = 16;
const KID_BYTES: usize = 16;

/// JWK members for the advertised HPKE-0 key (RFC 7517 / RFC 7518 §6.2, draft-22 §5.1).
pub(crate) const JWK_KTY_EC: &str = "EC";
pub(crate) const JWK_CRV_P256: &str = "P-256";
const JWK_USE_ENC: &str = "enc";
/// SEC1 uncompressed point: `0x04 || x || y` with 32-byte P-256 coordinates (SEC1 §2.3.3).
pub(crate) const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
pub(crate) const P256_COORDINATE_BYTES: usize = 32;
/// JWT NumericDates are whole seconds (RFC 7519 §2); session-core timestamps are milliseconds.
const MILLIS_PER_SECOND: u64 = 1000;
/// OpenID4VP `response_type` of every lab request (§5.2).
const RESPONSE_TYPE_VP_TOKEN: &str = "vp_token";
/// DCQL `format` of the synthetic credential query; deliberately not a registered format.
const SYNTHETIC_FORMAT: &str = "lab-synthetic";

/// Private-key handle stored per session; shared across sessions in bounded-trial mode.
type SessionKey = Arc<RecipientPrivateKey>;
type Registry = MemoryRegistry<SessionKey, ValidatedResponse>;

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

struct AppState {
    mode: Mode,
    client_id: ClientIdWire,
    /// Signs each request object once, at issue time.
    signer: RequestSigner,
    session_ttl: Duration,
    base_url: String,
    /// Unique-uri sessions; `RoutePolicy::UniquePerSession`, in every mode.
    unique: Registry,
    /// Research mode only; `RoutePolicy::Shared`.
    shared: Option<SharedRoute>,
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
    fn registry(&self, route: RouteKind) -> Option<&Registry> {
        match route {
            RouteKind::Unique => Some(&self.unique),
            RouteKind::Shared => self.shared.as_ref().map(|s| &s.registry),
        }
    }

    fn issued(&self) -> std::sync::MutexGuard<'_, Issued> {
        // Plain maps of immutable entries, each insert/remove pair done under one guard; a
        // panic elsewhere cannot leave them inconsistent.
        self.issued.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Expires and purges both registries, then drops request objects of purged sessions.
    /// A store failure just skips the round; the next tick retries.
    fn sweep(&self) {
        for registry in [
            Some(&self.unique),
            self.shared.as_ref().map(|s| &s.registry),
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
        let request_kid = config::check(&config)?;
        let listener = TcpListener::bind(config.bind).await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{addr}");

        let shared = match config.mode {
            Mode::Hardened => None,
            Mode::Research(strategy) => {
                let shared_key = match strategy {
                    SharedRouteStrategy::BoundedTrial(_) => {
                        let kid = KeyId::new(random_b64(KID_BYTES).ok_or(StartError::Rng)?)
                            .map_err(|_| StartError::Rng)?;
                        Some((Arc::new(generate_key()), kid))
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
        let signer = RequestSigner::new(config.request_signing_key, request_kid);
        let state = Arc::new(AppState {
            mode: config.mode,
            client_id: config.client_id,
            signer,
            session_ttl: config.session_ttl,
            base_url: base_url.clone(),
            unique: registry(RoutePolicy::UniquePerSession),
            shared,
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
        let header_read_timeout = config.header_read_timeout;
        let serve = tokio::spawn(serve(listener, app, header_read_timeout, stopped));
        Ok(Self {
            addr,
            base_url,
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

    /// `http://<addr>`, the prefix of every lab URL.
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
            ..
        } = self;
        let exited_early = serve.is_finished();
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

/// Accept loop: one hyper HTTP/1 connection task per accepted stream, with a header read
/// timeout (`axum::serve` gives hyper no timer, so it could never fire). When `stopped`
/// resolves it stops accepting and waits for every connection to finish (idle ones are closed
/// at once); [`LabServer::shutdown`] bounds that wait.
async fn serve(
    listener: CappedListener,
    app: Router,
    header_read_timeout: Duration,
    stopped: oneshot::Receiver<()>,
) {
    let graceful = GracefulShutdown::new();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let mut stopped = std::pin::pin!(stopped);
    loop {
        let stream = tokio::select! {
            stream = listener.accept() => stream,
            _ = &mut stopped => break,
        };
        let service = TowerToHyperService::new(app.clone());
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
fn generate_key() -> RecipientPrivateKey {
    RecipientPrivateKey::generate(&mut UnwrapErr(getrandom::SysRng))
}

/// `bytes` random bytes from the OS CSPRNG as unpadded base64url; `None` if the RNG fails.
fn random_b64(bytes: usize) -> Option<String> {
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
/// "nonce": "..."}`. `route` defaults to `unique`; `shared` and `nonce` (a caller-chosen nonce,
/// to model a Verifier that reuses nonces) are research-mode only.
async fn create_session(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let (route, nonce) = match parse_create(&state, &body) {
        Ok(v) => v,
        Err(description) => return error_response(StatusCode::BAD_REQUEST, description),
    };
    match issue(&state, route, nonce).await {
        Ok(created) => json_response(StatusCode::CREATED, created.to_string()),
        Err(InsertError::Capacity { .. }) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "session capacity reached")
        }
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "session not created"),
    }
}

fn parse_create(
    state: &AppState,
    body: &[u8],
) -> Result<(RouteKind, Option<NonceWire>), &'static str> {
    if body.is_empty() {
        return Ok((RouteKind::Unique, None));
    }
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(body) else {
        return Err("body must be a JSON object");
    };
    let research = matches!(state.mode, Mode::Research(_));
    let mut route = RouteKind::Unique;
    let mut nonce = None;
    for (name, value) in &request {
        match (name.as_str(), value.as_str()) {
            ("route", Some("unique")) => route = RouteKind::Unique,
            ("route", Some("shared")) if research => route = RouteKind::Shared,
            ("route", _) => return Err("unsupported route"),
            ("nonce", Some(n)) if research => {
                // Bounded so a matching presentation always fits the commit cap
                // (`validate::MAX_COMMITTED_VP_TOKEN_BYTES`, checked at compile time there).
                if n.len() > MAX_RESEARCH_NONCE_LEN {
                    return Err("nonce too long");
                }
                nonce = Some(NonceWire::new(n).map_err(|_| "invalid nonce")?);
            }
            _ => return Err("unsupported member"),
        }
    }
    Ok((route, nonce))
}

/// Creates and registers a session; returns the creation response.
async fn issue(
    state: &AppState,
    route: RouteKind,
    nonce: Option<NonceWire>,
) -> Result<Value, InsertError> {
    let fail = || InsertError::Unavailable(session_core::StoreUnavailable);
    let random = |n| random_b64(n).ok_or_else(fail);
    let id = SessionId::new(random(SESSION_ID_BYTES)?).map_err(|_| fail())?;
    let nonce = match nonce {
        Some(n) => n,
        None => NonceWire::new(random(NONCE_BYTES)?).map_err(|_| fail())?,
    };
    let (registry, route_token, response_uri, key, kid) = match (route, &state.shared) {
        (RouteKind::Shared, Some(shared)) => {
            let (key, kid) = match &shared.shared_key {
                Some((key, kid)) => (Arc::clone(key), kid.clone()),
                None => (
                    Arc::new(generate_key()),
                    KeyId::new(random(KID_BYTES)?).map_err(|_| fail())?,
                ),
            };
            let uri = format!("{}{RESPONSE_PATH}/{SHARED_SEGMENT}", state.base_url);
            (&shared.registry, shared.token.clone(), uri, key, kid)
        }
        _ => {
            let token = RouteToken::generate().map_err(|_| fail())?;
            let uri = format!(
                "{}{RESPONSE_PATH}/{}",
                state.base_url,
                token.to_url_segment()
            );
            let kid = KeyId::new(random(KID_BYTES)?).map_err(|_| fail())?;
            (&state.unique, token, uri, Arc::new(generate_key()), kid)
        }
    };
    let response_uri = ResponseUriWire::new(response_uri).map_err(|_| fail())?;
    let binding = RequestBinding::DirectPostJwt {
        client_id: state.client_id.clone(),
        nonce,
        response_uri,
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
    let request_object = state.signer.sign(
        request_object(stored.binding(), &key, &kid, lifetime)
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
    };
    // `client_id` is what the Authorization Request carries next to `request_uri`; the Request
    // Object's `client_id` must equal it (OpenID4VP 1.1 §5.10.1).
    let created = json!({
        "session_id": id.as_str(),
        "client_id": state.client_id.as_str(),
        "request_uri": request_uri,
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

/// The request object payload for `binding`: exactly the stored wire values, the HPKE-0 public
/// key in `client_metadata.jwks`, `aud` (OpenID4VP 1.1 §5.8, Static Discovery), `iat` and `exp`
/// ([`Lifetime`]). No `iss`: it MAY be present and Wallets MUST ignore it (§5). Signed by
/// `RequestSigner::sign`.
fn request_object(
    binding: &RequestBinding,
    key: &RecipientPrivateKey,
    kid: &KeyId,
    lifetime: Lifetime,
) -> Value {
    let RequestBinding::DirectPostJwt {
        client_id,
        nonce,
        response_uri,
    } = binding
    else {
        return Value::Null;
    };
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
    json!({
        "aud": REQUEST_OBJECT_AUD,
        "iat": lifetime.issued_at,
        "exp": lifetime.expires_at,
        "client_id": client_id.as_str(),
        "response_type": RESPONSE_TYPE_VP_TOKEN,
        "response_mode": EncryptedResponseMode::DirectPostJwt.as_str(),
        "response_uri": response_uri.as_str(),
        "nonce": nonce.as_str(),
        "dcql_query": {
            "credentials": [{ "id": SYNTHETIC_CREDENTIAL_QUERY_ID, "format": SYNTHETIC_FORMAT }]
        },
        "client_metadata": { "jwks": { "keys": [Value::Object(jwk)] } },
    })
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
/// the committed synthetic `vp_token` once consumed. Only the result token from the
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
        SessionState::Consumed { result, .. } => {
            json!({ "state": "consumed", "vp_token": result.vp_token() })
        }
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
    let response = match &record.rejection {
        None => json_response(StatusCode::OK, "{}".to_owned()),
        Some(Rejection::Admission(a)) => admission_response(*a),
        Some(_) => json_response(StatusCode::BAD_REQUEST, GENERIC_REJECTION_BODY.to_owned()),
    };
    state.evidence.push(record);
    response
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
    let response = single_response_param(&body).map_err(Rejection::Admission)?;
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
    #[cfg(feature = "lab-instrumentation")]
    let parked = ParkedTrial::enter(&state.parked_trials);
    let slot = Arc::clone(&state.decryptions).acquire_owned().await;
    #[cfg(feature = "lab-instrumentation")]
    drop(parked);
    let slot = slot.map_err(|_| Rejection::TrialAborted)?;
    let (trial, candidates) = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        (trial(&jwe, &candidates), candidates)
    })
    .await
    .map_err(|_| Rejection::TrialAborted)?;
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
    let (index, result) = match (trial.first, trial.validated) {
        (Some(first), 1) => first,
        (Some(_), validated) => {
            record.commit_result = CommitResult::RefusedAmbiguous;
            return Err(Rejection::Ambiguous { validated });
        }
        (None, _) => {
            return Err(trial
                .first_error
                .map_or(Rejection::Decrypt, Rejection::Validation));
        }
    };
    let candidate = candidates.get(index).ok_or(Rejection::TrialAborted)?;
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
            candidate.id(),
            candidate
                .expires_at()
                .saturating_add(DEFAULT_CONSUMED_RETENTION),
        )?;
    match SessionStore::claim(route.registry, candidate, digest, result).await {
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

/// Opens the JWE with every candidate's key and `session_info` and validates every plaintext.
/// Never stops at the first match: for bounded trial, a second validating candidate must be
/// seen to be refused. Only the first validated result is kept; later ones are counted and
/// dropped, so the work per candidate (and the timing) is the same either way. Unique
/// strategies return at most one candidate.
fn trial(jwe: &CompactJwe, candidates: &[Candidate<SessionKey>]) -> Trial {
    let mut out = Trial {
        attempts: 0,
        opened: 0,
        validated: 0,
        first: None,
        first_error: None,
    };
    for (index, candidate) in candidates.iter().enumerate() {
        out.attempts += 1;
        let info = SessionInfo::from_binding(candidate.binding());
        let Ok(plaintext) = jwe.open(candidate.key(), info.as_bytes()) else {
            continue;
        };
        out.opened += 1;
        match validate::validate(&plaintext, candidate.binding()) {
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
