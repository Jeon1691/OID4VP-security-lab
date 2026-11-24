//! axum application: session issuing, request objects, the response pipeline and the sweep.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
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
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::{ALG_HPKE_0, CompactJwe, RecipientPrivateKey, SessionInfo};
use protocol_model::{
    ClientIdWire, EncryptedResponseMode, KeyId, NonceWire, RequestBinding, ResponseUriWire,
    SessionId,
};
use serde_json::{Map, Value, json};
use session_core::{
    Candidate, IngressHint, InsertError, MemoryRegistry, NewSession, RegistryConfig,
    ResolutionStrategy, ResponseDigest, RoutePolicy, RouteToken, SessionState, SessionStore,
    SystemClock,
};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::config::SharedRouteStrategy;
use crate::config::{self, LabConfig, MAX_RESPONSE_BODY_BYTES, Mode, RouteKind, StartError};
use crate::evidence::{
    AdmissionError, CommitResult, CryptoResult, EvidenceLog, EvidenceRecord, Rejection,
    ValidationResult,
};
use crate::validate::{self, SYNTHETIC_CREDENTIAL_QUERY_ID, ValidatedResponse, ValidationError};

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
const JWK_KTY_EC: &str = "EC";
const JWK_CRV_P256: &str = "P-256";
const JWK_USE_ENC: &str = "enc";
/// SEC1 uncompressed point: `0x04 || x || y` with 32-byte P-256 coordinates (SEC1 §2.3.3).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
const P256_COORDINATE_BYTES: usize = 32;
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
    serve: JoinHandle<std::io::Result<()>>,
    sweep: JoinHandle<()>,
}

impl LabServer {
    /// Checks the configuration, binds the listener and starts serving and sweeping.
    ///
    /// # Errors
    /// [`StartError`]; a non-loopback address is refused before binding.
    pub async fn start(config: LabConfig) -> Result<Self, StartError> {
        config::check(&config)?;
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
        let state = Arc::new(AppState {
            mode: config.mode,
            client_id: config.client_id,
            session_ttl: config.session_ttl,
            base_url: base_url.clone(),
            unique: registry(RoutePolicy::UniquePerSession),
            shared,
            issued: Mutex::new(Issued::default()),
            decryptions: Arc::new(Semaphore::new(config.max_concurrent_decryptions)),
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
        let app = router(state, limits);
        let serve = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            addr,
            base_url,
            evidence,
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
    /// The serve loop's I/O error, or a panic of it as `std::io::Error`.
    pub async fn wait(self) -> std::io::Result<()> {
        let result = self.serve.await.map_err(std::io::Error::other)?;
        self.sweep.abort();
        result
    }

    /// Stops serving and sweeping. A serve or sweep task that panicked re-raises its panic, and
    /// one that exited early panics, so a broken server fails the caller (tests). A sweep panic
    /// surfaces only here: while running, a dead sweep only means expired sessions linger
    /// (session-core still checks TTLs lazily).
    pub async fn shutdown(self) {
        self.serve.abort();
        self.sweep.abort();
        match self.serve.await {
            Err(e) if e.is_cancelled() => {}
            Err(e) => std::panic::resume_unwind(e.into_panic()),
            Ok(result) => panic!("lab server exited early: {result:?}"),
        }
        match self.sweep.await {
            Err(e) if e.is_cancelled() => {}
            Err(e) => std::panic::resume_unwind(e.into_panic()),
            Ok(()) => panic!("sweep task exited early"),
        }
    }
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
    let request_object = request_object(&binding, &key, &kid).to_string();
    let response_uri = match &binding {
        RequestBinding::DirectPostJwt { response_uri, .. } => response_uri.as_str().to_owned(),
        RequestBinding::DcApiJwt { .. } => return Err(fail()),
    };
    SessionStore::insert(
        registry,
        NewSession {
            id: id.clone(),
            binding,
            route_token,
            kid: Some(kid),
            key,
            ttl: state.session_ttl,
        },
    )
    .await?;
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
    let created = json!({
        "session_id": id.as_str(),
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

/// The (unsigned) request object for `binding`: exactly the stored wire values, plus the
/// HPKE-0 public key in `client_metadata.jwks`. JAR signing is a follow-up and must sign these
/// same values.
fn request_object(binding: &RequestBinding, key: &RecipientPrivateKey, kid: &KeyId) -> Value {
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
        Some(object) => json_response(StatusCode::OK, object),
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
    record.rejection = pipeline(&mut record, &state.decryptions, route, headers, body)
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
    decryptions: &Arc<Semaphore>,
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
    let slot = Arc::clone(decryptions)
        .acquire_owned()
        .await
        .map_err(|_| Rejection::TrialAborted)?;
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
