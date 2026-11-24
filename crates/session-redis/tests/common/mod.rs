//! Shared fixtures for the session-redis tests: synthetic values, and one harness per backend
//! so the same contract tests run against `MemoryRegistry` and `RedisRegistry`.
//!
//! Redis tests read `REDIS_URL` and panic when it is unset: they are `#[ignore]`d in the
//! default test stage and run (and must pass) only in the `redis` gate stage.
#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use protocol_model::{
    ClientIdWire, KeyId, NonceWire, OriginWire, RequestBinding, ResponseUriWire, SessionId,
};
use session_core::{
    Candidate, IngressHint, ManualClock, MemoryRegistry, NewSession, RESPONSE_DIGEST_BYTES,
    RegistryConfig, ResolutionStrategy, ResponseDigest, RoutePolicy, RouteToken, SessionState,
    SessionStore, Timestamp,
};
use session_redis::{KeyTable, RedisRegistry};

/// Reason on every Redis-backed test; the `redis` gate stage runs them with `--ignored`.
pub const REDIS_IGNORE: &str = "requires Redis; run via scripts/ci_local.sh <dir> redis";

/// Opaque key handle stand-in; tests use the index to check which key a candidate carries.
#[derive(Debug, PartialEq, Eq)]
pub struct TestKey(pub usize);

/// Validated result stand-in.
pub type TestResult = String;

/// Arbitrary fixed start time (2023-11-14T22:13:20Z); only differences matter.
pub const T0: Timestamp = Timestamp::from_unix_millis(1_700_000_000_000);

/// Session lifetime of the fixtures: five minutes, a typical Authorization Request TTL.
pub const TTL: Duration = Duration::from_secs(300);

/// Session counts the strategy tests sweep (task matrix: 1, 2, 8, 32, 64, 128).
pub const SCALES: [usize; 6] = [1, 2, 8, 32, 64, 128];

const CLIENT_ID: &str = "x509_san_dns:verifier.lab.example";
const RESPONSE_URI_BASE: &str = "https://verifier.lab.example/post";
const DC_API_ORIGIN: &str = "https://wallet-caller.lab.example";

/// `REDIS_URL`, or a panic naming the gate stage that provides it.
pub fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| {
        panic!("REDIS_URL is not set; Redis tests {REDIS_IGNORE}");
    })
}

/// A namespace no other test uses, so tests share one Redis server without interfering.
pub fn fresh_namespace() -> String {
    format!("t-{}", route().to_url_segment())
}

/// One registry under test and the clock it judges TTLs by.
pub struct Harness<S> {
    pub clock: Arc<ManualClock>,
    pub store: Arc<S>,
}

/// A store implementation the contract suite runs against.
pub trait Backend {
    type Store: SessionStore<TestKey, TestResult> + 'static;

    /// An empty registry with `config`, on a manual clock at [`T0`].
    fn make(config: RegistryConfig) -> impl Future<Output = Harness<Self::Store>>;
}

pub struct Memory;

impl Backend for Memory {
    type Store = MemoryRegistry<TestKey, TestResult>;

    async fn make(config: RegistryConfig) -> Harness<Self::Store> {
        let clock = Arc::new(ManualClock::new(T0));
        let store = Arc::new(MemoryRegistry::with_config(clock.clone(), config));
        Harness { clock, store }
    }
}

pub struct Redis;

impl Backend for Redis {
    type Store = RedisRegistry<TestKey, TestResult>;

    async fn make(config: RegistryConfig) -> Harness<Self::Store> {
        let clock = Arc::new(ManualClock::new(T0));
        let store =
            redis_registry(&fresh_namespace(), clock.clone(), config, KeyTable::new()).await;
        Harness {
            clock,
            store: Arc::new(store),
        }
    }
}

/// A Redis registry (one worker) on `namespace`.
pub async fn redis_registry<K>(
    namespace: &str,
    clock: Arc<ManualClock>,
    config: RegistryConfig,
    keys: KeyTable<K>,
) -> RedisRegistry<K, TestResult> {
    RedisRegistry::connect(&redis_url(), namespace, clock, config, keys)
        .await
        .expect("Redis reachable at REDIS_URL")
}

pub fn shared() -> RegistryConfig {
    RegistryConfig {
        route_policy: RoutePolicy::Shared,
        ..RegistryConfig::default()
    }
}

pub fn sid(i: usize) -> SessionId {
    SessionId::new(format!("session-{i}")).expect("valid session id")
}

pub fn kid(i: usize) -> KeyId {
    KeyId::new(format!("kid-{i}")).expect("valid kid")
}

pub fn route() -> RouteToken {
    RouteToken::generate().expect("OS CSPRNG available")
}

/// A digest distinct for every `n`.
pub fn digest(n: usize) -> ResponseDigest {
    let mut bytes = [0u8; RESPONSE_DIGEST_BYTES];
    let le = n.to_le_bytes();
    bytes[..le.len()].copy_from_slice(&le);
    ResponseDigest::new(bytes)
}

pub fn binding(i: usize, route: &RouteToken) -> RequestBinding {
    RequestBinding::DirectPostJwt {
        client_id: ClientIdWire::new(CLIENT_ID).expect("valid client_id"),
        nonce: NonceWire::new(format!("nonce-{i}")).expect("valid nonce"),
        response_uri: ResponseUriWire::new(format!(
            "{RESPONSE_URI_BASE}/{}",
            route.to_url_segment()
        ))
        .expect("valid response_uri"),
    }
}

pub fn dc_api_binding(i: usize) -> RequestBinding {
    RequestBinding::DcApiJwt {
        origin: OriginWire::new(DC_API_ORIGIN).expect("valid origin"),
        nonce: NonceWire::new(format!("nonce-{i}")).expect("valid nonce"),
    }
}

pub fn new_session(i: usize, route: &RouteToken, kid: Option<KeyId>) -> NewSession<TestKey> {
    NewSession {
        id: sid(i),
        binding: binding(i, route),
        route_token: route.clone(),
        kid,
        key: TestKey(i),
        ttl: TTL,
    }
}

/// The single unique-uri candidate for `route`.
pub async fn candidate<S: SessionStore<TestKey, TestResult>>(
    store: &S,
    route: &RouteToken,
) -> Candidate<TestKey> {
    let mut found = store
        .resolve(
            &IngressHint::new(route.clone(), None),
            ResolutionStrategy::UniqueUri,
        )
        .await
        .expect("unique-uri resolves");
    assert_eq!(found.len(), 1);
    found.remove(0)
}

/// Inserts session `i` on a fresh route and returns its route and candidate.
pub async fn pending<S: SessionStore<TestKey, TestResult>>(
    store: &S,
    i: usize,
) -> (RouteToken, Candidate<TestKey>) {
    let r = route();
    store
        .insert(new_session(i, &r, None))
        .await
        .expect("insert");
    let c = candidate(store, &r).await;
    (r, c)
}

/// Current state of a session that must exist.
pub async fn state<S: SessionStore<TestKey, TestResult>>(
    store: &S,
    id: &SessionId,
) -> SessionState<TestResult> {
    store
        .snapshot(id)
        .await
        .expect("store")
        .expect("present")
        .state()
        .clone()
}
