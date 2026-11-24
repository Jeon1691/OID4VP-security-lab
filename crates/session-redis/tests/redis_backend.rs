//! Redis-only properties: several workers on one session state (STATE-03), fail closed when
//! Redis is unreachable or dies mid-run with no in-memory fallback (STATE-05), and the
//! key-material trust boundary (private keys never reach Redis; a record that names the wrong
//! key, or does not decode, fails closed).

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{
    TTL, TestKey, TestResult, binding, digest, fresh_namespace, kid, new_session, redis_registry,
    redis_url, route, sid,
};
use redis::AsyncCommands;
use session_core::{
    Candidate, ClaimError, IngressHint, InsertError, ManualClock, NewSession, RegistryConfig,
    ResolutionStrategy, ResolveError, SessionSnapshot, SessionStore, StoreUnavailable,
};
use session_redis::{KeyTable, RedisRegistry, SetupError};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

/// Concurrent claimers per session across both workers (task matrix: 2, 16, 128).
const CONTENDERS: [usize; 3] = [2, 16, 128];
/// Independent sessions raced per contender count.
const ROUNDS: usize = 8;
/// Upper bound for one call against a dead Redis: it must fail, not hang. Well above the
/// registry's own connect (1 s) + response (2 s) timeouts.
const FAIL_FAST: Duration = Duration::from_secs(10);

type Worker = RedisRegistry<TestKey, TestResult>;

/// Two workers of one registry: same namespace, clock and key table, separate connections.
async fn two_workers(config: RegistryConfig) -> (Arc<ManualClock>, Arc<Worker>, Arc<Worker>) {
    let ns = fresh_namespace();
    let clock = Arc::new(ManualClock::new(common::T0));
    let keys = KeyTable::new();
    let a = redis_registry(&ns, clock.clone(), config, keys.clone()).await;
    let b = redis_registry(&ns, clock.clone(), config, keys).await;
    (clock, Arc::new(a), Arc::new(b))
}

fn unique_uri(route: &session_core::RouteToken) -> IngressHint {
    IngressHint::new(route.clone(), None)
}

async fn only_candidate(w: &Worker, route: &session_core::RouteToken) -> Candidate<TestKey> {
    let mut found = w
        .resolve(&unique_uri(route), ResolutionStrategy::UniqueUri)
        .await
        .expect("resolve");
    assert_eq!(found.len(), 1);
    found.remove(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn two_workers_racing_claims_commit_exactly_once() {
    for n in CONTENDERS {
        for round in 0..ROUNDS {
            let (_clock, a, b) = two_workers(RegistryConfig::default()).await;
            let r = route();
            a.insert(new_session(round, &r, None))
                .await
                .expect("insert");
            // Each worker resolves the session itself, as two lab-server processes would.
            let ca = Arc::new(only_candidate(&a, &r).await);
            let cb = Arc::new(only_candidate(&b, &r).await);
            let barrier = Arc::new(tokio::sync::Barrier::new(n));
            let mut tasks = JoinSet::new();
            for t in 0..n {
                let (w, c) = if t % 2 == 0 {
                    (a.clone(), ca.clone())
                } else {
                    (b.clone(), cb.clone())
                };
                let barrier = barrier.clone();
                tasks.spawn(async move {
                    barrier.wait().await;
                    (t, w.claim(&c, digest(t), format!("winner-{t}")).await)
                });
            }
            let mut winners = Vec::new();
            while let Some(joined) = tasks.join_next().await {
                match joined.expect("claim task") {
                    (t, Ok(_)) => winners.push(t),
                    (_, Err(ClaimError::Replay { .. })) => {}
                    (_, Err(other)) => panic!("unexpected loser outcome: {other:?}"),
                }
            }
            assert_eq!(winners.len(), 1, "n={n} round={round}: {winners:?}");
            let winner = winners[0];
            // Both workers read the same committed record: the winner's result and digest.
            for w in [&a, &b] {
                let snap = w
                    .snapshot(&sid(round))
                    .await
                    .expect("store")
                    .expect("present");
                match snap.state() {
                    session_core::SessionState::Consumed { result, digest: d } => {
                        assert_eq!(**result, format!("winner-{winner}"));
                        assert_eq!(*d, digest(winner));
                    }
                    other => panic!("expected Consumed, got {other:?}"),
                }
            }
        }
    }
}

/// A free loopback port nothing listens on.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

#[tokio::test]
async fn unreachable_redis_fails_closed_at_connect() {
    let url = format!("redis://127.0.0.1:{}/", closed_port().await);
    let clock = Arc::new(ManualClock::new(common::T0));
    let outcome = tokio::time::timeout(
        FAIL_FAST,
        RedisRegistry::<TestKey, TestResult>::connect(
            &url,
            "unreachable",
            clock,
            RegistryConfig::default(),
            KeyTable::new(),
        ),
    )
    .await
    .expect("connect fails instead of hanging");
    assert!(matches!(
        outcome,
        Err(SetupError::Unavailable(StoreUnavailable))
    ));
}

#[tokio::test]
async fn connect_rejects_malformed_namespace() {
    let clock = Arc::new(ManualClock::new(common::T0));
    for ns in ["", "has space", "{tag}", "x:y", &"n".repeat(65)] {
        let outcome = RedisRegistry::<TestKey, TestResult>::connect(
            "redis://127.0.0.1:1/",
            ns,
            clock.clone(),
            RegistryConfig::default(),
            KeyTable::new(),
        )
        .await;
        assert!(
            matches!(outcome, Err(SetupError::InvalidNamespace)),
            "{ns:?}"
        );
    }
}

/// A loopback TCP proxy to Redis that can be cut: aborting the accept task drops the
/// `JoinSet` of connection tasks, which closes every proxied socket at once (Redis "killed"
/// from the registry's point of view, while the server itself keeps running for observers).
async fn start_proxy(upstream: String) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let url = format!("redis://{}/", listener.local_addr().expect("addr"));
    let handle = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        while let Ok((mut inbound, _)) = listener.accept().await {
            let upstream = upstream.clone();
            connections.spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(upstream).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (url, handle)
}

/// `host:port` of `REDIS_URL`.
fn redis_addr() -> String {
    let url = redis_url();
    let rest = url.strip_prefix("redis://").expect("redis:// URL");
    rest.trim_end_matches('/')
        .rsplit('@')
        .next()
        .expect("host")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn redis_killed_mid_run_fails_closed_without_memory_fallback() {
    let ns = fresh_namespace();
    let clock = Arc::new(ManualClock::new(common::T0));
    let keys = KeyTable::new();
    let (proxy_url, proxy) = start_proxy(redis_addr()).await;
    let worker: Worker = RedisRegistry::connect(
        &proxy_url,
        &ns,
        clock.clone(),
        RegistryConfig::default(),
        keys.clone(),
    )
    .await
    .expect("connect through proxy");
    // Observer with a direct connection: sees the authoritative state throughout.
    let observer = redis_registry(&ns, clock.clone(), RegistryConfig::default(), keys).await;

    let r = route();
    worker
        .insert(new_session(0, &r, None))
        .await
        .expect("insert");
    let c = only_candidate(&worker, &r).await;

    // Redis goes away mid-run.
    proxy.abort();
    let _ = proxy.await;

    let insert = tokio::time::timeout(FAIL_FAST, worker.insert(new_session(1, &route(), None)))
        .await
        .expect("insert fails fast");
    assert!(
        matches!(insert, Err(InsertError::Unavailable(_))),
        "{insert:?}"
    );
    let resolve = tokio::time::timeout(
        FAIL_FAST,
        worker.resolve(&unique_uri(&r), ResolutionStrategy::UniqueUri),
    )
    .await
    .expect("resolve fails fast");
    assert!(
        matches!(resolve, Err(ResolveError::Unavailable(_))),
        "{resolve:?}"
    );
    let claim = tokio::time::timeout(FAIL_FAST, worker.claim(&c, digest(1), "lost".into()))
        .await
        .expect("claim fails fast");
    assert!(
        matches!(claim, Err(ClaimError::Unavailable(_))),
        "{claim:?}"
    );
    let snapshot = tokio::time::timeout(FAIL_FAST, worker.snapshot(&sid(0)))
        .await
        .expect("snapshot fails fast");
    assert!(matches!(snapshot, Err(StoreUnavailable)), "{snapshot:?}");
    let expire = tokio::time::timeout(FAIL_FAST, worker.expire_due())
        .await
        .expect("expire_due fails fast");
    assert_eq!(expire, Err(StoreUnavailable));
    let purge = tokio::time::timeout(FAIL_FAST, worker.purge())
        .await
        .expect("purge fails fast");
    assert_eq!(purge, Err(StoreUnavailable));

    // No fallback store took over: nothing was inserted or committed anywhere, and the
    // session is still pending and claimable in Redis.
    assert!(observer.snapshot(&sid(1)).await.expect("store").is_none());
    let snap = observer
        .snapshot(&sid(0))
        .await
        .expect("store")
        .expect("present");
    assert!(snap.state().is_pending());
    let fresh = only_candidate(&observer, &r).await;
    observer
        .claim(&fresh, digest(2), "ok".into())
        .await
        .expect("the authoritative store still accepts the commit");
}

/// Key handle with a recognisable synthetic secret, to search Redis for.
struct SecretKey(String);

#[tokio::test]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn private_keys_never_reach_redis() {
    let ns = fresh_namespace();
    let marker = format!("SYNTHETIC-PRIVATE-KEY-{}", route().to_url_segment());
    let clock = Arc::new(ManualClock::new(common::T0));
    let reg: RedisRegistry<SecretKey, TestResult> =
        redis_registry(&ns, clock, common::shared(), KeyTable::new()).await;
    let r = route();
    for i in 0..2 {
        let session = NewSession {
            id: sid(i),
            binding: binding(i, &r),
            route_token: r.clone(),
            kid: Some(kid(i)),
            key: SecretKey(format!("{marker}-{i}")),
            ttl: TTL,
        };
        reg.insert(session).await.expect("insert");
    }
    let c = reg
        .resolve(
            &IngressHint::new(r.clone(), Some(kid(0))),
            ResolutionStrategy::UniqueKid,
        )
        .await
        .expect("resolve")
        .remove(0);
    assert!(
        c.key().0.starts_with(&marker),
        "the key is served from the local table"
    );
    reg.claim(&c, digest(0), "ok".into()).await.expect("claim");

    // Every key and every value under the namespace, of every type the model uses.
    let mut conn = raw_connection().await;
    let names: Vec<String> = conn.keys(format!("{{{ns}}}:*")).await.expect("KEYS");
    assert!(!names.is_empty());
    let mut dump: Vec<Vec<u8>> = Vec::new();
    for name in &names {
        dump.push(name.clone().into_bytes());
        let kind: String = redis::cmd("TYPE")
            .arg(name)
            .query_async(&mut conn)
            .await
            .expect("TYPE");
        let values: Vec<Vec<u8>> = match kind.as_str() {
            "string" => vec![conn.get(name).await.expect("GET")],
            "hash" => {
                let fields: HashMap<Vec<u8>, Vec<u8>> = conn.hgetall(name).await.expect("HGETALL");
                fields.into_iter().flat_map(|(k, v)| [k, v]).collect()
            }
            "zset" => conn.zrange(name, 0, -1).await.expect("ZRANGE"),
            other => panic!("unexpected key type {other} for {name}"),
        };
        dump.extend(values);
    }
    let needle = marker.as_bytes();
    for value in &dump {
        assert!(
            !value.windows(needle.len()).any(|w| w == needle),
            "key material found in Redis"
        );
    }
}

async fn raw_connection() -> redis::aio::MultiplexedConnection {
    redis::Client::open(redis_url())
        .expect("REDIS_URL parses")
        .get_multiplexed_async_connection()
        .await
        .expect("raw connection")
}

fn record_key(ns: &str, i: usize) -> String {
    format!("{{{ns}}}:s:{}", sid(i).as_str())
}

#[tokio::test]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn worker_without_the_key_fails_closed() {
    let ns = fresh_namespace();
    let clock = Arc::new(ManualClock::new(common::T0));
    let a: Worker = redis_registry(
        &ns,
        clock.clone(),
        RegistryConfig::default(),
        KeyTable::new(),
    )
    .await;
    // Same namespace, but its own (empty) key table: it cannot decrypt for A's sessions.
    let b: Worker = redis_registry(&ns, clock, RegistryConfig::default(), KeyTable::new()).await;
    let r = route();
    a.insert(new_session(0, &r, None)).await.expect("insert");
    assert_eq!(
        b.resolve(&unique_uri(&r), ResolutionStrategy::UniqueUri)
            .await,
        Err(ResolveError::Unavailable(StoreUnavailable))
    );
    only_candidate(&a, &r).await;
}

#[tokio::test]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn swapped_key_reference_fails_closed() {
    let ns = fresh_namespace();
    let clock = Arc::new(ManualClock::new(common::T0));
    let reg: Worker = redis_registry(&ns, clock, RegistryConfig::default(), KeyTable::new()).await;
    let (r0, r1) = (route(), route());
    reg.insert(new_session(0, &r0, None)).await.expect("insert");
    reg.insert(new_session(1, &r1, None)).await.expect("insert");

    // Tamper: point session 0's record at session 1's key.
    let mut conn = raw_connection().await;
    let other: String = conn.hget(record_key(&ns, 1), "keyref").await.expect("HGET");
    let () = conn
        .hset(record_key(&ns, 0), "keyref", other)
        .await
        .expect("HSET");

    assert_eq!(
        reg.resolve(&unique_uri(&r0), ResolutionStrategy::UniqueUri)
            .await,
        Err(ResolveError::Unavailable(StoreUnavailable)),
        "another session's key is never handed out"
    );
    assert_eq!(only_candidate(&reg, &r1).await.key(), &TestKey(1));
}

#[tokio::test]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn undecodable_record_fails_closed() {
    let ns = fresh_namespace();
    let clock = Arc::new(ManualClock::new(common::T0));
    let reg: Worker = redis_registry(&ns, clock, RegistryConfig::default(), KeyTable::new()).await;
    let r = route();
    reg.insert(new_session(0, &r, None)).await.expect("insert");
    let c = only_candidate(&reg, &r).await;

    // A nonce outside the OpenID4VP character set: the wire constructors refuse it on read.
    let mut conn = raw_connection().await;
    let () = conn
        .hset(record_key(&ns, 0), "b2", "not a nonce")
        .await
        .expect("HSET");
    assert_eq!(
        reg.resolve(&unique_uri(&r), ResolutionStrategy::UniqueUri)
            .await,
        Err(ResolveError::Unavailable(StoreUnavailable))
    );
    assert_eq!(
        reg.snapshot(&sid(0)).await.map(|s| s.is_some()),
        Err(StoreUnavailable)
    );

    // An unknown state is refused by the claim script itself, before any write.
    let () = conn
        .hset(record_key(&ns, 0), "state", "reserved")
        .await
        .expect("HSET");
    assert_eq!(
        reg.claim(&c, digest(1), "x".into()).await.unwrap_err(),
        ClaimError::Unavailable(StoreUnavailable)
    );
    let state: String = conn.hget(record_key(&ns, 0), "state").await.expect("HGET");
    assert_eq!(state, "reserved", "nothing was written");
}

#[tokio::test]
#[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
async fn local_keys_are_dropped_once_sessions_leave_pending() {
    let ns = fresh_namespace();
    let clock = Arc::new(ManualClock::new(common::T0));
    let keys = KeyTable::new();
    let reg: Worker =
        redis_registry(&ns, clock.clone(), RegistryConfig::default(), keys.clone()).await;
    let (r0, r1) = (route(), route());
    reg.insert(new_session(0, &r0, None)).await.expect("insert");
    reg.insert(new_session(1, &r1, None)).await.expect("insert");
    // A rejected insert leaves no key behind.
    assert_eq!(
        reg.insert(new_session(0, &route(), None))
            .await
            .unwrap_err(),
        InsertError::DuplicateSession
    );
    assert_eq!(keys.len(), Ok(2));

    let c0 = only_candidate(&reg, &r0).await;
    let _: SessionSnapshot<TestResult> =
        reg.claim(&c0, digest(0), "ok".into()).await.expect("claim");
    assert_eq!(keys.len(), Ok(1), "consumed: key dropped");
    // The candidate taken before the commit keeps its own handle.
    assert_eq!(c0.key(), &TestKey(0));

    clock.advance(TTL);
    assert_eq!(reg.expire_due().await, Ok(1));
    assert_eq!(keys.is_empty(), Ok(true), "expired: key dropped");
}
