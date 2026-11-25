//! Session-store timings without HTTP or crypto: `insert`, unique-uri `resolve` and `claim`
//! on session-core's `MemoryRegistry` and, when a Redis URL is given, session-redis's
//! `RedisRegistry` (server time, as in production), plus a Redis `PING` round trip.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, ensure};
use evidence_report::{Invariant, Row};
use protocol_model::{ClientIdWire, NonceWire, RequestBinding, ResponseUriWire, SessionId};
use session_core::{
    IngressHint, MemoryRegistry, NewSession, RESPONSE_DIGEST_BYTES, RegistryConfig,
    ResolutionStrategy, ResponseDigest, RouteToken, SessionStore, SystemClock,
};
use session_redis::{KeyTable, RedisRegistry, TimeSource};

use crate::stats::{Latencies, Usage};

/// Session lifetime of the store fixtures: five minutes, the lab's default request TTL.
const STORE_TTL: Duration = Duration::from_secs(300);
/// Synthetic binding values (reserved `.invalid` TLD, RFC 2606 §2).
const CLIENT_ID: &str = "x509_san_dns:verifier.lab.invalid";
const RESPONSE_URI_BASE: &str = "https://verifier.lab.invalid/post";
/// Stored "validated result" stand-in.
const RESULT: &str = "g6";
const RULE: &str = "every insert / resolve (exactly one candidate) / claim succeeds";

/// No key material: the store never looks at it.
type Key = ();

/// Per-operation latency of one backend.
///
/// No CPU time: one loop interleaves insert, resolve, claim (and PING) per cycle, so a process
/// CPU delta belongs to no single operation, and per-call sampling (`ps` / `/proc`, 10 ms
/// resolution on Linux) is far coarser than a microsecond store call. Store rows therefore
/// leave `cpu_ms` empty.
struct Ops {
    insert: Latencies,
    resolve: Latencies,
    claim: Latencies,
    ping: Latencies,
}

fn digest(i: u64) -> ResponseDigest {
    let mut bytes = [0u8; RESPONSE_DIGEST_BYTES];
    let le = i.to_le_bytes();
    bytes[..le.len()].copy_from_slice(&le);
    ResponseDigest::new(bytes)
}

async fn timed<T>(h: &mut Latencies, f: impl Future<Output = T>) -> T {
    let started = Instant::now();
    let out = f.await;
    h.record(started.elapsed());
    out
}

/// `warmup + iterations` insert → resolve → claim cycles; the warm-up ones are discarded.
async fn measure<S: SessionStore<Key, String>>(
    store: &S,
    iterations: u64,
    warmup: u64,
    mut ping: Option<&mut redis::aio::MultiplexedConnection>,
) -> Result<Ops> {
    let mut ops = Ops {
        insert: Latencies::new(),
        resolve: Latencies::new(),
        claim: Latencies::new(),
        ping: Latencies::new(),
    };
    for i in 0..warmup + iterations {
        if i == warmup {
            // Keep only measured samples.
            ops.insert = Latencies::new();
            ops.resolve = Latencies::new();
            ops.claim = Latencies::new();
            ops.ping = Latencies::new();
        }
        let route = RouteToken::generate().context("OS CSPRNG")?;
        let session = NewSession {
            id: SessionId::new(format!("g6-{i}"))?,
            binding: RequestBinding::DirectPostJwt {
                client_id: ClientIdWire::new(CLIENT_ID)?,
                nonce: NonceWire::new(format!("g6-nonce-{i}"))?,
                response_uri: ResponseUriWire::new(format!(
                    "{RESPONSE_URI_BASE}/{}",
                    route.to_url_segment()
                ))?,
            },
            route_token: route.clone(),
            kid: None,
            key: (),
            ttl: STORE_TTL,
        };
        timed(&mut ops.insert, store.insert(session))
            .await
            .context("insert")?;
        let hint = IngressHint::new(route, None);
        let mut candidates = timed(
            &mut ops.resolve,
            store.resolve(&hint, ResolutionStrategy::UniqueUri),
        )
        .await
        .context("resolve")?;
        ensure!(candidates.len() == 1, "unique-uri resolves one candidate");
        let candidate = candidates.remove(0);
        timed(
            &mut ops.claim,
            store.claim(&candidate, digest(i), RESULT.to_owned()),
        )
        .await
        .context("claim")?;
        if let Some(conn) = ping.as_deref_mut() {
            let pong: String = timed(&mut ops.ping, redis::cmd("PING").query_async(conn))
                .await
                .context("PING")?;
            ensure!(pong == "PONG", "PING answered {pong:?}");
        }
    }
    Ok(ops)
}

fn rows(run_id: &str, backend: &str, ops: Ops) -> Vec<Row> {
    let rss_kib = Usage::sample().map(|u| u.rss_kib);
    [
        ("insert", ops.insert),
        ("resolve_unique_uri", ops.resolve),
        ("claim", ops.claim),
        ("ping", ops.ping),
    ]
    .into_iter()
    .filter(|(_, h)| h.len() > 0)
    .map(|(case, h)| {
        let latency = h.percentiles();
        let throughput_rps = latency.map_or(0.0, |p| {
            if p.mean_us > 0.0 {
                MICROS_PER_SECOND / p.mean_us
            } else {
                0.0
            }
        });
        Row {
            run_id: run_id.to_owned(),
            scenario: "store".to_owned(),
            strategy: backend.to_owned(),
            pending: 0,
            budget: None,
            case: case.to_owned(),
            limits: "default".to_owned(),
            requests: h.len(),
            status_2xx: h.len(),
            status_4xx: 0,
            status_503: 0,
            committed: if case == "claim" { h.len() } else { 0 },
            attempts_min: 0,
            attempts_max: 0,
            attempts_mean: 0.0,
            candidates_max: 0,
            latency,
            trial: None,
            throughput_rps,
            rejection_ratio: 0.0,
            // See `Ops`: not attributable to one operation.
            cpu_ms: None,
            rss_kib,
            invariant: Invariant::Pass(RULE.to_owned()),
        }
    })
    .collect()
}

const MICROS_PER_SECOND: f64 = 1_000_000.0;

/// Memory rows always; Redis rows when `redis_url` is given (namespace fresh per run, so a
/// shared server is not disturbed; the URL is never logged, it may carry a password).
pub async fn run(
    run_id: &str,
    iterations: u64,
    warmup: u64,
    redis_url: Option<&str>,
) -> Result<Vec<Row>> {
    eprintln!("store: memory");
    let memory: MemoryRegistry<Key, String> =
        MemoryRegistry::with_config(Arc::new(SystemClock), RegistryConfig::default());
    let mut out = rows(
        run_id,
        "memory",
        measure(&memory, iterations, warmup, None).await?,
    );
    if let Some(url) = redis_url {
        eprintln!("store: redis");
        let namespace = fresh_namespace()?;
        let mut conn = connect(url).await?;
        let ping = conn.clone();
        let ops = in_namespace(
            &mut conn,
            &namespace,
            measure_redis(url, &namespace, ping, iterations, warmup),
        )
        .await?;
        out.extend(rows(run_id, "redis", ops));
    }
    Ok(out)
}

/// A namespace no other run uses: `g6-` and 128 random bits, so `[A-Za-z0-9_-]` only (no
/// glob metacharacter, which matters for the cleanup's `SCAN MATCH`).
fn fresh_namespace() -> Result<String> {
    Ok(format!(
        "g6-{}",
        RouteToken::generate()
            .context("OS CSPRNG")?
            .to_url_segment()
    ))
}

/// A connection for `PING` and cleanup. Errors are replaced, not wrapped: their text may repeat
/// the URL.
async fn connect(url: &str) -> Result<redis::aio::MultiplexedConnection> {
    redis::Client::open(url)
        .map_err(|_| anyhow!("invalid Redis URL"))?
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| anyhow!("Redis unreachable"))
}

/// The Redis store cycles in `namespace`, with `PING` on `ping`.
async fn measure_redis(
    url: &str,
    namespace: &str,
    mut ping: redis::aio::MultiplexedConnection,
    iterations: u64,
    warmup: u64,
) -> Result<Ops> {
    let redis: RedisRegistry<Key, String> = RedisRegistry::connect(
        url,
        namespace,
        TimeSource::RedisServer,
        RegistryConfig::default(),
        KeyTable::new(),
    )
    .await
    .context("Redis reachable")?;
    measure(&redis, iterations, warmup, Some(&mut ping)).await
}

/// Runs `work` and then removes `namespace` from Redis, whether `work` succeeded or not, so no
/// run leaves its sessions behind on a shared server. The cleanup is outside every timed
/// interval. The work's error wins over a cleanup error.
async fn in_namespace<T>(
    conn: &mut redis::aio::MultiplexedConnection,
    namespace: &str,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    let outcome = work.await;
    let cleaned = remove_namespace(conn, namespace).await;
    let value = outcome?;
    cleaned.context("removing the benchmark's Redis namespace")?;
    Ok(value)
}

/// `SCAN` page size of the cleanup: Redis' own default is 10. A few hundred keys per round trip
/// keeps the cleanup of a run's few thousand keys to a handful of calls without one long
/// blocking command.
const CLEANUP_SCAN_COUNT: usize = 500;

/// Deletes every key of `namespace` and nothing else: `SCAN MATCH {ns}:*` (session-redis
/// prefixes every key of a registry with the hash-tagged `{ns}:`; the store test checks that
/// nothing of the run survives), each key re-checked for the exact prefix, then `UNLINK` (memory
/// freed off the main thread) per page. Returns how many keys were removed.
async fn remove_namespace(
    conn: &mut redis::aio::MultiplexedConnection,
    namespace: &str,
) -> Result<u64> {
    ensure!(
        !namespace.is_empty()
            && namespace
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
        "namespace must be [A-Za-z0-9_-]"
    );
    let prefix = format!("{{{namespace}}}:");
    let pattern = format!("{prefix}*");
    let mut cursor: u64 = 0;
    let mut removed = 0;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(CLEANUP_SCAN_COUNT)
            .query_async(conn)
            .await
            .context("SCAN")?;
        let own: Vec<&String> = keys.iter().filter(|k| k.starts_with(&prefix)).collect();
        if !own.is_empty() {
            let n: u64 = redis::cmd("UNLINK")
                .arg(&own)
                .query_async(conn)
                .await
                .context("UNLINK")?;
            removed += n;
        }
        if next == 0 {
            return Ok(removed);
        }
        cursor = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITERATIONS: u64 = 5;
    const WARMUP: u64 = 1;

    /// One loop interleaves insert, resolve and claim, so its CPU time belongs to no single
    /// operation: store rows must not report it as if it did.
    #[tokio::test]
    async fn store_rows_leave_cpu_ms_empty() {
        let rows = run("t", ITERATIONS, WARMUP, None)
            .await
            .expect("memory store");
        assert!(!rows.is_empty());
        for row in rows {
            assert_eq!(row.cpu_ms, None, "{}", row.case);
            assert_eq!(row.requests, ITERATIONS, "{}", row.case);
        }
    }

    /// Reason on the Redis-backed tests; the `redis` gate stage runs them with `--ignored`.
    const REDIS_IGNORE: &str = "requires Redis; run via scripts/ci_local.sh <dir> redis";

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| panic!("REDIS_URL unset: {REDIS_IGNORE}"))
    }

    /// Keys next to the benchmark's namespace that cleanup must not touch: another namespace
    /// sharing its text as a prefix, the same hash tag without the `:` separator, and an
    /// unrelated key.
    fn neighbours(namespace: &str) -> [String; 3] {
        [
            format!("{{{namespace}-other}}:k"),
            format!("{{{namespace}}}x"),
            format!("unrelated-{namespace}"),
        ]
    }

    async fn set(conn: &mut redis::aio::MultiplexedConnection, keys: &[String]) {
        for key in keys {
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg("v")
                .query_async(conn)
                .await
                .expect("SET");
        }
    }

    async fn exists(conn: &mut redis::aio::MultiplexedConnection, key: &str) -> bool {
        let n: u64 = redis::cmd("EXISTS")
            .arg(key)
            .query_async(conn)
            .await
            .expect("EXISTS");
        n == 1
    }

    async fn own_keys(conn: &mut redis::aio::MultiplexedConnection, namespace: &str) -> usize {
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{{{namespace}}}:*"))
            .query_async(conn)
            .await
            .expect("KEYS");
        keys.len()
    }

    async fn cleanup_neighbours(conn: &mut redis::aio::MultiplexedConnection, keys: &[String]) {
        let _: u64 = redis::cmd("DEL")
            .arg(keys)
            .query_async(conn)
            .await
            .expect("DEL");
    }

    #[tokio::test]
    #[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
    async fn redis_namespace_is_removed_after_a_run_and_neighbours_survive() {
        let url = redis_url();
        let namespace = fresh_namespace().expect("namespace");
        let mut conn = connect(&url).await.expect("Redis");
        let others = neighbours(&namespace);
        set(&mut conn, &others).await;
        let ping = conn.clone();
        let mut probe = conn.clone();
        let ns = namespace.clone();
        let ops = in_namespace(&mut conn, &namespace, async move {
            let ops = measure_redis(&url, &ns, ping, ITERATIONS, WARMUP).await?;
            // The run really wrote session keys before the cleanup.
            ensure!(own_keys(&mut probe, &ns).await > 0, "the run wrote no keys");
            Ok(ops)
        })
        .await
        .expect("measured and cleaned");
        assert_eq!(ops.claim.len(), ITERATIONS);
        assert_eq!(
            own_keys(&mut conn, &namespace).await,
            0,
            "namespace left behind"
        );
        for key in &others {
            assert!(exists(&mut conn, key).await, "{key} was removed");
        }
        cleanup_neighbours(&mut conn, &others).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
    async fn redis_namespace_is_removed_when_a_bench_op_fails() {
        let url = redis_url();
        let namespace = fresh_namespace().expect("namespace");
        let mut conn = connect(&url).await.expect("Redis");
        let others = neighbours(&namespace);
        set(&mut conn, &others).await;
        let ns = namespace.clone();
        let mut probe = conn.clone();
        let outcome: Result<()> = in_namespace(&mut conn, &namespace, async move {
            let redis: RedisRegistry<Key, String> = RedisRegistry::connect(
                &url,
                &ns,
                TimeSource::RedisServer,
                RegistryConfig::default(),
                KeyTable::new(),
            )
            .await?;
            let route = RouteToken::generate()?;
            redis
                .insert(NewSession {
                    id: SessionId::new("g6-failing")?,
                    binding: RequestBinding::DirectPostJwt {
                        client_id: ClientIdWire::new(CLIENT_ID)?,
                        nonce: NonceWire::new("g6-nonce")?,
                        response_uri: ResponseUriWire::new(format!(
                            "{RESPONSE_URI_BASE}/{}",
                            route.to_url_segment()
                        ))?,
                    },
                    route_token: route,
                    kid: None,
                    key: (),
                    ttl: STORE_TTL,
                })
                .await?;
            ensure!(own_keys(&mut probe, &ns).await > 0, "the op wrote no keys");
            Err(anyhow!("simulated bench op failure"))
        })
        .await;
        let error = outcome.expect_err("the work's error is returned");
        assert!(
            error.to_string().contains("simulated bench op failure"),
            "{error:#}"
        );
        assert_eq!(
            own_keys(&mut conn, &namespace).await,
            0,
            "namespace left behind"
        );
        for key in &others {
            assert!(exists(&mut conn, key).await, "{key} was removed");
        }
        cleanup_neighbours(&mut conn, &others).await;
    }
}
