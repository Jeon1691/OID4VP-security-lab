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
struct Ops {
    insert: Latencies,
    resolve: Latencies,
    claim: Latencies,
    ping: Latencies,
    cpu: Option<Duration>,
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
        cpu: None,
    };
    let mut before = None;
    for i in 0..warmup + iterations {
        if i == warmup {
            // Keep only measured samples.
            ops.insert = Latencies::new();
            ops.resolve = Latencies::new();
            ops.claim = Latencies::new();
            ops.ping = Latencies::new();
            before = Usage::sample();
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
    ops.cpu = Usage::sample()
        .zip(before)
        .map(|(after, before)| after.cpu.saturating_sub(before.cpu));
    Ok(ops)
}

const MILLIS_PER_SECOND: f64 = 1_000.0;

fn rows(run_id: &str, backend: &str, ops: Ops) -> Vec<Row> {
    let cpu_ms = ops.cpu.map(|c| c.as_secs_f64() * MILLIS_PER_SECOND);
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
            cpu_ms,
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
        let namespace = format!(
            "g6-{}",
            RouteToken::generate()
                .context("OS CSPRNG")?
                .to_url_segment()
        );
        let redis: RedisRegistry<Key, String> = RedisRegistry::connect(
            url,
            &namespace,
            TimeSource::RedisServer,
            RegistryConfig::default(),
            KeyTable::new(),
        )
        .await
        .context("Redis reachable")?;
        // Errors are replaced, not wrapped: their text may repeat the URL.
        let mut conn = redis::Client::open(url)
            .map_err(|_| anyhow!("invalid Redis URL"))?
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| anyhow!("Redis unreachable"))?;
        out.extend(rows(
            run_id,
            "redis",
            measure(&redis, iterations, warmup, Some(&mut conn)).await?,
        ));
    }
    Ok(out)
}
