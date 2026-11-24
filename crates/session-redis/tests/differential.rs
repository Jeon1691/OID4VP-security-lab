//! Differential property test: random operation sequences (inserts on shared and unique
//! routes and kids, resolves under every strategy, claims with fresh and stale candidates,
//! clock moves, sweeps, purges, id reuse, capacity pressure) are applied to a
//! `MemoryRegistry` (the reference, itself checked against a model in session-core) and to a
//! `RedisRegistry`. Every result and, after every step, every session snapshot must agree.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{
    T0, TestKey, TestResult, digest, fresh_namespace, kid, new_session, redis_registry, sid,
};
use proptest::prelude::*;
use session_core::{
    Candidate, CandidateBudget, ClaimError, IngressHint, ManualClock, MemoryRegistry,
    RegistryConfig, ResolutionStrategy, RoutePolicy, RouteToken, SessionSnapshot, SessionState,
    SessionStore,
};
use session_redis::KeyTable;

/// Session ids, routes and kids per case: small pools, so operations collide often.
const IDS: usize = 4;
const ROUTES: usize = 2;
const KIDS: usize = 2;
/// Operations per case.
const MAX_OPS: usize = 48;
/// TTLs are 1..=this many milliseconds, clock steps 0..=this, retention 0..=this.
const MAX_MILLIS: u64 = 1_000;
/// Cases per run: each case is a fresh Redis namespace and some hundred round trips.
const CASES: u32 = 64;
/// Bounded-trial budget used by resolves: below `IDS`, so over-budget refusals happen too.
const BUDGET: usize = 2;

#[derive(Debug, Clone)]
enum Op {
    Insert {
        id: usize,
        route: usize,
        kid: Option<usize>,
        ttl: u64,
    },
    Resolve {
        route: usize,
        kid: Option<usize>,
        strategy: u8,
    },
    Claim {
        id: usize,
        tag: u8,
    },
    Advance {
        millis: u64,
    },
    ExpireDue,
    Purge,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..IDS, 0..ROUTES, proptest::option::of(0..KIDS), 1..=MAX_MILLIS)
            .prop_map(|(id, route, kid, ttl)| Op::Insert { id, route, kid, ttl }),
        4 => (0..ROUTES, proptest::option::of(0..KIDS), 0..3u8)
            .prop_map(|(route, kid, strategy)| Op::Resolve { route, kid, strategy }),
        4 => (0..IDS, any::<u8>()).prop_map(|(id, tag)| Op::Claim { id, tag }),
        2 => (0..=MAX_MILLIS).prop_map(|millis| Op::Advance { millis }),
        1 => Just(Op::ExpireDue),
        1 => Just(Op::Purge),
    ]
}

#[derive(Debug, Clone)]
struct Case {
    shared: bool,
    max_pending: usize,
    retention: u64,
    ops: Vec<Op>,
}

fn case() -> impl Strategy<Value = Case> {
    (
        any::<bool>(),
        1..=IDS,
        0..=MAX_MILLIS,
        prop::collection::vec(op(), 1..=MAX_OPS),
    )
        .prop_map(|(shared, max_pending, retention, ops)| Case {
            shared,
            max_pending,
            retention,
            ops,
        })
}

/// What a candidate exposes, comparable across backends.
type CandidateView = (String, u64, u64, Option<String>, usize);

fn view(c: &Candidate<TestKey>) -> CandidateView {
    (
        c.id().as_str().to_owned(),
        c.revision().get(),
        c.expires_at().as_unix_millis(),
        c.kid().map(|k| k.as_str().to_owned()),
        c.key().0,
    )
}

/// What a snapshot exposes, comparable across backends.
fn snap_view(s: &SessionSnapshot<TestResult>) -> String {
    let state = match s.state() {
        SessionState::Pending => "pending".to_owned(),
        SessionState::Expired => "expired".to_owned(),
        SessionState::Consumed { result, digest } => format!("consumed {digest:?} {result}"),
    };
    format!(
        "{} rev={} exp={} kid={:?} route={} {:?} {state}",
        s.id().as_str(),
        s.revision().get(),
        s.expires_at().as_unix_millis(),
        s.kid(),
        s.route_token().to_url_segment(),
        s.binding(),
    )
}

fn claim_view(r: &Result<SessionSnapshot<TestResult>, ClaimError>) -> Result<String, ClaimError> {
    r.as_ref().map(snap_view).map_err(|e| *e)
}

async fn run_case(case: Case) -> Result<(), TestCaseError> {
    let config = RegistryConfig {
        max_pending: case.max_pending,
        consumed_retention: Duration::from_millis(case.retention),
        route_policy: if case.shared {
            RoutePolicy::Shared
        } else {
            RoutePolicy::UniquePerSession
        },
    };
    let clock = Arc::new(ManualClock::new(T0));
    let memory: MemoryRegistry<TestKey, TestResult> =
        MemoryRegistry::with_config(clock.clone(), config);
    let redis = redis_registry(&fresh_namespace(), clock.clone(), config, KeyTable::new()).await;
    let routes: Vec<RouteToken> = (0..ROUTES).map(|_| common::route()).collect();
    let budget = CandidateBudget::new(BUDGET).expect("budget");
    // Latest candidate per session id from each backend, taken from the same resolve.
    let mut held: HashMap<String, (Candidate<TestKey>, Candidate<TestKey>)> = HashMap::new();

    for op in case.ops {
        match op {
            Op::Insert {
                id,
                route,
                kid: k,
                ttl,
            } => {
                let mk = || {
                    let mut s = new_session(id, &routes[route], k.map(kid));
                    s.ttl = Duration::from_millis(ttl);
                    s
                };
                let m = SessionStore::insert(&memory, mk())
                    .await
                    .map(|s| snap_view(&s));
                let r = redis.insert(mk()).await.map(|s| snap_view(&s));
                prop_assert_eq!(m, r, "insert {}", id);
            }
            Op::Resolve {
                route,
                kid: k,
                strategy,
            } => {
                let hint = IngressHint::new(routes[route].clone(), k.map(kid));
                let strategy = match strategy {
                    0 => ResolutionStrategy::UniqueUri,
                    1 => ResolutionStrategy::UniqueKid,
                    _ => ResolutionStrategy::BoundedTrial(budget),
                };
                let m = SessionStore::resolve(&memory, &hint, strategy).await;
                let r = redis.resolve(&hint, strategy).await;
                let views = |x: &Result<Vec<Candidate<TestKey>>, _>| {
                    x.as_ref()
                        .map(|cs| cs.iter().map(view).collect::<Vec<_>>())
                        .map_err(|e| *e)
                };
                prop_assert_eq!(views(&m), views(&r), "resolve {:?}", strategy);
                if let (Ok(ms), Ok(rs)) = (m, r) {
                    for (mc, rc) in ms.into_iter().zip(rs) {
                        held.insert(mc.id().as_str().to_owned(), (mc, rc));
                    }
                }
            }
            Op::Claim { id, tag } => {
                let Some((mc, rc)) = held.get(sid(id).as_str()) else {
                    continue;
                };
                let result = format!("r{tag}");
                let d = digest(usize::from(tag));
                let m = SessionStore::claim(&memory, mc, d, result.clone()).await;
                let r = redis.claim(rc, d, result).await;
                prop_assert_eq!(claim_view(&m), claim_view(&r), "claim {}", id);
            }
            Op::Advance { millis } => clock.advance(Duration::from_millis(millis)),
            Op::ExpireDue => {
                let m = SessionStore::expire_due(&memory).await;
                prop_assert_eq!(m, redis.expire_due().await, "expire_due");
            }
            Op::Purge => {
                let m = SessionStore::purge(&memory).await;
                prop_assert_eq!(m, redis.purge().await, "purge");
            }
        }
        for i in 0..IDS {
            let m = SessionStore::snapshot(&memory, &sid(i))
                .await
                .map(|s| s.as_ref().map(snap_view));
            let r = redis
                .snapshot(&sid(i))
                .await
                .map(|s| s.as_ref().map(snap_view));
            prop_assert_eq!(m, r, "snapshot {}", i);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    #[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
    fn redis_matches_memory_registry_on_random_operation_sequences(case in case()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(run_case(case))?;
    }
}
