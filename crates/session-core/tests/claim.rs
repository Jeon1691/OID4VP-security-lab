//! Atomic `Pending -> Consumed` commit (IMP-011, IMP-012): one successful claim per session
//! under any interleaving, replay and expiry rejection, and failed attempts leave no trace.

mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use common::{
    Registry, TTL, TestKey, TestResult, digest, kid, new_session, pending, registry, registry_with,
    route, sid,
};
use protocol_model::SessionId;
use session_core::{
    Candidate, ClaimError, DEFAULT_CONSUMED_RETENTION, IngressHint, InsertError, RegistryConfig,
    ResolutionStrategy, ResolveError, ResponseDigest, SessionSnapshot, SessionState, SessionStore,
};

/// Concurrent claimers per session (task matrix: 2, 16, 128).
const CONTENDERS: [usize; 3] = [2, 16, 128];
/// Independent sessions raced per contender count, to hit more interleavings per run.
const ROUNDS: usize = 16;

/// Counts successful commits; any loser must have seen the session already consumed.
fn tally<R>(outcomes: &[Result<SessionSnapshot<R>, ClaimError>]) -> usize {
    let mut wins = 0;
    for outcome in outcomes {
        match outcome {
            Ok(_) => wins += 1,
            Err(ClaimError::Replay { .. } | ClaimError::RevisionMismatch { .. }) => {}
            Err(other) => panic!("unexpected loser outcome: {other:?}"),
        }
    }
    wins
}

fn state(reg: &Registry, id: &SessionId) -> SessionState<TestResult> {
    reg.snapshot(id)
        .expect("store")
        .expect("present")
        .state()
        .clone()
}

#[test]
fn concurrent_claims_of_one_session_commit_exactly_once() {
    for n in CONTENDERS {
        for round in 0..ROUNDS {
            let (_clock, reg) = registry();
            let (_route, c) = pending(&reg, round);
            let barrier = Barrier::new(n);

            let outcomes: Vec<_> = thread::scope(|s| {
                let handles: Vec<_> = (0..n)
                    .map(|t| {
                        let (reg, barrier, c) = (&reg, &barrier, &c);
                        s.spawn(move || {
                            barrier.wait();
                            reg.claim(c, digest(t), format!("winner-{t}"))
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("claimer thread"))
                    .collect()
            });

            assert_eq!(tally(&outcomes), 1, "n={n} round={round}");
            assert!(state(&reg, c.id()).is_consumed());
        }
    }
}

/// Drives the claim through the async `SessionStore` trait the lab-server will use.
async fn claim_via_store<S>(
    store: Arc<S>,
    candidate: Arc<Candidate<TestKey>>,
    digest: ResponseDigest,
    result: TestResult,
    barrier: Arc<tokio::sync::Barrier>,
) -> Result<SessionSnapshot<TestResult>, ClaimError>
where
    S: SessionStore<TestKey, TestResult>,
{
    barrier.wait().await;
    store.claim(&candidate, digest, result).await
}

// 8 workers: real parallelism on CI runners; the attribute only takes a literal.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_async_claims_commit_exactly_once() {
    for n in CONTENDERS {
        for round in 0..ROUNDS {
            let (_clock, reg) = registry();
            let reg = Arc::new(reg);
            let (_route, c) = pending(&reg, round);
            let c = Arc::new(c);
            let barrier = Arc::new(tokio::sync::Barrier::new(n));

            let tasks: Vec<_> = (0..n)
                .map(|t| {
                    tokio::spawn(claim_via_store(
                        reg.clone(),
                        c.clone(),
                        digest(t),
                        format!("winner-{t}"),
                        barrier.clone(),
                    ))
                })
                .collect();
            let mut outcomes = Vec::with_capacity(n);
            for task in tasks {
                outcomes.push(task.await.expect("claim task"));
            }

            assert_eq!(tally(&outcomes), 1, "n={n} round={round}");
            assert!(state(&reg, c.id()).is_consumed());
        }
    }
}

#[tokio::test]
async fn dropped_claim_future_commits_nothing() {
    let (_clock, reg) = registry();
    let (_route, c) = pending(&reg, 0);

    // The trait futures are lazy: creating one and dropping it unpolled (a cancelled handler)
    // must not commit.
    let unpolled = SessionStore::claim(&reg, &c, digest(1), "never".into());
    drop(unpolled);
    assert!(state(&reg, c.id()).is_pending());

    SessionStore::claim(&reg, &c, digest(2), "ok".into())
        .await
        .expect("a polled claim commits");
    assert!(state(&reg, c.id()).is_consumed());
}

#[test]
fn sequential_replay_after_consume_is_rejected() {
    let (_clock, reg) = registry();
    let (_route, c) = pending(&reg, 0);
    let committed = reg
        .claim(&c, digest(1), "first".into())
        .expect("first claim");

    // Same response again, and a different response for the same session.
    assert_eq!(
        reg.claim(&c, digest(1), "again".into()).unwrap_err(),
        ClaimError::Replay {
            same_response: true
        }
    );
    assert_eq!(
        reg.claim(&c, digest(2), "other".into()).unwrap_err(),
        ClaimError::Replay {
            same_response: false
        }
    );

    // The first commit is what stays recorded.
    let snap = reg.snapshot(&sid(0)).expect("store").expect("present");
    match snap.state() {
        SessionState::Consumed { result, digest: d } => {
            assert_eq!(result.as_str(), "first");
            assert_eq!(*d, digest(1));
        }
        other => panic!("expected Consumed, got {other:?}"),
    }
    assert_eq!(snap.revision(), committed.revision());
}

#[test]
fn claim_after_expiry_is_rejected() {
    let (clock, reg) = registry();
    let (r, c) = pending(&reg, 0);

    // TTL elapses between resolve (and the caller's decrypt/validate) and the claim.
    clock.advance(TTL);
    assert_eq!(
        reg.claim(&c, digest(1), "late".into()).unwrap_err(),
        ClaimError::SessionExpired
    );
    assert!(state(&reg, c.id()).is_expired());
    assert_eq!(
        reg.resolve(&IngressHint::new(r, None), ResolutionStrategy::UniqueUri),
        Err(ResolveError::SessionExpired)
    );
}

#[test]
fn claim_just_before_expiry_succeeds() {
    let (clock, reg) = registry();
    let (_route, c) = pending(&reg, 0);
    clock.advance(TTL - Duration::from_millis(1));
    reg.claim(&c, digest(1), "in time".into())
        .expect("last millisecond is still valid");
}

#[test]
fn failed_attempt_leaves_session_pending_and_claimable() {
    // Pins the read-only contract of `resolve`: resolving hands out a candidate but reserves,
    // locks or bumps nothing, so a response that later fails decryption or validation (and is
    // therefore never claimed) leaves the session exactly as it was.
    let (_clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, Some(kid(0))))
        .expect("insert");
    let hint = IngressHint::new(r, Some(kid(0)));
    let before = reg
        .resolve(&hint, ResolutionStrategy::UniqueUri)
        .expect("resolve")
        .remove(0);

    // Decryption or presentation validation failed: the caller drops the candidate.
    drop(before.clone());
    let after = reg
        .resolve(&hint, ResolutionStrategy::UniqueUri)
        .expect("still resolvable");
    assert_eq!(after, vec![before.clone()]);
    let snap = reg.snapshot(&sid(0)).expect("store").expect("present");
    assert!(snap.state().is_pending());
    assert_eq!(snap.revision(), before.revision());

    reg.claim(&before, digest(1), "ok".into())
        .expect("a later valid response still commits");
}

#[test]
fn stale_candidate_cannot_claim_a_reinserted_session() {
    let (clock, reg) = registry();
    let (_route, stale) = pending(&reg, 0);
    clock.advance(TTL);
    assert_eq!(reg.expire_due(), Ok(1));
    assert_eq!(reg.purge(), Ok(1));

    // Same id, new session: a candidate from the old one must not commit it.
    let (_route, fresh) = pending(&reg, 0);
    assert_eq!(
        reg.claim(&stale, digest(1), "stale".into()).unwrap_err(),
        ClaimError::UnknownSession
    );
    assert!(state(&reg, fresh.id()).is_pending());
    reg.claim(&fresh, digest(2), "ok".into())
        .expect("fresh claim");
}

#[test]
fn claim_of_unknown_session_is_rejected() {
    let (_clock, reg) = registry();
    let (_route, c) = pending(&reg, 0);
    let (_clock, other) = registry();
    // A candidate from another registry names a session this one never had.
    assert_eq!(
        other.claim(&c, digest(1), "x".into()).unwrap_err(),
        ClaimError::UnknownSession
    );
}

#[test]
fn expire_and_purge_touch_only_due_sessions() {
    let (clock, reg) = registry();
    let (_r0, _c0) = pending(&reg, 0);
    let (_r1, c1) = pending(&reg, 1);
    reg.claim(&c1, digest(1), "ok".into()).expect("claim");
    clock.advance(TTL / 2);
    let (_r2, _c2) = pending(&reg, 2);
    clock.advance(TTL / 2);

    // Session 0 is due; 1 is Consumed and inside its retention window; 2 has half its TTL left.
    assert_eq!(reg.expire_due(), Ok(1));
    assert_eq!(reg.expire_due(), Ok(0), "idempotent");
    assert_eq!(reg.purge(), Ok(1));
    assert!(reg.snapshot(&sid(0)).expect("store").is_none());
    assert!(state(&reg, &sid(1)).is_consumed());
    assert!(state(&reg, &sid(2)).is_pending());
}

#[test]
fn consumed_records_are_purged_after_retention() {
    let (clock, reg) = registry();
    let (r, c) = pending(&reg, 0);
    reg.claim(&c, digest(1), "ok".into()).expect("claim");
    let hint = IngressHint::new(r, None);

    // Inside expires_at + retention the replay is still reported as such.
    clock.advance(TTL + DEFAULT_CONSUMED_RETENTION - Duration::from_millis(1));
    assert_eq!(reg.purge(), Ok(0));
    assert_eq!(
        reg.resolve(&hint, ResolutionStrategy::UniqueUri),
        Err(ResolveError::Replay)
    );

    // After it the record is gone: a replay is still refused, but only as an unknown route.
    clock.advance(Duration::from_millis(1));
    assert_eq!(reg.purge(), Ok(1));
    assert_eq!(
        reg.resolve(&hint, ResolutionStrategy::UniqueUri),
        Err(ResolveError::NoCandidate)
    );
    assert_eq!(
        reg.claim(&c, digest(1), "again".into()).unwrap_err(),
        ClaimError::UnknownSession
    );
}

#[test]
fn insert_beyond_pending_capacity_is_rejected() {
    const LIMIT: usize = 2;
    let (clock, reg) = registry_with(RegistryConfig {
        max_pending: LIMIT,
        ..RegistryConfig::default()
    });
    let (_r0, c0) = pending(&reg, 0);
    let (_r1, _c1) = pending(&reg, 1);
    assert_eq!(
        reg.insert(new_session(2, &route(), None)).unwrap_err(),
        InsertError::Capacity { limit: LIMIT }
    );

    // A consumed session frees its slot.
    reg.claim(&c0, digest(1), "ok".into()).expect("claim");
    let (_r2, _c2) = pending(&reg, 2);
    assert_eq!(
        reg.insert(new_session(3, &route(), None)).unwrap_err(),
        InsertError::Capacity { limit: LIMIT }
    );

    // Sessions past their TTL are expired on the spot instead of holding slots until a sweep.
    clock.advance(TTL);
    let (_r3, _c3) = pending(&reg, 3);
    assert!(state(&reg, &sid(1)).is_expired());
}

#[test]
fn unique_route_policy_rejects_duplicate_route_token() {
    let (_clock, reg) = registry();
    let (r, c) = pending(&reg, 0);
    assert_eq!(
        reg.insert(new_session(1, &r, None)).unwrap_err(),
        InsertError::DuplicateRoute
    );
    // Also once the first session is consumed: reusing its route would send replays of the
    // old response to the new session.
    reg.claim(&c, digest(1), "ok".into()).expect("claim");
    assert_eq!(
        reg.insert(new_session(1, &r, None)).unwrap_err(),
        InsertError::DuplicateRoute
    );
}

#[test]
fn insert_rejects_duplicate_id_and_zero_ttl() {
    let (_clock, reg) = registry();
    let (_r, _c) = pending(&reg, 0);
    assert_eq!(
        reg.insert(new_session(0, &route(), None)).unwrap_err(),
        InsertError::DuplicateSession
    );
    let mut zero = new_session(1, &route(), None);
    zero.ttl = Duration::ZERO;
    assert_eq!(reg.insert(zero).unwrap_err(), InsertError::ZeroTtl);
}
