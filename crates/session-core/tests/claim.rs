//! Atomic `Pending -> Consumed` commit (IMP-011, IMP-012): one successful claim per session
//! under any interleaving, replay and expiry rejection, and failed attempts leave no trace.

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use common::{Registry, TTL, TestKey, TestResult, digest, kid, new_session, registry, route, sid};
use protocol_model::SessionId;
use session_core::{
    ClaimError, IngressHint, InsertError, ResolutionStrategy, ResolveError, ResponseDigest,
    Revision, SessionState, SessionStore,
};

/// Concurrent claimers per session (task matrix: 2, 16, 128).
const CONTENDERS: [usize; 3] = [2, 16, 128];
/// Independent sessions raced per contender count, to hit more interleavings per run.
const ROUNDS: usize = 16;

/// One claim attempt's outcome, reduced to what the exactly-once check counts.
fn tally<R>(outcomes: &[Result<session_core::SessionSnapshot<R>, ClaimError>]) -> usize {
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

fn assert_consumed_once(reg: &Registry, id: &SessionId) {
    let snap = reg.snapshot(id).expect("store").expect("present");
    match snap.state() {
        SessionState::Consumed { .. } => {}
        other => panic!("expected Consumed, got {other:?}"),
    }
}

#[test]
fn concurrent_claims_of_one_session_commit_exactly_once() {
    for n in CONTENDERS {
        for round in 0..ROUNDS {
            let (_clock, reg) = registry();
            let r = route();
            reg.insert(new_session(round, &r, None)).expect("insert");
            let candidate = reg
                .resolve(&IngressHint::new(r, None), ResolutionStrategy::UniqueUri)
                .expect("resolve")
                .remove(0);
            let barrier = Barrier::new(n);

            let outcomes: Vec<_> = thread::scope(|s| {
                let handles: Vec<_> = (0..n)
                    .map(|t| {
                        let (reg, barrier, candidate) = (&reg, &barrier, &candidate);
                        s.spawn(move || {
                            barrier.wait();
                            reg.claim(
                                candidate.id(),
                                candidate.revision(),
                                digest(u8::try_from(t % 256).expect("fits")),
                                format!("winner-{t}"),
                            )
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("claimer thread"))
                    .collect()
            });

            assert_eq!(tally(&outcomes), 1, "n={n} round={round}");
            assert_consumed_once(&reg, candidate.id());
        }
    }
}

/// Drives the claim through the async `SessionStore` trait the lab-server will use.
async fn claim_via_store<S>(
    store: Arc<S>,
    id: SessionId,
    revision: Revision,
    digest: ResponseDigest,
    result: TestResult,
    barrier: Arc<tokio::sync::Barrier>,
) -> Result<session_core::SessionSnapshot<TestResult>, ClaimError>
where
    S: SessionStore<TestKey, TestResult>,
{
    barrier.wait().await;
    store.claim(&id, revision, digest, result).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_async_claims_commit_exactly_once() {
    for n in CONTENDERS {
        let (_clock, reg) = registry();
        let reg = Arc::new(reg);
        let r = route();
        reg.insert(new_session(0, &r, None)).expect("insert");
        let barrier = Arc::new(tokio::sync::Barrier::new(n));

        let tasks: Vec<_> = (0..n)
            .map(|t| {
                tokio::spawn(claim_via_store(
                    reg.clone(),
                    sid(0),
                    Revision::INITIAL,
                    digest(u8::try_from(t % 256).expect("fits")),
                    format!("winner-{t}"),
                    barrier.clone(),
                ))
            })
            .collect();
        let mut outcomes = Vec::with_capacity(n);
        for task in tasks {
            outcomes.push(task.await.expect("claim task"));
        }

        assert_eq!(tally(&outcomes), 1, "n={n}");
        assert_consumed_once(&reg, &sid(0));
    }
}

#[test]
fn sequential_replay_after_consume_is_rejected() {
    let (_clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, None)).expect("insert");
    let committed = reg
        .claim(&sid(0), Revision::INITIAL, digest(1), "first".into())
        .expect("first claim");

    // Same response again, and a different response with the stale and the current revision.
    assert_eq!(
        reg.claim(&sid(0), Revision::INITIAL, digest(1), "again".into())
            .unwrap_err(),
        ClaimError::Replay {
            same_response: true
        }
    );
    assert_eq!(
        reg.claim(&sid(0), Revision::INITIAL, digest(2), "other".into())
            .unwrap_err(),
        ClaimError::Replay {
            same_response: false
        }
    );
    assert_eq!(
        reg.claim(&sid(0), committed.revision(), digest(2), "other".into())
            .unwrap_err(),
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
    let r = route();
    reg.insert(new_session(0, &r, None)).expect("insert");
    let candidate = reg
        .resolve(
            &IngressHint::new(r.clone(), None),
            ResolutionStrategy::UniqueUri,
        )
        .expect("resolve")
        .remove(0);

    // TTL elapses between resolve (and the caller's decrypt/validate) and the claim.
    clock.advance(TTL);
    assert_eq!(
        reg.claim(
            candidate.id(),
            candidate.revision(),
            digest(1),
            "late".into()
        )
        .unwrap_err(),
        ClaimError::SessionExpired
    );
    let snap = reg.snapshot(&sid(0)).expect("store").expect("present");
    assert!(snap.state().is_expired());
    assert_eq!(
        reg.resolve(&IngressHint::new(r, None), ResolutionStrategy::UniqueUri),
        Err(ResolveError::SessionExpired)
    );
}

#[test]
fn claim_just_before_expiry_succeeds() {
    let (clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, None)).expect("insert");
    clock.advance(TTL - std::time::Duration::from_millis(1));
    reg.claim(&sid(0), Revision::INITIAL, digest(1), "in time".into())
        .expect("last millisecond is still valid");
}

#[test]
fn failed_attempt_leaves_session_pending_and_claimable() {
    let (_clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, Some(kid(0))))
        .expect("insert");
    let hint = IngressHint::new(r, Some(kid(0)));
    let before = reg
        .resolve(&hint, ResolutionStrategy::UniqueUri)
        .expect("resolve")
        .remove(0);

    // Decryption or presentation validation failed: the caller drops the candidate and never
    // claims. Nothing about the session may change.
    drop(before.clone());
    let after = reg
        .resolve(&hint, ResolutionStrategy::UniqueUri)
        .expect("still resolvable");
    assert_eq!(after, vec![before.clone()]);
    let snap = reg.snapshot(&sid(0)).expect("store").expect("present");
    assert!(snap.state().is_pending());
    assert_eq!(snap.revision(), before.revision());

    reg.claim(before.id(), before.revision(), digest(1), "ok".into())
        .expect("a later valid response still commits");
}

#[test]
fn wrong_revision_is_rejected_without_consuming() {
    let (_clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, None)).expect("insert");
    let wrong = Revision::new(Revision::INITIAL.get() + 1);

    assert_eq!(
        reg.claim(&sid(0), wrong, digest(1), "bad".into())
            .unwrap_err(),
        ClaimError::RevisionMismatch {
            expected: wrong,
            actual: Revision::INITIAL
        }
    );
    let snap = reg.snapshot(&sid(0)).expect("store").expect("present");
    assert!(snap.state().is_pending());
    assert_eq!(snap.revision(), Revision::INITIAL);
    reg.claim(&sid(0), Revision::INITIAL, digest(1), "ok".into())
        .expect("correct revision still commits");
}

#[test]
fn claim_of_unknown_session_is_rejected() {
    let (_clock, reg) = registry();
    assert_eq!(
        reg.claim(&sid(0), Revision::INITIAL, digest(1), "x".into())
            .unwrap_err(),
        ClaimError::UnknownSession
    );
}

#[test]
fn expire_and_purge_touch_only_due_sessions() {
    let (clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, None)).expect("insert");
    reg.insert(new_session(1, &r, None)).expect("insert");
    reg.claim(&sid(1), Revision::INITIAL, digest(1), "ok".into())
        .expect("claim");
    clock.advance(TTL / 2);
    reg.insert(new_session(2, &r, None)).expect("insert");
    clock.advance(TTL / 2);

    // Session 0 is due; 1 is Consumed (kept as replay evidence); 2 has half its TTL left.
    assert_eq!(reg.expire_due(), Ok(1));
    assert_eq!(reg.expire_due(), Ok(0), "idempotent");
    assert_eq!(reg.purge_expired(), Ok(1));
    assert!(reg.snapshot(&sid(0)).expect("store").is_none());
    assert!(
        reg.snapshot(&sid(1))
            .expect("store")
            .expect("kept")
            .state()
            .is_consumed()
    );
    assert!(
        reg.snapshot(&sid(2))
            .expect("store")
            .expect("kept")
            .state()
            .is_pending()
    );
}

#[test]
fn insert_rejects_duplicate_id_and_zero_ttl() {
    let (_clock, reg) = registry();
    let r = route();
    reg.insert(new_session(0, &r, None)).expect("insert");
    assert_eq!(
        reg.insert(new_session(0, &route(), None)).unwrap_err(),
        InsertError::DuplicateSession
    );
    let mut zero = new_session(1, &r, None);
    zero.ttl = std::time::Duration::ZERO;
    assert_eq!(reg.insert(zero).unwrap_err(), InsertError::ZeroTtl);
}
