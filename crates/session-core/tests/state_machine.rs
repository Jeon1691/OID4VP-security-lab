//! Model-based property test of the MVP session state machine (Notion 02 §9, 06 §5).
//!
//! Random interleavings of claims (with right and wrong revisions), clock moves, expiry sweeps,
//! purges and resolves are applied both to the registry and to a tiny reference model. Every
//! outcome must match the model exactly, and no session may ever see a second successful commit.

mod common;

use std::time::Duration;

use common::{digest, new_session, registry, route, sid};
use proptest::prelude::*;
use session_core::{
    ClaimError, IngressHint, ResolutionStrategy, ResolveError, Revision, RouteToken, SessionState,
};

/// Up to this many sessions per case; small so ops collide on the same session often.
const MAX_SESSIONS: usize = 4;
/// Up to this many operations per case.
const MAX_OPS: usize = 64;
/// Session TTLs are drawn from 1..=this many milliseconds, and clock steps from 0..=this.
const MAX_MILLIS: u64 = 1_000;
/// Revisions drawn for claims: 0 (initial), 1 (after one transition) and 2 (never reached).
const MAX_REVISION: u64 = 2;

#[derive(Debug, Clone)]
enum Op {
    Claim {
        session: usize,
        revision: u64,
        tag: u8,
    },
    Advance {
        millis: u64,
    },
    ExpireDue,
    Purge,
    Resolve {
        session: usize,
    },
}

fn op(sessions: usize) -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..sessions, 0..=MAX_REVISION, any::<u8>())
            .prop_map(|(session, revision, tag)| Op::Claim { session, revision, tag }),
        2 => (0..=MAX_MILLIS).prop_map(|millis| Op::Advance { millis }),
        1 => Just(Op::ExpireDue),
        1 => Just(Op::Purge),
        2 => (0..sessions).prop_map(|session| Op::Resolve { session }),
    ]
}

fn case() -> impl Strategy<Value = (Vec<u64>, Vec<Op>)> {
    (1..=MAX_SESSIONS).prop_flat_map(|n| {
        (
            prop::collection::vec(1..=MAX_MILLIS, n),
            prop::collection::vec(op(n), 1..=MAX_OPS),
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelState {
    Pending,
    Consumed(u8),
    Expired,
    Purged,
}

#[derive(Debug)]
struct ModelSession {
    state: ModelState,
    revision: u64,
    expires_at: u64,
    commits: usize,
}

proptest! {
    #[test]
    fn at_most_one_successful_commit_per_session((ttls, ops) in case()) {
        let (clock, reg) = registry();
        let mut now = 0u64;
        let routes: Vec<RouteToken> = ttls.iter().map(|_| route()).collect();
        let mut model: Vec<ModelSession> = Vec::new();
        for (i, ttl) in ttls.iter().enumerate() {
            let mut s = new_session(i, &routes[i], None);
            s.ttl = Duration::from_millis(*ttl);
            reg.insert(s).expect("insert");
            model.push(ModelSession {
                state: ModelState::Pending,
                revision: Revision::INITIAL.get(),
                expires_at: now + ttl,
                commits: 0,
            });
        }

        for op in ops {
            match op {
                Op::Claim { session, revision, tag } => {
                    let m = &mut model[session];
                    let expected = match m.state {
                        ModelState::Purged => Err(ClaimError::UnknownSession),
                        ModelState::Consumed(t) => Err(ClaimError::Replay { same_response: t == tag }),
                        ModelState::Expired => Err(ClaimError::SessionExpired),
                        ModelState::Pending if now >= m.expires_at => {
                            m.state = ModelState::Expired;
                            m.revision += 1;
                            Err(ClaimError::SessionExpired)
                        }
                        ModelState::Pending if revision != m.revision => {
                            Err(ClaimError::RevisionMismatch {
                                expected: Revision::new(revision),
                                actual: Revision::new(m.revision),
                            })
                        }
                        ModelState::Pending => {
                            m.state = ModelState::Consumed(tag);
                            m.revision += 1;
                            m.commits += 1;
                            Ok(())
                        }
                    };
                    let actual = reg
                        .claim(&sid(session), Revision::new(revision), digest(tag), format!("r{tag}"))
                        .map(|_| ());
                    prop_assert_eq!(actual, expected);
                    prop_assert!(m.commits <= 1, "second commit on session {}", session);
                }
                Op::Advance { millis } => {
                    now += millis;
                    clock.advance(Duration::from_millis(millis));
                }
                Op::ExpireDue => {
                    let mut due = 0;
                    for m in &mut model {
                        if m.state == ModelState::Pending && now >= m.expires_at {
                            m.state = ModelState::Expired;
                            m.revision += 1;
                            due += 1;
                        }
                    }
                    prop_assert_eq!(reg.expire_due(), Ok(due));
                }
                Op::Purge => {
                    let mut purged = 0;
                    for m in &mut model {
                        if m.state == ModelState::Expired {
                            m.state = ModelState::Purged;
                            purged += 1;
                        }
                    }
                    prop_assert_eq!(reg.purge_expired(), Ok(purged));
                }
                Op::Resolve { session } => {
                    let m = &model[session];
                    let expected = match m.state {
                        ModelState::Purged => Err(ResolveError::NoCandidate),
                        ModelState::Consumed(_) => Err(ResolveError::Replay),
                        ModelState::Expired => Err(ResolveError::SessionExpired),
                        ModelState::Pending if now >= m.expires_at => Err(ResolveError::SessionExpired),
                        ModelState::Pending => Ok(vec![(sid(session), Revision::new(m.revision))]),
                    };
                    let actual = reg
                        .resolve(&IngressHint::new(routes[session].clone(), None), ResolutionStrategy::UniqueUri)
                        .map(|cs| cs.iter().map(|c| (c.id().clone(), c.revision())).collect::<Vec<_>>());
                    prop_assert_eq!(actual, expected);
                }
            }

            // The authoritative record agrees with the model after every step.
            for (i, m) in model.iter().enumerate() {
                let snap = reg.snapshot(&sid(i)).expect("store");
                match (m.state, snap) {
                    (ModelState::Purged, None) => {}
                    (state, Some(snap)) => {
                        prop_assert_eq!(snap.revision(), Revision::new(m.revision));
                        let same = match (state, snap.state()) {
                            (ModelState::Pending, SessionState::Pending)
                            | (ModelState::Expired, SessionState::Expired) => true,
                            (ModelState::Consumed(t), SessionState::Consumed { digest: d, .. }) => {
                                *d == digest(t)
                            }
                            _ => false,
                        };
                        prop_assert!(same, "session {} model {:?} vs {:?}", i, state, snap.state());
                    }
                    (state, None) => prop_assert!(false, "session {} missing, model {:?}", i, state),
                }
            }
        }
    }
}
