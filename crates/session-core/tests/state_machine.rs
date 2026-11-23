//! Model-based property test of the MVP session state machine (Notion 02 §9, 06 §5).
//!
//! Random interleavings of resolves, claims (with fresh and stale candidates), clock moves,
//! expiry sweeps, purges and re-inserts of purged ids are applied both to the registry and to a
//! tiny reference model. Every outcome must match the model exactly, and the registry must never
//! return a second successful commit for the same session.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::{TestKey, digest, new_session, registry_with, route, sid};
use proptest::prelude::*;
use session_core::{
    Candidate, ClaimError, IngressHint, InsertError, RegistryConfig, ResolutionStrategy,
    ResolveError, Revision, RouteToken, SessionState,
};

/// Up to this many session ids per case; small so ops collide on the same session often.
const MAX_SESSIONS: usize = 4;
/// Up to this many operations per case.
const MAX_OPS: usize = 64;
/// Session TTLs are drawn from 1..=this many milliseconds, and clock steps from 0..=this.
const MAX_MILLIS: u64 = 1_000;
/// Consumed-record retention for the property test: half the TTL range, so purges of consumed
/// sessions both happen and don't within one case.
const RETENTION_MILLIS: u64 = MAX_MILLIS / 2;

#[derive(Debug, Clone)]
enum Op {
    Resolve { session: usize },
    Claim { session: usize, tag: u8 },
    Advance { millis: u64 },
    ExpireDue,
    Purge,
    Reinsert { session: usize, ttl: u64 },
}

fn op(sessions: usize) -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..sessions).prop_map(|session| Op::Resolve { session }),
        4 => (0..sessions, any::<u8>()).prop_map(|(session, tag)| Op::Claim { session, tag }),
        2 => (0..=MAX_MILLIS).prop_map(|millis| Op::Advance { millis }),
        1 => Just(Op::ExpireDue),
        1 => Just(Op::Purge),
        1 => (0..sessions, 1..=MAX_MILLIS).prop_map(|(session, ttl)| Op::Reinsert { session, ttl }),
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
    incarnation: usize,
    route: RouteToken,
}

/// Candidate the caller holds for a session id, with the model's view of whom it names.
struct Held {
    candidate: Candidate<TestKey>,
    incarnation: usize,
    revision: u64,
}

proptest! {
    #[test]
    fn at_most_one_successful_commit_per_session((ttls, ops) in case()) {
        let (clock, reg) = registry_with(RegistryConfig {
            consumed_retention: Duration::from_millis(RETENTION_MILLIS),
            ..RegistryConfig::default()
        });
        let mut now = 0u64;
        let mut model: Vec<ModelSession> = Vec::new();
        for (i, ttl) in ttls.iter().enumerate() {
            let r = route();
            let mut s = new_session(i, &r, None);
            s.ttl = Duration::from_millis(*ttl);
            reg.insert(s).expect("insert");
            model.push(ModelSession {
                state: ModelState::Pending,
                revision: Revision::INITIAL.get(),
                expires_at: now + ttl,
                incarnation: 0,
                route: r,
            });
        }
        let mut held: Vec<Option<Held>> = model.iter().map(|_| None).collect();
        // Successful commits the registry actually returned, per (session id, incarnation).
        let mut commits: HashMap<(usize, usize), usize> = HashMap::new();

        for op in ops {
            match op {
                Op::Resolve { session } => {
                    let m = &model[session];
                    let expected = match m.state {
                        ModelState::Purged => Err(ResolveError::NoCandidate),
                        ModelState::Consumed(_) => Err(ResolveError::Replay),
                        ModelState::Expired => Err(ResolveError::SessionExpired),
                        ModelState::Pending if now >= m.expires_at => Err(ResolveError::SessionExpired),
                        ModelState::Pending => Ok(vec![(sid(session), Revision::new(m.revision))]),
                    };
                    let actual = reg.resolve(
                        &IngressHint::new(m.route.clone(), None),
                        ResolutionStrategy::UniqueUri,
                    );
                    let seen = actual
                        .as_ref()
                        .map(|cs| cs.iter().map(|c| (c.id().clone(), c.revision())).collect::<Vec<_>>())
                        .map_err(|e| *e);
                    prop_assert_eq!(seen, expected);
                    if let Ok(mut cs) = actual {
                        held[session] = Some(Held {
                            candidate: cs.remove(0),
                            incarnation: m.incarnation,
                            revision: m.revision,
                        });
                    }
                }
                Op::Claim { session, tag } => {
                    let Some(h) = &held[session] else { continue };
                    let m = &mut model[session];
                    let expected = match m.state {
                        ModelState::Purged => Err(ClaimError::UnknownSession),
                        _ if h.incarnation != m.incarnation => Err(ClaimError::UnknownSession),
                        ModelState::Consumed(t) => Err(ClaimError::Replay { same_response: t == tag }),
                        ModelState::Expired => Err(ClaimError::SessionExpired),
                        ModelState::Pending if now >= m.expires_at => {
                            m.state = ModelState::Expired;
                            m.revision += 1;
                            Err(ClaimError::SessionExpired)
                        }
                        ModelState::Pending if h.revision != m.revision => {
                            Err(ClaimError::RevisionMismatch {
                                expected: Revision::new(h.revision),
                                actual: Revision::new(m.revision),
                            })
                        }
                        ModelState::Pending => {
                            m.state = ModelState::Consumed(tag);
                            m.revision += 1;
                            Ok(())
                        }
                    };
                    let actual = reg
                        .claim(&h.candidate, digest(usize::from(tag)), format!("r{tag}"))
                        .map(|_| ());
                    if actual.is_ok() {
                        let n = commits.entry((session, m.incarnation)).or_default();
                        *n += 1;
                        prop_assert!(*n <= 1, "second commit on session {}", session);
                    }
                    prop_assert_eq!(actual, expected);
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
                        let gone = match m.state {
                            ModelState::Expired => true,
                            ModelState::Consumed(_) => now >= m.expires_at + RETENTION_MILLIS,
                            ModelState::Pending | ModelState::Purged => false,
                        };
                        if gone {
                            m.state = ModelState::Purged;
                            purged += 1;
                        }
                    }
                    prop_assert_eq!(reg.purge(), Ok(purged));
                }
                Op::Reinsert { session, ttl } => {
                    let r = route();
                    let mut s = new_session(session, &r, None);
                    s.ttl = Duration::from_millis(ttl);
                    let m = &mut model[session];
                    if m.state == ModelState::Purged {
                        reg.insert(s).expect("purged id can be reused");
                        *m = ModelSession {
                            state: ModelState::Pending,
                            revision: Revision::INITIAL.get(),
                            expires_at: now + ttl,
                            incarnation: m.incarnation + 1,
                            route: r,
                        };
                    } else {
                        prop_assert_eq!(reg.insert(s).map(|_| ()), Err(InsertError::DuplicateSession));
                    }
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
                                *d == digest(usize::from(t))
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
