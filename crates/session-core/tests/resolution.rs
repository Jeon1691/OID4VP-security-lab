//! Candidate resolution strategies (IMP-007): which sessions an untrusted ingress hint may be
//! trial-decrypted against, decided before any decryption.

mod common;

use common::{
    Registry, SCALES, TTL, TestKey, candidate, digest, kid, new_session, registry, route,
    shared_registry, sid,
};
use protocol_model::SessionId;
use session_core::{
    BudgetError, Candidate, CandidateBudget, IngressHint, MAX_CANDIDATE_BUDGET, ResolutionStrategy,
    ResolveError, Revision,
};

fn budget(n: usize) -> CandidateBudget {
    CandidateBudget::new(n).expect("budget within range")
}

fn ids<K>(candidates: &[Candidate<K>]) -> Vec<SessionId> {
    candidates.iter().map(|c| c.id().clone()).collect()
}

/// Claims every candidate (as if each response had validated).
fn consume_all(reg: &Registry, candidates: &[Candidate<TestKey>]) {
    for (n, c) in candidates.iter().enumerate() {
        reg.claim(c, digest(n), "ok".into()).expect("claim");
    }
}

#[test]
fn unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid() {
    for n in SCALES {
        let (_clock, reg) = registry();
        let shared_kid = kid(0);
        let routes: Vec<_> = (0..n).map(|_| route()).collect();
        for (i, r) in routes.iter().enumerate() {
            reg.insert(new_session(i, r, Some(shared_kid.clone())))
                .expect("insert");
        }
        for (i, r) in routes.iter().enumerate() {
            let hint = IngressHint::new(r.clone(), Some(shared_kid.clone()));
            let found = reg
                .resolve(&hint, ResolutionStrategy::UniqueUri)
                .expect("unique-uri resolves");
            assert_eq!(ids(&found), vec![sid(i)], "n={n} i={i}");
            assert_eq!(found[0].key().0, i, "candidate carries its own key");
        }
    }
}

#[test]
fn unique_kid_yields_exactly_one_candidate_among_sessions_sharing_route() {
    for n in SCALES {
        let (_clock, reg) = shared_registry();
        let shared_route = route();
        for i in 0..n {
            reg.insert(new_session(i, &shared_route, Some(kid(i))))
                .expect("insert");
        }
        for i in 0..n {
            let hint = IngressHint::new(shared_route.clone(), Some(kid(i)));
            let found = reg
                .resolve(&hint, ResolutionStrategy::UniqueKid)
                .expect("unique-kid resolves");
            assert_eq!(ids(&found), vec![sid(i)], "n={n} i={i}");
        }
    }
}

#[test]
fn bounded_trial_returns_all_candidates_within_budget() {
    for n in SCALES {
        let (_clock, reg) = shared_registry();
        let shared_route = route();
        let shared_kid = kid(0);
        for i in 0..n {
            reg.insert(new_session(i, &shared_route, Some(shared_kid.clone())))
                .expect("insert");
        }
        let hint = IngressHint::new(shared_route.clone(), Some(shared_kid.clone()));
        let expected: Vec<_> = (0..n).map(sid).collect();

        // Budget exactly N and budget above N both return every live session, in insertion order.
        for b in [n, n + 1] {
            let found = reg
                .resolve(&hint, ResolutionStrategy::BoundedTrial(budget(b)))
                .expect("within budget");
            assert_eq!(ids(&found), expected, "n={n} budget={b}");
        }
    }
}

#[test]
fn bounded_trial_rejects_more_candidates_than_budget() {
    for n in SCALES.into_iter().filter(|&n| n > 1) {
        let (_clock, reg) = shared_registry();
        let shared_route = route();
        let shared_kid = kid(0);
        for i in 0..n {
            reg.insert(new_session(i, &shared_route, Some(shared_kid.clone())))
                .expect("insert");
        }
        let hint = IngressHint::new(shared_route.clone(), Some(shared_kid.clone()));
        let b = n - 1;
        // Never a silent truncation to the first `b` sessions: the whole request is refused.
        assert_eq!(
            reg.resolve(&hint, ResolutionStrategy::BoundedTrial(budget(b))),
            Err(ResolveError::CandidateBudgetExceeded {
                found: n,
                budget: b
            }),
            "n={n}"
        );
    }
}

#[test]
fn bounded_trial_budget_counts_only_live_sessions() {
    const SESSIONS: usize = 10;
    const CONSUMED: usize = 5;
    let (_clock, reg) = shared_registry();
    let shared_route = route();
    let shared_kid = kid(0);
    for i in 0..SESSIONS {
        reg.insert(new_session(i, &shared_route, Some(shared_kid.clone())))
            .expect("insert");
    }
    let hint = IngressHint::new(shared_route, Some(shared_kid));
    let all = reg
        .resolve(&hint, ResolutionStrategy::BoundedTrial(budget(SESSIONS)))
        .expect("resolve");
    consume_all(&reg, &all[..CONSUMED]);
    let found = reg
        .resolve(
            &hint,
            ResolutionStrategy::BoundedTrial(budget(SESSIONS - CONSUMED)),
        )
        .expect("only the pending half counts against the budget");
    assert_eq!(
        ids(&found),
        (CONSUMED..SESSIONS).map(sid).collect::<Vec<_>>()
    );
}

#[test]
fn expired_sessions_are_never_candidates() {
    let (clock, reg) = shared_registry();
    let unique_route = route();
    let shared_route = route();
    reg.insert(new_session(0, &unique_route, Some(kid(0))))
        .expect("insert");
    reg.insert(new_session(1, &shared_route, Some(kid(1))))
        .expect("insert");
    reg.insert(new_session(2, &shared_route, Some(kid(1))))
        .expect("insert");

    // Expiry is judged by the clock at resolve time, before any sweep has run.
    clock.advance(TTL);

    assert_eq!(
        reg.resolve(
            &IngressHint::new(unique_route.clone(), Some(kid(0))),
            ResolutionStrategy::UniqueUri
        ),
        Err(ResolveError::SessionExpired)
    );
    assert_eq!(
        reg.resolve(
            &IngressHint::new(shared_route.clone(), Some(kid(1))),
            ResolutionStrategy::BoundedTrial(budget(2))
        ),
        Err(ResolveError::SessionExpired)
    );

    // Same after the sweep has moved them to Expired.
    assert_eq!(reg.expire_due(), Ok(3));
    assert_eq!(
        reg.resolve(
            &IngressHint::new(unique_route, Some(kid(0))),
            ResolutionStrategy::UniqueKid
        ),
        Err(ResolveError::SessionExpired)
    );
    assert_eq!(
        reg.resolve(
            &IngressHint::new(shared_route, None),
            ResolutionStrategy::BoundedTrial(budget(2))
        ),
        Err(ResolveError::SessionExpired)
    );
}

#[test]
fn consumed_sessions_are_never_candidates() {
    let (_clock, reg) = shared_registry();
    let unique_route = route();
    let shared_route = route();
    reg.insert(new_session(0, &unique_route, Some(kid(0))))
        .expect("insert");
    reg.insert(new_session(1, &shared_route, Some(kid(1))))
        .expect("insert");
    reg.insert(new_session(2, &shared_route, Some(kid(1))))
        .expect("insert");
    consume_all(&reg, &[candidate(&reg, &unique_route)]);
    let shared = reg
        .resolve(
            &IngressHint::new(shared_route.clone(), Some(kid(1))),
            ResolutionStrategy::BoundedTrial(budget(2)),
        )
        .expect("resolve");
    consume_all(&reg, &shared);

    assert_eq!(
        reg.resolve(
            &IngressHint::new(unique_route.clone(), Some(kid(0))),
            ResolutionStrategy::UniqueUri
        ),
        Err(ResolveError::Replay)
    );
    assert_eq!(
        reg.resolve(
            &IngressHint::new(unique_route, Some(kid(0))),
            ResolutionStrategy::UniqueKid
        ),
        Err(ResolveError::Replay)
    );
    assert_eq!(
        reg.resolve(
            &IngressHint::new(shared_route, Some(kid(1))),
            ResolutionStrategy::BoundedTrial(budget(2))
        ),
        Err(ResolveError::Replay),
        "bounded trial reports the replay too (research evidence)"
    );
}

#[test]
fn unknown_route_token_or_kid_yields_no_candidate() {
    let (_clock, reg) = registry();
    let known_route = route();
    reg.insert(new_session(0, &known_route, Some(kid(0))))
        .expect("insert");
    let strategies = [
        ResolutionStrategy::UniqueUri,
        ResolutionStrategy::UniqueKid,
        ResolutionStrategy::BoundedTrial(budget(1)),
    ];

    for strategy in strategies {
        let unknown_route = IngressHint::new(route(), Some(kid(0)));
        assert_eq!(
            reg.resolve(&unknown_route, strategy),
            Err(ResolveError::NoCandidate),
            "{strategy:?} unknown route"
        );
    }
    // A kid no session holds: every strategy filters on a kid the hint carries.
    let unknown_kid = IngressHint::new(known_route.clone(), Some(kid(99)));
    for strategy in strategies {
        assert_eq!(
            reg.resolve(&unknown_kid, strategy),
            Err(ResolveError::NoCandidate),
            "{strategy:?} unknown kid"
        );
    }
    // unique-kid cannot pick a session without a kid hint.
    assert_eq!(
        reg.resolve(
            &IngressHint::new(known_route, None),
            ResolutionStrategy::UniqueKid
        ),
        Err(ResolveError::MissingKid)
    );
}

#[test]
fn unique_strategy_refuses_an_ambiguous_hint() {
    let (_clock, reg) = shared_registry();
    let shared_route = route();
    let shared_kid = kid(0);
    reg.insert(new_session(0, &shared_route, Some(shared_kid.clone())))
        .expect("insert");
    reg.insert(new_session(1, &shared_route, Some(shared_kid.clone())))
        .expect("insert");
    let hint = IngressHint::new(shared_route, Some(shared_kid));

    // Deployment violated the uniqueness the strategy relies on: fail, never pick one.
    for strategy in [ResolutionStrategy::UniqueUri, ResolutionStrategy::UniqueKid] {
        assert_eq!(
            reg.resolve(&hint, strategy),
            Err(ResolveError::NotUnique { found: 2 }),
            "{strategy:?}"
        );
    }
}

#[test]
fn candidate_budget_rejects_zero_and_values_above_maximum() {
    assert_eq!(CandidateBudget::new(0), Err(BudgetError::Zero));
    assert_eq!(
        CandidateBudget::new(MAX_CANDIDATE_BUDGET + 1),
        Err(BudgetError::AboveMaximum {
            requested: MAX_CANDIDATE_BUDGET + 1,
            maximum: MAX_CANDIDATE_BUDGET
        })
    );
    assert_eq!(budget(MAX_CANDIDATE_BUDGET).get(), MAX_CANDIDATE_BUDGET);
    assert!(
        MAX_CANDIDATE_BUDGET >= SCALES[SCALES.len() - 1],
        "largest scale must fit"
    );
}

#[test]
fn snapshots_are_point_in_time_copies() {
    let (_clock, reg) = registry();
    let r = route();
    let inserted = reg.insert(new_session(0, &r, None)).expect("insert");
    let candidate = candidate(&reg, &r);

    reg.claim(&candidate, digest(1), "ok".into())
        .expect("claim");

    // Values handed out earlier do not follow (or allow) changes to the authoritative record.
    assert!(inserted.state().is_pending());
    assert_eq!(candidate.revision(), Revision::INITIAL);
    let now = reg.snapshot(&sid(0)).expect("store").expect("present");
    assert!(now.state().is_consumed());
    assert_ne!(now.revision(), Revision::INITIAL);
}

#[test]
fn unique_uri_checks_route_uniqueness_before_kid() {
    let (_clock, reg) = shared_registry();
    let shared_route = route();
    reg.insert(new_session(0, &shared_route, Some(kid(0))))
        .expect("insert");
    reg.insert(new_session(1, &shared_route, Some(kid(1))))
        .expect("insert");

    // The attacker picks the JWE kid. Filtering on it first would make the duplicated route
    // look unique (one match per kid) and hide the deployment bug.
    for k in [Some(kid(0)), Some(kid(1)), Some(kid(99)), None] {
        assert_eq!(
            reg.resolve(
                &IngressHint::new(shared_route.clone(), k.clone()),
                ResolutionStrategy::UniqueUri
            ),
            Err(ResolveError::NotUnique { found: 2 }),
            "kid hint {k:?}"
        );
    }
}

#[test]
fn unique_kid_checks_kid_uniqueness_before_route() {
    let (_clock, reg) = shared_registry();
    let (route_a, route_b) = (route(), route());
    reg.insert(new_session(0, &route_a, Some(kid(0))))
        .expect("insert");
    reg.insert(new_session(1, &route_b, Some(kid(0))))
        .expect("insert");

    // The route segment is attacker-chosen as well; a duplicated kid is refused on any route.
    for r in [route_a, route_b, route()] {
        assert_eq!(
            reg.resolve(
                &IngressHint::new(r, Some(kid(0))),
                ResolutionStrategy::UniqueKid
            ),
            Err(ResolveError::NotUnique { found: 2 })
        );
    }
}
