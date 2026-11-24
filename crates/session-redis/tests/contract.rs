//! The `SessionStore` contract, run against both backends: `memory::*` (default test stage)
//! and `redis::*` (ignored there; the `redis` gate stage runs them against a real server).
//! Same tests, same expectations: the Redis registry must be indistinguishable from the
//! in-memory one (resolution strategies, exactly-once claim, replay, expiry, capacity,
//! retention).

mod common;

/// Generic test bodies; each takes the backend as a type parameter.
mod suite {
    use std::sync::Arc;
    use std::time::Duration;

    use protocol_model::SessionId;
    use session_core::{
        Candidate, CandidateBudget, ClaimError, DEFAULT_CONSUMED_RETENTION, IngressHint,
        InsertError, NewSession, RegistryConfig, ResolutionStrategy, ResolveError, ResponseDigest,
        Revision, SessionSnapshot, SessionState, SessionStore,
    };

    use crate::common::{
        Backend, SCALES, TTL, TestKey, TestResult, candidate, dc_api_binding, digest, kid,
        new_session, pending, route, shared, sid, state,
    };

    /// Concurrent claimers per session (task matrix: 2, 16, 128).
    const CONTENDERS: [usize; 3] = [2, 16, 128];
    /// Independent sessions raced per contender count.
    const ROUNDS: usize = 4;

    fn budget(n: usize) -> CandidateBudget {
        CandidateBudget::new(n).expect("budget within range")
    }

    fn ids<K>(candidates: &[Candidate<K>]) -> Vec<SessionId> {
        candidates.iter().map(|c| c.id().clone()).collect()
    }

    async fn consume_all<S: SessionStore<TestKey, TestResult>>(
        store: &S,
        candidates: &[Candidate<TestKey>],
    ) {
        for (n, c) in candidates.iter().enumerate() {
            store.claim(c, digest(n), "ok".into()).await.expect("claim");
        }
    }

    /// Counts successful commits; every loser must have seen the session already consumed.
    pub fn tally<R>(outcomes: &[Result<SessionSnapshot<R>, ClaimError>]) -> usize {
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

    pub async fn unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid<B: Backend>() {
        for n in SCALES {
            let h = B::make(RegistryConfig::default()).await;
            let shared_kid = kid(0);
            let routes: Vec<_> = (0..n).map(|_| route()).collect();
            for (i, r) in routes.iter().enumerate() {
                h.store
                    .insert(new_session(i, r, Some(shared_kid.clone())))
                    .await
                    .expect("insert");
            }
            for (i, r) in routes.iter().enumerate() {
                let hint = IngressHint::new(r.clone(), Some(shared_kid.clone()));
                let found = h
                    .store
                    .resolve(&hint, ResolutionStrategy::UniqueUri)
                    .await
                    .expect("unique-uri resolves");
                assert_eq!(ids(&found), vec![sid(i)], "n={n} i={i}");
                assert_eq!(found[0].key().0, i, "candidate carries its own key");
            }
        }
    }

    pub async fn unique_kid_yields_exactly_one_candidate_among_sessions_sharing_route<
        B: Backend,
    >() {
        for n in SCALES {
            let h = B::make(shared()).await;
            let shared_route = route();
            for i in 0..n {
                h.store
                    .insert(new_session(i, &shared_route, Some(kid(i))))
                    .await
                    .expect("insert");
            }
            for i in 0..n {
                let hint = IngressHint::new(shared_route.clone(), Some(kid(i)));
                let found = h
                    .store
                    .resolve(&hint, ResolutionStrategy::UniqueKid)
                    .await
                    .expect("unique-kid resolves");
                assert_eq!(ids(&found), vec![sid(i)], "n={n} i={i}");
                assert_eq!(found[0].key().0, i);
            }
        }
    }

    pub async fn bounded_trial_returns_all_candidates_within_budget<B: Backend>() {
        for n in SCALES {
            let h = B::make(shared()).await;
            let shared_route = route();
            for i in 0..n {
                h.store
                    .insert(new_session(i, &shared_route, Some(kid(0))))
                    .await
                    .expect("insert");
            }
            let hint = IngressHint::new(shared_route.clone(), Some(kid(0)));
            let expected: Vec<_> = (0..n).map(sid).collect();
            // Budget exactly N and above N both return every live session, in insertion order.
            for b in [n, n + 1] {
                let found = h
                    .store
                    .resolve(&hint, ResolutionStrategy::BoundedTrial(budget(b)))
                    .await
                    .expect("within budget");
                assert_eq!(ids(&found), expected, "n={n} budget={b}");
            }
        }
    }

    pub async fn bounded_trial_rejects_more_candidates_than_budget<B: Backend>() {
        for n in SCALES.into_iter().filter(|&n| n > 1) {
            let h = B::make(shared()).await;
            let shared_route = route();
            for i in 0..n {
                h.store
                    .insert(new_session(i, &shared_route, Some(kid(0))))
                    .await
                    .expect("insert");
            }
            let hint = IngressHint::new(shared_route.clone(), Some(kid(0)));
            let b = n - 1;
            assert_eq!(
                h.store
                    .resolve(&hint, ResolutionStrategy::BoundedTrial(budget(b)))
                    .await,
                Err(ResolveError::CandidateBudgetExceeded {
                    found: n,
                    budget: b
                }),
                "n={n}"
            );
        }
    }

    pub async fn bounded_trial_budget_counts_only_live_sessions<B: Backend>() {
        const SESSIONS: usize = 10;
        const CONSUMED: usize = 5;
        let h = B::make(shared()).await;
        let shared_route = route();
        for i in 0..SESSIONS {
            h.store
                .insert(new_session(i, &shared_route, Some(kid(0))))
                .await
                .expect("insert");
        }
        let hint = IngressHint::new(shared_route, Some(kid(0)));
        let all = h
            .store
            .resolve(&hint, ResolutionStrategy::BoundedTrial(budget(SESSIONS)))
            .await
            .expect("resolve");
        consume_all(&*h.store, &all[..CONSUMED]).await;
        let found = h
            .store
            .resolve(
                &hint,
                ResolutionStrategy::BoundedTrial(budget(SESSIONS - CONSUMED)),
            )
            .await
            .expect("only the pending half counts against the budget");
        assert_eq!(
            ids(&found),
            (CONSUMED..SESSIONS).map(sid).collect::<Vec<_>>()
        );
    }

    pub async fn expired_sessions_are_never_candidates<B: Backend>() {
        let h = B::make(shared()).await;
        let unique_route = route();
        let shared_route = route();
        h.store
            .insert(new_session(0, &unique_route, Some(kid(0))))
            .await
            .expect("insert");
        for i in [1, 2] {
            h.store
                .insert(new_session(i, &shared_route, Some(kid(1))))
                .await
                .expect("insert");
        }

        // Expiry is judged by the clock at resolve time, before any sweep has run.
        h.clock.advance(TTL);
        let unique_hint = IngressHint::new(unique_route, Some(kid(0)));
        assert_eq!(
            h.store
                .resolve(&unique_hint, ResolutionStrategy::UniqueUri)
                .await,
            Err(ResolveError::SessionExpired)
        );
        assert_eq!(
            h.store
                .resolve(
                    &IngressHint::new(shared_route.clone(), Some(kid(1))),
                    ResolutionStrategy::BoundedTrial(budget(2))
                )
                .await,
            Err(ResolveError::SessionExpired)
        );

        // Same after the sweep has moved them to Expired.
        assert_eq!(h.store.expire_due().await, Ok(3));
        assert_eq!(
            h.store
                .resolve(&unique_hint, ResolutionStrategy::UniqueKid)
                .await,
            Err(ResolveError::SessionExpired)
        );
        assert_eq!(
            h.store
                .resolve(
                    &IngressHint::new(shared_route, None),
                    ResolutionStrategy::BoundedTrial(budget(2))
                )
                .await,
            Err(ResolveError::SessionExpired)
        );
    }

    pub async fn consumed_sessions_are_never_candidates<B: Backend>() {
        let h = B::make(shared()).await;
        let unique_route = route();
        let shared_route = route();
        h.store
            .insert(new_session(0, &unique_route, Some(kid(0))))
            .await
            .expect("insert");
        for i in [1, 2] {
            h.store
                .insert(new_session(i, &shared_route, Some(kid(1))))
                .await
                .expect("insert");
        }
        consume_all(&*h.store, &[candidate(&*h.store, &unique_route).await]).await;
        let shared_hint = IngressHint::new(shared_route, Some(kid(1)));
        let found = h
            .store
            .resolve(&shared_hint, ResolutionStrategy::BoundedTrial(budget(2)))
            .await
            .expect("resolve");
        consume_all(&*h.store, &found).await;

        let unique_hint = IngressHint::new(unique_route, Some(kid(0)));
        for strategy in [ResolutionStrategy::UniqueUri, ResolutionStrategy::UniqueKid] {
            assert_eq!(
                h.store.resolve(&unique_hint, strategy).await,
                Err(ResolveError::Replay),
                "{strategy:?}"
            );
        }
        assert_eq!(
            h.store
                .resolve(&shared_hint, ResolutionStrategy::BoundedTrial(budget(2)))
                .await,
            Err(ResolveError::Replay)
        );
    }

    pub async fn unknown_route_token_or_kid_yields_no_candidate<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let known_route = route();
        h.store
            .insert(new_session(0, &known_route, Some(kid(0))))
            .await
            .expect("insert");
        let strategies = [
            ResolutionStrategy::UniqueUri,
            ResolutionStrategy::UniqueKid,
            ResolutionStrategy::BoundedTrial(budget(1)),
        ];
        for strategy in strategies {
            let unknown_route = IngressHint::new(route(), Some(kid(0)));
            assert_eq!(
                h.store.resolve(&unknown_route, strategy).await,
                Err(ResolveError::NoCandidate),
                "{strategy:?} unknown route"
            );
            let unknown_kid = IngressHint::new(known_route.clone(), Some(kid(99)));
            assert_eq!(
                h.store.resolve(&unknown_kid, strategy).await,
                Err(ResolveError::NoCandidate),
                "{strategy:?} unknown kid"
            );
        }
        assert_eq!(
            h.store
                .resolve(
                    &IngressHint::new(known_route, None),
                    ResolutionStrategy::UniqueKid
                )
                .await,
            Err(ResolveError::MissingKid)
        );
    }

    pub async fn unique_strategy_refuses_an_ambiguous_hint<B: Backend>() {
        let h = B::make(shared()).await;
        let shared_route = route();
        for i in [0, 1] {
            h.store
                .insert(new_session(i, &shared_route, Some(kid(0))))
                .await
                .expect("insert");
        }
        let hint = IngressHint::new(shared_route, Some(kid(0)));
        for strategy in [ResolutionStrategy::UniqueUri, ResolutionStrategy::UniqueKid] {
            assert_eq!(
                h.store.resolve(&hint, strategy).await,
                Err(ResolveError::NotUnique { found: 2 }),
                "{strategy:?}"
            );
        }
    }

    pub async fn unique_uri_checks_route_uniqueness_before_kid<B: Backend>() {
        let h = B::make(shared()).await;
        let shared_route = route();
        for i in [0, 1] {
            h.store
                .insert(new_session(i, &shared_route, Some(kid(i))))
                .await
                .expect("insert");
        }
        // Filtering on the attacker-chosen kid first would hide the duplicated route.
        for k in [Some(kid(0)), Some(kid(1)), Some(kid(99)), None] {
            assert_eq!(
                h.store
                    .resolve(
                        &IngressHint::new(shared_route.clone(), k.clone()),
                        ResolutionStrategy::UniqueUri
                    )
                    .await,
                Err(ResolveError::NotUnique { found: 2 }),
                "kid hint {k:?}"
            );
        }
    }

    pub async fn unique_kid_checks_kid_uniqueness_before_route<B: Backend>() {
        let h = B::make(shared()).await;
        let (route_a, route_b) = (route(), route());
        h.store
            .insert(new_session(0, &route_a, Some(kid(0))))
            .await
            .expect("insert");
        h.store
            .insert(new_session(1, &route_b, Some(kid(0))))
            .await
            .expect("insert");
        for r in [route_a, route_b, route()] {
            assert_eq!(
                h.store
                    .resolve(
                        &IngressHint::new(r, Some(kid(0))),
                        ResolutionStrategy::UniqueKid
                    )
                    .await,
                Err(ResolveError::NotUnique { found: 2 })
            );
        }
    }

    async fn claim_task<S: SessionStore<TestKey, TestResult>>(
        store: Arc<S>,
        candidate: Arc<Candidate<TestKey>>,
        digest: ResponseDigest,
        result: TestResult,
        barrier: Arc<tokio::sync::Barrier>,
    ) -> Result<SessionSnapshot<TestResult>, ClaimError> {
        barrier.wait().await;
        store.claim(&candidate, digest, result).await
    }

    pub async fn concurrent_async_claims_commit_exactly_once<B: Backend>() {
        for n in CONTENDERS {
            for round in 0..ROUNDS {
                let h = B::make(RegistryConfig::default()).await;
                let (_route, c) = pending(&*h.store, round).await;
                let c = Arc::new(c);
                let barrier = Arc::new(tokio::sync::Barrier::new(n));
                let tasks: Vec<_> = (0..n)
                    .map(|t| {
                        tokio::spawn(claim_task(
                            h.store.clone(),
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
                assert!(state(&*h.store, c.id()).await.is_consumed());
            }
        }
    }

    pub async fn dropped_claim_future_commits_nothing<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_route, c) = pending(&*h.store, 0).await;
        // An unpolled, dropped future (a cancelled handler) must not commit.
        let unpolled = h.store.claim(&c, digest(1), "never".into());
        drop(unpolled);
        assert!(state(&*h.store, c.id()).await.is_pending());
        h.store
            .claim(&c, digest(2), "ok".into())
            .await
            .expect("a polled claim commits");
        assert!(state(&*h.store, c.id()).await.is_consumed());
    }

    pub async fn sequential_replay_after_consume_is_rejected<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_route, c) = pending(&*h.store, 0).await;
        let committed = h
            .store
            .claim(&c, digest(1), "first".into())
            .await
            .expect("first claim");
        assert_eq!(
            h.store
                .claim(&c, digest(1), "again".into())
                .await
                .unwrap_err(),
            ClaimError::Replay {
                same_response: true
            }
        );
        assert_eq!(
            h.store
                .claim(&c, digest(2), "other".into())
                .await
                .unwrap_err(),
            ClaimError::Replay {
                same_response: false
            }
        );
        // The first commit is what stays recorded, result and digest included.
        let snap = h
            .store
            .snapshot(&sid(0))
            .await
            .expect("store")
            .expect("present");
        match snap.state() {
            SessionState::Consumed { result, digest: d } => {
                assert_eq!(result.as_str(), "first");
                assert_eq!(*d, digest(1));
            }
            other => panic!("expected Consumed, got {other:?}"),
        }
        assert_eq!(snap.revision(), committed.revision());
        assert_eq!(snap.revision(), Revision::new(1));
    }

    pub async fn claim_after_expiry_is_rejected<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (r, c) = pending(&*h.store, 0).await;
        h.clock.advance(TTL);
        assert_eq!(
            h.store
                .claim(&c, digest(1), "late".into())
                .await
                .unwrap_err(),
            ClaimError::SessionExpired
        );
        assert!(state(&*h.store, c.id()).await.is_expired());
        assert_eq!(
            h.store
                .resolve(&IngressHint::new(r, None), ResolutionStrategy::UniqueUri)
                .await,
            Err(ResolveError::SessionExpired)
        );
    }

    pub async fn claim_just_before_expiry_succeeds<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_route, c) = pending(&*h.store, 0).await;
        h.clock.advance(TTL - Duration::from_millis(1));
        h.store
            .claim(&c, digest(1), "in time".into())
            .await
            .expect("last millisecond is still valid");
    }

    pub async fn failed_attempt_leaves_session_pending_and_claimable<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let r = route();
        h.store
            .insert(new_session(0, &r, Some(kid(0))))
            .await
            .expect("insert");
        let hint = IngressHint::new(r, Some(kid(0)));
        let before = h
            .store
            .resolve(&hint, ResolutionStrategy::UniqueUri)
            .await
            .expect("resolve")
            .remove(0);
        // Decryption or validation failed: the caller drops the candidate, claims nothing.
        let after = h
            .store
            .resolve(&hint, ResolutionStrategy::UniqueUri)
            .await
            .expect("still resolvable");
        assert_eq!(after, vec![before.clone()]);
        let snap = h
            .store
            .snapshot(&sid(0))
            .await
            .expect("store")
            .expect("present");
        assert!(snap.state().is_pending());
        assert_eq!(snap.revision(), before.revision());
        h.store
            .claim(&before, digest(1), "ok".into())
            .await
            .expect("a later valid response still commits");
    }

    pub async fn stale_candidate_cannot_claim_a_reinserted_session<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_route, stale) = pending(&*h.store, 0).await;
        h.clock.advance(TTL);
        assert_eq!(h.store.expire_due().await, Ok(1));
        assert_eq!(h.store.purge().await, Ok(1));
        let (_route, fresh) = pending(&*h.store, 0).await;
        assert_eq!(
            h.store
                .claim(&stale, digest(1), "stale".into())
                .await
                .unwrap_err(),
            ClaimError::UnknownSession
        );
        assert!(state(&*h.store, fresh.id()).await.is_pending());
        h.store
            .claim(&fresh, digest(2), "ok".into())
            .await
            .expect("fresh claim");
    }

    pub async fn claim_of_unknown_session_is_rejected<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_route, c) = pending(&*h.store, 0).await;
        let other = B::make(RegistryConfig::default()).await;
        assert_eq!(
            other
                .store
                .claim(&c, digest(1), "x".into())
                .await
                .unwrap_err(),
            ClaimError::UnknownSession
        );
    }

    pub async fn expire_and_purge_touch_only_due_sessions<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_r0, _c0) = pending(&*h.store, 0).await;
        let (_r1, c1) = pending(&*h.store, 1).await;
        h.store
            .claim(&c1, digest(1), "ok".into())
            .await
            .expect("claim");
        h.clock.advance(TTL / 2);
        let (_r2, _c2) = pending(&*h.store, 2).await;
        h.clock.advance(TTL / 2);

        assert_eq!(h.store.expire_due().await, Ok(1));
        assert_eq!(h.store.expire_due().await, Ok(0), "idempotent");
        assert_eq!(h.store.purge().await, Ok(1));
        assert!(h.store.snapshot(&sid(0)).await.expect("store").is_none());
        assert!(state(&*h.store, &sid(1)).await.is_consumed());
        assert!(state(&*h.store, &sid(2)).await.is_pending());
    }

    pub async fn consumed_records_are_purged_after_retention<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (r, c) = pending(&*h.store, 0).await;
        h.store
            .claim(&c, digest(1), "ok".into())
            .await
            .expect("claim");
        let hint = IngressHint::new(r, None);

        h.clock
            .advance(TTL + DEFAULT_CONSUMED_RETENTION - Duration::from_millis(1));
        assert_eq!(h.store.purge().await, Ok(0));
        assert_eq!(
            h.store.resolve(&hint, ResolutionStrategy::UniqueUri).await,
            Err(ResolveError::Replay)
        );

        h.clock.advance(Duration::from_millis(1));
        assert_eq!(h.store.purge().await, Ok(1));
        assert_eq!(
            h.store.resolve(&hint, ResolutionStrategy::UniqueUri).await,
            Err(ResolveError::NoCandidate)
        );
        assert_eq!(
            h.store
                .claim(&c, digest(1), "again".into())
                .await
                .unwrap_err(),
            ClaimError::UnknownSession
        );
    }

    pub async fn insert_beyond_pending_capacity_is_rejected<B: Backend>() {
        const LIMIT: usize = 2;
        let h = B::make(RegistryConfig {
            max_pending: LIMIT,
            ..RegistryConfig::default()
        })
        .await;
        let (_r0, c0) = pending(&*h.store, 0).await;
        let (_r1, _c1) = pending(&*h.store, 1).await;
        assert_eq!(
            h.store
                .insert(new_session(2, &route(), None))
                .await
                .unwrap_err(),
            InsertError::Capacity { limit: LIMIT }
        );
        // A consumed session frees its slot.
        h.store
            .claim(&c0, digest(1), "ok".into())
            .await
            .expect("claim");
        let (_r2, _c2) = pending(&*h.store, 2).await;
        assert_eq!(
            h.store
                .insert(new_session(3, &route(), None))
                .await
                .unwrap_err(),
            InsertError::Capacity { limit: LIMIT }
        );
        // Sessions past their TTL are expired on the spot instead of holding slots.
        h.clock.advance(TTL);
        let (_r3, _c3) = pending(&*h.store, 3).await;
        assert!(state(&*h.store, &sid(1)).await.is_expired());
    }

    pub async fn unique_route_policy_rejects_duplicate_route_token<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (r, c) = pending(&*h.store, 0).await;
        assert_eq!(
            h.store.insert(new_session(1, &r, None)).await.unwrap_err(),
            InsertError::DuplicateRoute
        );
        h.store
            .claim(&c, digest(1), "ok".into())
            .await
            .expect("claim");
        assert_eq!(
            h.store.insert(new_session(1, &r, None)).await.unwrap_err(),
            InsertError::DuplicateRoute
        );
    }

    pub async fn insert_rejects_duplicate_id_and_zero_ttl<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let (_r, _c) = pending(&*h.store, 0).await;
        assert_eq!(
            h.store
                .insert(new_session(0, &route(), None))
                .await
                .unwrap_err(),
            InsertError::DuplicateSession
        );
        let mut zero = new_session(1, &route(), None);
        zero.ttl = Duration::ZERO;
        assert_eq!(
            h.store.insert(zero).await.unwrap_err(),
            InsertError::ZeroTtl
        );
    }

    pub async fn snapshots_are_point_in_time_copies<B: Backend>() {
        let h = B::make(RegistryConfig::default()).await;
        let r = route();
        let inserted = h
            .store
            .insert(new_session(0, &r, None))
            .await
            .expect("insert");
        let c = candidate(&*h.store, &r).await;
        h.store
            .claim(&c, digest(1), "ok".into())
            .await
            .expect("claim");
        assert!(inserted.state().is_pending());
        assert_eq!(c.revision(), Revision::INITIAL);
        let now = h
            .store
            .snapshot(&sid(0))
            .await
            .expect("store")
            .expect("present");
        assert!(now.state().is_consumed());
        assert_ne!(now.revision(), Revision::INITIAL);
    }

    pub async fn snapshot_round_trips_every_field<B: Backend>() {
        let h = B::make(shared()).await;
        let r = route();
        let session = NewSession {
            binding: dc_api_binding(7),
            ..new_session(7, &r, Some(kid(7)))
        };
        let inserted = h.store.insert(session).await.expect("insert");
        let stored = h
            .store
            .snapshot(&sid(7))
            .await
            .expect("store")
            .expect("present");
        assert_eq!(stored.binding(), &dc_api_binding(7));
        assert_eq!(stored.route_token(), &r);
        assert_eq!(stored.kid(), Some(&kid(7)));
        assert_eq!(stored.expires_at(), inserted.expires_at());
        assert_eq!(stored.revision(), Revision::INITIAL);

        let c = h
            .store
            .resolve(
                &IngressHint::new(r, Some(kid(7))),
                ResolutionStrategy::UniqueKid,
            )
            .await
            .expect("resolve")
            .remove(0);
        assert_eq!(c.binding(), &dc_api_binding(7));
        assert_eq!(c.key(), &TestKey(7));
        let result = "result with \"quotes\", unicode \u{2603} and \0 bytes".to_owned();
        let committed = h
            .store
            .claim(&c, digest(9), result.clone())
            .await
            .expect("claim");
        let stored = h
            .store
            .snapshot(&sid(7))
            .await
            .expect("store")
            .expect("present");
        for snap in [&committed, &stored] {
            match snap.state() {
                SessionState::Consumed {
                    result: r,
                    digest: d,
                } => {
                    assert_eq!(**r, result);
                    assert_eq!(*d, digest(9));
                }
                other => panic!("expected Consumed, got {other:?}"),
            }
            assert_eq!(snap.binding(), &dc_api_binding(7));
            assert_eq!(snap.expires_at(), inserted.expires_at());
        }
        assert_eq!(committed.revision(), stored.revision());
    }
}

/// One `#[tokio::test]` per suite function for `$backend`, with optional extra attributes.
macro_rules! contract_tests {
    ($backend:ty $(, #[$attr:meta])?) => {
        contract_tests!(@each $backend, [$(#[$attr])?],
            unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid,
            unique_kid_yields_exactly_one_candidate_among_sessions_sharing_route,
            bounded_trial_returns_all_candidates_within_budget,
            bounded_trial_rejects_more_candidates_than_budget,
            bounded_trial_budget_counts_only_live_sessions,
            expired_sessions_are_never_candidates,
            consumed_sessions_are_never_candidates,
            unknown_route_token_or_kid_yields_no_candidate,
            unique_strategy_refuses_an_ambiguous_hint,
            unique_uri_checks_route_uniqueness_before_kid,
            unique_kid_checks_kid_uniqueness_before_route,
            concurrent_async_claims_commit_exactly_once,
            dropped_claim_future_commits_nothing,
            sequential_replay_after_consume_is_rejected,
            claim_after_expiry_is_rejected,
            claim_just_before_expiry_succeeds,
            failed_attempt_leaves_session_pending_and_claimable,
            stale_candidate_cannot_claim_a_reinserted_session,
            claim_of_unknown_session_is_rejected,
            expire_and_purge_touch_only_due_sessions,
            consumed_records_are_purged_after_retention,
            insert_beyond_pending_capacity_is_rejected,
            unique_route_policy_rejects_duplicate_route_token,
            insert_rejects_duplicate_id_and_zero_ttl,
            snapshots_are_point_in_time_copies,
            snapshot_round_trips_every_field,
        );
    };
    (@each $backend:ty, $attrs:tt, $($name:ident),* $(,)?) => {
        $( contract_tests!(@one $backend, $attrs, $name); )*
    };
    (@one $backend:ty, [$(#[$attr:meta])?], $name:ident) => {
        // 4 workers: real parallelism for the concurrent claim test; the attribute only takes
        // a literal.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        $(#[$attr])?
        async fn $name() {
            crate::suite::$name::<$backend>().await;
        }
    };
}

mod memory {
    contract_tests!(crate::common::Memory);
}

mod redis {
    contract_tests!(
        crate::common::Redis,
        #[ignore = "requires Redis; run via scripts/ci_local.sh <dir> redis"]
    );
}
