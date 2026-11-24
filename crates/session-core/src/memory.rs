//! In-process authoritative registry (MVP; the Redis-backed one is crate `session-redis`).

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use protocol_model::{KeyId, RequestBinding, SessionId};

use crate::clock::{Clock, Timestamp};
use crate::config::{RegistryConfig, RoutePolicy};
use crate::route::{IngressHint, ResolutionStrategy, RouteToken};
use crate::session::{
    Candidate, ClaimError, InsertError, NewSession, ResolveError, ResponseDigest, Revision,
    SessionSnapshot, SessionState, StoreUnavailable,
};
use crate::store::SessionStore;

/// The authoritative record. Never leaves the registry; callers only get copies.
struct SessionRecord<K, R> {
    incarnation: u64,
    binding: RequestBinding,
    route_token: RouteToken,
    kid: Option<KeyId>,
    key: Arc<K>,
    revision: Revision,
    expires_at: Timestamp,
    state: SessionState<R>,
}

impl<K, R> SessionRecord<K, R> {
    fn snapshot(&self, id: &SessionId) -> SessionSnapshot<R> {
        SessionSnapshot {
            id: id.clone(),
            binding: self.binding.clone(),
            route_token: self.route_token.clone(),
            kid: self.kid.clone(),
            revision: self.revision,
            expires_at: self.expires_at,
            state: self.state.clone(),
        }
    }

    fn candidate(&self, id: &SessionId) -> Candidate<K> {
        Candidate {
            id: id.clone(),
            incarnation: self.incarnation,
            binding: self.binding.clone(),
            kid: self.kid.clone(),
            key: Arc::clone(&self.key),
            revision: self.revision,
            expires_at: self.expires_at,
        }
    }

    /// Expired at `now`: the TTL is half-open, `[inserted, expires_at)`.
    fn is_due(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// A `kid` in the hint must equal the session's; no `kid` in the hint filters nothing.
    fn kid_matches(&self, hint: &IngressHint) -> bool {
        hint.kid
            .as_ref()
            .is_none_or(|k| self.kid.as_ref() == Some(k))
    }
}

/// Which terminal state a session reached.
#[derive(Clone, Copy)]
enum Terminal {
    Consumed,
    Expired,
}

/// Terminal sessions still held for a route (or route and `kid`). Lets a resolve that finds no
/// live candidate report `Replay` / `SessionExpired` in O(1), without scanning history.
#[derive(Default, Clone, Copy)]
struct TerminalCounts {
    consumed: usize,
    expired: usize,
}

impl TerminalCounts {
    fn slot(&mut self, t: Terminal) -> &mut usize {
        match t {
            Terminal::Consumed => &mut self.consumed,
            Terminal::Expired => &mut self.expired,
        }
    }

    fn is_empty(self) -> bool {
        self.consumed == 0 && self.expired == 0
    }
}

fn count_up<T: Eq + Hash>(map: &mut HashMap<T, TerminalCounts>, key: T, t: Terminal) {
    *map.entry(key).or_default().slot(t) += 1;
}

fn count_down<T: Eq + Hash>(map: &mut HashMap<T, TerminalCounts>, key: T, t: Terminal) {
    if let Entry::Occupied(mut e) = map.entry(key) {
        let n = e.get_mut().slot(t);
        *n = n.saturating_sub(1);
        if e.get().is_empty() {
            e.remove();
        }
    }
}

/// Removes `gone` from the id lists under `keys`, one `retain` per affected key.
fn unindex<T: Eq + Hash>(
    index: &mut HashMap<T, Vec<SessionId>>,
    keys: HashSet<T>,
    gone: &HashSet<SessionId>,
) {
    for key in keys {
        if let Entry::Occupied(mut e) = index.entry(key) {
            e.get_mut().retain(|id| !gone.contains(id));
            if e.get().is_empty() {
                e.remove();
            }
        }
    }
}

/// A session leaving `Pending`: what the indexes need to forget it.
struct Leaving {
    id: SessionId,
    route_token: RouteToken,
    kid: Option<KeyId>,
}

struct Inner<K, R> {
    sessions: HashMap<SessionId, SessionRecord<K, R>>,
    /// `Pending` sessions only (including ones past their TTL that no sweep has moved yet), in
    /// insertion order (bounded-trial order). Bounded by `max_pending`, so resolve never scans
    /// consumed or expired history.
    pending_by_route: HashMap<RouteToken, Vec<SessionId>>,
    pending_by_kid: HashMap<KeyId, Vec<SessionId>>,
    pending: usize,
    /// Held terminal sessions per route and per (route, kid).
    terminal_by_route: HashMap<RouteToken, TerminalCounts>,
    terminal_by_route_kid: HashMap<(RouteToken, KeyId), TerminalCounts>,
    next_incarnation: u64,
}

/// Live and past-TTL pending sessions under one index entry.
type Split<'a, K, R> = (
    Vec<(&'a SessionId, &'a SessionRecord<K, R>)>,
    Vec<&'a SessionRecord<K, R>>,
);

impl<K, R> Inner<K, R> {
    /// Moves the listed sessions out of the pending indexes and into the terminal counts.
    fn leave_pending(&mut self, leaving: Vec<Leaving>, t: Terminal) {
        let gone: HashSet<SessionId> = leaving.iter().map(|l| l.id.clone()).collect();
        let routes: HashSet<RouteToken> = leaving.iter().map(|l| l.route_token.clone()).collect();
        let kids: HashSet<KeyId> = leaving.iter().filter_map(|l| l.kid.clone()).collect();
        unindex(&mut self.pending_by_route, routes, &gone);
        unindex(&mut self.pending_by_kid, kids, &gone);
        self.pending = self.pending.saturating_sub(leaving.len());
        for l in leaving {
            if let Some(k) = l.kid {
                count_up(
                    &mut self.terminal_by_route_kid,
                    (l.route_token.clone(), k),
                    t,
                );
            }
            count_up(&mut self.terminal_by_route, l.route_token, t);
        }
    }

    /// Moves every pending session past its TTL to `Expired`.
    fn expire_due(&mut self, now: Timestamp) -> usize {
        let due: Vec<SessionId> = self
            .pending_by_route
            .values()
            .flatten()
            .filter(|id| self.sessions.get(*id).is_some_and(|r| r.is_due(now)))
            .cloned()
            .collect();
        let mut leaving = Vec::with_capacity(due.len());
        for id in due {
            if let Some(record) = self.sessions.get_mut(&id) {
                record.state = SessionState::Expired;
                record.revision = record.revision.next();
                leaving.push(Leaving {
                    route_token: record.route_token.clone(),
                    kid: record.kid.clone(),
                    id,
                });
            }
        }
        let moved = leaving.len();
        self.leave_pending(leaving, Terminal::Expired);
        moved
    }

    fn pending_on<'a>(
        &'a self,
        ids: Option<&'a Vec<SessionId>>,
        now: Timestamp,
    ) -> Split<'a, K, R> {
        let mut live = Vec::new();
        let mut due = Vec::new();
        for (id, record) in ids
            .into_iter()
            .flatten()
            .filter_map(|id| self.sessions.get(id).map(|r| (id, r)))
        {
            if record.is_due(now) {
                due.push(record);
            } else {
                live.push((id, record));
            }
        }
        (live, due)
    }

    /// Error for a hint with no live candidate, from the terminal counts and past-TTL pending
    /// sessions it matches.
    fn no_live_candidate(
        &self,
        route: &RouteToken,
        kid: Option<&KeyId>,
        saw_due: bool,
    ) -> ResolveError {
        let counts = match kid {
            None => self.terminal_by_route.get(route),
            Some(k) => self.terminal_by_route_kid.get(&(route.clone(), k.clone())),
        }
        .copied()
        .unwrap_or_default();
        if counts.consumed > 0 {
            ResolveError::Replay
        } else if counts.expired > 0 || saw_due {
            ResolveError::SessionExpired
        } else {
            ResolveError::NoCandidate
        }
    }

    fn resolve(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
        now: Timestamp,
    ) -> Result<Vec<Candidate<K>>, ResolveError> {
        let route = &hint.route_token;
        match strategy {
            ResolutionStrategy::UniqueUri => {
                // Uniqueness on the route alone, before the attacker-chosen kid is consulted.
                let (live, due) = self.pending_on(self.pending_by_route.get(route), now);
                match live.as_slice() {
                    [] => Err(self.no_live_candidate(route, None, !due.is_empty())),
                    [(id, r)] if r.kid_matches(hint) => Ok(vec![r.candidate(id)]),
                    [_] => Err(ResolveError::NoCandidate),
                    many => Err(ResolveError::NotUnique { found: many.len() }),
                }
            }
            ResolutionStrategy::UniqueKid => {
                let kid = hint.kid.as_ref().ok_or(ResolveError::MissingKid)?;
                // Uniqueness on the kid alone, before the attacker-chosen route is consulted.
                let (live, due) = self.pending_on(self.pending_by_kid.get(kid), now);
                match live.as_slice() {
                    [] => {
                        let saw_due = due.iter().any(|r| r.route_token == *route);
                        Err(self.no_live_candidate(route, Some(kid), saw_due))
                    }
                    [(id, r)] if r.route_token == *route => Ok(vec![r.candidate(id)]),
                    [_] => Err(ResolveError::NoCandidate),
                    many => Err(ResolveError::NotUnique { found: many.len() }),
                }
            }
            ResolutionStrategy::BoundedTrial(budget) => {
                let (mut live, due) = self.pending_on(self.pending_by_route.get(route), now);
                live.retain(|(_, r)| r.kid_matches(hint));
                if live.is_empty() {
                    let saw_due = due.iter().any(|r| r.kid_matches(hint));
                    return Err(self.no_live_candidate(route, hint.kid.as_ref(), saw_due));
                }
                if live.len() > budget.get() {
                    return Err(ResolveError::CandidateBudgetExceeded {
                        found: live.len(),
                        budget: budget.get(),
                    });
                }
                Ok(live.into_iter().map(|(id, r)| r.candidate(id)).collect())
            }
        }
    }

    /// Check and set. Returns the caller's `result` when it was not stored, so it can be dropped
    /// after the lock is released.
    fn claim(
        &mut self,
        candidate: &Candidate<K>,
        digest: ResponseDigest,
        result: R,
        now: Timestamp,
    ) -> (Result<SessionSnapshot<R>, ClaimError>, Option<R>) {
        let id = &candidate.id;
        let Some(record) = self
            .sessions
            .get_mut(id)
            .filter(|r| r.incarnation == candidate.incarnation)
        else {
            return (Err(ClaimError::UnknownSession), Some(result));
        };
        let (terminal, unused) = match &record.state {
            SessionState::Consumed {
                digest: committed, ..
            } => {
                let same_response = *committed == digest;
                return (Err(ClaimError::Replay { same_response }), Some(result));
            }
            SessionState::Expired => return (Err(ClaimError::SessionExpired), Some(result)),
            SessionState::Pending if record.is_due(now) => {
                record.state = SessionState::Expired;
                (Terminal::Expired, Some(result))
            }
            SessionState::Pending if record.revision != candidate.revision => {
                let actual = record.revision;
                let err = ClaimError::RevisionMismatch {
                    expected: candidate.revision,
                    actual,
                };
                return (Err(err), Some(result));
            }
            SessionState::Pending => {
                record.state = SessionState::Consumed {
                    result: Arc::new(result),
                    digest,
                };
                (Terminal::Consumed, None)
            }
        };
        record.revision = record.revision.next();
        let snapshot = record.snapshot(id);
        let leaving = Leaving {
            id: id.clone(),
            route_token: record.route_token.clone(),
            kid: record.kid.clone(),
        };
        self.leave_pending(vec![leaving], terminal);
        let outcome = match terminal {
            Terminal::Consumed => Ok(snapshot),
            Terminal::Expired => Err(ClaimError::SessionExpired),
        };
        (outcome, unused)
    }

    /// Admission checks for `insert`; returns the new session's `expires_at`. Takes the session
    /// by reference so a rejected one is dropped by the caller, outside the lock.
    fn admit(
        &mut self,
        session: &NewSession<K>,
        now: Timestamp,
        config: &RegistryConfig,
    ) -> Result<Timestamp, InsertError> {
        let expires_at = now.saturating_add(session.ttl);
        if expires_at <= now {
            return Err(InsertError::ZeroTtl);
        }
        if self.sessions.contains_key(&session.id) {
            return Err(InsertError::DuplicateSession);
        }
        let route_held = self.pending_by_route.contains_key(&session.route_token)
            || self.terminal_by_route.contains_key(&session.route_token);
        if config.route_policy == RoutePolicy::UniquePerSession && route_held {
            return Err(InsertError::DuplicateRoute);
        }
        if self.pending >= config.max_pending {
            // Lazy check: sessions past their TTL should not hold slots until the next sweep.
            self.expire_due(now);
            if self.pending >= config.max_pending {
                let limit = config.max_pending;
                return Err(InsertError::Capacity { limit });
            }
        }
        Ok(expires_at)
    }

    /// Stores an admitted session.
    fn insert(&mut self, session: NewSession<K>, expires_at: Timestamp) -> SessionSnapshot<R> {
        let NewSession {
            id,
            binding,
            route_token,
            kid,
            key,
            ttl: _,
        } = session;
        self.pending_by_route
            .entry(route_token.clone())
            .or_default()
            .push(id.clone());
        if let Some(k) = &kid {
            self.pending_by_kid
                .entry(k.clone())
                .or_default()
                .push(id.clone());
        }
        self.pending += 1;
        let incarnation = self.next_incarnation;
        self.next_incarnation = self.next_incarnation.saturating_add(1);
        let record = SessionRecord {
            incarnation,
            binding,
            route_token,
            kid,
            key: Arc::new(key),
            revision: Revision::INITIAL,
            expires_at,
            state: SessionState::Pending,
        };
        let snapshot = record.snapshot(&id);
        self.sessions.insert(id, record);
        snapshot
    }

    /// Removes expired records and consumed ones past retention; returns them for dropping
    /// after the lock is released.
    fn purge(&mut self, now: Timestamp, config: &RegistryConfig) -> Vec<SessionRecord<K, R>> {
        let doomed: Vec<(SessionId, Terminal)> = self
            .sessions
            .iter()
            .filter_map(|(id, r)| {
                let t = match r.state {
                    SessionState::Pending => return None,
                    SessionState::Expired => Terminal::Expired,
                    SessionState::Consumed { .. } => {
                        let until = r.expires_at.saturating_add(config.consumed_retention);
                        if now < until {
                            return None;
                        }
                        Terminal::Consumed
                    }
                };
                Some((id.clone(), t))
            })
            .collect();
        let mut removed = Vec::with_capacity(doomed.len());
        for (id, t) in doomed {
            if let Some(record) = self.sessions.remove(&id) {
                if let Some(k) = &record.kid {
                    let key = (record.route_token.clone(), k.clone());
                    count_down(&mut self.terminal_by_route_kid, key, t);
                }
                count_down(&mut self.terminal_by_route, record.route_token.clone(), t);
                removed.push(record);
            }
        }
        removed
    }
}

/// In-memory [`SessionStore`] behind one `RwLock`.
///
/// Every operation is a short critical section with no I/O and no `.await` inside, so the
/// inherent methods are synchronous; the [`SessionStore`] impl runs them when its future is
/// polled. Holding the write lock across the whole check-and-set of [`claim`](Self::claim) is
/// what makes the commit atomic. Caller values the registry does not keep (a losing claim's
/// result, a rejected insert, purged records) are dropped after the lock is released, so their
/// destructors cannot run inside, or re-enter, a critical section.
///
/// # Failure behaviour
///
/// * A poisoned lock fails closed: every later call returns [`StoreUnavailable`]. The clock is
///   read inside the critical sections, so a panicking [`Clock`] poisons the store this way.
/// * If the clock steps back, sessions are judged by the earlier time: pending sessions past
///   their TTL may become live again until a sweep or claim moves them to `Expired`, which is
///   terminal, so swept sessions never come back. Consumed records are kept longer.
pub struct MemoryRegistry<K, R> {
    clock: Arc<dyn Clock>,
    config: RegistryConfig,
    inner: RwLock<Inner<K, R>>,
}

impl<K, R> MemoryRegistry<K, R> {
    /// An empty registry with [`RegistryConfig::default`] (unique route tokens).
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_config(clock, RegistryConfig::default())
    }

    /// An empty registry judging TTLs by `clock`.
    #[must_use]
    pub fn with_config(clock: Arc<dyn Clock>, config: RegistryConfig) -> Self {
        Self {
            clock,
            config,
            inner: RwLock::new(Inner {
                sessions: HashMap::new(),
                pending_by_route: HashMap::new(),
                pending_by_kid: HashMap::new(),
                pending: 0,
                terminal_by_route: HashMap::new(),
                terminal_by_route_kid: HashMap::new(),
                next_incarnation: 0,
            }),
        }
    }

    /// See [`SessionStore::insert`].
    ///
    /// # Errors
    /// See [`InsertError`].
    pub fn insert(&self, session: NewSession<K>) -> Result<SessionSnapshot<R>, InsertError> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        let now = self.clock.now();
        match inner.admit(&session, now, &self.config) {
            Ok(expires_at) => Ok(inner.insert(session, expires_at)),
            Err(err) => {
                drop(inner);
                drop(session);
                Err(err)
            }
        }
    }

    /// See [`SessionStore::resolve`]. Read-only: it never changes a session, even one it finds
    /// past its TTL.
    ///
    /// # Errors
    /// See [`ResolveError`].
    pub fn resolve(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
    ) -> Result<Vec<Candidate<K>>, ResolveError> {
        let inner = self.inner.read().map_err(|_| StoreUnavailable)?;
        let now = self.clock.now();
        inner.resolve(hint, strategy, now)
    }

    /// See [`SessionStore::claim`]. Check and set happen under one write lock.
    ///
    /// Precedence: a candidate for a purged or re-inserted id reports
    /// [`ClaimError::UnknownSession`]; a consumed session reports [`ClaimError::Replay`], so the
    /// losers of a race see `Replay`; a pending session past its TTL is moved to `Expired` and
    /// reports [`ClaimError::SessionExpired`]; only then is the revision compared.
    ///
    /// # Errors
    /// See [`ClaimError`].
    pub fn claim(
        &self,
        candidate: &Candidate<K>,
        digest: ResponseDigest,
        result: R,
    ) -> Result<SessionSnapshot<R>, ClaimError> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        // Read under the lock, so time spent waiting for it counts against the TTL.
        let now = self.clock.now();
        let (outcome, unused) = inner.claim(candidate, digest, result, now);
        drop(inner);
        drop(unused);
        outcome
    }

    /// See [`SessionStore::snapshot`].
    ///
    /// # Errors
    /// [`StoreUnavailable`].
    pub fn snapshot(&self, id: &SessionId) -> Result<Option<SessionSnapshot<R>>, StoreUnavailable> {
        let inner = self.inner.read().map_err(|_| StoreUnavailable)?;
        Ok(inner.sessions.get(id).map(|r| r.snapshot(id)))
    }

    /// See [`SessionStore::expire_due`].
    ///
    /// # Errors
    /// [`StoreUnavailable`].
    pub fn expire_due(&self) -> Result<usize, StoreUnavailable> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        let now = self.clock.now();
        Ok(inner.expire_due(now))
    }

    /// See [`SessionStore::purge`].
    ///
    /// # Errors
    /// [`StoreUnavailable`].
    pub fn purge(&self) -> Result<usize, StoreUnavailable> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        let now = self.clock.now();
        let removed = inner.purge(now, &self.config);
        drop(inner);
        let count = removed.len();
        drop(removed);
        Ok(count)
    }
}

// `async fn` bodies run only when the future is polled, so an unpolled, dropped future does
// nothing (a cancelled handler cannot half-commit). The compiler checks the futures are `Send`.
impl<K: Send + Sync, R: Send + Sync> SessionStore<K, R> for MemoryRegistry<K, R> {
    async fn insert(&self, session: NewSession<K>) -> Result<SessionSnapshot<R>, InsertError> {
        Self::insert(self, session)
    }

    async fn resolve(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
    ) -> Result<Vec<Candidate<K>>, ResolveError> {
        Self::resolve(self, hint, strategy)
    }

    async fn claim(
        &self,
        candidate: &Candidate<K>,
        digest: ResponseDigest,
        result: R,
    ) -> Result<SessionSnapshot<R>, ClaimError> {
        Self::claim(self, candidate, digest, result)
    }

    async fn snapshot(
        &self,
        id: &SessionId,
    ) -> Result<Option<SessionSnapshot<R>>, StoreUnavailable> {
        Self::snapshot(self, id)
    }

    async fn expire_due(&self) -> Result<usize, StoreUnavailable> {
        Self::expire_due(self)
    }

    async fn purge(&self) -> Result<usize, StoreUnavailable> {
        Self::purge(self)
    }
}
