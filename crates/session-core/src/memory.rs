//! In-process authoritative registry (MVP; Redis follows after G1).

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::{Future, ready};
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use protocol_model::{KeyId, RequestBinding, SessionId};

use crate::clock::{Clock, Timestamp};
use crate::route::{IngressHint, ResolutionStrategy, RouteToken};
use crate::session::{
    Candidate, ClaimError, InsertError, NewSession, ResolveError, ResponseDigest, Revision,
    SessionSnapshot, SessionState, StoreUnavailable,
};
use crate::store::SessionStore;

/// The authoritative record. Never leaves the registry; callers only get copies.
struct SessionRecord<K, R> {
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

    fn matches(&self, hint: &IngressHint) -> bool {
        self.route_token == hint.route_token
            && hint
                .kid
                .as_ref()
                .is_none_or(|k| self.kid.as_ref() == Some(k))
    }
}

struct Inner<K, R> {
    sessions: HashMap<SessionId, SessionRecord<K, R>>,
    /// Session ids per route token / kid, in insertion order (bounded-trial order).
    by_route: HashMap<RouteToken, Vec<SessionId>>,
    by_kid: HashMap<KeyId, Vec<SessionId>>,
}

fn unindex<T: Eq + Hash>(index: &mut HashMap<T, Vec<SessionId>>, key: &T, id: &SessionId) {
    if let Some(ids) = index.get_mut(key) {
        ids.retain(|x| x != id);
        if ids.is_empty() {
            index.remove(key);
        }
    }
}

/// In-memory [`SessionStore`] behind one `RwLock`.
///
/// Every operation is a short critical section with no I/O and no `.await` inside, so the
/// inherent methods are synchronous and the [`SessionStore`] impl wraps them in ready futures.
/// Holding the write lock across the whole check-and-set of [`claim`](Self::claim) is what makes
/// the commit atomic. A poisoned lock fails closed with [`StoreUnavailable`].
pub struct MemoryRegistry<K, R> {
    clock: Arc<dyn Clock>,
    inner: RwLock<Inner<K, R>>,
}

impl<K, R> MemoryRegistry<K, R> {
    /// An empty registry judging TTLs by `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            inner: RwLock::new(Inner {
                sessions: HashMap::new(),
                by_route: HashMap::new(),
                by_kid: HashMap::new(),
            }),
        }
    }

    /// See [`SessionStore::insert`].
    ///
    /// # Errors
    /// [`InsertError::DuplicateSession`], [`InsertError::ZeroTtl`], or
    /// [`InsertError::Unavailable`].
    pub fn insert(&self, session: NewSession<K>) -> Result<SessionSnapshot<R>, InsertError> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        let now = self.clock.now();
        let expires_at = now.saturating_add(session.ttl);
        if expires_at <= now {
            return Err(InsertError::ZeroTtl);
        }
        let NewSession {
            id,
            binding,
            route_token,
            kid,
            key,
            ttl: _,
        } = session;
        let Inner {
            sessions,
            by_route,
            by_kid,
        } = &mut *inner;
        let Entry::Vacant(slot) = sessions.entry(id.clone()) else {
            return Err(InsertError::DuplicateSession);
        };
        by_route
            .entry(route_token.clone())
            .or_default()
            .push(id.clone());
        if let Some(k) = &kid {
            by_kid.entry(k.clone()).or_default().push(id.clone());
        }
        let record = slot.insert(SessionRecord {
            binding,
            route_token,
            kid,
            key: Arc::new(key),
            revision: Revision::INITIAL,
            expires_at,
            state: SessionState::Pending,
        });
        Ok(record.snapshot(&id))
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
        let indexed = match strategy {
            ResolutionStrategy::UniqueKid => {
                let kid = hint.kid.as_ref().ok_or(ResolveError::MissingKid)?;
                inner.by_kid.get(kid)
            }
            ResolutionStrategy::UniqueUri | ResolutionStrategy::BoundedTrial(_) => {
                inner.by_route.get(&hint.route_token)
            }
        };

        let mut live = Vec::new();
        let (mut consumed, mut expired) = (false, false);
        let matching = indexed
            .into_iter()
            .flatten()
            .filter_map(|id| inner.sessions.get(id).map(|r| (id, r)))
            .filter(|(_, r)| r.matches(hint));
        for (id, record) in matching {
            match record.state {
                SessionState::Pending if !record.is_due(now) => live.push((id, record)),
                SessionState::Pending | SessionState::Expired => expired = true,
                SessionState::Consumed { .. } => consumed = true,
            }
        }

        match strategy {
            ResolutionStrategy::UniqueUri | ResolutionStrategy::UniqueKid => match live.len() {
                1 => {}
                0 if consumed => return Err(ResolveError::Replay),
                0 if expired => return Err(ResolveError::SessionExpired),
                0 => return Err(ResolveError::NoCandidate),
                found => return Err(ResolveError::NotUnique { found }),
            },
            ResolutionStrategy::BoundedTrial(budget) => {
                if live.is_empty() {
                    return Err(ResolveError::NoCandidate);
                }
                if live.len() > budget.get() {
                    return Err(ResolveError::CandidateBudgetExceeded {
                        found: live.len(),
                        budget: budget.get(),
                    });
                }
            }
        }
        Ok(live.into_iter().map(|(id, r)| r.candidate(id)).collect())
    }

    /// See [`SessionStore::claim`]. Check and set happen under one write lock.
    ///
    /// Precedence: a consumed session reports [`ClaimError::Replay`] whatever the revision, so
    /// the losers of a race see `Replay`; a pending session past its TTL is moved to `Expired`
    /// and reports [`ClaimError::SessionExpired`]; only then is the revision compared.
    ///
    /// # Errors
    /// See [`ClaimError`].
    pub fn claim(
        &self,
        id: &SessionId,
        expected: Revision,
        digest: ResponseDigest,
        result: R,
    ) -> Result<SessionSnapshot<R>, ClaimError> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        // Read under the lock, so time spent waiting for it counts against the TTL.
        let now = self.clock.now();
        let record = inner
            .sessions
            .get_mut(id)
            .ok_or(ClaimError::UnknownSession)?;
        match &record.state {
            SessionState::Consumed {
                digest: committed, ..
            } => Err(ClaimError::Replay {
                same_response: *committed == digest,
            }),
            SessionState::Expired => Err(ClaimError::SessionExpired),
            SessionState::Pending if record.is_due(now) => {
                record.state = SessionState::Expired;
                record.revision = record.revision.next();
                Err(ClaimError::SessionExpired)
            }
            SessionState::Pending if record.revision != expected => {
                Err(ClaimError::RevisionMismatch {
                    expected,
                    actual: record.revision,
                })
            }
            SessionState::Pending => {
                record.state = SessionState::Consumed {
                    result: Arc::new(result),
                    digest,
                };
                record.revision = record.revision.next();
                Ok(record.snapshot(id))
            }
        }
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
        let mut moved = 0;
        for record in inner.sessions.values_mut() {
            if record.state.is_pending() && record.is_due(now) {
                record.state = SessionState::Expired;
                record.revision = record.revision.next();
                moved += 1;
            }
        }
        Ok(moved)
    }

    /// See [`SessionStore::purge_expired`].
    ///
    /// # Errors
    /// [`StoreUnavailable`].
    pub fn purge_expired(&self) -> Result<usize, StoreUnavailable> {
        let mut inner = self.inner.write().map_err(|_| StoreUnavailable)?;
        let Inner {
            sessions,
            by_route,
            by_kid,
        } = &mut *inner;
        let mut removed = 0;
        sessions.retain(|id, record| {
            if !record.state.is_expired() {
                return true;
            }
            unindex(by_route, &record.route_token, id);
            if let Some(k) = &record.kid {
                unindex(by_kid, k, id);
            }
            removed += 1;
            false
        });
        Ok(removed)
    }
}

impl<K: Send + Sync, R: Send + Sync> SessionStore<K, R> for MemoryRegistry<K, R> {
    fn insert(
        &self,
        session: NewSession<K>,
    ) -> impl Future<Output = Result<SessionSnapshot<R>, InsertError>> + Send {
        ready(Self::insert(self, session))
    }

    fn resolve(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
    ) -> impl Future<Output = Result<Vec<Candidate<K>>, ResolveError>> + Send {
        ready(Self::resolve(self, hint, strategy))
    }

    fn claim(
        &self,
        id: &SessionId,
        expected: Revision,
        digest: ResponseDigest,
        result: R,
    ) -> impl Future<Output = Result<SessionSnapshot<R>, ClaimError>> + Send {
        ready(Self::claim(self, id, expected, digest, result))
    }

    fn snapshot(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<SessionSnapshot<R>>, StoreUnavailable>> + Send {
        ready(Self::snapshot(self, id))
    }

    fn expire_due(&self) -> impl Future<Output = Result<usize, StoreUnavailable>> + Send {
        ready(Self::expire_due(self))
    }

    fn purge_expired(&self) -> impl Future<Output = Result<usize, StoreUnavailable>> + Send {
        ready(Self::purge_expired(self))
    }
}
