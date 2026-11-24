//! The store contract shared by the in-memory registry and the Redis one (crate `session-redis`).

use std::future::Future;

use protocol_model::SessionId;

use crate::route::{IngressHint, ResolutionStrategy};
use crate::session::{
    Candidate, ClaimError, InsertError, NewSession, ResolveError, ResponseDigest, SessionSnapshot,
    StoreUnavailable,
};

/// Authoritative session store, generic over the opaque key handle `K` and the validated
/// result `R` stored on commit.
///
/// Async because the production-shaped implementation (Redis) does network I/O and the
/// lab-server calls it from axum handlers. The futures are `Send`, so they can be awaited from
/// multi-threaded tokio tasks, and lazy: nothing happens until they are polled, so dropping an
/// unpolled future (a cancelled handler) changes nothing. Static dispatch only: callers are
/// generic over `S: SessionStore`.
///
/// Required call order for one incoming response: [`resolve`](Self::resolve), then trial
/// decryption and full validation by the caller, then [`claim`](Self::claim) with the
/// candidate. Neither a matching hint nor a successful decryption authenticates anything; only
/// `claim` after validation changes state. Error variants are internal evidence; see
/// [`ResolveError`] and [`ClaimError`].
pub trait SessionStore<K, R>: Send + Sync {
    /// Registers a session when its signed Authorization Request is issued.
    fn insert(
        &self,
        session: NewSession<K>,
    ) -> impl Future<Output = Result<SessionSnapshot<R>, InsertError>> + Send;

    /// Live candidates for an untrusted hint under `strategy`. Read-only.
    fn resolve(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
    ) -> impl Future<Output = Result<Vec<Candidate<K>>, ResolveError>> + Send;

    /// Atomically moves the candidate's session from `Pending` at the candidate's revision to
    /// `Consumed(result, digest)`. At most one claim per session ever succeeds.
    fn claim(
        &self,
        candidate: &Candidate<K>,
        digest: ResponseDigest,
        result: R,
    ) -> impl Future<Output = Result<SessionSnapshot<R>, ClaimError>> + Send;

    /// Current copy of a session, or `None` if unknown or purged.
    fn snapshot(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<SessionSnapshot<R>>, StoreUnavailable>> + Send;

    /// Moves every `Pending` session past its TTL to `Expired`; returns how many moved.
    fn expire_due(&self) -> impl Future<Output = Result<usize, StoreUnavailable>> + Send;

    /// Removes `Expired` sessions, and `Consumed` sessions whose retention window after
    /// `expires_at` has passed; returns how many were removed. Inside the window, replays keep
    /// being reported as such.
    fn purge(&self) -> impl Future<Output = Result<usize, StoreUnavailable>> + Send;
}
