//! The store contract shared by the in-memory registry and the later Redis implementation.

use std::future::Future;

use protocol_model::SessionId;

use crate::route::{IngressHint, ResolutionStrategy};
use crate::session::{
    Candidate, ClaimError, InsertError, NewSession, ResolveError, ResponseDigest, Revision,
    SessionSnapshot, StoreUnavailable,
};

/// Authoritative session store, generic over the opaque key handle `K` and the validated
/// result `R` stored on commit.
///
/// Async because the production-shaped implementation (Redis) does network I/O and the
/// lab-server calls it from axum handlers. The futures are `Send`, so they can be awaited from
/// multi-threaded tokio tasks. Static dispatch only: callers are generic over `S: SessionStore`.
///
/// Required call order for one incoming response: [`resolve`](Self::resolve), then trial
/// decryption and full validation by the caller, then [`claim`](Self::claim) with the
/// candidate's revision. Neither a matching hint nor a successful decryption authenticates
/// anything; only `claim` after validation changes state.
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

    /// Atomically moves the session from `Pending` at `expected` to `Consumed(result, digest)`.
    /// At most one claim per session ever succeeds.
    fn claim(
        &self,
        id: &SessionId,
        expected: Revision,
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

    /// Removes `Expired` sessions; returns how many were removed. `Consumed` sessions are kept so
    /// that replays keep being reported as such.
    fn purge_expired(&self) -> impl Future<Output = Result<usize, StoreUnavailable>> + Send;
}
