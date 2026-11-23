//! Session values handed across the registry boundary, and the errors it returns.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use protocol_model::{KeyId, RequestBinding, SessionId};

use crate::clock::Timestamp;
use crate::route::RouteToken;

/// Length of a [`ResponseDigest`]: the output size of SHA-256, the hash the caller is expected
/// to apply to the compact JWE it received.
pub const RESPONSE_DIGEST_BYTES: usize = 32;

/// Version of a session record, compared and bumped by every state transition (compare-and-set).
///
/// In the MVP a session transitions at most once (`Pending` to `Consumed` or `Expired`), so the
/// revision is `INITIAL` while pending and `INITIAL + 1` afterwards. It is part of the API now
/// so the claim contract already matches a versioned store (Redis, later lease phases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(u64);

impl Revision {
    /// Revision of a newly inserted session.
    pub const INITIAL: Self = Self(0);

    /// A revision with the given number (for stores that persist it).
    #[must_use]
    pub const fn new(revision: u64) -> Self {
        Self(revision)
    }

    /// The revision number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The revision after one more transition. Saturation is unreachable in the MVP, where a
    /// session transitions at most once.
    pub(crate) const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Caller-supplied digest of the encrypted response that consumed a session (e.g. SHA-256 of
/// the compact JWE). Kept with the commit so a later claim can be reported as an exact replay
/// of the same response or as a different response for an already consumed session.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseDigest([u8; RESPONSE_DIGEST_BYTES]);

impl ResponseDigest {
    /// Wraps a digest computed by the caller.
    #[must_use]
    pub const fn new(bytes: [u8; RESPONSE_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RESPONSE_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ResponseDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseDigest(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// MVP session state (Notion 02 §9, 06 §5). `Consumed` and `Expired` are terminal.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionState<R> {
    /// Awaiting a response; the only state in which a session is a candidate or claimable.
    Pending,
    /// A fully validated response was committed.
    Consumed {
        /// The caller's validated result.
        result: Arc<R>,
        /// Digest of the response that was committed.
        digest: ResponseDigest,
    },
    /// The TTL passed before any response was committed.
    Expired,
}

impl<R> SessionState<R> {
    /// `true` for [`SessionState::Pending`].
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// `true` for [`SessionState::Consumed`].
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        matches!(self, Self::Consumed { .. })
    }

    /// `true` for [`SessionState::Expired`].
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        matches!(self, Self::Expired)
    }
}

// Manual impl: `Arc<R>` is cloneable without `R: Clone`.
impl<R> Clone for SessionState<R> {
    fn clone(&self) -> Self {
        match self {
            Self::Pending => Self::Pending,
            Self::Consumed { result, digest } => Self::Consumed {
                result: Arc::clone(result),
                digest: *digest,
            },
            Self::Expired => Self::Expired,
        }
    }
}

/// A session to register when its signed Authorization Request is issued.
pub struct NewSession<K> {
    /// Lab-internal identifier; must be unique in the registry.
    pub id: SessionId,
    /// Exact values the request was signed with (feeds HPKE `session_info` later).
    pub binding: RequestBinding,
    /// Route token embedded in the request's `response_uri`.
    pub route_token: RouteToken,
    /// `kid` of the advertised response-encryption key, if it has one.
    pub kid: Option<KeyId>,
    /// Opaque private-key handle used to trial-decrypt responses for this session.
    pub key: K,
    /// Lifetime from insertion; millisecond resolution.
    pub ttl: Duration,
}

impl<K> fmt::Debug for NewSession<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSession")
            .field("id", &self.id)
            .field("binding", &self.binding)
            .field("route_token", &self.route_token)
            .field("kid", &self.kid)
            .field("key", &format_args!("<opaque>"))
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// A pending session that an ingress hint matched: everything needed to trial-decrypt the
/// response and then claim the session at the revision seen here.
///
/// A copy taken under the registry lock; it never reflects or causes later changes. The key is
/// shared read-only (`Arc`), and nothing here can modify the authoritative record.
pub struct Candidate<K> {
    pub(crate) id: SessionId,
    pub(crate) binding: RequestBinding,
    pub(crate) kid: Option<KeyId>,
    pub(crate) key: Arc<K>,
    pub(crate) revision: Revision,
    pub(crate) expires_at: Timestamp,
}

impl<K> Candidate<K> {
    /// Session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Signed request values, for HPKE `session_info` and presentation validation.
    #[must_use]
    pub const fn binding(&self) -> &RequestBinding {
        &self.binding
    }

    /// `kid` of the session's key.
    #[must_use]
    pub const fn kid(&self) -> Option<&KeyId> {
        self.kid.as_ref()
    }

    /// Private-key handle for trial decryption.
    #[must_use]
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Revision to pass to `claim`.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// When the session expires.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl<K> Clone for Candidate<K> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            binding: self.binding.clone(),
            kid: self.kid.clone(),
            key: Arc::clone(&self.key),
            revision: self.revision,
            expires_at: self.expires_at,
        }
    }
}

impl<K: PartialEq> PartialEq for Candidate<K> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.binding == other.binding
            && self.kid == other.kid
            && self.key == other.key
            && self.revision == other.revision
            && self.expires_at == other.expires_at
    }
}

impl<K> fmt::Debug for Candidate<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("id", &self.id)
            .field("binding", &self.binding)
            .field("kid", &self.kid)
            .field("key", &format_args!("<opaque>"))
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Point-in-time copy of a session record, for results and evidence. Carries no key material.
pub struct SessionSnapshot<R> {
    pub(crate) id: SessionId,
    pub(crate) binding: RequestBinding,
    pub(crate) route_token: RouteToken,
    pub(crate) kid: Option<KeyId>,
    pub(crate) revision: Revision,
    pub(crate) expires_at: Timestamp,
    pub(crate) state: SessionState<R>,
}

impl<R> SessionSnapshot<R> {
    /// Session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Signed request values.
    #[must_use]
    pub const fn binding(&self) -> &RequestBinding {
        &self.binding
    }

    /// Route token of the session's `response_uri`.
    #[must_use]
    pub const fn route_token(&self) -> &RouteToken {
        &self.route_token
    }

    /// `kid` of the session's key.
    #[must_use]
    pub const fn kid(&self) -> Option<&KeyId> {
        self.kid.as_ref()
    }

    /// Revision at the time of the snapshot.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// When the session expires.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// State at the time of the snapshot.
    #[must_use]
    pub const fn state(&self) -> &SessionState<R> {
        &self.state
    }
}

impl<R> Clone for SessionSnapshot<R> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            binding: self.binding.clone(),
            route_token: self.route_token.clone(),
            kid: self.kid.clone(),
            revision: self.revision,
            expires_at: self.expires_at,
            state: self.state.clone(),
        }
    }
}

impl<R: fmt::Debug> fmt::Debug for SessionSnapshot<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSnapshot")
            .field("id", &self.id)
            .field("binding", &self.binding)
            .field("route_token", &self.route_token)
            .field("kid", &self.kid)
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

/// The store could not be read or written (for the memory registry: a poisoned lock after a
/// panic inside a critical section; for a networked store: a backend failure). Callers must
/// treat it as "not consumed" and reject the response, never as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("session store unavailable")]
pub struct StoreUnavailable;

/// Errors from inserting a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InsertError {
    /// A session with this id already exists.
    #[error("duplicate session id")]
    DuplicateSession,
    /// The TTL is zero at millisecond resolution, so the session would be born expired.
    #[error("session TTL must be at least one millisecond")]
    ZeroTtl,
    /// See [`StoreUnavailable`].
    #[error(transparent)]
    Unavailable(#[from] StoreUnavailable),
}

/// Errors from resolving an ingress hint to candidates. All of them mean "do not decrypt".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// No session matches the hint.
    #[error("no candidate session")]
    NoCandidate,
    /// The unique-kid strategy needs a `kid` in the JWE header.
    #[error("unique-kid resolution needs a kid")]
    MissingKid,
    /// A unique strategy matched more than one live session: the deployment broke the
    /// uniqueness the strategy relies on, so no session is chosen.
    #[error("{found} sessions match a hint that must be unique")]
    NotUnique { found: usize },
    /// Bounded trial: more live sessions than the budget. The response is refused as a whole.
    #[error("{found} candidate sessions exceed the budget of {budget}")]
    CandidateBudgetExceeded { found: usize, budget: usize },
    /// The session the unique hint names has expired.
    #[error("session expired")]
    SessionExpired,
    /// The session the unique hint names was already consumed.
    #[error("session already consumed")]
    Replay,
    /// See [`StoreUnavailable`].
    #[error(transparent)]
    Unavailable(#[from] StoreUnavailable),
}

/// Errors from claiming a session. None of them change the session, except that a claim
/// arriving after the TTL records the expiry it observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    /// No such session (never inserted, or purged).
    #[error("unknown session")]
    UnknownSession,
    /// The session was already consumed. `same_response` tells an exact replay of the committed
    /// response apart from a different response for the same session.
    #[error("session already consumed (same response: {same_response})")]
    Replay { same_response: bool },
    /// The session expired before the claim.
    #[error("session expired")]
    SessionExpired,
    /// The session is pending but at a different revision than the caller resolved.
    #[error("revision mismatch: expected {expected:?}, actual {actual:?}")]
    RevisionMismatch {
        expected: Revision,
        actual: Revision,
    },
    /// See [`StoreUnavailable`].
    #[error(transparent)]
    Unavailable(#[from] StoreUnavailable),
}
