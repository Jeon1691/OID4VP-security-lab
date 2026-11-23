//! Registry limits and policies (memory bounds, route-token uniqueness).

use std::time::Duration;

/// Default cap on `Pending` sessions: 32 times the largest lab scenario (128 concurrent
/// sessions).
///
/// Every pending session holds a private-key handle and its signed binding until it is
/// consumed or expires, and sessions are created by unauthenticated request-issuing traffic.
/// Without a cap that traffic could grow the registry without bound. At the cap, `insert`
/// refuses new sessions ([`InsertError::Capacity`](crate::InsertError::Capacity)); it never
/// evicts a pending one, because that would silently break a legitimate flow.
pub const DEFAULT_MAX_PENDING_SESSIONS: usize = 4096;

/// Default time a `Consumed` record is kept after its `expires_at`: ten minutes, two typical
/// five-minute request TTLs.
///
/// While the record exists, a replayed response is reported as a replay (evidence for the
/// replay scenarios, which re-post within seconds to minutes). After the window the record is
/// purged and a replay resolves as `NoCandidate`: still refused, just no longer labelled as a
/// replay. Until `expires_at` the session would be rejected anyway, so the window only has to
/// cover late replays.
pub const DEFAULT_CONSUMED_RETENTION: Duration = Duration::from_secs(600);

/// Whether several sessions may share one route token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePolicy {
    /// Unique-URI deployments: `insert` rejects a route token any held session (pending,
    /// consumed or expired) already uses, so an old response can never reach a new session.
    UniquePerSession,
    /// Shared-URI deployments (unique-kid, bounded-trial): sessions may share a route token.
    Shared,
}

/// Configuration of a [`MemoryRegistry`](crate::MemoryRegistry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryConfig {
    /// Maximum number of `Pending` sessions; see [`DEFAULT_MAX_PENDING_SESSIONS`].
    pub max_pending: usize,
    /// How long `Consumed` records outlive their `expires_at`; see
    /// [`DEFAULT_CONSUMED_RETENTION`].
    pub consumed_retention: Duration,
    /// Route-token sharing policy.
    pub route_policy: RoutePolicy,
}

impl Default for RegistryConfig {
    /// The hardened configuration: unique route token per session and the default bounds.
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING_SESSIONS,
            consumed_retention: DEFAULT_CONSUMED_RETENTION,
            route_policy: RoutePolicy::UniquePerSession,
        }
    }
}
