//! Injected time source, so TTL behaviour is testable without sleeping.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock instant in whole milliseconds since the Unix epoch.
///
/// Milliseconds because that is the resolution a Redis-backed store (`PEXPIREAT`) works in, so
/// both implementations judge expiry on the same scale. Sub-millisecond parts of a TTL are
/// truncated, which can only shorten a session's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// From milliseconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_unix_millis(self) -> u64 {
        self.0
    }

    /// `self + duration`, saturating at the end of the representable range.
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(millis))
    }
}

/// Source of the current time for TTL decisions.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// The system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// A clock set before 1970 reads as the epoch itself; sessions created then expire as soon as
    /// the clock is corrected, never later.
    fn now(&self) -> Timestamp {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Timestamp::from_unix_millis(u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock that only moves when told to; for deterministic tests and scenario runs.
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock reading `start`.
    #[must_use]
    pub const fn new(start: Timestamp) -> Self {
        Self(AtomicU64::new(start.0))
    }

    /// Sets the current time (may move backwards, to model clock skew).
    pub fn set(&self, now: Timestamp) {
        self.0.store(now.0, Ordering::SeqCst);
    }

    /// Moves the clock forward by `duration`, saturating.
    pub fn advance(&self, duration: Duration) {
        let step = Timestamp(0).saturating_add(duration).0;
        // The closure always returns `Some`, so `try_update` cannot fail.
        let _ = self.0.try_update(Ordering::SeqCst, Ordering::SeqCst, |t| {
            Some(t.saturating_add(step))
        });
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}
