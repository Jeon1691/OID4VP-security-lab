//! Server modes, configuration and startup errors.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use jose_hpke::MAX_COMPACT_JWE_LEN;
use protocol_model::ClientIdWire;
use session_core::{CandidateBudget, ResolutionStrategy};

/// Default request lifetime: five minutes, the typical request TTL session-core's consumed
/// retention window is sized for (`DEFAULT_CONSUMED_RETENTION` = two TTLs).
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// Default interval of the background expiry/purge sweep: a tenth of [`DEFAULT_SESSION_TTL`].
///
/// Correctness never depends on the sweep (session-core checks TTLs lazily in resolve, claim
/// and insert); it only bounds how long expired sessions and their request objects stay in
/// memory, here to at most 10% beyond their lifetime.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Room for the form encoding around the JWE: the `response=` name (9 bytes) plus slack for a
/// client that percent-encodes some of the base64url/`.` characters. Anything else is rejected
/// by the form check anyway.
const FORM_OVERHEAD_BYTES: usize = 4096;

/// Body limit of the response endpoints, enforced before any other check.
///
/// At least [`MAX_COMPACT_JWE_LEN`], as jose-hpke asks of the HTTP layer, so every JWE the
/// codec would accept still fits after form encoding; anything larger is refused with 413
/// before the body is parsed.
pub const MAX_RESPONSE_BODY_BYTES: usize = MAX_COMPACT_JWE_LEN + FORM_OVERHEAD_BYTES;

/// Synthetic Verifier `client_id` (OpenID4VP 1.1 §5.9.3 `decentralized_identifier` prefix).
///
/// The did:key of the SpruceID fixture key G0-C/G0-D already sign Request Objects with
/// (`tests/fixtures/spruce_verifier.jwk`), so adding JAR signing later does not change the
/// stored wire value.
pub const DEFAULT_CLIENT_ID: &str =
    "decentralized_identifier:did:key:zDnaeaDj3YpPR4JXos2kCCNPS86hdELeN5PZh97KGkoFzUtGn";

/// Loopback, OS-chosen port.
const DEFAULT_BIND: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Which route a session's `response_uri` points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// `POST /lab/v1/response/{token}`: one unguessable route token per session (unique-uri).
    Unique,
    /// `POST /lab/v1/response/shared`: one route for many sessions (research mode only).
    Shared,
}

/// Strategy of the shared research route. Fixed when the server starts, never per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRouteStrategy {
    /// Shared route, shared key and `kid` (the OIDF #792 shape): every live session is tried, up
    /// to the budget.
    BoundedTrial(CandidateBudget),
    /// Shared route, per-session key and `kid`: the JWE `kid` selects one session.
    UniqueKid,
}

impl SharedRouteStrategy {
    /// The session-core strategy served on the shared route.
    #[must_use]
    pub const fn resolution(self) -> ResolutionStrategy {
        match self {
            Self::BoundedTrial(budget) => ResolutionStrategy::BoundedTrial(budget),
            Self::UniqueKid => ResolutionStrategy::UniqueKid,
        }
    }
}

/// Server mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Default: unique-uri routes only; the shared route does not exist (404).
    Hardened,
    /// Adds the shared route with the given strategy. Loopback binds only (ADR-005). Unique-uri
    /// routes keep working as in hardened mode.
    Research(SharedRouteStrategy),
}

/// Lab server configuration.
#[derive(Debug, Clone)]
pub struct LabConfig {
    /// Server mode.
    pub mode: Mode,
    /// Listen address. Research mode requires a loopback address.
    pub bind: SocketAddr,
    /// `client_id` of every request object.
    pub client_id: ClientIdWire,
    /// Lifetime of each session from creation.
    pub session_ttl: Duration,
    /// Interval of the background expiry/purge sweep.
    pub sweep_interval: Duration,
}

impl LabConfig {
    /// `mode` on `127.0.0.1:0` with the default client id, TTL and sweep interval.
    ///
    /// # Panics
    /// Never: [`DEFAULT_CLIENT_ID`] is a valid `ClientIdWire`.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            bind: DEFAULT_BIND,
            client_id: ClientIdWire::new(DEFAULT_CLIENT_ID).expect("constant client_id is valid"),
            session_ttl: DEFAULT_SESSION_TTL,
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
        }
    }
}

/// Errors from [`crate::LabServer::start`].
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Research mode was asked to bind a non-loopback address. Checked before binding.
    #[error("research mode binds to loopback addresses only")]
    ResearchRequiresLoopback,
    /// The unspecified address (`0.0.0.0` / `::`) cannot appear in an exact `response_uri`.
    #[error("bind address must be a concrete IP, not the unspecified address")]
    UnspecifiedAddress,
    /// The sweep interval is zero.
    #[error("sweep interval must be non-zero")]
    ZeroSweepInterval,
    /// Binding or reading the listener address failed.
    #[error("bind failed: {0}")]
    Bind(#[from] std::io::Error),
    /// The OS random number generator failed while creating server keys.
    #[error("OS random number generator unavailable")]
    Rng,
}

/// Checks `config` before anything is bound.
pub(crate) fn check(config: &LabConfig) -> Result<(), StartError> {
    if matches!(config.mode, Mode::Research(_)) && !config.bind.ip().is_loopback() {
        return Err(StartError::ResearchRequiresLoopback);
    }
    if config.bind.ip().is_unspecified() {
        return Err(StartError::UnspecifiedAddress);
    }
    if config.sweep_interval.is_zero() {
        return Err(StartError::ZeroSweepInterval);
    }
    Ok(())
}
