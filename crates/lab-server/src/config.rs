//! Server modes, configuration and startup errors.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use jose_hpke::MAX_COMPACT_JWE_LEN;
use protocol_model::ClientIdWire;
use session_core::{CandidateBudget, ResolutionStrategy};

use crate::jar::RequestSigningKey;
use crate::validate::MAX_CLIENT_ID_LEN;

/// Default request lifetime: five minutes, the typical request TTL session-core's consumed
/// retention window is sized for (`DEFAULT_CONSUMED_RETENTION` = two TTLs).
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// Default interval of the background expiry/purge sweep: a tenth of [`DEFAULT_SESSION_TTL`].
///
/// Correctness never depends on the sweep (session-core checks TTLs lazily in resolve, claim
/// and insert); it only bounds how long expired sessions and their request objects stay in
/// memory, here to at most 10% beyond their lifetime.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Default upper bound on one request, headers to response (config candidate, not normative).
///
/// Loopback requests finish in milliseconds: a full 1 MiB body arrives almost at once, and the
/// worst trial (256 candidates, one P-256 ECDH plus AEAD open each) takes well under a second
/// in a debug build. Ten seconds only cuts off clients that stall a request (slow or missing
/// body) while holding an in-flight slot; they are answered 408.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on requests in flight at once (config candidate, not normative): four times the
/// largest concurrent scenario (STATE-02, 128 POSTs). Above it the server answers 503 at once
/// instead of queueing, so overload is visible in results. `/health` is exempt.
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 512;

/// Default cap on HPKE trials running at once (config candidate, not normative).
///
/// Trials are CPU-bound and run on tokio's blocking pool; more of them than cores only adds
/// contention. Eight covers typical developer and CI machines while leaving the async workers
/// free, and bounds the CPU that concurrent unauthenticated POSTs can claim (each trial is at
/// most `MAX_CANDIDATE_BUDGET` attempts). Further trials wait for a slot.
pub const DEFAULT_MAX_CONCURRENT_DECRYPTIONS: usize = 8;

/// Default cap on accepted connections (config candidate, not normative): twice
/// [`DEFAULT_MAX_IN_FLIGHT_REQUESTS`], so idle keep-alive connections never use up request
/// capacity. Connections beyond it wait in the kernel backlog until one closes. It also bounds
/// connections that stall before sending headers, which the request limit and timeout cannot
/// see (no request exists yet). Keep it below the process file-descriptor limit.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2 * DEFAULT_MAX_IN_FLIGHT_REQUESTS;

/// Default time a client gets to deliver one complete set of request headers (config
/// candidate, not normative). It starts when the connection opens and again after each
/// response, so it also closes idle keep-alive connections.
///
/// Loopback clients send headers in microseconds; five seconds tolerates a stalled test
/// runner or a debugger pause while a connection that sends nothing, or dribbles bytes, frees
/// its [`DEFAULT_MAX_CONNECTIONS`] slot well within the request timeout's order of magnitude.
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Extra time beyond [`DEFAULT_REQUEST_TIMEOUT`] the shutdown drain waits.
const DRAIN_SLACK: Duration = Duration::from_secs(2);

/// Default graceful-shutdown drain deadline: every in-flight request ends within the request
/// timeout (or is answered 408), so the drain waits that long plus a little slack before it
/// stops waiting and closes commits.
pub const DEFAULT_SHUTDOWN_DRAIN: Duration = DEFAULT_REQUEST_TIMEOUT.saturating_add(DRAIN_SLACK);

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
/// (`tests/fixtures/spruce_verifier.jwk`). A server using this `client_id` must be given that
/// key as [`LabConfig::request_signing_key`], or wallets resolving the did:key refuse its
/// request objects; the key itself is never compiled in.
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
    /// Adds the shared route with the given strategy. Unique-uri routes keep working as in
    /// hardened mode.
    Research(SharedRouteStrategy),
}

/// Lab server configuration.
#[derive(Debug, Clone)]
pub struct LabConfig {
    /// Server mode.
    pub mode: Mode,
    /// Listen address. Must be loopback in every mode (`IpAddr::is_loopback`: `127.0.0.0/8` or
    /// `::1`). Lab policy: synthetic data, loopback only (ADR-005); serving anything else
    /// needs an explicit future ADR.
    pub bind: SocketAddr,
    /// `client_id` of every request object.
    pub client_id: ClientIdWire,
    /// Signs every request object (JAR). For a `decentralized_identifier:did:key:` client id it
    /// must be the key of that did:key; the server cannot check this, wallets do.
    pub request_signing_key: RequestSigningKey,
    /// Lifetime of each session from creation.
    pub session_ttl: Duration,
    /// Interval of the background expiry/purge sweep.
    pub sweep_interval: Duration,
    /// Upper bound on one request; see [`DEFAULT_REQUEST_TIMEOUT`].
    pub request_timeout: Duration,
    /// Requests in flight before 503; see [`DEFAULT_MAX_IN_FLIGHT_REQUESTS`].
    pub max_in_flight_requests: usize,
    /// HPKE trials at once; see [`DEFAULT_MAX_CONCURRENT_DECRYPTIONS`].
    pub max_concurrent_decryptions: usize,
    /// Accepted connections at once; see [`DEFAULT_MAX_CONNECTIONS`].
    pub max_connections: usize,
    /// Time to read one request's headers before the connection is closed; see
    /// [`DEFAULT_HEADER_READ_TIMEOUT`].
    pub header_read_timeout: Duration,
    /// Graceful-shutdown drain deadline; see [`DEFAULT_SHUTDOWN_DRAIN`].
    pub shutdown_drain: Duration,
}

impl LabConfig {
    /// `mode` on `127.0.0.1:0` with the default client id, TTL and sweep interval, signing
    /// request objects with `request_signing_key`.
    ///
    /// # Panics
    /// Never: [`DEFAULT_CLIENT_ID`] is a valid `ClientIdWire`.
    #[must_use]
    pub fn new(mode: Mode, request_signing_key: RequestSigningKey) -> Self {
        Self {
            mode,
            bind: DEFAULT_BIND,
            client_id: ClientIdWire::new(DEFAULT_CLIENT_ID).expect("constant client_id is valid"),
            request_signing_key,
            session_ttl: DEFAULT_SESSION_TTL,
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_in_flight_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            max_concurrent_decryptions: DEFAULT_MAX_CONCURRENT_DECRYPTIONS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            shutdown_drain: DEFAULT_SHUTDOWN_DRAIN,
        }
    }
}

/// Errors from [`crate::LabServer::start`].
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// A non-loopback bind address (including `0.0.0.0`, `::` and IPv4-mapped addresses, which
    /// `IpAddr::is_loopback` does not count as loopback). Checked before binding.
    #[error("the lab binds to loopback addresses only")]
    LoopbackOnly,
    /// `client_id` longer than `MAX_CLIENT_ID_LEN`.
    #[error("client_id exceeds the lab length limit")]
    ClientIdTooLong,
    /// A zero sweep interval, request timeout or concurrency limit.
    #[error("intervals, timeouts and limits must be non-zero")]
    ZeroLimit,
    /// Binding or reading the listener address failed.
    #[error("bind failed: {0}")]
    Bind(#[from] std::io::Error),
    /// The OS random number generator failed while creating server keys.
    #[error("OS random number generator unavailable")]
    Rng,
}

/// Checks `config` before anything is bound.
pub(crate) fn check(config: &LabConfig) -> Result<(), StartError> {
    if !config.bind.ip().is_loopback() {
        return Err(StartError::LoopbackOnly);
    }
    if config.client_id.as_str().len() > MAX_CLIENT_ID_LEN {
        return Err(StartError::ClientIdTooLong);
    }
    if config.sweep_interval.is_zero()
        || config.request_timeout.is_zero()
        || config.max_in_flight_requests == 0
        || config.max_concurrent_decryptions == 0
        || config.max_connections == 0
        || config.header_read_timeout.is_zero()
    {
        return Err(StartError::ZeroLimit);
    }
    Ok(())
}
