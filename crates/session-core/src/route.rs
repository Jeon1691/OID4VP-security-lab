//! Untrusted ingress hints and the strategies that turn them into candidate sessions (IMP-007).

use std::fmt;
use std::hash::{Hash, Hasher};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use protocol_model::KeyId;

/// Random bytes in a [`RouteToken`]: 128 bits.
///
/// The token is the unguessable part of a capability-style `response_uri` (W3C TAG, "Good
/// Practices for Capability URLs"), so its entropy is what stops a third party from steering a
/// response to someone else's session. 128 bits keeps online guessing infeasible even across
/// many live sessions, and is twice the 64-bit floor OWASP sets for session identifiers.
pub const ROUTE_TOKEN_BYTES: usize = 16;

/// Length of the unpadded base64url form of a token (6 bits per character, rounded up).
const ROUTE_TOKEN_ENCODED_LEN: usize = (ROUTE_TOKEN_BYTES * 8).div_ceil(6);

/// Encoded characters `Debug` shows: 24 bits, enough to tell log lines apart, while the
/// remaining 104 bits keep a logged prefix useless for guessing the token.
const ROUTE_TOKEN_DEBUG_PREFIX: usize = 4;

/// Largest [`CandidateBudget`] accepted: twice the largest scenario size (128 sessions).
///
/// Every candidate costs the verifier one trial decryption (a P-256 ECDH plus an AEAD open),
/// so the budget is the amplification factor one unauthenticated POST can buy. A hard ceiling
/// keeps a misconfigured research run from turning into an unbounded CPU sink.
pub const MAX_CANDIDATE_BUDGET: usize = 256;

/// Errors from creating or parsing a [`RouteToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteTokenError {
    /// The operating system random number generator failed.
    #[error("OS random number generator unavailable")]
    Rng,
    /// Not exactly [`ROUTE_TOKEN_BYTES`] bytes of canonical, unpadded base64url.
    #[error("malformed route token")]
    Malformed,
}

/// Per-request unguessable path segment of the `response_uri` (unique-uri strategy), or a token
/// shared by every session behind one endpoint (shared-URI strategies).
///
/// A routing key only: knowing it is never authentication, and a response that arrives on the
/// right route still has to decrypt and validate. It is still treated like a capability:
///
/// * `Debug` shows only a short prefix, because the token ends up in logs and evidence files
///   and a leaked token lets anyone aim forged or replayed responses at that session.
/// * There is no `Display`; [`RouteToken::to_url_segment`] is the one explicit way to get the
///   full value, for building the `response_uri`.
/// * Equality has no early exit, so comparison time does not depend on where tokens differ.
#[derive(Clone)]
pub struct RouteToken([u8; ROUTE_TOKEN_BYTES]);

impl RouteToken {
    /// A fresh token from the OS CSPRNG.
    ///
    /// # Errors
    /// [`RouteTokenError::Rng`] if the operating system cannot provide randomness.
    pub fn generate() -> Result<Self, RouteTokenError> {
        let mut bytes = [0u8; ROUTE_TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RouteTokenError::Rng)?;
        Ok(Self(bytes))
    }

    /// Parses the path segment of an incoming request.
    ///
    /// # Errors
    /// [`RouteTokenError::Malformed`] unless `segment` is exactly the unpadded base64url
    /// encoding of [`ROUTE_TOKEN_BYTES`] bytes (non-canonical trailing bits are rejected).
    pub fn parse(segment: &str) -> Result<Self, RouteTokenError> {
        // Length first, so oversized attacker input is never decoded.
        if segment.len() != ROUTE_TOKEN_ENCODED_LEN {
            return Err(RouteTokenError::Malformed);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|_| RouteTokenError::Malformed)?;
        let bytes = <[u8; ROUTE_TOKEN_BYTES]>::try_from(decoded.as_slice())
            .map_err(|_| RouteTokenError::Malformed)?;
        Ok(Self(bytes))
    }

    /// The full token as an unpadded base64url path segment.
    #[must_use]
    pub fn to_url_segment(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl PartialEq for RouteToken {
    fn eq(&self, other: &Self) -> bool {
        // Accumulate every byte difference instead of returning at the first mismatch. Best
        // effort (no formal constant-time guarantee); lookups go through a randomly keyed hash
        // first, so this only matters for the final comparison inside a bucket.
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl Eq for RouteToken {}

impl Hash for RouteToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for RouteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = self.to_url_segment();
        let prefix = encoded.get(..ROUTE_TOKEN_DEBUG_PREFIX).unwrap_or_default();
        write!(f, "RouteToken({prefix}…)")
    }
}

/// What the verifier knows about an incoming encrypted response before decrypting it.
///
/// Both fields are attacker-controlled: the route token is copied from the request path and the
/// `kid` from the unauthenticated JWE protected header. They only narrow the set of sessions to
/// try; they never establish which session the response belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressHint {
    /// Token from the request path the response was posted to.
    pub route_token: RouteToken,
    /// `kid` from the JWE protected header, if present.
    pub kid: Option<KeyId>,
}

impl IngressHint {
    /// A hint from the request route and the optional JWE `kid`.
    #[must_use]
    pub const fn new(route_token: RouteToken, kid: Option<KeyId>) -> Self {
        Self { route_token, kid }
    }
}

/// Errors from [`CandidateBudget::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// A budget of zero could never match a session.
    #[error("candidate budget must be at least 1")]
    Zero,
    /// Above [`MAX_CANDIDATE_BUDGET`].
    #[error("candidate budget {requested} exceeds maximum {maximum}")]
    AboveMaximum { requested: usize, maximum: usize },
}

/// Maximum number of sessions a bounded-trial resolution may return for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateBudget(usize);

impl CandidateBudget {
    /// # Errors
    /// Zero, or above [`MAX_CANDIDATE_BUDGET`].
    pub const fn new(budget: usize) -> Result<Self, BudgetError> {
        if budget == 0 {
            Err(BudgetError::Zero)
        } else if budget > MAX_CANDIDATE_BUDGET {
            Err(BudgetError::AboveMaximum {
                requested: budget,
                maximum: MAX_CANDIDATE_BUDGET,
            })
        } else {
            Ok(Self(budget))
        }
    }

    /// The budget.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// How an [`IngressHint`] is turned into candidate sessions.
///
/// Every strategy requires the session's route token to equal the hint's, and when the hint
/// carries a `kid`, the session's `kid` to equal it (a session advertised without `kid` then does
/// not match). Only `Pending`, unexpired sessions are ever candidates. When none is live but a
/// consumed or expired session matches, the error says so (`Replay` / `SessionExpired`).
///
/// The strategy is fixed per route by the deployment, never chosen per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    /// Hardened default: the route token is unique per request, so at most one session matches.
    /// Uniqueness is checked on the route token alone, before the attacker-chosen `kid` filter,
    /// so a `kid` cannot mask a duplicated route.
    UniqueUri,
    /// Shared `response_uri`, per-session key: the hint's `kid` selects at most one session.
    /// Uniqueness is checked on the `kid` alone, before the (equally attacker-chosen) route.
    UniqueKid,
    /// Research mode only (shared URI and shared `kid`, loopback research route): every live
    /// session on the route is a candidate, up to the budget. More live sessions than the
    /// budget is an error, never a silent truncation, because testing only the first K would
    /// drop the right session. The caller tries every candidate; more than one that decrypts
    /// and validates is an integrity failure (reject, claim nothing, record evidence).
    BoundedTrial(CandidateBudget),
}
