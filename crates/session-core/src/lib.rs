//! Session resolution and the authoritative atomic session registry (IMP-007, IMP-011, IMP-012).
//!
//! Covers unique-uri / unique-kid / bounded-trial candidate resolution and the MVP
//! `Pending -> Consumed(result)` compare-and-set state machine. See Notion 02 · Architecture §8-9.
//!
//! # Flow for one encrypted response
//!
//! ```text
//! insert(NewSession)            when the signed Authorization Request is issued
//! resolve(IngressHint, strategy) before decryption, from untrusted hints only
//!   -> caller trial-decrypts each Candidate with its key, validates the presentation
//! claim(id, revision, digest, result)   only after full validation; atomic, at most once
//! ```
//!
//! * Hints (route token, JWE `kid`) are never authentication; they only limit which sessions
//!   are tried. Successful decryption is not holder authentication either.
//! * A failed decryption or validation must not touch the store: the caller simply does not
//!   claim, and the session stays `Pending` and claimable.
//! * Expired sessions are never returned as candidates, so no decryption is attempted for them.
//!
//! # State machine (MVP)
//!
//! ```text
//! Pending --claim(rev) after validation--> Consumed(result, digest)   (terminal; later claims: Replay)
//! Pending --TTL elapsed----------------->  Expired                    (terminal; purgeable)
//! ```
//!
//! Every transition bumps the session's [`Revision`]. Reserved / lease / fencing states are out of
//! scope until the Redis phase.
//!
//! # Sync or async
//!
//! [`SessionStore`] is async (`impl Future + Send` in the trait), because the Redis store will do
//! network I/O and the lab-server awaits it in axum handlers. [`MemoryRegistry`] does no I/O, so
//! its inherent methods are synchronous (a `std::sync::RwLock` that is never held across an
//! `.await`) and its trait impl returns ready futures. Tests and the property test use the sync
//! methods directly; one concurrency test goes through the trait on a multi-thread runtime.
//!
//! Key material is the opaque type parameter `K` (the lab-server plugs in its jose-hpke private
//! key handle), so this crate depends on neither jose-hpke nor HTTP.

mod clock;
mod memory;
mod route;
mod session;
mod store;

pub use clock::{Clock, ManualClock, SystemClock, Timestamp};
pub use memory::MemoryRegistry;
pub use route::{
    BudgetError, CandidateBudget, IngressHint, MAX_CANDIDATE_BUDGET, ROUTE_TOKEN_BYTES,
    ResolutionStrategy, RouteToken, RouteTokenError,
};
pub use session::{
    Candidate, ClaimError, InsertError, NewSession, RESPONSE_DIGEST_BYTES, ResolveError,
    ResponseDigest, Revision, SessionSnapshot, SessionState, StoreUnavailable,
};
pub use store::SessionStore;
