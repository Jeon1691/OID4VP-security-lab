//! Redis-backed authoritative session registry (G5, IMP-014).
//!
//! [`RedisRegistry`] implements [`session_core::SessionStore`] with the same semantics as
//! [`session_core::MemoryRegistry`] (the shared contract suite in `tests/contract.rs` runs
//! against both, and a differential property test compares them on random operation
//! sequences), but its state lives in Redis, so several workers (registry instances, each
//! with its own connection) can serve one set of sessions.
//!
//! # Data model
//!
//! All keys of one registry start with the hash-tagged namespace `{ns}:`, so they share one
//! hash slot.
//!
//! | Key | Type | Content |
//! | --- | --- | --- |
//! | `{ns}:s:<id>` | hash | `inc`, `rev`, `exp`, `state` (`pending`/`consumed`/`expired`), `route`, `kid`, `keyref`, binding (`mode`, `b1`..`b4`: the `session_info` inputs, then the `state`); once consumed also `digest`, `result` |
//! | `{ns}:incarnation` | string | counter; `INCR` gives every insert a fresh incarnation |
//! | `{ns}:pr:<route>` | zset | pending ids on a route, score = incarnation (insertion order) |
//! | `{ns}:pk:<kid>` | zset | pending ids with a `kid`, score = incarnation |
//! | `{ns}:pending` | zset | all pending ids, score = `exp` (capacity count, expiry sweep) |
//! | `{ns}:tr:<route>` / `{ns}:trk:<route>:<kid>` | hash | `consumed` / `expired` counts of held terminal sessions |
//! | `{ns}:purge` | zset | terminal ids, score = when purge may delete them (`0` for expired, `exp + retention` for consumed) |
//!
//! These mirror the indexes of `MemoryRegistry` one to one. Timestamps are absolute Unix
//! milliseconds, the unit `PEXPIREAT` takes. Redis-side key expiry is deliberately **not** used
//! for session state: it would skip the `Expired` state (a late response would read as unknown
//! instead of expired) and leave the indexes pointing at deleted records. Removal is explicit,
//! through `expire_due` and `purge`, exactly as in memory.
//!
//! # Time
//!
//! With [`TimeSource::RedisServer`] (the default, and the production setting) every script
//! reads the server clock (`TIME`) itself: `insert` computes `expires_at` from it, and
//! `resolve`, `claim`, `expire_due` and `purge` judge expiry by it at the moment they run. So a
//! claim that was dispatched in time but reaches Redis after the TTL is refused, as
//! `MemoryRegistry` refuses one that waits for its lock past the TTL, and all workers judge
//! expiry on one clock regardless of their own. [`TimeSource::Injected`] sends the caller's
//! clock reading instead; it exists for deterministic tests and lab scenarios and has the
//! in-transit caveat (a call is judged at its dispatch time).
//!
//! # Atomicity: Lua, not `MULTI`/`WATCH`
//!
//! Every state change (`insert`, `claim`, `expire_due`, `purge`) is one Lua script, and `resolve`
//! is one read-only script (`flags=no-writes`). Redis runs a script without interleaving any
//! other command, so `claim` reads the record, checks incarnation, state, TTL and revision, and
//! writes `Consumed` with the digest and result, and updates every index, as one indivisible
//! step: the compare-and-set and the result write are the same operation.
//!
//! `MULTI`/`WATCH` could express the same CAS, but: the decision (replay with
//! same/different response, expired, revision mismatch) needs the read values, so it would
//! take a `WATCH`, a read round trip, client-side logic and an `EXEC` that aborts whenever any
//! watched key changed; under a 128-way race every loser's `EXEC` aborts and must re-read to
//! learn it lost, which is more round trips and a retry loop exactly where contention is
//! highest. The script is one round trip with no retries, and its outcome is final.
//!
//! # Key material trust boundary
//!
//! Redis is trusted for the integrity and availability of session **state** (it is the
//! authority on pending/consumed, as the memory registry is in-process), but not with private
//! keys. The opaque key handle `K` is never serialized; `K` has no serde bound at all. Each
//! insert stores `K` in a process-local [`KeyTable`] under a random 128-bit key reference, and
//! Redis stores only that reference. `resolve` maps the reference back through the table and
//! checks that the table entry was registered for the same session id, so a reference swapped
//! inside Redis cannot hand out another session's key. A pending session whose key is not in
//! the local table fails closed ([`session_core::StoreUnavailable`]).
//!
//! Trade-off: every worker that resolves a session needs its key, so workers must share a
//! key table. In-process workers (the tests) share one [`KeyTable`]; workers in separate
//! processes would need a shared key service (KMS/HSM), which is out of scope for the lab.
//! What does go to Redis is not secret from the store: request bindings (`client_id`, nonce,
//! `response_uri`, which the wallet also sees), route tokens and `kid`s (routing hints, never
//! authentication), response digests and the validated results.
//!
//! # Failure behaviour (STATE-05)
//!
//! Every Redis error, timeout or undecodable reply is [`session_core::StoreUnavailable`] (or
//! the `Unavailable` variant of the operation's error). There is no in-memory fallback: a
//! registry that cannot reach Redis refuses every operation, so a response is never accepted
//! without the authoritative commit. A call waits at most two seconds for its reply. A call
//! that finds the connection dropped fails immediately and is not retried; the connection
//! manager then reconnects in the background (one retry after the first attempt, short
//! backoff), calls made meanwhile wait for that attempt and fail if it fails, and once Redis is
//! back the same registry works again.
//!
//! Index entries are cross-checked against their records (state `Pending`, route or `kid` equal
//! to the indexed value), in the script and again in Rust; a mismatch fails closed instead of
//! being resolved around. The local key table is bounded (`max_pending` +
//! [`KEY_TABLE_SLACK`]) and sheds keys past their TTL on every sweep before contacting Redis, so
//! it stays bounded during an outage.
//!
//! **Committed but unacknowledged.** A call whose script reached Redis has run in full, even if
//! the caller then sees `Unavailable` (reply timeout, connection lost before the reply) or
//! nothing at all (its future was dropped). For `claim` that means the session can be
//! `Consumed` in Redis while no caller was told: at-most-once still holds, and the caller,
//! having seen no success, rejects the response, so that session can no longer complete. For
//! `insert` the session can exist although the caller saw an error; its key is therefore kept
//! locally until the TTL. Only a refused connection proves a call was not sent.
//!
//! # Concurrency across workers, and why no lease
//!
//! The MVP state machine (`Pending -> Consumed` after validation) needs no `Reserved` state:
//! workers decrypt and validate in parallel without touching the store, and only the claim
//! writes. Because the claim is one atomic script that requires `Pending` at the resolved
//! origin, incarnation and revision, exactly one claim per session commits regardless of how many
//! workers race (tests: 2/16/128-way across two registries on separate connections); the losers
//! see `Replay`. A lease with fencing tokens would only be needed if the commit were not a
//! single atomic step (e.g. results written to a second system after the CAS) or to stop
//! duplicate decryption work; neither applies here.
//!
//! Candidates are bound to the record that issued them: the record's random key reference is
//! the candidate's origin token, and `claim` checks it before anything else, so a candidate from
//! another namespace (or registry) is `UnknownSession` even if id, incarnation and revision
//! coincide.
//!
//! Single Redis server only; the scripts build key names from the prefix instead of declaring
//! them in `KEYS`, so Redis Cluster is not supported (the shared hash tag keeps a port feasible).

mod codec;
mod keys;
mod registry;
mod scripts;

pub use keys::{KEY_TABLE_SLACK, KeyTable};
pub use registry::{RedisRegistry, SetupError, TimeSource};
