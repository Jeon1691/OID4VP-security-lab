//! [`RedisRegistry`]: the [`SessionStore`] backed by one Redis server.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use protocol_model::{KeyId, SessionId};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, Script};
use serde::Serialize;
use serde::de::DeserializeOwned;
use session_core::{
    Candidate, ClaimError, Clock, IngressHint, InsertError, NewSession, RegistryConfig,
    ResolutionStrategy, ResolveError, ResponseDigest, Revision, RoutePolicy, SessionSnapshot,
    SessionState, SessionStore, StoreUnavailable, Timestamp,
};

use crate::codec::{self, Fields, Record, Reply};
use crate::keys::{KEY_TABLE_SLACK, KeyTable, new_key_ref};
use crate::scripts::{RECORD_FIELDS, SCRIPTS};

/// How long one Redis call may take before it fails closed. Loopback Redis answers in well
/// under a millisecond and the heaviest script (a capacity-triggered sweep over
/// `max_pending` sessions) in milliseconds; two seconds leaves wide headroom and still fails
/// far inside the lab-server's 10 s request timeout.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long one TCP connect to Redis may take. Loopback connects are immediate; one second
/// bounds the wait when the server is gone and the port does not answer.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

/// Reconnect behaviour of the connection manager. A call that finds the connection dropped
/// fails at once (it is never retried, so nothing is sent twice); the manager then reconnects
/// in the background with up to `RECONNECT_RETRIES` further attempts after the first, backing
/// off between `RECONNECT_MIN_DELAY` and `RECONNECT_MAX_DELAY`. Calls made meanwhile wait for
/// that attempt and fail if it fails, so while Redis is down a call fails within about two
/// connect timeouts plus the delay, and a restarted Redis is picked up without a new registry.
const RECONNECT_RETRIES: usize = 1;
const RECONNECT_MIN_DELAY: Duration = Duration::from_millis(50);
const RECONNECT_MAX_DELAY: Duration = Duration::from_millis(200);

/// Records a unique strategy needs back from `resolve`: whether there are zero, one or more
/// live matches is all it decides on.
const UNIQUE_LIMIT: usize = 2;

/// Longest namespace accepted. Key names repeat it, so it is kept short; 64 characters
/// is ample for a run identifier.
const MAX_NAMESPACE_LEN: usize = 64;

/// Whether a failed call can have reached Redis.
enum Outcome {
    /// The connection was refused: nothing was sent.
    NotSent,
    /// Anything else: the script may have run.
    Unknown,
}

/// Errors from [`RedisRegistry::connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// The namespace is empty, longer than 64 characters, or not `[A-Za-z0-9_-]`.
    #[error("invalid namespace")]
    InvalidNamespace,
    /// The Redis URL did not parse. (The URL is not repeated: it may carry a password.)
    #[error("invalid Redis URL")]
    InvalidUrl,
    /// Redis could not be reached.
    #[error(transparent)]
    Unavailable(#[from] StoreUnavailable),
}

/// Authoritative session registry in Redis, for several workers (registry instances, each
/// with its own connection) that share one session state. See the [crate docs](crate) for the
/// data model, the scripts and the key-material trust boundary.
///
/// Every Redis or decoding failure is [`StoreUnavailable`]; there is no fallback store.
pub struct RedisRegistry<K, R> {
    conn: ConnectionManager,
    /// `{<namespace>}:`, the hash-tagged prefix of every key.
    prefix: String,
    clock: Arc<dyn Clock>,
    config: RegistryConfig,
    keys: KeyTable<K>,
    // Results are serialized into Redis, never held: no `R` value lives in the registry.
    _results: PhantomData<fn(R) -> R>,
}

impl<K, R> RedisRegistry<K, R> {
    /// Connects to `url` and serves sessions under `namespace`, judging TTLs by `clock`.
    ///
    /// Registries with the same namespace on the same server are workers of one registry and
    /// must use the same `config`. `keys` holds the private-key handles; share it between
    /// registries that should resolve each other's sessions.
    ///
    /// # Errors
    /// See [`SetupError`].
    pub async fn connect(
        url: &str,
        namespace: &str,
        clock: Arc<dyn Clock>,
        config: RegistryConfig,
        keys: KeyTable<K>,
    ) -> Result<Self, SetupError> {
        let valid = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
        if namespace.is_empty()
            || namespace.len() > MAX_NAMESPACE_LEN
            || !namespace.chars().all(valid)
        {
            return Err(SetupError::InvalidNamespace);
        }
        let client = Client::open(url).map_err(|_| SetupError::InvalidUrl)?;
        let manager_config = ConnectionManagerConfig::new()
            .set_response_timeout(Some(RESPONSE_TIMEOUT))
            .set_connection_timeout(Some(CONNECTION_TIMEOUT))
            .set_number_of_retries(RECONNECT_RETRIES)
            .set_min_delay(RECONNECT_MIN_DELAY)
            .set_max_delay(RECONNECT_MAX_DELAY);
        let conn = ConnectionManager::new_with_config(client, manager_config)
            .await
            .map_err(|_| StoreUnavailable)?;
        Ok(Self {
            conn,
            prefix: format!("{{{namespace}}}:"),
            clock,
            config,
            keys,
            _results: PhantomData,
        })
    }

    /// The key table this registry resolves keys from.
    #[must_use]
    pub const fn key_table(&self) -> &KeyTable<K> {
        &self.keys
    }

    fn now(&self) -> Timestamp {
        codec::clamp(self.clock.now())
    }

    fn millis(d: Duration) -> u64 {
        codec::clamp(Timestamp::from_unix_millis(0).saturating_add(d)).as_unix_millis()
    }

    /// Runs `script` with the prefix as `ARGV[1]` followed by `args`.
    async fn run(&self, script: &Script, args: &[&[u8]]) -> Result<Fields, StoreUnavailable> {
        self.invoke(script, args)
            .await
            .map_err(|_| StoreUnavailable)
    }

    /// Like [`run`](Self::run), but tells whether the call can have reached Redis. Only a
    /// refused connection proves it did not: the script was then never sent (a `NOSCRIPT`
    /// reload is not an exception: `NOSCRIPT` means the script did not run either). Any other
    /// error (timeout, dropped connection, bad reply) may have followed a script that ran.
    async fn invoke(&self, script: &Script, args: &[&[u8]]) -> Result<Fields, Outcome> {
        let mut invocation = script.prepare_invoke();
        invocation.arg(self.prefix.as_str());
        for a in args {
            invocation.arg(*a);
        }
        let mut conn = self.conn.clone();
        let reply: Reply = invocation.invoke_async(&mut conn).await.map_err(|e| {
            if e.is_connection_refusal() {
                Outcome::NotSent
            } else {
                Outcome::Unknown
            }
        })?;
        Ok(Fields::new(reply))
    }

    /// Drops local keys the store reported as no longer needed.
    fn forget(&self, refs: &[String]) {
        self.keys.remove(refs.iter().map(String::as_str));
    }

    async fn insert_impl(&self, session: NewSession<K>) -> Result<SessionSnapshot<R>, InsertError> {
        let now = self.now();
        let expires_at = codec::clamp(now.saturating_add(session.ttl));
        if expires_at <= now {
            return Err(InsertError::ZeroTtl);
        }
        let NewSession {
            id,
            binding,
            route_token,
            kid,
            key,
            ttl: _,
        } = session;
        let key_ref = new_key_ref()?;
        // The key is in the table before the record is visible in Redis, so another worker
        // never sees a pending session whose key it cannot find. It is removed again when
        // Redis rejected the insert or it was provably never sent. After any other error, or a
        // cancelled call, the script may still have run, so the key stays until `purge` /
        // `expire_due` drop it at its TTL; the table cap bounds how many such keys pile up.
        let cap = self.config.max_pending.saturating_add(KEY_TABLE_SLACK);
        self.keys
            .insert(key_ref.clone(), (id.clone(), expires_at, key), cap, now)?;
        let route = route_token.to_url_segment();
        let [mode, b1, b2, b3] = codec::encode_binding(&binding);
        let unique = if self.config.route_policy == RoutePolicy::UniquePerSession {
            "1"
        } else {
            "0"
        };
        let (now_s, exp_s, max_s) = (
            now.as_unix_millis().to_string(),
            expires_at.as_unix_millis().to_string(),
            self.config.max_pending.to_string(),
        );
        let kid_s = kid.as_ref().map_or("", KeyId::as_str);
        let args: [&[u8]; 12] = [
            id.as_bytes(),
            now_s.as_bytes(),
            exp_s.as_bytes(),
            route.as_bytes(),
            kid_s.as_bytes(),
            key_ref.as_bytes(),
            unique.as_bytes(),
            max_s.as_bytes(),
            mode.as_bytes(),
            b1.as_bytes(),
            b2.as_bytes(),
            b3.as_bytes(),
        ];
        let mut f = match self.invoke(&SCRIPTS.insert, &args).await {
            Ok(f) => f,
            Err(Outcome::NotSent) => {
                self.forget(&[key_ref]);
                return Err(StoreUnavailable.into());
            }
            Err(Outcome::Unknown) => return Err(StoreUnavailable.into()),
        };
        match f.text()?.as_str() {
            "ok" => {
                let _incarnation = f.number()?;
                self.forget(&f.rest()?);
                Ok(SessionSnapshot::from_store_record(
                    id,
                    binding,
                    route_token,
                    kid,
                    Revision::INITIAL,
                    expires_at,
                    SessionState::Pending,
                ))
            }
            "capacity" => {
                self.forget(&f.rest()?);
                self.forget(&[key_ref]);
                let limit = self.config.max_pending;
                Err(InsertError::Capacity { limit })
            }
            "duplicate_session" => {
                self.forget(&[key_ref]);
                Err(InsertError::DuplicateSession)
            }
            "duplicate_route" => {
                self.forget(&[key_ref]);
                Err(InsertError::DuplicateRoute)
            }
            _ => Err(StoreUnavailable.into()),
        }
    }

    async fn resolve_impl(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
    ) -> Result<Vec<Candidate<K>>, ResolveError> {
        let route = hint.route_token.to_url_segment();
        let route_kid = |k: &KeyId| format!("trk:{route}:{}", k.as_str());
        // Same index and terminal counts as `MemoryRegistry`: uniqueness is judged on the
        // route (unique-uri, bounded-trial) or the kid (unique-kid) alone, before the other,
        // equally attacker-chosen hint is consulted.
        let hint_kid = hint.kid.as_ref().map(KeyId::as_str);
        let (kind, value, counts, due_route, filter_kid, limit) = match strategy {
            ResolutionStrategy::UniqueUri => (
                "pr",
                route.as_str(),
                format!("tr:{route}"),
                "",
                "",
                UNIQUE_LIMIT,
            ),
            ResolutionStrategy::UniqueKid => {
                let kid = hint.kid.as_ref().ok_or(ResolveError::MissingKid)?;
                (
                    "pk",
                    kid.as_str(),
                    route_kid(kid),
                    route.as_str(),
                    "",
                    UNIQUE_LIMIT,
                )
            }
            ResolutionStrategy::BoundedTrial(budget) => (
                "pr",
                route.as_str(),
                hint.kid
                    .as_ref()
                    .map_or_else(|| format!("tr:{route}"), route_kid),
                "",
                hint_kid.unwrap_or(""),
                // One more than the budget is enough to tell "over budget".
                budget.get().saturating_add(1),
            ),
        };
        let now_ts = self.now();
        let now = now_ts.as_unix_millis().to_string();
        let limit_s = limit.to_string();
        let args: [&[u8]; 7] = [
            kind.as_bytes(),
            value.as_bytes(),
            counts.as_bytes(),
            now.as_bytes(),
            limit_s.as_bytes(),
            due_route.as_bytes(),
            filter_kid.as_bytes(),
        ];
        let mut f = self.run(&SCRIPTS.resolve, &args).await?;
        let (consumed, expired) = (f.number()?, f.number()?);
        let saw_due = f.text()? == "1";
        let live = usize::try_from(f.number()?).map_err(|_| StoreUnavailable)?;
        let mut records = Vec::new();
        while !f.is_done() {
            let id = codec::session_id(f.text()?)?;
            let record = Record::read(&mut f)?.ok_or(StoreUnavailable)?;
            // The script already refused an index entry that does not match its record; check
            // again here, so a reply that disagrees with the index is never trusted either.
            let consistent = record.state == "pending"
                && !record.is_due(now_ts)
                && match kind {
                    "pr" => record.route == hint.route_token,
                    _ => record.kid.as_ref().map(KeyId::as_str) == Some(value),
                }
                && (filter_kid.is_empty() || record.kid.as_ref().map(KeyId::as_str) == hint_kid);
            if !consistent {
                return Err(StoreUnavailable.into());
            }
            records.push((id, record));
        }
        if records.len() != live.min(limit) {
            return Err(StoreUnavailable.into());
        }
        if live == 0 {
            return Err(if consumed > 0 {
                ResolveError::Replay
            } else if expired > 0 || saw_due {
                ResolveError::SessionExpired
            } else {
                ResolveError::NoCandidate
            });
        }
        let kid_matches = |r: &Record| hint.kid.as_ref().is_none_or(|k| r.kid.as_ref() == Some(k));
        let chosen = match strategy {
            ResolutionStrategy::UniqueUri | ResolutionStrategy::UniqueKid if live > 1 => {
                return Err(ResolveError::NotUnique { found: live });
            }
            // Only now the secondary hint: the kid on a unique route, the route for a unique kid.
            ResolutionStrategy::UniqueUri if !kid_matches(&records[0].1) => {
                return Err(ResolveError::NoCandidate);
            }
            ResolutionStrategy::UniqueKid if records[0].1.route != hint.route_token => {
                return Err(ResolveError::NoCandidate);
            }
            ResolutionStrategy::BoundedTrial(budget) if live > budget.get() => {
                return Err(ResolveError::CandidateBudgetExceeded {
                    found: live,
                    budget: budget.get(),
                });
            }
            _ => records,
        };
        chosen
            .into_iter()
            .map(|(id, r)| {
                let key = self.keys.get(&r.key_ref, &id)?;
                Ok(Candidate::from_store_record(
                    id,
                    r.incarnation,
                    r.binding,
                    r.kid,
                    key,
                    r.revision,
                    r.expires_at,
                ))
            })
            .collect()
    }

    async fn claim_impl(
        &self,
        candidate: &Candidate<K>,
        digest: ResponseDigest,
        result: R,
    ) -> Result<SessionSnapshot<R>, ClaimError>
    where
        R: Serialize,
    {
        // A result that cannot be stored is never committed.
        let encoded = serde_json::to_vec(&result).map_err(|_| StoreUnavailable)?;
        let now = self.now();
        let (inc, rev, now_s, retention) = (
            candidate.incarnation().to_string(),
            candidate.revision().get().to_string(),
            now.as_unix_millis().to_string(),
            Self::millis(self.config.consumed_retention).to_string(),
        );
        let args: [&[u8]; 7] = [
            candidate.id().as_bytes(),
            inc.as_bytes(),
            rev.as_bytes(),
            digest.as_bytes(),
            &encoded,
            now_s.as_bytes(),
            retention.as_bytes(),
        ];
        let mut f = self.run(&SCRIPTS.claim, &args).await?;
        match f.text()?.as_str() {
            "ok" => {
                let revision = Revision::new(f.number()?);
                self.forget(&[f.text()?]);
                let route = codec::route(&f.text()?)?;
                Ok(SessionSnapshot::from_store_record(
                    candidate.id().clone(),
                    candidate.binding().clone(),
                    route,
                    candidate.kid().cloned(),
                    revision,
                    candidate.expires_at(),
                    SessionState::Consumed {
                        result: Arc::new(result),
                        digest,
                    },
                ))
            }
            "unknown" => Err(ClaimError::UnknownSession),
            "replay" => {
                let same_response = f.text()? == "1";
                Err(ClaimError::Replay { same_response })
            }
            "expired" => {
                self.forget(&f.rest()?);
                Err(ClaimError::SessionExpired)
            }
            "mismatch" => Err(ClaimError::RevisionMismatch {
                expected: candidate.revision(),
                actual: Revision::new(f.number()?),
            }),
            _ => Err(StoreUnavailable.into()),
        }
    }

    async fn snapshot_impl(
        &self,
        id: &SessionId,
    ) -> Result<Option<SessionSnapshot<R>>, StoreUnavailable>
    where
        R: DeserializeOwned,
    {
        let mut cmd = redis::cmd("HMGET");
        cmd.arg(format!("{}s:{}", self.prefix, id.as_str()))
            .arg(&RECORD_FIELDS[..])
            .arg("digest")
            .arg("result");
        let mut conn = self.conn.clone();
        let reply: Reply = cmd
            .query_async(&mut conn)
            .await
            .map_err(|_| StoreUnavailable)?;
        let mut f = Fields::new(reply);
        let Some(record) = Record::read(&mut f)? else {
            return Ok(None);
        };
        let (digest, result) = (f.raw()?, f.raw()?);
        let state = match (record.state.as_str(), digest, result) {
            ("pending", None, None) => SessionState::Pending,
            ("expired", None, None) => SessionState::Expired,
            ("consumed", Some(d), Some(r)) => SessionState::Consumed {
                result: Arc::new(serde_json::from_slice(&r).map_err(|_| StoreUnavailable)?),
                digest: codec::digest(d)?,
            },
            _ => return Err(StoreUnavailable),
        };
        Ok(Some(SessionSnapshot::from_store_record(
            id.clone(),
            record.binding,
            record.route,
            record.kid,
            record.revision,
            record.expires_at,
            state,
        )))
    }

    /// Drops local keys past their TTL, then runs a sweep script and drops the keys it reports.
    /// The local step comes first, so it also happens while Redis is unreachable.
    async fn sweep(&self, script: &Script) -> Result<usize, StoreUnavailable> {
        let now = self.now();
        self.keys.remove_due(now)?;
        let now_s = now.as_unix_millis().to_string();
        let refs = self.run(script, &[now_s.as_bytes()]).await?.rest()?;
        self.forget(&refs);
        Ok(refs.len())
    }
}

// `async fn` bodies run only when polled, so an unpolled, dropped future sends nothing. A
// future dropped (or timed out) after its script was sent may have changed state that the
// caller never sees acknowledged; see the crate docs.
impl<K, R> SessionStore<K, R> for RedisRegistry<K, R>
where
    K: Send + Sync,
    R: Serialize + DeserializeOwned + Send + Sync,
{
    async fn insert(&self, session: NewSession<K>) -> Result<SessionSnapshot<R>, InsertError> {
        self.insert_impl(session).await
    }

    async fn resolve(
        &self,
        hint: &IngressHint,
        strategy: ResolutionStrategy,
    ) -> Result<Vec<Candidate<K>>, ResolveError> {
        self.resolve_impl(hint, strategy).await
    }

    async fn claim(
        &self,
        candidate: &Candidate<K>,
        digest: ResponseDigest,
        result: R,
    ) -> Result<SessionSnapshot<R>, ClaimError> {
        self.claim_impl(candidate, digest, result).await
    }

    async fn snapshot(
        &self,
        id: &SessionId,
    ) -> Result<Option<SessionSnapshot<R>>, StoreUnavailable> {
        self.snapshot_impl(id).await
    }

    async fn expire_due(&self) -> Result<usize, StoreUnavailable> {
        self.sweep(&SCRIPTS.expire_due).await
    }

    async fn purge(&self) -> Result<usize, StoreUnavailable> {
        self.sweep(&SCRIPTS.purge).await
    }
}
