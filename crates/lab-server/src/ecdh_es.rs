//! The OpenID4VP 1.0-style ECDH-ES research route (`ecdh-es-research` feature, research mode
//! only; docs/adr/0001-ecdh-es-research-route.md).
//!
//! `POST /lab/v1/response/ecdh-es` is one shared `response_uri` with ONE ECDH-ES P-256 key and
//! `kid` for every session on it: the 1.0 shape behind OIDF OpenID4VP #792 (C3, C9). It exists
//! to *observe* that shape next to the HPKE-0 routes, never as a fallback for them: the HPKE-0
//! routes keep refusing every `alg` but `HPKE-0` (`Rejection::JweParse`), and this route refuses
//! every `alg` but `ECDH-ES` (`Rejection::EcdhEsJweParse`), `HPKE-0` included.
//!
//! # Pipeline (per POST, in this order)
//!
//! 1. Admission, exactly as on the HPKE-0 routes (body limit, media type, exactly one
//!    `response`; a plaintext `vp_token` is refused).
//! 2. `jose_ecdh_es::CompactJwe::parse`: structure and header policy, no key.
//! 3. `kid` required (OpenID4VP 1.0 §8.3: the JWE carries the chosen JWK's `kid`).
//! 4. The live sessions on the route, through session-core (`BoundedTrial` over the route
//!    token and the JWE `kid`; a `kid` other than the route's matches none). This does not
//!    select a session: every session on the route has the same route token, `kid` and key.
//! 5. On the blocking pool: open the JWE with each live session's key, i.e. the route's key
//!    alone (ECDH-ES has no `session_info` or other transaction binding). All of them open, or
//!    none: decryption cannot select a session, and the evidence records it
//!    (`hpke_attempts` = live sessions, `CryptoResult::Opened` = how many opened).
//! 6. 1.0 correlation: the decrypted `state` selects the session. `validate` checks `state`
//!    first, so a session whose `state` differs is simply not this response's
//!    (`ValidationError::StateMismatch`, not recorded); holder binding (KB-JWT `aud` /
//!    `nonce` / `sd_hash`) runs only for the session(s) the `state` names. A `state` that names
//!    no live session on the route is `ValidationError::StateUnknown`; a missing one
//!    `StateMissing`. More than one session that validates (research `nonce` and `state`
//!    knobs reused) is `Ambiguous`, as under bounded trial.
//! 7. The Verifier-wide replay guard and the atomic claim, shared with the HPKE-0 routes.
//!
//! # Indexing sessions by `state`
//!
//! There is no `state` index: step 4 already yields every live session on the route, bounded
//! by [`MAX_ECDH_ES_SESSIONS`], and step 6 scans their stored `state`. That needs no change to
//! session-core (no new strategy, no store-backend contract for session-redis) and no second
//! map that would have to follow the registry through claims, expiry, purge and the consumed
//! retention window. The scan costs at most [`MAX_ECDH_ES_SESSIONS`] SHA-256 comparisons next
//! to as many ECDH operations, which step 5 performs anyway as the measurement.
//!
//! # Cost
//!
//! Like bounded trial, one unauthenticated POST costs one ECDH per live session on the route,
//! at most [`MAX_ECDH_ES_SESSIONS`]. Research mode only, loopback only.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::HeaderMap;
use axum::response::Response;
use jose_ecdh_es::rand_core::UnwrapErr;
use jose_ecdh_es::{ALG_ECDH_ES, CompactJwe, ENC_A128GCM, ENC_A256GCM, RecipientPrivateKey};
use protocol_model::KeyId;
use serde_json::{Value, json};
use session_core::{
    Candidate, CandidateBudget, Clock as _, IngressHint, MAX_CANDIDATE_BUDGET, MemoryRegistry,
    RegistryConfig, ResolutionStrategy, RoutePolicy, RouteToken, SessionStore, SystemClock,
};

use crate::config::{RouteKind, StartError};
use crate::evidence::{EvidenceRecord, Rejection};
use crate::sd_jwt::TrustedIssuerKey;
use crate::server::{
    self, AppState, JWK_USE_ENC, KID_BYTES, LabKey, MILLIS_PER_SECOND, Registry, SessionKey, Trial,
};
use crate::validate::{self, ValidationError};

/// Last path segment of the ECDH-ES route. Never a valid route token (wrong length), so it
/// cannot collide with a unique route.
pub(crate) const ECDH_ES_SEGMENT: &str = "ecdh-es";
/// `route` value of `POST /lab/v1/sessions` for this route.
pub(crate) const ECDH_ES_ROUTE_NAME: &str = "ecdh_es_shared";

/// Most pending sessions on the route, and the candidate budget of step 4: session-core's
/// [`MAX_CANDIDATE_BUDGET`] (twice the largest scenario), the same ceiling on ECDH work per
/// POST as bounded trial. The registry refuses further sessions at the cap (503 at creation), so
/// a POST never meets more live sessions than the budget.
pub(crate) const MAX_ECDH_ES_SESSIONS: usize = MAX_CANDIDATE_BUDGET;

/// `client_metadata` member listing the content encryption algorithms (OpenID4VP 1.0 §5.1 and
/// §8.3: "MUST be present for anything other than the default single value of `A128GCM`").
const ENC_VALUES_SUPPORTED: &str = "encrypted_response_enc_values_supported";

/// The route: its fixed route token, the one key and `kid` every session on it shares, and
/// its registry (`RoutePolicy::Shared`, at most [`MAX_ECDH_ES_SESSIONS`] pending).
pub(crate) struct EcdhEsRoute {
    pub(crate) token: RouteToken,
    pub(crate) key: SessionKey,
    pub(crate) kid: KeyId,
    pub(crate) registry: Registry,
}

impl EcdhEsRoute {
    /// A fresh key and `kid` from the OS CSPRNG. `UnwrapErr` panics if the OS RNG fails while
    /// drawing the key, which fails closed (no key is made from bad randomness).
    pub(crate) fn new() -> Result<Self, StartError> {
        let kid = KeyId::new(server::random_b64(KID_BYTES).ok_or(StartError::Rng)?)
            .map_err(|_| StartError::Rng)?;
        let key = RecipientPrivateKey::generate(&mut UnwrapErr(getrandom::SysRng));
        Ok(Self {
            token: RouteToken::generate().map_err(|_| StartError::Rng)?,
            key: Arc::new(LabKey::EcdhEs(key)),
            kid,
            registry: MemoryRegistry::with_config(
                Arc::new(SystemClock),
                RegistryConfig {
                    max_pending: MAX_ECDH_ES_SESSIONS,
                    route_policy: RoutePolicy::Shared,
                    ..RegistryConfig::default()
                },
            ),
        })
    }

    /// Step 4's strategy: every live session on the route, up to [`MAX_ECDH_ES_SESSIONS`].
    const fn strategy() -> ResolutionStrategy {
        ResolutionStrategy::BoundedTrial(BUDGET)
    }
}

/// [`MAX_ECDH_ES_SESSIONS`] as a budget, checked at compile time (it is the largest budget
/// `CandidateBudget::new` accepts).
const BUDGET: CandidateBudget = match CandidateBudget::new(MAX_ECDH_ES_SESSIONS) {
    Ok(budget) => budget,
    Err(_) => panic!("MAX_ECDH_ES_SESSIONS must be a valid candidate budget"),
};

impl LabKey {
    /// The ECDH-ES key, if this is one.
    const fn ecdh_es(&self) -> Option<&RecipientPrivateKey> {
        match self {
            Self::EcdhEs(key) => Some(key),
            Self::Hpke(_) => None,
        }
    }
}

/// `client_metadata` of an ECDH-ES session (OpenID4VP 1.0 §5.1, §8.3): `jwks` with the route's
/// public key (`alg` `ECDH-ES`, `use` `enc`, `kid`; the 1.0 §8.3 example's members) and
/// `encrypted_response_enc_values_supported` = [`ENC_A128GCM`, `ENC_A256GCM`], the two `enc`
/// values jose-ecdh-es implements.
pub(crate) fn client_metadata(key: &RecipientPrivateKey, kid: &KeyId) -> Value {
    let mut jwk = key.public_key().to_jwk();
    if let Some(members) = jwk.as_object_mut() {
        members.insert("use".into(), JWK_USE_ENC.into());
        members.insert("alg".into(), ALG_ECDH_ES.into());
        members.insert("kid".into(), kid.as_str().into());
    }
    json!({
        "jwks": { "keys": [jwk] },
        ENC_VALUES_SUPPORTED: [ENC_A128GCM, ENC_A256GCM],
    })
}

/// `POST /lab/v1/response/ecdh-es` (research mode only; not routed otherwise).
pub(crate) async fn post_ecdh_es(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let mut record = EvidenceRecord::new(RouteKind::EcdhEs, EcdhEsRoute::strategy());
    record.rejection = pipeline(&mut record, &state, &headers, body).await.err();
    server::answer(&state, record)
}

/// Steps 1-7 of the module docs.
async fn pipeline(
    record: &mut EvidenceRecord,
    state: &AppState,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(), Rejection> {
    let route = state.ecdh_es.as_ref().ok_or(Rejection::TrialAborted)?;
    let response = server::admit(headers, body)?;
    let jwe = CompactJwe::parse(&response).map_err(Rejection::EcdhEsJweParse)?;
    let kid = jwe.header().kid().cloned().ok_or(Rejection::MissingKid)?;
    let hint = IngressHint::new(route.token.clone(), Some(kid));
    let candidates = SessionStore::resolve(&route.registry, &hint, EcdhEsRoute::strategy())
        .await
        .map_err(Rejection::Resolve)?;
    record.candidate_count = candidates.len();

    let slot = server::decryption_slot(state).await?;
    let issuer = state.trusted_issuer.clone();
    // KB-JWT freshness is judged on this clock, in NumericDate seconds (RFC 7519 §2).
    let now = SystemClock.now().as_unix_millis() / MILLIS_PER_SECOND;
    let (trial, trial_time, candidates) = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let started = Instant::now();
        let trial = trial(&jwe, &candidates, &issuer, now);
        (trial, started.elapsed(), candidates)
    })
    .await
    .map_err(|_| Rejection::TrialAborted)?;
    record.trial_time = trial_time;
    let (index, validated) = server::select(record, trial)?;
    let candidate = candidates.get(index).ok_or(Rejection::TrialAborted)?;
    server::commit(
        record,
        state,
        &route.registry,
        candidate,
        &response,
        validated,
    )
    .await
}

/// Steps 5-6: opens the JWE with every candidate's key (the measurement: with one shared key,
/// all open or none), then lets the decrypted `state` select. Each opened plaintext is
/// validated against its own candidate with `state` checked first, so a candidate the `state`
/// does not name ends at `StateMismatch`, which is not an error of this response and is not
/// recorded. Errors of the candidate(s) it does name (holder binding), or a missing `state` or
/// non-JSON plaintext, are; if nothing else was recorded, no live session has this `state`.
fn trial(
    jwe: &CompactJwe,
    candidates: &[Candidate<SessionKey>],
    issuer: &TrustedIssuerKey,
    now: u64,
) -> Trial {
    let mut out = Trial::default();
    for (index, candidate) in candidates.iter().enumerate() {
        out.attempts += 1;
        let Some(key) = candidate.key().ecdh_es() else {
            continue;
        };
        let Ok(plaintext) = jwe.open(key) else {
            continue;
        };
        out.opened += 1;
        match validate::validate(&plaintext, candidate.binding(), issuer, now) {
            Ok(result) => {
                out.validated += 1;
                if out.first.is_none() {
                    out.first = Some((index, result));
                }
            }
            Err(ValidationError::StateMismatch) => {}
            Err(e) => {
                out.first_error.get_or_insert(e);
            }
        }
    }
    if out.opened > 0 && out.validated == 0 {
        out.first_error.get_or_insert(ValidationError::StateUnknown);
    }
    out
}
