//! Per-request evidence, kept in process for tests and scenario runs.
//!
//! Records hold counts, strategies and error variants only: never keys, plaintext, nonces,
//! route tokens or JWE bytes. The session id of a committed session is included; it names the
//! session in the lab's own result endpoint and is not a capability for posting responses.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use protocol_model::SessionId;
use session_core::{ClaimError, ResolutionStrategy, ResolveError};

use crate::config::RouteKind;
use crate::validate::ValidationError;

/// Records kept before the oldest is dropped: 16 times the largest concurrent scenario
/// (128 POSTs), so a test or scenario that drains the log between steps never loses records,
/// while a long-running server cannot grow it without bound.
pub const MAX_EVIDENCE_RECORDS: usize = 2048;

/// Admission failures: rejected before the JWE is parsed. Their HTTP answers may differ from
/// the generic rejection, since they reveal nothing about any session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// Body above [`crate::MAX_RESPONSE_BODY_BYTES`] (413).
    BodyTooLarge,
    /// Body could not be read (400).
    BodyUnreadable,
    /// Content-Type is not `application/x-www-form-urlencoded` (415).
    UnsupportedMediaType,
    /// A plaintext `vp_token` parameter: a `direct_post` downgrade of a `direct_post.jwt`
    /// request (found in G0-D). Refused even next to a `response` parameter.
    PlaintextVpToken,
    /// More than one `response` parameter.
    DuplicateResponse,
    /// A parameter other than `response` (lab policy: `direct_post.jwt` carries everything
    /// inside the JWE, OpenID4VP 1.1 §8.3.2).
    UnexpectedParameter,
    /// No `response` parameter, or an empty one.
    MissingResponse,
}

/// Where a request was finally refused. `None` in [`EvidenceRecord::rejection`] means success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// Admission control (body, media type, form).
    Admission(AdmissionError),
    /// [`jose_hpke::CompactJwe::parse`] refused the JWE (structure or header policy).
    JweParse(jose_hpke::Error),
    /// No candidate session (session-core [`ResolveError`]).
    Resolve(ResolveError),
    /// No candidate decrypted.
    Decrypt,
    /// Decrypted, but no candidate validated; the first validation error.
    Validation(ValidationError),
    /// Bounded trial: more than one candidate decrypted and validated (integrity failure).
    Ambiguous {
        /// Candidates that validated.
        validated: usize,
    },
    /// The atomic claim failed (session-core [`ClaimError`]).
    Claim(ClaimError),
}

/// HPKE outcome over all candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoResult {
    /// No HPKE open was attempted.
    NotAttempted,
    /// Every attempted open failed.
    NoneOpened,
    /// This many candidates opened.
    Opened {
        /// Candidates whose key and `session_info` opened the JWE.
        opened: usize,
    },
}

/// Validation outcome over the candidates that opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Nothing opened, so nothing was validated.
    NotRun,
    /// No opened candidate validated; the first error.
    Failed(ValidationError),
    /// This many candidates validated.
    Passed {
        /// Candidates that validated.
        validated: usize,
    },
}

/// Commit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitResult {
    /// No claim was attempted.
    NotRun,
    /// Claimed: the session moved to `Consumed`.
    Committed,
    /// The claim was refused by the store.
    Rejected(ClaimError),
    /// Several candidates validated; nothing was claimed.
    RefusedAmbiguous,
}

/// One POST to a response endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Route the response was posted to.
    pub route: RouteKind,
    /// Strategy fixed for that route.
    pub strategy: ResolutionStrategy,
    /// Candidates `resolve` returned (0 when rejected earlier).
    pub candidate_count: usize,
    /// HPKE open attempts made for this request.
    pub hpke_attempts: usize,
    /// HPKE outcome.
    pub crypto_result: CryptoResult,
    /// Validation outcome.
    pub validation_result: ValidationResult,
    /// Commit outcome.
    pub commit_result: CommitResult,
    /// Final internal reason for refusing; `None` on success.
    pub rejection: Option<Rejection>,
    /// The session consumed by this request, on success.
    pub committed_session: Option<SessionId>,
}

impl EvidenceRecord {
    pub(crate) const fn new(route: RouteKind, strategy: ResolutionStrategy) -> Self {
        Self {
            route,
            strategy,
            candidate_count: 0,
            hpke_attempts: 0,
            crypto_result: CryptoResult::NotAttempted,
            validation_result: ValidationResult::NotRun,
            commit_result: CommitResult::NotRun,
            rejection: None,
            committed_session: None,
        }
    }
}

/// In-process handle to the evidence of a running server. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct EvidenceLog(Arc<Mutex<VecDeque<EvidenceRecord>>>);

impl EvidenceLog {
    pub(crate) fn push(&self, record: EvidenceRecord) {
        // Evidence is append-only plain data; a panic elsewhere cannot leave it inconsistent.
        let mut log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if log.len() == MAX_EVIDENCE_RECORDS {
            log.pop_front();
        }
        log.push_back(record);
    }

    /// Removes and returns every record, oldest first.
    #[must_use]
    pub fn take(&self) -> Vec<EvidenceRecord> {
        let mut log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        log.drain(..).collect()
    }

    /// Copies every record, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<EvidenceRecord> {
        let log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        log.iter().cloned().collect()
    }
}
