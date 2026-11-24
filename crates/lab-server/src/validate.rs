//! Synthetic presentation validation (Evidence level 2).
//!
//! The decrypted payload must be a JSON object whose `vp_token` answers the lab's single DCQL
//! credential query with exactly one synthetic presentation, a JSON object carrying `nonce` and
//! `aud` byte-equal to the session's stored `nonce` and `client_id`.
//!
//! This is a stand-in for holder binding, not holder authentication: there is no signature
//! and no key-binding JWT. It exists so that a response which merely *decrypts* (HPKE alone
//! authenticates nothing about the holder) is still checked against the session it is about to
//! consume. Real SD-JWT KB-JWT / mdoc DeviceAuth validation is out of scope for this wave.

use protocol_model::RequestBinding;
use serde_json::Value;

/// DCQL credential query id of every lab request, and the only `vp_token` member accepted.
pub const SYNTHETIC_CREDENTIAL_QUERY_ID: &str = "synthetic-credential";
/// Authorization Response parameter carrying the presentations (OpenID4VP 1.1 §8.1).
pub(crate) const VP_TOKEN: &str = "vp_token";
/// Synthetic presentation members bound to the session.
pub(crate) const PRESENTATION_NONCE: &str = "nonce";
pub(crate) const PRESENTATION_AUD: &str = "aud";

/// Why a decrypted payload was not accepted. Internal evidence only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The plaintext is not a JSON object.
    #[error("payload is not a JSON object")]
    NotJsonObject,
    /// No `vp_token` object member.
    #[error("payload has no vp_token object")]
    MissingVpToken,
    /// `vp_token` does not answer exactly the lab's credential query.
    #[error("vp_token does not answer exactly the requested credential query")]
    QueryMismatch,
    /// The query answer is not an array of exactly one JSON-object presentation.
    #[error("presentation has the wrong shape")]
    PresentationShape,
    /// Presentation `nonce` differs from the session's nonce.
    #[error("presentation nonce does not match the session")]
    NonceMismatch,
    /// Presentation `aud` differs from the session's client_id.
    #[error("presentation audience does not match the session")]
    AudienceMismatch,
    /// The session's binding is not `direct_post.jwt` (unreachable: the lab issues no other).
    #[error("unsupported response mode")]
    UnsupportedMode,
}

/// What a validated response commits: the synthetic `vp_token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedResponse {
    /// The `vp_token` exactly as decrypted.
    pub vp_token: Value,
}

/// Validates `plaintext` against the session's stored `binding`.
pub(crate) fn validate(
    plaintext: &[u8],
    binding: &RequestBinding,
) -> Result<ValidatedResponse, ValidationError> {
    let RequestBinding::DirectPostJwt {
        client_id, nonce, ..
    } = binding
    else {
        return Err(ValidationError::UnsupportedMode);
    };
    let payload: Value =
        serde_json::from_slice(plaintext).map_err(|_| ValidationError::NotJsonObject)?;
    let payload = payload.as_object().ok_or(ValidationError::NotJsonObject)?;
    let vp_token = payload
        .get(VP_TOKEN)
        .filter(|v| v.is_object())
        .ok_or(ValidationError::MissingVpToken)?;
    let answers = vp_token
        .as_object()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get(SYNTHETIC_CREDENTIAL_QUERY_ID))
        .ok_or(ValidationError::QueryMismatch)?;
    let presentation = match answers.as_array().map(Vec::as_slice) {
        Some([Value::Object(p)]) => p,
        _ => return Err(ValidationError::PresentationShape),
    };
    let field = |name| presentation.get(name).and_then(Value::as_str);
    if field(PRESENTATION_NONCE) != Some(nonce.as_str()) {
        return Err(ValidationError::NonceMismatch);
    }
    if field(PRESENTATION_AUD) != Some(client_id.as_str()) {
        return Err(ValidationError::AudienceMismatch);
    }
    Ok(ValidatedResponse {
        vp_token: vp_token.clone(),
    })
}
