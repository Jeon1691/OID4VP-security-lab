//! Synthetic presentation validation (Evidence level 2).
//!
//! The decrypted payload must be a JSON object whose `vp_token` answers the lab's single DCQL
//! credential query with exactly one synthetic presentation: a JSON object with exactly the
//! members `nonce` and `aud`, byte-equal to the session's stored `nonce` and `client_id`. The
//! serialized `vp_token` is capped at [`MAX_COMMITTED_VP_TOKEN_BYTES`], and only the bounded
//! [`ValidatedResponse`] (copies of the session's own wire values) is committed, so a consumed
//! record never retains attacker-sized data for its TTL plus retention window.
//!
//! This is a stand-in for holder binding, not holder authentication: there is no signature
//! and no key-binding JWT. It exists so that a response which merely *decrypts* (HPKE alone
//! authenticates nothing about the holder) is still checked against the session it is about to
//! consume. Real SD-JWT KB-JWT / mdoc DeviceAuth validation is out of scope for this wave.

use protocol_model::{ClientIdWire, NonceWire, RequestBinding};
use serde_json::Value;

/// DCQL credential query id of every lab request, and the only `vp_token` member accepted.
pub const SYNTHETIC_CREDENTIAL_QUERY_ID: &str = "synthetic-credential";
/// Authorization Response parameter carrying the presentations (OpenID4VP 1.1 §8.1).
pub(crate) const VP_TOKEN: &str = "vp_token";
/// Synthetic presentation members bound to the session.
pub(crate) const PRESENTATION_NONCE: &str = "nonce";
pub(crate) const PRESENTATION_AUD: &str = "aud";
/// The only members of a synthetic presentation.
const PRESENTATION_MEMBERS: [&str; 2] = [PRESENTATION_NONCE, PRESENTATION_AUD];

/// Largest accepted serialized `vp_token`, in bytes (lab policy).
///
/// A valid synthetic `vp_token` is the query id plus two short strings (a 22-character nonce
/// and the `client_id`), well under 300 bytes; 4 KiB leaves room for long configured client
/// ids. The cap bounds validation work on the decrypted `vp_token`; together with the bounded
/// [`ValidatedResponse`] it keeps consumed records small (at most 4096 pending sessions per
/// registry by default).
pub const MAX_COMMITTED_VP_TOKEN_BYTES: usize = 4096;

/// Longest `client_id` the server accepts in its configuration (lab policy). Real identifiers
/// (DIDs, `x509_hash:` values, URLs) stay well under 200 characters; 1 KiB leaves room for
/// experiments while keeping a matching presentation under [`MAX_COMMITTED_VP_TOKEN_BYTES`].
pub const MAX_CLIENT_ID_LEN: usize = 1024;

/// Longest caller-chosen nonce for a research session (generated nonces are 22 characters).
/// 512 bytes leaves room for nonce-format experiments; see the size relation below.
pub const MAX_RESEARCH_NONCE_LEN: usize = 512;

/// The serialized synthetic `vp_token` with every name and value empty:
/// `{"<query id>":[{"<nonce>":"<value>","<aud>":"<value>"}]}`.
const VP_TOKEN_SKELETON: &str = r#"{"":[{"":"","":""}]}"#;
/// Bytes of a synthetic `vp_token` that do not depend on the session's values.
const VP_TOKEN_FIXED_BYTES: usize = VP_TOKEN_SKELETON.len()
    + SYNTHETIC_CREDENTIAL_QUERY_ID.len()
    + PRESENTATION_NONCE.len()
    + PRESENTATION_AUD.len();
/// JSON string escaping at most doubles a visible-ASCII `client_id` (`"` and `\` become two
/// bytes; nothing else in `%x20-7E` is escaped). Nonces use only the §5.2 URL-safe set, which
/// is never escaped.
const JSON_ESCAPE_FACTOR: usize = 2;

// A presentation matching any allowed session (longest client_id, all of it escaped, and the
// longest research nonce) always fits under the commit cap, so the cap never rejects an honest
// response.
const _: () = assert!(
    VP_TOKEN_FIXED_BYTES + JSON_ESCAPE_FACTOR * MAX_CLIENT_ID_LEN + MAX_RESEARCH_NONCE_LEN
        <= MAX_COMMITTED_VP_TOKEN_BYTES
);

/// Why a decrypted payload was not accepted. Internal evidence only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The plaintext is not a JSON object.
    #[error("payload is not a JSON object")]
    NotJsonObject,
    /// No `vp_token` object member.
    #[error("payload has no vp_token object")]
    MissingVpToken,
    /// The serialized `vp_token` exceeds [`MAX_COMMITTED_VP_TOKEN_BYTES`].
    #[error("vp_token exceeds the size limit")]
    VpTokenTooLarge,
    /// `vp_token` does not answer exactly the lab's credential query.
    #[error("vp_token does not answer exactly the requested credential query")]
    QueryMismatch,
    /// The query answer is not an array of exactly one JSON-object presentation.
    #[error("presentation has the wrong shape")]
    PresentationShape,
    /// The presentation has a member other than `nonce` and `aud`.
    #[error("presentation has an unexpected member")]
    UnexpectedPresentationMember,
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

/// What a validated response commits. Bounded: it holds copies of the session's own wire
/// values (which the presentation matched byte for byte), never decrypted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedResponse {
    /// The presentation's `nonce` (= the session nonce).
    pub nonce: NonceWire,
    /// The presentation's `aud` (= the session `client_id`).
    pub audience: ClientIdWire,
}

impl ValidatedResponse {
    /// The committed synthetic `vp_token`, re-serialized from the bounded fields.
    #[must_use]
    pub fn vp_token(&self) -> Value {
        serde_json::json!({
            SYNTHETIC_CREDENTIAL_QUERY_ID: [{
                PRESENTATION_NONCE: self.nonce.as_str(),
                PRESENTATION_AUD: self.audience.as_str(),
            }]
        })
    }
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
    if vp_token.to_string().len() > MAX_COMMITTED_VP_TOKEN_BYTES {
        return Err(ValidationError::VpTokenTooLarge);
    }
    let answers = vp_token
        .as_object()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get(SYNTHETIC_CREDENTIAL_QUERY_ID))
        .ok_or(ValidationError::QueryMismatch)?;
    let presentation = match answers.as_array().map(Vec::as_slice) {
        Some([Value::Object(p)]) => p,
        _ => return Err(ValidationError::PresentationShape),
    };
    if presentation
        .keys()
        .any(|k| !PRESENTATION_MEMBERS.contains(&k.as_str()))
    {
        return Err(ValidationError::UnexpectedPresentationMember);
    }
    let field = |name| presentation.get(name).and_then(Value::as_str);
    if field(PRESENTATION_NONCE) != Some(nonce.as_str()) {
        return Err(ValidationError::NonceMismatch);
    }
    if field(PRESENTATION_AUD) != Some(client_id.as_str()) {
        return Err(ValidationError::AudienceMismatch);
    }
    Ok(ValidatedResponse {
        nonce: nonce.clone(),
        audience: client_id.clone(),
    })
}
