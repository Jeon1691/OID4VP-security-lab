//! Presentation validation with holder binding (Evidence level 3, synthetic credentials).
//!
//! The decrypted payload must be a JSON object (unique member names) whose `vp_token` answers
//! the lab's single DCQL Credential Query (OpenID4VP 1.1 §6.1, B.3.5) with exactly one
//! presentation (§8.1: keyed by the query `id`, an array of one Presentation since `multiple`
//! is omitted): a compact SD-JWT+KB string (B.3.6). It is verified by
//! [`crate::verify_sd_jwt_vc`] against the configured trusted issuer key, with the KB-JWT bound
//! to the session's stored `client_id` (`aud`) and `nonce`, exactly (B.3.6, §14.2.2).
//!
//! HPKE decryption alone still authenticates nothing about the holder; what this adds is proof
//! that the holder of the credential's `cnf` key signed this session's `aud` / `nonce` over
//! exactly the presented SD-JWT (`sd_hash`). Credentials, issuer and holder keys are all
//! synthetic.
//!
//! Only the bounded [`ValidatedResponse`] is committed: the requested claims (each at most
//! `MAX_COMMITTED_CLAIM_BYTES`), the `vct`, the holder key thumbprint and the disclosed claim
//! names. Never the presentation, so a consumed record does not retain attacker-sized data for
//! its TTL plus retention window.

use protocol_model::RequestBinding;
use serde_json::{Map, Value, json};

use crate::jose;
use crate::sd_jwt::{
    self, CredentialQuery, KB_JWT_TYP, KeyBindingContext, MAX_KB_JWT_LEN, SD_JWT_VC_TYP,
    TrustedIssuerKey,
};

/// DCQL Credential Query id of every lab request, and the only `vp_token` member accepted
/// (OpenID4VP 1.1 §6.1: alphanumeric, `_` or `-`).
pub const SYNTHETIC_CREDENTIAL_QUERY_ID: &str = "synthetic-credential";
/// `vct` of the synthetic lab credential (SD-JWT VC draft-27 §2.2.2.1). Under the reserved
/// `.invalid` TLD (RFC 2606 §2), so it can never name a real credential type or resolve to Type
/// Metadata.
pub const SYNTHETIC_CREDENTIAL_VCT: &str = "https://credentials.lab.invalid/synthetic-identity/v1";
/// Claims the lab requests (top-level claims paths, OpenID4VP 1.1 §7.1), all required (§6.4.1:
/// `claims` without `claim_sets`). The synthetic credential also carries a `birthdate`, which
/// the lab does not request.
pub const REQUESTED_CLAIMS: [&str; 3] = ["given_name", "family_name", "age_over_18"];
/// The lab's Credential Query as the verifier evaluates it.
pub const SYNTHETIC_CREDENTIAL_QUERY: CredentialQuery<'static> = CredentialQuery {
    vct: SYNTHETIC_CREDENTIAL_VCT,
    claims: &REQUESTED_CLAIMS,
};
/// Authorization Response parameter carrying the presentations (OpenID4VP 1.1 §8.1).
pub(crate) const VP_TOKEN: &str = "vp_token";
/// DCQL members (OpenID4VP 1.1 §6, §6.1, §6.3, B.3.5).
pub(crate) const DCQL_CREDENTIALS: &str = "credentials";
pub(crate) const DCQL_ID: &str = "id";
pub(crate) const DCQL_FORMAT: &str = "format";
pub(crate) const DCQL_META: &str = "meta";
pub(crate) const DCQL_VCT_VALUES: &str = "vct_values";
pub(crate) const DCQL_CLAIMS: &str = "claims";
pub(crate) const DCQL_PATH: &str = "path";
const DCQL_HOLDER_BINDING: &str = "require_cryptographic_holder_binding";

/// Longest `client_id` the server accepts in its configuration (lab policy). Real identifiers
/// (DIDs, `x509_hash:` values, URLs) stay well under 200 characters; 1 KiB leaves room for
/// experiments while keeping an honest KB-JWT under `MAX_KB_JWT_LEN`.
pub const MAX_CLIENT_ID_LEN: usize = 1024;

/// Longest caller-chosen nonce for a research session (generated nonces are 22 characters).
/// 512 bytes leaves room for nonce-format experiments; see the size relation below.
pub const MAX_RESEARCH_NONCE_LEN: usize = 512;

/// The serialized KB-JWT payload with every value empty (RFC 9901 §4.3 members).
const KB_PAYLOAD_SKELETON: &str = r#"{"iat":,"aud":"","nonce":"","sd_hash":""}"#;
/// Digits of the largest `u64` NumericDate.
const MAX_NUMERIC_DATE_DIGITS: usize = 20;
/// base64url length of a SHA-256 digest (`sd_hash`): 32 bytes, unpadded.
const SHA256_B64_LEN: usize = b64_len(32);
/// The KB-JWT protected header the wallet sends.
const KB_HEADER_SKELETON: &str = r#"{"alg":"ES256","typ":""}"#;
/// base64url length of an ES256 signature (64 bytes, RFC 7518 §3.4).
const ES256_SIGNATURE_B64_LEN: usize = b64_len(64);
/// JSON string escaping at most doubles a visible-ASCII `client_id` (`"` and `\` become two
/// bytes; nothing else in `%x20-7E` is escaped). Nonces use only the §5.2 URL-safe set, which
/// is never escaped.
const JSON_ESCAPE_FACTOR: usize = 2;

/// Unpadded base64url length of `n` bytes (RFC 4648 §5).
const fn b64_len(n: usize) -> usize {
    (4 * n).div_ceil(3)
}

/// Longest honest KB-JWT: header, payload with the longest `client_id` (all escaped) and the
/// longest research nonce, signature, two `.` separators.
const LONGEST_HONEST_KB_JWT: usize = b64_len(KB_HEADER_SKELETON.len() + KB_JWT_TYP.len())
    + b64_len(
        KB_PAYLOAD_SKELETON.len()
            + MAX_NUMERIC_DATE_DIGITS
            + JSON_ESCAPE_FACTOR * MAX_CLIENT_ID_LEN
            + MAX_RESEARCH_NONCE_LEN
            + SHA256_B64_LEN,
    )
    + ES256_SIGNATURE_B64_LEN
    + 2;

// A KB-JWT for any allowed session (longest client_id, all of it escaped, and the longest
// research nonce) always fits the KB-JWT bound, so the bound never rejects an honest wallet.
const _: () = assert!(LONGEST_HONEST_KB_JWT <= MAX_KB_JWT_LEN);

/// Why a decrypted payload was not accepted. Internal evidence only: every variant answers the
/// same generic HTTP error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The plaintext is not a JSON object with unique member names.
    #[error("payload is not a JSON object")]
    NotJsonObject,
    /// No `vp_token` object member (OpenID4VP 1.1 §8.1).
    #[error("payload has no vp_token object")]
    MissingVpToken,
    /// `vp_token` does not answer exactly the lab's credential query (§8.1).
    #[error("vp_token does not answer exactly the requested credential query")]
    QueryMismatch,
    /// The query answer is not an array of exactly one string presentation (§8.1, B.3.6).
    #[error("presentation has the wrong shape")]
    PresentationShape,
    /// The presentation exceeds `MAX_PRESENTATION_LEN`.
    #[error("presentation exceeds the size limit")]
    PresentationTooLarge,
    /// Not `<JWT>~...~<KB-JWT>` (RFC 9901 §4).
    #[error("SD-JWT is malformed")]
    SdJwtMalformed,
    /// More than `MAX_DISCLOSURES` Disclosures.
    #[error("too many disclosures")]
    TooManyDisclosures,
    /// The final component is empty: an SD-JWT without Key Binding (RFC 9901 §7.3 step 2).
    #[error("key binding JWT missing")]
    KeyBindingMissing,
    /// Issuer JWT not three canonical base64url segments of JSON objects with unique members,
    /// a `crit` header, or over `MAX_ISSUER_JWT_LEN`.
    #[error("issuer JWT is malformed")]
    IssuerJwtMalformed,
    /// Issuer JWT `typ` is not `dc+sd-jwt` (SD-JWT VC §2.2.1).
    #[error("issuer JWT has the wrong typ")]
    IssuerTyp,
    /// Issuer JWT `alg` is not ES256, including `none` (RFC 9901 §7.1 step 2a).
    #[error("issuer JWT alg is not accepted")]
    IssuerAlg,
    /// The issuer signature does not verify with the trusted issuer key (§7.1 step 2b-c).
    #[error("issuer signature does not verify with the trusted key")]
    IssuerSignature,
    /// `_sd_alg` is present and not `sha-256` (§4.1.1, §7.1 step 2d).
    #[error("unsupported _sd_alg")]
    SdAlgUnsupported,
    /// A Disclosure is not canonical base64url of a 2- or 3-element JSON array with a string
    /// salt (and name), is over `MAX_DISCLOSURE_LEN`, or has the wrong shape for where its digest
    /// was found (§4.2.1, §4.2.2, §7.1 step 3c).
    #[error("disclosure is malformed")]
    DisclosureMalformed,
    /// The same Disclosure was sent more than once (§4).
    #[error("duplicate disclosure")]
    DuplicateDisclosure,
    /// A digest appears more than once in the payload (§4.1, §7.1 step 4).
    #[error("duplicate digest")]
    DuplicateDigest,
    /// A disclosed claim name already exists at its level (§7.1 step 3c.ii.3).
    #[error("disclosed claim name collides with an existing claim")]
    ClaimNameCollision,
    /// A Disclosure names the claim `_sd` or `...` (§7.1 step 3c.ii.2).
    #[error("disclosure uses a reserved claim name")]
    ReservedClaimName,
    /// A Disclosure no digest refers to (§7.1 step 5).
    #[error("unreferenced disclosure")]
    UnreferencedDisclosure,
    /// `_sd` not an array of strings, a malformed `...` element, `...` or nested `_sd_alg` keys,
    /// a non-integer `exp`/`nbf`, or nesting deeper than `MAX_SD_DEPTH` (§4.1, §4.2.4).
    #[error("SD-JWT payload is malformed")]
    PayloadMalformed,
    /// The credential is expired or not yet valid (§7.1 step 6).
    #[error("credential is not valid now")]
    CredentialValidity,
    /// `cnf.jwk` missing or not an EC P-256 public JWK (§4.1.2; RFC 7800 §3.2).
    #[error("holder key is missing or invalid")]
    HolderKeyInvalid,
    /// A claim SD-JWT VC §2.2.2.3 forbids in Disclosures came from one.
    #[error("a non-disclosable claim was disclosed")]
    NonDisclosableClaimDisclosed,
    /// `vct` missing or not the requested type (SD-JWT VC §2.2.2.1; OpenID4VP 1.1 B.3.5).
    #[error("credential type does not match the query")]
    VctMismatch,
    /// A top-level claim was disclosed that the query did not request (OpenID4VP 1.1 §6.4.1).
    #[error("an unrequested claim was disclosed")]
    UnrequestedClaimDisclosed,
    /// A requested claim is absent (§6.4.1, §8.6).
    #[error("a requested claim is missing")]
    RequestedClaimMissing,
    /// A requested claim's value exceeds `MAX_COMMITTED_CLAIM_BYTES`.
    #[error("a claim value exceeds the size limit")]
    ClaimValueTooLarge,
    /// KB-JWT not three canonical base64url segments of unique-member JSON objects, a `crit`
    /// header, over `MAX_KB_JWT_LEN`, or a required claim of the wrong type (RFC 9901 §4.3).
    #[error("key binding JWT is malformed")]
    KbJwtMalformed,
    /// KB-JWT `typ` is not `kb+jwt` (§7.3 step 5d).
    #[error("key binding JWT has the wrong typ")]
    KbTyp,
    /// KB-JWT `alg` is not ES256, including `none` (§7.3 step 5b).
    #[error("key binding JWT alg is not accepted")]
    KbAlg,
    /// The KB-JWT signature does not verify with the `cnf` key (§4.3.2, §7.3 step 5c).
    #[error("key binding JWT signature does not verify with the holder key")]
    KbSignature,
    /// KB-JWT `iat` outside the freshness window, or `exp`/`nbf` not satisfied (§7.3 step 5e).
    #[error("key binding JWT is not fresh")]
    KbIatOutOfWindow,
    /// KB-JWT `nonce` differs from the session nonce (OpenID4VP 1.1 B.3.6, §14.2.2).
    #[error("key binding JWT nonce does not match the session")]
    KbNonceMismatch,
    /// KB-JWT `aud` differs from the session `client_id` (B.3.6, §14.2.2).
    #[error("key binding JWT audience does not match the session")]
    KbAudienceMismatch,
    /// KB-JWT `sd_hash` is not the hash of the presented SD-JWT (RFC 9901 §4.3.1, §7.3 step 5g).
    #[error("key binding JWT sd_hash does not match the presentation")]
    KbSdHashMismatch,
    /// The session's binding is not `direct_post.jwt` (unreachable: the lab issues no other).
    #[error("unsupported response mode")]
    UnsupportedMode,
}

/// What a validated response commits. Bounded: the requested claims (fixed names, each value
/// at most `MAX_COMMITTED_CLAIM_BYTES` serialized), the requested `vct`, a 43-character
/// thumbprint and disclosed names drawn from the requested ones. Never the presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedResponse {
    /// The credential type (= the requested `vct`).
    pub vct: String,
    /// RFC 7638 thumbprint of the holder key that signed the KB-JWT.
    pub holder_key_thumbprint: String,
    /// The requested claims, in query order.
    pub claims: Vec<(String, Value)>,
    /// Top-level claims that came from Disclosures, sorted.
    pub disclosed_claim_names: Vec<String>,
}

impl ValidatedResponse {
    /// The committed result as served by the result endpoint.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let claims: Map<String, Value> = self.claims.iter().cloned().collect();
        json!({
            "vct": self.vct,
            "holder_key_thumbprint": self.holder_key_thumbprint,
            "claims": claims,
            "disclosed_claim_names": self.disclosed_claim_names,
        })
    }
}

/// The `dcql_query` of every lab Request Object (OpenID4VP 1.1 §6): one `dc+sd-jwt` Credential
/// Query for [`SYNTHETIC_CREDENTIAL_VCT`] with [`REQUESTED_CLAIMS`], holder binding required
/// (the §6.1 default, stated explicitly).
pub(crate) fn dcql_query() -> Value {
    let claims: Vec<Value> = REQUESTED_CLAIMS
        .iter()
        .map(|name| json!({ DCQL_PATH: [name] }))
        .collect();
    json!({
        DCQL_CREDENTIALS: [{
            DCQL_ID: SYNTHETIC_CREDENTIAL_QUERY_ID,
            DCQL_FORMAT: SD_JWT_VC_TYP,
            DCQL_META: { DCQL_VCT_VALUES: [SYNTHETIC_CREDENTIAL_VCT] },
            DCQL_HOLDER_BINDING: true,
            DCQL_CLAIMS: claims,
        }]
    })
}

/// Validates `plaintext` against the session's stored `binding`, the trusted issuer and `now`
/// (seconds since the Unix epoch).
pub(crate) fn validate(
    plaintext: &[u8],
    binding: &RequestBinding,
    issuer: &TrustedIssuerKey,
    now: u64,
) -> Result<ValidatedResponse, ValidationError> {
    let RequestBinding::DirectPostJwt {
        client_id, nonce, ..
    } = binding
    else {
        return Err(ValidationError::UnsupportedMode);
    };
    let payload = jose::parse_strict_object(plaintext).ok_or(ValidationError::NotJsonObject)?;
    let vp_token = payload
        .get(VP_TOKEN)
        .and_then(Value::as_object)
        .ok_or(ValidationError::MissingVpToken)?;
    let answers = Some(vp_token)
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get(SYNTHETIC_CREDENTIAL_QUERY_ID))
        .ok_or(ValidationError::QueryMismatch)?;
    let presentation = match answers.as_array().map(Vec::as_slice) {
        Some([Value::String(p)]) => p,
        _ => return Err(ValidationError::PresentationShape),
    };
    sd_jwt::verify_sd_jwt_vc(
        presentation,
        issuer,
        &SYNTHETIC_CREDENTIAL_QUERY,
        &KeyBindingContext {
            audience: client_id.as_str(),
            nonce: nonce.as_str(),
            now,
        },
    )
}
