//! Presentation validation with holder binding (Evidence level 3, synthetic credentials).
//!
//! The decrypted payload must be a JSON object (unique member names). Its members, checked in
//! this order (§8.3: the response parameters are "top-level JSON members"):
//!
//! | Member | Policy |
//! | --- | --- |
//! | `state` | Required, a string equal to the session's stored `state` (§14.4.2; RFC 6749 §4.1.2: echoed because the request carried one). Absent: [`ValidationError::StateMissing`]; not a string or another value: [`ValidationError::StateMismatch`]. Compared as SHA-256 digests without early exit. Checked first, before any holder-binding work |
//! | `vp_token` | Required: answers the server's single DCQL Credential Query ([`CredentialRequest`]) (OpenID4VP 1.1 §6.1, B.3.5) with exactly one presentation (§8.1: keyed by the query `id`, an array of one Presentation since `multiple` is omitted), a compact SD-JWT+KB string (B.3.6) |
//! | anything else | Ignored: §8.1 "The Client MUST ignore any unrecognized parameters" (`unrecognized_payload_members_are_ignored`) |
//!
//! The presentation is verified by [`crate::verify_sd_jwt_vc`] against the configured trusted
//! issuer key, with the KB-JWT bound to the session's stored `client_id` (`aud`) and `nonce`,
//! exactly (B.3.6, §14.2.2).
//!
//! The `state` check adds nothing against a deliberate sender: `state` is in the Request
//! Object, the sender chooses the plaintext, and `session_info` already selected the session.
//! It catches inadvertent responses (§14.4.2): a payload meant for another request, or one that
//! echoes no `state`.
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

use protocol_model::{RequestBinding, StateWire};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::jose;
use crate::sd_jwt::{
    self, CredentialQuery, KB_JWT_TYP, KeyBindingContext, MAX_KB_JWT_LEN, SD_JWT_VC_TYP,
    TrustedIssuerKey,
};
use crate::server::P256_COORDINATE_BYTES;
use crate::status_list::StatusReference;

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
/// The lab's default Credential Query as the verifier evaluates it
/// ([`CredentialRequest::synthetic`]).
pub const SYNTHETIC_CREDENTIAL_QUERY: CredentialQuery<'static> = CredentialQuery {
    vct: SYNTHETIC_CREDENTIAL_VCT,
    claims: &REQUESTED_CLAIMS,
};
/// Longest configured DCQL Credential Query `id` (lab policy): ids are short labels
/// (OpenID4VP §6.1 sets no length), and one is repeated in every `vp_token`.
pub const MAX_CREDENTIAL_QUERY_ID_LEN: usize = 128;
/// Longest configured `vct` (lab policy): type identifiers are URIs or URNs (SD-JWT VC
/// draft-27 §2.2.2.1), typically under 100 characters; the value is committed with every
/// consumed session.
pub const MAX_VCT_LEN: usize = 1024;
/// Longest configured claim name (lab policy): claim names are short JSON member names, and
/// each is committed with every consumed session.
pub const MAX_CLAIM_NAME_LEN: usize = 128;
/// Claim names with SD-JWT meaning, never a credential claim (RFC 9901 §4.1.1, §4.2.4.1,
/// §4.2.4.2), so never requestable.
const RESERVED_CLAIM_NAMES: [&str; 3] = ["_sd", "...", "_sd_alg"];
/// Authorization Response parameter carrying the presentations (OpenID4VP 1.1 §8.1).
pub(crate) const VP_TOKEN: &str = "vp_token";
/// Request parameter and response member `state` (OpenID4VP 1.1 §5.2; RFC 6749 §4.1.1,
/// §4.1.2).
pub(crate) const RESPONSE_STATE: &str = "state";
/// Request parameter `nonce` (OpenID4VP 1.1 §5.2).
pub(crate) const REQUEST_NONCE: &str = "nonce";
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

/// Longest caller-chosen `state` for a research session (generated states are 22 characters).
/// The same 512 bytes as the research nonce, for the same experiments; `state` is not in the
/// KB-JWT, so it only adds to the JWE, which stays far below `MAX_COMPACT_JWE_LEN`.
pub const MAX_RESEARCH_STATE_LEN: usize = 512;

/// The serialized KB-JWT payload with every value empty (RFC 9901 §4.3 members).
const KB_PAYLOAD_SKELETON: &str = r#"{"iat":,"aud":"","nonce":"","sd_hash":""}"#;
/// Digits of the largest `u64` NumericDate.
const MAX_NUMERIC_DATE_DIGITS: usize = 20;
/// Bytes of a SHA-256 digest (FIPS 180-4 §6.2), the `sd_hash` input to base64url.
const SHA256_DIGEST_BYTES: usize = 32;
/// base64url length of a SHA-256 digest (`sd_hash`), unpadded.
const SHA256_B64_LEN: usize = b64_len(SHA256_DIGEST_BYTES);
/// The KB-JWT protected header the wallet sends.
const KB_HEADER_SKELETON: &str = r#"{"alg":"ES256","typ":""}"#;
/// base64url length of an ES256 signature: `R || S`, one P-256 coordinate each (RFC 7518 §3.4).
const ES256_SIGNATURE_B64_LEN: usize = b64_len(2 * P256_COORDINATE_BYTES);
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
#[non_exhaustive]
pub enum ValidationError {
    /// The plaintext is not a JSON object with unique member names.
    #[error("payload is not a JSON object")]
    NotJsonObject,
    /// No `state` member, although the session's request carried one (RFC 6749 §4.1.2;
    /// OpenID4VP 1.1 §14.4.2).
    #[error("payload has no state")]
    StateMissing,
    /// `state` is not a string, or not this session's `state` (§14.4.2).
    #[error("state does not match the session")]
    StateMismatch,
    /// ECDH-ES research route: the decrypted `state` names no live session on the route (not a
    /// string, unknown, consumed or another route's). Under ECDH-ES the key opens the response
    /// for every session, so `state` is the only selector and this is where an unmatched one
    /// ends (OpenID4VP 1.0 correlation; docs/adr/0001-ecdh-es-research-route.md).
    #[cfg(feature = "ecdh-es-research")]
    #[error("state names no live session on the route")]
    StateUnknown,
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
    /// A claim SD-JWT VC §2.2.2.3 forbids in Disclosures came from one (for the plain RFC 9901
    /// entry point: `cnf`).
    #[error("a non-disclosable claim was disclosed")]
    NonDisclosableClaimDisclosed,
    /// A non-disclosable claim (as above) carries an `_sd` or `...` digest somewhere in its
    /// subtree, decoys included: it must be permanent (SD-JWT VC §2.2.2.3; lab policy for
    /// decoys and nested digests).
    #[error("a non-disclosable claim carries digests")]
    DigestInNonDisclosableClaim,
    /// `vct` missing or not the requested type (SD-JWT VC §2.2.2.1; OpenID4VP 1.1 B.3.5).
    #[error("credential type does not match the query")]
    VctMismatch,
    /// A Disclosure (at any depth, array elements included) lies outside every requested
    /// claim. Lab data-minimisation policy: OpenID4VP 1.1 §6.4.1 restricts what the Wallet
    /// sends but sets no Verifier MUST.
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
    /// KB-JWT `iat` outside the freshness window (§7.3 step 5e).
    #[error("key binding JWT is not fresh")]
    KbIatOutOfWindow,
    /// KB-JWT optional `exp` / `nbf` present and valid NumericDates, but not satisfied now
    /// (§7.3 step 5h; RFC 7519 §4.1.4, §4.1.5).
    #[error("key binding JWT exp or nbf is not satisfied")]
    KbValidityClaims,
    /// KB-JWT `nonce` differs from the session nonce (OpenID4VP 1.1 B.3.6, §14.2.2).
    #[error("key binding JWT nonce does not match the session")]
    KbNonceMismatch,
    /// KB-JWT `aud` differs from the session `client_id` (B.3.6, §14.2.2).
    #[error("key binding JWT audience does not match the session")]
    KbAudienceMismatch,
    /// KB-JWT `sd_hash` is not the hash of the presented SD-JWT (RFC 9901 §4.3.1, §7.3 step 5g).
    #[error("key binding JWT sd_hash does not match the presentation")]
    KbSdHashMismatch,
    /// A `status` claim without a well-formed `status_list` reference: not an object, no
    /// `status_list` object, `idx` not a non-negative integer, or `uri` not a non-empty string
    /// of at most `MAX_STATUS_URI_LEN` bytes (draft-ietf-oauth-status-list-14 §6.2, §8.3
    /// step 1). The status itself is checked later, before commit (`crate::StatusError`).
    #[error("status claim is malformed")]
    StatusClaimMalformed,
    /// The session's binding is not `direct_post.jwt` (unreachable: the lab issues no other).
    #[error("unsupported response mode")]
    UnsupportedMode,
}

/// What a validated response commits. Bounded: the requested claims (fixed names, each value
/// at most `MAX_COMMITTED_CLAIM_BYTES` serialized), the requested `vct`, a 43-character
/// thumbprint and JSON Pointers that all point into the requested claims (at most
/// `MAX_DISCLOSURES` of them, each bounded by the size of the claim it points into).
/// Never the presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedResponse {
    /// The credential type (= the requested `vct`).
    pub vct: String,
    /// RFC 7638 thumbprint of the holder key that signed the KB-JWT.
    pub holder_key_thumbprint: String,
    /// The requested claims, in query order.
    pub claims: Vec<(String, Value)>,
    /// RFC 6901 JSON Pointers of every claim that came from a Disclosure (nested properties and
    /// array elements included), sorted.
    pub disclosed_claim_names: Vec<String>,
    /// Conformance mode with a response `redirect_uri` only: the fresh Response Code put into
    /// that redirect for this response (OpenID4VP 1.0 §8.2, §13.3), stored with the consumed
    /// session and shown by the result endpoint. `None` otherwise.
    pub response_code: Option<String>,
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

/// The one `dc+sd-jwt` Credential Query of every Request Object a server issues (OpenID4VP
/// 1.0 / 1.1 §6.1, B.3.5): its `id`, the single `vct` in `meta.vct_values`, and the requested
/// claims as one-element claims paths (§7.1), all required (§6.4.1: `claims` without
/// `claim_sets`). Comes from [`crate::LabConfig::credential_request`]; the default is the
/// synthetic lab credential. The Verifier accepts exactly this: the `vp_token` must be keyed by
/// `id`, the credential's `vct` must equal `vct`, and nothing outside `claims` may be disclosed
/// (lab data-minimisation policy, [`crate::verify_sd_jwt_vc`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    id: String,
    vct: String,
    claims: Vec<String>,
}

/// Why a configured Credential Query was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialRequestError {
    /// `id` empty, over [`MAX_CREDENTIAL_QUERY_ID_LEN`], or outside the §6.1 charset
    /// (alphanumeric, `_`, `-`).
    #[error(
        "credential query id must be 1 to {MAX_CREDENTIAL_QUERY_ID_LEN} characters of [A-Za-z0-9_-]"
    )]
    Id,
    /// `vct` empty, over [`MAX_VCT_LEN`], or not visible ASCII.
    #[error("vct must be 1 to {MAX_VCT_LEN} visible ASCII characters")]
    Vct,
    /// No claims, more than [`crate::MAX_DISCLOSURES`], a duplicate, or an empty, over-long
    /// ([`MAX_CLAIM_NAME_LEN`]) or reserved (`_sd`, `...`, `_sd_alg`) claim name.
    #[error(
        "claims must be 1 to {max} distinct, non-reserved claim names of at most \
         {MAX_CLAIM_NAME_LEN} bytes",
        max = sd_jwt::MAX_DISCLOSURES
    )]
    Claims,
}

impl CredentialRequest {
    /// A Credential Query for `vct` asking for the top-level `claims`, keyed by `id`.
    ///
    /// # Errors
    /// [`CredentialRequestError`].
    pub fn new(
        id: impl Into<String>,
        vct: impl Into<String>,
        claims: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, CredentialRequestError> {
        let (id, vct) = (id.into(), vct.into());
        let claims: Vec<String> = claims.into_iter().map(Into::into).collect();
        let id_ok = !id.is_empty()
            && id.len() <= MAX_CREDENTIAL_QUERY_ID_LEN
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !id_ok {
            return Err(CredentialRequestError::Id);
        }
        if vct.is_empty() || vct.len() > MAX_VCT_LEN || !vct.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(CredentialRequestError::Vct);
        }
        let distinct = claims
            .iter()
            .enumerate()
            .all(|(i, name)| !claims[..i].contains(name));
        let names_ok = claims.iter().all(|name| {
            !name.is_empty()
                && name.len() <= MAX_CLAIM_NAME_LEN
                && !RESERVED_CLAIM_NAMES.contains(&name.as_str())
        });
        if claims.is_empty() || claims.len() > sd_jwt::MAX_DISCLOSURES || !distinct || !names_ok {
            return Err(CredentialRequestError::Claims);
        }
        Ok(Self { id, vct, claims })
    }

    /// The synthetic lab credential: [`SYNTHETIC_CREDENTIAL_QUERY_ID`],
    /// [`SYNTHETIC_CREDENTIAL_VCT`], [`REQUESTED_CLAIMS`].
    #[must_use]
    pub fn synthetic() -> Self {
        Self {
            id: SYNTHETIC_CREDENTIAL_QUERY_ID.to_owned(),
            vct: SYNTHETIC_CREDENTIAL_VCT.to_owned(),
            claims: REQUESTED_CLAIMS.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    /// The Credential Query `id` (the `vp_token` key).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The requested `vct`.
    #[must_use]
    pub fn vct(&self) -> &str {
        &self.vct
    }

    /// The requested top-level claim names, in query order.
    #[must_use]
    pub fn claims(&self) -> &[String] {
        &self.claims
    }

    /// The `dcql_query` Request Object parameter (OpenID4VP §6): this one Credential Query,
    /// holder binding required (the §6.1 default, stated explicitly).
    pub(crate) fn dcql_query(&self) -> Value {
        let claims: Vec<Value> = self
            .claims
            .iter()
            .map(|name| json!({ DCQL_PATH: [name] }))
            .collect();
        json!({
            DCQL_CREDENTIALS: [{
                DCQL_ID: self.id,
                DCQL_FORMAT: SD_JWT_VC_TYP,
                DCQL_META: { DCQL_VCT_VALUES: [self.vct] },
                DCQL_HOLDER_BINDING: true,
                DCQL_CLAIMS: claims,
            }]
        })
    }
}

/// What every presentation is verified against: the configured trusted issuer and Credential
/// Query. Shared (`Arc`) with the decryption trials on the blocking pool.
#[derive(Debug, Clone)]
pub(crate) struct Acceptance {
    pub(crate) issuer: TrustedIssuerKey,
    pub(crate) request: CredentialRequest,
}

/// A validated response: what is committed, and the digest the replay guard binds to the
/// session (never committed or logged).
pub(crate) struct Validated {
    pub(crate) response: ValidatedResponse,
    /// [`holder_proof_digest`] of the verified presentation.
    pub(crate) holder_proof: [u8; SHA256_DIGEST_BYTES],
    /// The credential's Token Status List reference, checked before commit
    /// (`crate::status_list::check`); never committed or logged.
    pub(crate) status: Option<StatusReference>,
}

/// Digest of the verified holder proof, for the Verifier-wide replay guard: SHA-256 of the
/// KB-JWT's JWS Signing Input (`BASE64URL(header) '.' BASE64URL(payload)`, RFC 7515 §5.2
/// step 8) exactly as received.
///
/// Why the KB-JWT and not the whole presentation: its payload carries `sd_hash` over the issuer
/// JWT and the selected Disclosures (RFC 9901 §4.3.1), so equal KB-JWTs mean equal SD-JWTs; a
/// different Disclosure set needs a new holder signature, which only the holder can make. Why
/// without the signature: ECDSA signatures are malleable (`(r, s)` and `(r, n - s)` both
/// verify, and the Verifier does not require low-S), so anyone holding a proof could mint a
/// second valid encoding with a fresh digest. The signing input cannot change without failing
/// verification, and canonical base64url leaves it one spelling.
fn holder_proof_digest(presentation: &str) -> [u8; SHA256_DIGEST_BYTES] {
    let kb_jwt = presentation.rsplit('~').next().unwrap_or_default();
    let signing_input = kb_jwt.rsplit_once('.').map_or(kb_jwt, |(input, _)| input);
    Sha256::digest(signing_input.as_bytes()).into()
}

/// The decrypted `state` member against the session's stored `state` (OpenID4VP 1.1 §14.4.2).
/// Both are hashed first, so the comparison runs over two fixed-length digests and does not
/// stop at the first differing byte; best effort, as for `RouteToken` (no formal constant-time
/// guarantee). The stored `state` is no secret from the sender (it is in the Request Object);
/// this keeps the check from timing how much of a guess matched.
fn check_state(received: Option<&Value>, stored: &StateWire) -> Result<(), ValidationError> {
    let received = received.ok_or(ValidationError::StateMissing)?;
    let received = received.as_str().ok_or(ValidationError::StateMismatch)?;
    let (a, b): ([u8; SHA256_DIGEST_BYTES], [u8; SHA256_DIGEST_BYTES]) = (
        Sha256::digest(received.as_bytes()).into(),
        Sha256::digest(stored.as_bytes()).into(),
    );
    let differ = a.iter().zip(&b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    if differ == 0 {
        Ok(())
    } else {
        Err(ValidationError::StateMismatch)
    }
}

/// Validates `plaintext` against the session's stored `binding`, the trusted issuer and
/// Credential Query of `acceptance`, and `now` (seconds since the Unix epoch).
pub(crate) fn validate(
    plaintext: &[u8],
    binding: &RequestBinding,
    acceptance: &Acceptance,
    now: u64,
) -> Result<Validated, ValidationError> {
    validate_payload(&parse_payload(plaintext)?, binding, acceptance, now)
}

/// The decrypted payload as a JSON object with unique member names at every depth.
pub(crate) fn parse_payload(plaintext: &[u8]) -> Result<Map<String, Value>, ValidationError> {
    jose::parse_strict_object(plaintext).ok_or(ValidationError::NotJsonObject)
}

/// Whether the payload's `state` is a string equal to the stored `state` of `binding`
/// (the comparison of `check_state`). The ECDH-ES route selects its session(s) with it.
#[cfg(feature = "ecdh-es-research")]
pub(crate) fn names_session(payload: &Map<String, Value>, binding: &RequestBinding) -> bool {
    let RequestBinding::DirectPostJwt { state, .. } = binding else {
        return false;
    };
    check_state(payload.get(RESPONSE_STATE), state).is_ok()
}

/// `true` when the payload has a `state` member at all (of any type).
#[cfg(feature = "ecdh-es-research")]
pub(crate) fn has_state(payload: &Map<String, Value>) -> bool {
    payload.contains_key(RESPONSE_STATE)
}

/// [`validate`] on an already parsed payload.
pub(crate) fn validate_payload(
    payload: &Map<String, Value>,
    binding: &RequestBinding,
    acceptance: &Acceptance,
    now: u64,
) -> Result<Validated, ValidationError> {
    let RequestBinding::DirectPostJwt {
        client_id,
        nonce,
        state,
        ..
    } = binding
    else {
        return Err(ValidationError::UnsupportedMode);
    };
    check_state(payload.get(RESPONSE_STATE), state)?;
    let vp_token = payload
        .get(VP_TOKEN)
        .and_then(Value::as_object)
        .ok_or(ValidationError::MissingVpToken)?;
    let answers = Some(vp_token)
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get(acceptance.request.id()))
        .ok_or(ValidationError::QueryMismatch)?;
    let presentation = match answers.as_array().map(Vec::as_slice) {
        Some([Value::String(p)]) => p,
        _ => return Err(ValidationError::PresentationShape),
    };
    let claims: Vec<&str> = acceptance
        .request
        .claims()
        .iter()
        .map(String::as_str)
        .collect();
    let (response, status) = sd_jwt::verify_sd_jwt_vc_with_status(
        presentation,
        &acceptance.issuer,
        &CredentialQuery {
            vct: acceptance.request.vct(),
            claims: &claims,
        },
        &KeyBindingContext {
            audience: client_id.as_str(),
            nonce: nonce.as_str(),
            now,
        },
    )?;
    Ok(Validated {
        response,
        holder_proof: holder_proof_digest(presentation),
        status,
    })
}
