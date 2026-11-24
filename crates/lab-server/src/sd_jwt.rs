//! SD-JWT+KB verification (RFC 9901) and the SD-JWT VC profile (draft-ietf-oauth-sd-jwt-vc-27)
//! as OpenID4VP 1.1 Appendix B.3 uses it. Verifier side; in the default build.
//!
//! [`verify_sd_jwt_kb`] is RFC 9901 §7.1 + §7.3 with Key Binding always required:
//!
//! | Check | Source |
//! | --- | --- |
//! | Compact form `<JWT>~<D.1>~...~<D.N>~<KB-JWT>`, bounded sizes and counts | RFC 9901 §4; lab policy ([`MAX_PRESENTATION_LEN`] and friends) |
//! | KB-JWT present (last component non-empty) | RFC 9901 §7.3 steps 1-2; OpenID4VP 1.1 §6.1 `require_cryptographic_holder_binding` (default `true`), B.3 |
//! | Issuer JWT: canonical base64url, unique JSON members, no `crit`, `typ` exact, `alg` = ES256, signature by the configured trusted key | RFC 9901 §4.1, §7.1 step 2a-c; RFC 7515 §5.2; RFC 8725 §3.1, §3.11 |
//! | `_sd_alg` absent or `sha-256` (top level only) | RFC 9901 §4.1.1, §7.1 step 2d |
//! | Disclosures `[salt, name, value]` / `[salt, value]`, names not `_sd` / `...`, digest = base64url(SHA-256(ASCII of the Disclosure)) | RFC 9901 §4.2.1-§4.2.3, §7.1 step 3 |
//! | Every embedded digest at most once; unmatched digests (decoys) dropped; a claim name never overwritten | RFC 9901 §4.1, §7.1 steps 3c-3e, 4 |
//! | Every Disclosure referenced exactly once (no duplicates, no unreferenced) | RFC 9901 §4, §7.1 step 5 |
//! | `exp` / `nbf` of the processed payload | RFC 9901 §7.1 step 6; RFC 7519 §4.1.4-§4.1.5 |
//! | Holder key = `cnf.jwk`, EC P-256 public JWK | RFC 9901 §4.1.2, §4.3.2; RFC 7800 §3.2; SD-JWT VC §2.2.2.3 |
//! | KB-JWT: no `crit`, `typ` `kb+jwt`, `alg` ES256, signature by the `cnf` key | RFC 9901 §4.3, §7.3 steps 5a-5d |
//! | KB-JWT `iat` within [`KB_JWT_MAX_AGE_SECS`] / [`KB_JWT_MAX_FUTURE_SKEW_SECS`] | RFC 9901 §7.3 step 5e |
//! | KB-JWT `nonce` = session nonce, `aud` = session `client_id`, exactly | RFC 9901 §7.3 step 5f; OpenID4VP 1.1 B.3.6, §14.2.2 |
//! | KB-JWT `sd_hash` = base64url(SHA-256(presentation up to and including the last `~`)) | RFC 9901 §4.3.1, §7.3 step 5g |
//!
//! [`verify_sd_jwt_vc`] adds the SD-JWT VC and DCQL checks: `typ` `dc+sd-jwt` (SD-JWT VC
//! §2.2.1), `vct` equal to the requested type (§2.2.2.1; OpenID4VP 1.1 B.3.5 `vct_values`), the
//! claims SD-JWT VC §2.2.2.3 forbids in Disclosures never disclosed, and exactly the requested
//! claims (OpenID4VP 1.1 §6.4.1, §8.6) disclosed at the top level, each bounded in size.
//!
//! Crypto is RustCrypto `p256` (ECDSA P-256) and `sha2`; nothing is hand-rolled.

use std::collections::{HashMap, HashSet};

use p256::ecdsa::VerifyingKey;
use serde_json::{Map, Value};

use crate::jose::{self, CompactJws, HeaderError};
use crate::validate::{ValidatedResponse, ValidationError};

/// `typ` of an SD-JWT VC issuer-signed JWT (SD-JWT VC draft-27 §2.2.1; OpenID4VP 1.1 B.3.1
/// Credential Format Identifier `dc+sd-jwt`).
pub const SD_JWT_VC_TYP: &str = "dc+sd-jwt";
/// `typ` of a Key Binding JWT (RFC 9901 §4.3).
pub const KB_JWT_TYP: &str = "kb+jwt";

/// Largest issuer-signed JWT, in bytes (lab policy). The lab's synthetic credential is about
/// 1 KiB; RFC 9901 Appendix A.3 (a full PID with 20 digests) is about 1.6 KiB.
pub const MAX_ISSUER_JWT_LEN: usize = 8192;
/// Largest single Disclosure, in bytes (lab policy). Every RFC 9901 example Disclosure is under
/// 512 bytes.
pub const MAX_DISCLOSURE_LEN: usize = 1024;
/// Most Disclosures in one presentation (lab policy): the lab credential has four, RFC 9901
/// Appendix A.3 issues 21 and presents three. Each one costs a SHA-256 and a JSON parse.
pub const MAX_DISCLOSURES: usize = 16;
/// Largest Key Binding JWT, in bytes (lab policy). An honest KB-JWT for the longest allowed
/// `client_id` and research nonce stays below it (checked at compile time in `validate`).
pub const MAX_KB_JWT_LEN: usize = 8192;
/// Largest presentation: every part at its bound, plus one `~` after the issuer JWT and after
/// each Disclosure (RFC 9901 §4).
pub const MAX_PRESENTATION_LEN: usize =
    MAX_ISSUER_JWT_LEN + 1 + MAX_DISCLOSURES * (MAX_DISCLOSURE_LEN + 1) + MAX_KB_JWT_LEN;
/// Deepest object/array nesting processed for embedded digests (lab policy; the RFC 9901
/// examples nest at most three levels). Bounds the recursion of §7.1 steps (*) / (**).
pub const MAX_SD_DEPTH: usize = 16;
/// Largest serialized value of one committed claim, in bytes (lab policy). Keeps the result a
/// consumed session retains for its TTL plus retention window small.
pub const MAX_COMMITTED_CLAIM_BYTES: usize = 256;
/// Oldest accepted KB-JWT `iat`, in seconds before now: RFC 9901 §7.3 step 5e leaves "an
/// acceptable window" to the Verifier. Five minutes = `DEFAULT_SESSION_TTL`: a KB-JWT older
/// than the longest-lived request it could answer is not a fresh answer to it.
pub const KB_JWT_MAX_AGE_SECS: u64 = 300;
/// Largest accepted KB-JWT `iat` in the future, in seconds (clock skew between Wallet and
/// Verifier; lab policy, both run on one host).
pub const KB_JWT_MAX_FUTURE_SKEW_SECS: u64 = 60;

/// The only `_sd_alg` the lab accepts, and the default when absent (RFC 9901 §4.1.1).
const SD_ALG_SHA256: &str = "sha-256";
/// Separator of the compact SD-JWT parts (RFC 9901 §4).
const PART_SEPARATOR: char = '~';
/// Payload members with SD-JWT meaning (RFC 9901 §4.1.1, §4.2.4.1, §4.2.4.2).
const SD_ALG: &str = "_sd_alg";
const SD: &str = "_sd";
const ARRAY_DIGEST: &str = "...";
/// Confirmation claim and its JWK method (RFC 7800 §3.1, §3.2).
const CNF: &str = "cnf";
const CNF_JWK: &str = "jwk";
/// Registered JWT claims checked here (RFC 7519 §4.1.3-§4.1.6) and the KB-JWT claims (RFC 9901
/// §4.3).
const EXP: &str = "exp";
const NBF: &str = "nbf";
const IAT: &str = "iat";
const AUD: &str = "aud";
const NONCE: &str = "nonce";
const SD_HASH: &str = "sd_hash";
/// Credential type claim (SD-JWT VC draft-27 §2.2.2.1).
const VCT: &str = "vct";
/// Claims SD-JWT VC draft-27 §2.2.2.3 says "MUST NOT be included in Disclosures".
const NON_DISCLOSABLE_CLAIMS: [&str; 8] = [
    "iss",
    NBF,
    EXP,
    CNF,
    VCT,
    "vct#integrity",
    "aka_vcts",
    "status",
];

/// The issuer public key the Verifier trusts (RFC 9901 §7.1 step 2c: "the signing key belongs
/// to this Issuer"). Comes from configuration; the default build contains none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuerKey {
    key: VerifyingKey,
}

/// Why a trusted issuer JWK was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssuerKeyError {
    /// Not a JSON object with unique member names.
    #[error("issuer key JWK is malformed")]
    Malformed,
    /// Not an EC P-256 public key on the curve, or it carries a private scalar `d`.
    #[error("issuer key must be an EC P-256 public JWK without d")]
    Unsupported,
}

impl TrustedIssuerKey {
    /// Parses an EC P-256 public JWK (RFC 7518 §6.2.1). A JWK with `d` is refused: the Verifier
    /// is configured with the issuer's public key only.
    ///
    /// # Errors
    /// [`IssuerKeyError`].
    pub fn from_jwk(jwk: &str) -> Result<Self, IssuerKeyError> {
        let object = jose::parse_strict_object(jwk.as_bytes()).ok_or(IssuerKeyError::Malformed)?;
        let key = jose::p256_public_jwk(&object).ok_or(IssuerKeyError::Unsupported)?;
        Ok(Self { key })
    }

    #[cfg(feature = "wallet-sim")]
    pub(crate) const fn from_verifying_key(key: VerifyingKey) -> Self {
        Self { key }
    }

    /// RFC 7638 thumbprint (SHA-256, base64url) of the key.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        jose::p256_thumbprint(&self.key)
    }
}

/// What the Key Binding JWT must be bound to: the session's exact `client_id` and `nonce`
/// (OpenID4VP 1.1 B.3.6), and the Verifier's clock.
#[derive(Debug, Clone, Copy)]
pub struct KeyBindingContext<'a> {
    /// Expected `aud`: the full Client Identifier, prefix included (OpenID4VP 1.1 §14.11).
    pub audience: &'a str,
    /// Expected `nonce`: the Authorization Request's `nonce`.
    pub nonce: &'a str,
    /// Now, in seconds since the Unix epoch.
    pub now: u64,
}

/// The requested credential: one DCQL Credential Query of format `dc+sd-jwt` (OpenID4VP 1.1
/// §6.1, B.3.5) whose claims are top-level claim names (one-element claims paths, §7).
#[derive(Debug, Clone, Copy)]
pub struct CredentialQuery<'a> {
    /// The single allowed `vct` (`meta.vct_values`).
    pub vct: &'a str,
    /// The requested claims, all required (`claims` without `claim_sets`, §6.4.1).
    pub claims: &'a [&'a str],
}

/// An SD-JWT+KB that passed [`verify_sd_jwt_kb`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedSdJwt {
    /// The Processed SD-JWT Payload (RFC 9901 §7.1): disclosed claims inserted, digests,
    /// `_sd` and `_sd_alg` removed.
    pub payload: Map<String, Value>,
    /// RFC 7638 thumbprint of the holder key (`cnf.jwk`) that signed the KB-JWT.
    pub holder_key_thumbprint: String,
    /// Names of the top-level claims that came from Disclosures, in processing order.
    pub disclosed_claim_names: Vec<String>,
}

/// base64url(SHA-256(US-ASCII bytes of the Disclosure)) (RFC 9901 §4.2.3).
#[must_use]
pub fn disclosure_digest(disclosure: &str) -> String {
    jose::sha256_b64(disclosure.as_bytes())
}

/// Verifies an SD-JWT+KB (RFC 9901 §7.1 and §7.3, Key Binding required) whose issuer JWT has
/// header `typ` = `issuer_typ`, signed by `issuer`, bound to `kb`. Checks run in the order of
/// the module table; the first failure is returned.
///
/// # Errors
/// The first [`ValidationError`].
pub fn verify_sd_jwt_kb(
    presentation: &str,
    issuer: &TrustedIssuerKey,
    issuer_typ: &str,
    kb: &KeyBindingContext<'_>,
) -> Result<ProcessedSdJwt, ValidationError> {
    use ValidationError as E;
    if presentation.len() > MAX_PRESENTATION_LEN {
        return Err(E::PresentationTooLarge);
    }
    // RFC 9901 §4: the SD-JWT is everything up to and including the last `~`; what follows is
    // the KB-JWT (empty for an SD-JWT without Key Binding).
    let last = presentation
        .rfind(PART_SEPARATOR)
        .ok_or(E::SdJwtMalformed)?;
    let (sd_jwt, kb_jwt) = presentation.split_at(last + PART_SEPARATOR.len_utf8());
    let mut parts = sd_jwt[..last].split(PART_SEPARATOR);
    let issuer_jwt = parts.next().unwrap_or_default();
    let disclosures: Vec<&str> = parts.collect();
    if disclosures.len() > MAX_DISCLOSURES {
        return Err(E::TooManyDisclosures);
    }
    if issuer_jwt.is_empty() || issuer_jwt.len() > MAX_ISSUER_JWT_LEN {
        return Err(E::IssuerJwtMalformed);
    }
    if kb_jwt.is_empty() {
        return Err(E::KeyBindingMissing);
    }
    if kb_jwt.len() > MAX_KB_JWT_LEN {
        return Err(E::KbJwtMalformed);
    }

    // §7.1 step 2: the issuer-signed JWT.
    let jwt = CompactJws::parse(issuer_jwt).ok_or(E::IssuerJwtMalformed)?;
    jwt.check_header(issuer_typ).map_err(|e| match e {
        HeaderError::Malformed => E::IssuerJwtMalformed,
        HeaderError::Typ => E::IssuerTyp,
        HeaderError::Alg => E::IssuerAlg,
    })?;
    if !jwt.verify_es256(&issuer.key) {
        return Err(E::IssuerSignature);
    }
    let mut payload = jwt.payload;
    match payload.remove(SD_ALG) {
        None => {}
        Some(Value::String(alg)) if alg == SD_ALG_SHA256 => {}
        Some(_) => return Err(E::SdAlgUnsupported),
    }

    // §7.1 steps 3-5: Disclosures and embedded digests.
    let mut state = Processing {
        disclosures: decode_disclosures(&disclosures)?,
        seen: HashSet::new(),
    };
    let mut disclosed_claim_names = Vec::new();
    state.object(&mut payload, 0, Some(&mut disclosed_claim_names))?;
    if state.disclosures.values().any(Option::is_some) {
        return Err(E::UnreferencedDisclosure);
    }

    // §7.1 step 6: validity of the processed payload.
    if !time_claims_hold(&payload, kb.now).ok_or(E::PayloadMalformed)? {
        return Err(E::CredentialValidity);
    }

    // §4.1.2 / §7.3 step 5a: the holder key.
    let holder = payload
        .get(CNF)
        .and_then(Value::as_object)
        .and_then(|cnf| cnf.get(CNF_JWK))
        .and_then(Value::as_object)
        .and_then(jose::p256_public_jwk)
        .ok_or(E::HolderKeyInvalid)?;

    verify_key_binding(kb_jwt, &holder, sd_jwt, kb)?;
    Ok(ProcessedSdJwt {
        payload,
        holder_key_thumbprint: jose::p256_thumbprint(&holder),
        disclosed_claim_names,
    })
}

/// [`verify_sd_jwt_kb`] with `typ` `dc+sd-jwt`, then the SD-JWT VC and DCQL checks (module
/// docs). The result holds only `query`'s claims, each at most
/// [`MAX_COMMITTED_CLAIM_BYTES`] serialized, plus evidence (holder key thumbprint, `vct`, names
/// of the disclosed claims); never the presentation itself.
///
/// # Errors
/// The first [`ValidationError`].
pub fn verify_sd_jwt_vc(
    presentation: &str,
    issuer: &TrustedIssuerKey,
    query: &CredentialQuery<'_>,
    kb: &KeyBindingContext<'_>,
) -> Result<ValidatedResponse, ValidationError> {
    use ValidationError as E;
    let processed = verify_sd_jwt_kb(presentation, issuer, SD_JWT_VC_TYP, kb)?;
    let disclosed = &processed.disclosed_claim_names;
    if disclosed
        .iter()
        .any(|name| NON_DISCLOSABLE_CLAIMS.contains(&name.as_str()))
    {
        return Err(E::NonDisclosableClaimDisclosed);
    }
    if processed.payload.get(VCT).and_then(Value::as_str) != Some(query.vct) {
        return Err(E::VctMismatch);
    }
    if disclosed
        .iter()
        .any(|name| !query.claims.contains(&name.as_str()))
    {
        return Err(E::UnrequestedClaimDisclosed);
    }
    let mut claims = Vec::with_capacity(query.claims.len());
    for name in query.claims {
        let value = processed
            .payload
            .get(*name)
            .ok_or(E::RequestedClaimMissing)?;
        if value.to_string().len() > MAX_COMMITTED_CLAIM_BYTES {
            return Err(E::ClaimValueTooLarge);
        }
        claims.push(((*name).to_owned(), value.clone()));
    }
    let mut disclosed_claim_names = processed.disclosed_claim_names;
    disclosed_claim_names.sort_unstable();
    Ok(ValidatedResponse {
        vct: query.vct.to_owned(),
        holder_key_thumbprint: processed.holder_key_thumbprint,
        claims,
        disclosed_claim_names,
    })
}

/// A decoded Disclosure (RFC 9901 §4.2.1, §4.2.2).
enum Disclosed {
    /// `[salt, claim name, claim value]`.
    Property { name: String, value: Value },
    /// `[salt, array element]`.
    Element(Value),
}

/// Decodes every Disclosure, keyed by its digest. Two Disclosures with one digest are the
/// same Disclosure sent twice (RFC 9901 §4: "MUST NOT ... send a Disclosure more than once").
fn decode_disclosures(
    encoded: &[&str],
) -> Result<HashMap<String, Option<Disclosed>>, ValidationError> {
    use ValidationError as E;
    let mut table = HashMap::with_capacity(encoded.len());
    for disclosure in encoded {
        if disclosure.is_empty() || disclosure.len() > MAX_DISCLOSURE_LEN {
            return Err(E::DisclosureMalformed);
        }
        let json = jose::b64_decode(disclosure)
            .and_then(|bytes| jose::parse_strict_json(&bytes))
            .ok_or(E::DisclosureMalformed)?;
        let decoded = match json {
            Value::Array(items) => match <[Value; 3]>::try_from(items) {
                Ok([Value::String(_salt), Value::String(name), value]) => {
                    // §7.1 step 3c.ii.2.
                    if name == SD || name == ARRAY_DIGEST {
                        return Err(E::ReservedClaimName);
                    }
                    Disclosed::Property { name, value }
                }
                Ok(_) => return Err(E::DisclosureMalformed),
                Err(items) => match <[Value; 2]>::try_from(items) {
                    Ok([Value::String(_salt), value]) => Disclosed::Element(value),
                    _ => return Err(E::DisclosureMalformed),
                },
            },
            _ => return Err(E::DisclosureMalformed),
        };
        if table
            .insert(disclosure_digest(disclosure), Some(decoded))
            .is_some()
        {
            return Err(E::DuplicateDisclosure);
        }
    }
    Ok(table)
}

/// RFC 9901 §7.1 step 3 over the payload: each Disclosure is taken out of the table when its
/// digest is found, so a leftover entry is unreferenced (step 5).
struct Processing {
    disclosures: HashMap<String, Option<Disclosed>>,
    /// Every embedded digest met so far, decoys included (step 4).
    seen: HashSet<String>,
}

impl Processing {
    fn value(&mut self, value: &mut Value, depth: usize) -> Result<(), ValidationError> {
        match value {
            Value::Object(object) => self.object(object, depth, None),
            Value::Array(items) => self.array(items, depth),
            _ => Ok(()),
        }
    }

    /// An object: its permanently disclosed members first, then each `_sd` digest (step 3c.ii).
    /// `top_level` collects the names inserted at the top level.
    fn object(
        &mut self,
        object: &mut Map<String, Value>,
        depth: usize,
        mut top_level: Option<&mut Vec<String>>,
    ) -> Result<(), ValidationError> {
        use ValidationError as E;
        // `...` is only an array-element digest (§4.1 item 7, §4.2.4.2); `_sd_alg` only at the
        // top level (§4.1.1), where the caller already removed it.
        if depth > MAX_SD_DEPTH || object.contains_key(ARRAY_DIGEST) || object.contains_key(SD_ALG)
        {
            return Err(E::PayloadMalformed);
        }
        let digests = match object.remove(SD) {
            None => Vec::new(),
            Some(Value::Array(digests)) => digests,
            Some(_) => return Err(E::PayloadMalformed),
        };
        for member in object.values_mut() {
            self.value(member, depth + 1)?;
        }
        for digest in digests {
            let Value::String(digest) = digest else {
                return Err(E::PayloadMalformed);
            };
            match self.take(digest)? {
                None => {}
                Some(Disclosed::Element(_)) => return Err(E::DisclosureMalformed),
                Some(Disclosed::Property { name, mut value }) => {
                    if object.contains_key(&name) {
                        return Err(E::ClaimNameCollision);
                    }
                    self.value(&mut value, depth + 1)?;
                    if let Some(names) = top_level.as_deref_mut() {
                        names.push(name.clone());
                    }
                    object.insert(name, value);
                }
            }
        }
        Ok(())
    }

    /// An array: `{"...": digest}` elements are replaced by their Disclosure or removed
    /// (steps 3c.iii, 3d); other elements are processed in place.
    fn array(&mut self, items: &mut Vec<Value>, depth: usize) -> Result<(), ValidationError> {
        use ValidationError as E;
        if depth > MAX_SD_DEPTH {
            return Err(E::PayloadMalformed);
        }
        let mut out = Vec::with_capacity(items.len());
        for mut item in std::mem::take(items) {
            let digest = match &item {
                Value::Object(element) if element.contains_key(ARRAY_DIGEST) => {
                    match (element.len(), element.get(ARRAY_DIGEST)) {
                        (1, Some(Value::String(digest))) => Some(digest.clone()),
                        _ => return Err(E::PayloadMalformed),
                    }
                }
                _ => None,
            };
            match digest {
                None => {
                    self.value(&mut item, depth + 1)?;
                    out.push(item);
                }
                Some(digest) => match self.take(digest)? {
                    None => {}
                    Some(Disclosed::Property { .. }) => return Err(E::DisclosureMalformed),
                    Some(Disclosed::Element(mut value)) => {
                        self.value(&mut value, depth + 1)?;
                        out.push(value);
                    }
                },
            }
        }
        *items = out;
        Ok(())
    }

    /// Records `digest` (each at most once, step 4) and takes its Disclosure, if any.
    fn take(&mut self, digest: String) -> Result<Option<Disclosed>, ValidationError> {
        let disclosure = self.disclosures.get_mut(&digest).and_then(Option::take);
        if !self.seen.insert(digest) {
            return Err(ValidationError::DuplicateDigest);
        }
        Ok(disclosure)
    }
}

/// `exp` / `nbf` of `claims`, if present (RFC 7519 §4.1.4, §4.1.5): `Some(true)` if both hold
/// at `now`, `None` if either is not a NumericDate (an integer here).
fn time_claims_hold(claims: &Map<String, Value>, now: u64) -> Option<bool> {
    let date = |name| claims.get(name).map(Value::as_u64);
    let expired = match date(EXP) {
        None => false,
        Some(exp) => now >= exp?,
    };
    let not_yet = match date(NBF) {
        None => false,
        Some(nbf) => nbf? > now,
    };
    Some(!expired && !not_yet)
}

/// RFC 9901 §7.3 step 5 for `kb_jwt`, signed by `holder`, over `sd_jwt`.
fn verify_key_binding(
    kb_jwt: &str,
    holder: &VerifyingKey,
    sd_jwt: &str,
    kb: &KeyBindingContext<'_>,
) -> Result<(), ValidationError> {
    use ValidationError as E;
    let jwt = CompactJws::parse(kb_jwt).ok_or(E::KbJwtMalformed)?;
    jwt.check_header(KB_JWT_TYP).map_err(|e| match e {
        HeaderError::Malformed => E::KbJwtMalformed,
        HeaderError::Typ => E::KbTyp,
        HeaderError::Alg => E::KbAlg,
    })?;
    if !jwt.verify_es256(holder) {
        return Err(E::KbSignature);
    }
    let claims = &jwt.payload;
    let string = |name| claims.get(name).and_then(Value::as_str);
    let iat = claims
        .get(IAT)
        .and_then(Value::as_u64)
        .ok_or(E::KbJwtMalformed)?;
    if iat.saturating_add(KB_JWT_MAX_AGE_SECS) < kb.now
        || iat > kb.now.saturating_add(KB_JWT_MAX_FUTURE_SKEW_SECS)
    {
        return Err(E::KbIatOutOfWindow);
    }
    // Optional registered claims must still be valid if present (§7.3 step 5h, RFC 7519).
    if !time_claims_hold(claims, kb.now).ok_or(E::KbJwtMalformed)? {
        return Err(E::KbIatOutOfWindow);
    }
    // `nonce` is a string and `aud` a single string (§4.3).
    if string(NONCE).ok_or(E::KbJwtMalformed)? != kb.nonce {
        return Err(E::KbNonceMismatch);
    }
    if string(AUD).ok_or(E::KbJwtMalformed)? != kb.audience {
        return Err(E::KbAudienceMismatch);
    }
    // §4.3.1: same hash algorithm as the Disclosures (sha-256, the only one accepted).
    if string(SD_HASH).ok_or(E::KbJwtMalformed)? != jose::sha256_b64(sd_jwt.as_bytes()) {
        return Err(E::KbSdHashMismatch);
    }
    Ok(())
}

/// Disclosure and digest handling against hand-built SD-JWTs (each a single RFC 9901 rule).
/// Keys are deterministic synthetic test scalars.
#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use serde_json::json;

    use super::*;
    use crate::jose::BASE64URL;

    const NOW: u64 = 1_800_000_000;
    const AUD: &str = "decentralized_identifier:did:key:zSyntheticTestVerifier";
    const NONCE: &str = "test-nonce";
    const TEST_VCT: &str = "https://credentials.lab.invalid/test/v1";
    const ISSUER_SCALAR: [u8; 32] = [1; 32];
    const HOLDER_SCALAR: [u8; 32] = [2; 32];

    fn key(scalar: [u8; 32]) -> SigningKey {
        SigningKey::from_slice(&scalar).expect("valid scalar")
    }

    fn trusted() -> TrustedIssuerKey {
        TrustedIssuerKey {
            key: *key(ISSUER_SCALAR).verifying_key(),
        }
    }

    fn context() -> KeyBindingContext<'static> {
        KeyBindingContext {
            audience: AUD,
            nonce: NONCE,
            now: NOW,
        }
    }

    /// Compact JWS over the exact `header` / `payload` bytes.
    fn jws(signer: &SigningKey, header: &str, payload: &str) -> String {
        let input = format!("{}.{}", BASE64URL.encode(header), BASE64URL.encode(payload));
        let signature: Signature = signer.sign(input.as_bytes());
        format!("{input}.{}", BASE64URL.encode(signature.to_bytes()))
    }

    fn disclosure(array: &Value) -> String {
        BASE64URL.encode(array.to_string())
    }

    /// Issuer payload: `vct`, validity and `cnf`, plus `extra` members.
    fn payload(extra: Value) -> Value {
        let holder = Value::Object(jose::p256_jwk_value(key(HOLDER_SCALAR).verifying_key()));
        let mut payload = json!({
            "iat": NOW - 10,
            "exp": NOW + 1000,
            "vct": TEST_VCT,
            "cnf": { "jwk": holder },
        });
        if let (Some(p), Value::Object(extra)) = (payload.as_object_mut(), extra) {
            p.extend(extra);
        }
        payload
    }

    fn issuer_jwt(payload: &Value) -> String {
        jws(
            &key(ISSUER_SCALAR),
            r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#,
            &payload.to_string(),
        )
    }

    /// An honest KB-JWT for `sd_jwt` with `claims` merged over the honest ones.
    fn kb_jwt(sd_jwt: &str, header: &str, claims: Value) -> String {
        let mut payload = json!({
            "iat": NOW,
            "aud": AUD,
            "nonce": NONCE,
            "sd_hash": jose::sha256_b64(sd_jwt.as_bytes()),
        });
        if let (Some(p), Value::Object(claims)) = (payload.as_object_mut(), claims) {
            p.extend(claims);
        }
        jws(&key(HOLDER_SCALAR), header, &payload.to_string())
    }

    const KB_HEADER: &str = r#"{"alg":"ES256","typ":"kb+jwt"}"#;

    fn present(issuer_jwt: &str, disclosures: &[&str]) -> String {
        let mut sd_jwt = format!("{issuer_jwt}~");
        for d in disclosures {
            sd_jwt.push_str(d);
            sd_jwt.push('~');
        }
        let kb = kb_jwt(&sd_jwt, KB_HEADER, json!({}));
        format!("{sd_jwt}{kb}")
    }

    fn verify(presentation: &str) -> Result<ProcessedSdJwt, ValidationError> {
        verify_sd_jwt_kb(presentation, &trusted(), SD_JWT_VC_TYP, &context())
    }

    fn name_disclosure(name: &str, value: Value) -> String {
        disclosure(&json!(["c2FsdC1mb3ItdGVzdHM", name, value]))
    }

    #[test]
    fn object_array_and_recursive_disclosures_are_reconstructed_and_decoys_dropped() {
        let street = name_disclosure("street", json!("Main St"));
        let address = name_disclosure("address", json!({ "_sd": [disclosure_digest(&street)] }));
        let element = disclosure(&json!(["c2FsdA", "DE"]));
        let name = name_disclosure("given_name", json!("Alex"));
        let decoy = jose::sha256_b64(b"decoy");
        let p = payload(json!({
            "_sd_alg": "sha-256",
            "_sd": [disclosure_digest(&name), disclosure_digest(&address), decoy],
            "nationalities": [{ "...": disclosure_digest(&element) }, { "...": jose::sha256_b64(b"x") }, "FR"],
        }));
        let processed = verify(&present(
            &issuer_jwt(&p),
            &[&name, &address, &street, &element],
        ))
        .expect("valid presentation");
        assert_eq!(processed.payload["given_name"], "Alex");
        assert_eq!(processed.payload["address"], json!({ "street": "Main St" }));
        assert_eq!(processed.payload["nationalities"], json!(["DE", "FR"]));
        assert!(
            !processed.payload.contains_key("_sd") && !processed.payload.contains_key("_sd_alg")
        );
        assert_eq!(processed.disclosed_claim_names, ["given_name", "address"]);
        assert_eq!(
            processed.holder_key_thumbprint,
            jose::p256_thumbprint(key(HOLDER_SCALAR).verifying_key())
        );
    }

    #[test]
    fn duplicate_digest_and_claim_name_collision_are_rejected() {
        let name = name_disclosure("given_name", json!("Alex"));
        let digest = disclosure_digest(&name);
        // The same digest twice (RFC 9901 §4.1, §7.1 step 4), also across levels.
        let twice = payload(json!({ "_sd": [digest, digest] }));
        assert_eq!(
            verify(&present(&issuer_jwt(&twice), &[&name])),
            Err(ValidationError::DuplicateDigest)
        );
        let nested = payload(json!({ "_sd": [digest], "inner": { "_sd": [digest] } }));
        assert_eq!(
            verify(&present(&issuer_jwt(&nested), &[&name])),
            Err(ValidationError::DuplicateDigest)
        );
        // A disclosed name that already exists in plaintext (§7.1 step 3c.ii.3).
        let collision = payload(json!({ "_sd": [digest], "given_name": "Eve" }));
        assert_eq!(
            verify(&present(&issuer_jwt(&collision), &[&name])),
            Err(ValidationError::ClaimNameCollision)
        );
    }

    #[test]
    fn duplicate_unreferenced_and_reserved_disclosures_are_rejected() {
        let name = name_disclosure("given_name", json!("Alex"));
        let p = payload(json!({ "_sd": [disclosure_digest(&name)] }));
        let jwt = issuer_jwt(&p);
        assert_eq!(
            verify(&present(&jwt, &[&name, &name])),
            Err(ValidationError::DuplicateDisclosure)
        );
        let stray = name_disclosure("nickname", json!("Lex"));
        assert_eq!(
            verify(&present(&jwt, &[&name, &stray])),
            Err(ValidationError::UnreferencedDisclosure)
        );
        for reserved in [SD, ARRAY_DIGEST] {
            let bad = name_disclosure(reserved, json!("x"));
            let p = payload(json!({ "_sd": [disclosure_digest(&bad)] }));
            assert_eq!(
                verify(&present(&issuer_jwt(&p), &[&bad])),
                Err(ValidationError::ReservedClaimName)
            );
        }
    }

    #[test]
    fn disclosure_shape_must_match_where_its_digest_is_found() {
        let element = disclosure(&json!(["c2FsdA", "DE"]));
        let property = name_disclosure("given_name", json!("Alex"));
        let in_sd = payload(json!({ "_sd": [disclosure_digest(&element)] }));
        assert_eq!(
            verify(&present(&issuer_jwt(&in_sd), &[&element])),
            Err(ValidationError::DisclosureMalformed)
        );
        let in_array = payload(json!({ "a": [{ "...": disclosure_digest(&property) }] }));
        assert_eq!(
            verify(&present(&issuer_jwt(&in_array), &[&property])),
            Err(ValidationError::DisclosureMalformed)
        );
        for bad in [
            disclosure(&json!(["only-salt"])),
            disclosure(&json!([1, "name", "value"])),
            disclosure(&json!({ "salt": "x" })),
            BASE64URL.encode(r#"["s","n","v","w"]"#),
            BASE64URL.encode(r#"["s","n",{"a":1,"a":2}]"#),
            "not base64url!".to_owned(),
        ] {
            let p = payload(json!({ "_sd": [disclosure_digest(&bad)] }));
            assert_eq!(
                verify(&present(&issuer_jwt(&p), &[&bad])),
                Err(ValidationError::DisclosureMalformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn sd_alg_and_payload_structure_are_strict() {
        let sha512 = payload(json!({ "_sd_alg": "sha-512" }));
        assert_eq!(
            verify(&present(&issuer_jwt(&sha512), &[])),
            Err(ValidationError::SdAlgUnsupported)
        );
        for bad in [
            json!({ "inner": { "_sd_alg": "sha-256" } }),
            json!({ "_sd": "not-an-array" }),
            json!({ "_sd": [1] }),
            json!({ "...": "top-level ellipsis" }),
            json!({ "a": [{ "...": "digest", "extra": 1 }] }),
            json!({ "exp": "tomorrow" }),
        ] {
            let p = payload(bad.clone());
            assert_eq!(
                verify(&present(&issuer_jwt(&p), &[])),
                Err(ValidationError::PayloadMalformed),
                "{bad}"
            );
        }
        let mut deep = json!("leaf");
        for _ in 0..=MAX_SD_DEPTH {
            deep = json!([deep]);
        }
        let p = payload(json!({ "deep": deep }));
        assert_eq!(
            verify(&present(&issuer_jwt(&p), &[])),
            Err(ValidationError::PayloadMalformed)
        );
    }

    #[test]
    fn issuer_jwt_policy_and_validity_are_enforced() {
        let p = payload(json!({}));
        let signed = |header: &str| jws(&key(ISSUER_SCALAR), header, &p.to_string());
        assert!(
            verify(&present(
                &signed(r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#),
                &[]
            ))
            .is_ok()
        );
        let cases = [
            (r#"{"alg":"ES256","typ":"JWT"}"#, ValidationError::IssuerTyp),
            (
                r#"{"alg":"ES384","typ":"dc+sd-jwt"}"#,
                ValidationError::IssuerAlg,
            ),
            (
                r#"{"alg":"ES256","typ":"dc+sd-jwt","crit":["x"]}"#,
                ValidationError::IssuerJwtMalformed,
            ),
            (
                r#"{"alg":"ES256","alg":"ES256","typ":"dc+sd-jwt"}"#,
                ValidationError::IssuerJwtMalformed,
            ),
        ];
        for (header, want) in cases {
            assert_eq!(
                verify(&present(&signed(header), &[])),
                Err(want),
                "{header}"
            );
        }
        let untrusted = jws(
            &key(HOLDER_SCALAR),
            r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#,
            &p.to_string(),
        );
        assert_eq!(
            verify(&present(&untrusted, &[])),
            Err(ValidationError::IssuerSignature)
        );
        let duplicate = r#"{"vct":"a","vct":"b"}"#;
        let jwt = jws(
            &key(ISSUER_SCALAR),
            r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#,
            duplicate,
        );
        assert_eq!(
            verify(&present(&jwt, &[])),
            Err(ValidationError::IssuerJwtMalformed)
        );
        let expired = payload(json!({ "exp": NOW }));
        assert_eq!(
            verify(&present(&issuer_jwt(&expired), &[])),
            Err(ValidationError::CredentialValidity)
        );
        let early = payload(json!({ "nbf": NOW + 1 }));
        assert_eq!(
            verify(&present(&issuer_jwt(&early), &[])),
            Err(ValidationError::CredentialValidity)
        );
        let mut no_cnf = payload(json!({}));
        if let Some(p) = no_cnf.as_object_mut() {
            p.remove(CNF);
        }
        assert_eq!(
            verify(&present(&issuer_jwt(&no_cnf), &[])),
            Err(ValidationError::HolderKeyInvalid)
        );
    }

    #[test]
    fn key_binding_jwt_claims_and_header_are_enforced() {
        let jwt = issuer_jwt(&payload(json!({})));
        let sd_jwt = format!("{jwt}~");
        let with =
            |header: &str, claims: Value| format!("{sd_jwt}{}", kb_jwt(&sd_jwt, header, claims));
        assert!(verify(&with(KB_HEADER, json!({}))).is_ok());
        let cases = [
            (
                KB_HEADER,
                json!({ "aud": "other" }),
                ValidationError::KbAudienceMismatch,
            ),
            (
                KB_HEADER,
                json!({ "aud": [AUD] }),
                ValidationError::KbJwtMalformed,
            ),
            (
                KB_HEADER,
                json!({ "nonce": "other" }),
                ValidationError::KbNonceMismatch,
            ),
            (
                KB_HEADER,
                json!({ "iat": NOW - KB_JWT_MAX_AGE_SECS - 1 }),
                ValidationError::KbIatOutOfWindow,
            ),
            (
                KB_HEADER,
                json!({ "iat": NOW + KB_JWT_MAX_FUTURE_SKEW_SECS + 1 }),
                ValidationError::KbIatOutOfWindow,
            ),
            (
                KB_HEADER,
                json!({ "exp": NOW }),
                ValidationError::KbIatOutOfWindow,
            ),
            (
                KB_HEADER,
                json!({ "exp": null }),
                ValidationError::KbJwtMalformed,
            ),
            (
                KB_HEADER,
                json!({ "sd_hash": jose::sha256_b64(b"other") }),
                ValidationError::KbSdHashMismatch,
            ),
            (
                r#"{"alg":"ES256","typ":"JWT"}"#,
                json!({}),
                ValidationError::KbTyp,
            ),
            (
                r#"{"alg":"none","typ":"kb+jwt"}"#,
                json!({}),
                ValidationError::KbAlg,
            ),
            (
                r#"{"alg":"ES256","typ":"kb+jwt","crit":["x"]}"#,
                json!({}),
                ValidationError::KbJwtMalformed,
            ),
        ];
        for (header, claims, want) in cases {
            assert_eq!(
                verify(&with(header, claims.clone())),
                Err(want),
                "{header} {claims}"
            );
        }
        // The window edges are inclusive.
        assert!(
            verify(&with(
                KB_HEADER,
                json!({ "iat": NOW - KB_JWT_MAX_AGE_SECS })
            ))
            .is_ok()
        );
        assert!(
            verify(&with(
                KB_HEADER,
                json!({ "iat": NOW + KB_JWT_MAX_FUTURE_SKEW_SECS })
            ))
            .is_ok()
        );
        let by_issuer = jws(&key(ISSUER_SCALAR), KB_HEADER, &json!({
            "iat": NOW, "aud": AUD, "nonce": NONCE, "sd_hash": jose::sha256_b64(sd_jwt.as_bytes()),
        }).to_string());
        assert_eq!(
            verify(&format!("{sd_jwt}{by_issuer}")),
            Err(ValidationError::KbSignature)
        );
        assert_eq!(verify(&sd_jwt), Err(ValidationError::KeyBindingMissing));
    }

    #[test]
    fn sizes_and_counts_are_bounded_before_any_crypto() {
        let jwt = issuer_jwt(&payload(json!({})));
        assert_eq!(
            verify(&"a".repeat(MAX_PRESENTATION_LEN + 1)),
            Err(ValidationError::PresentationTooLarge)
        );
        let many = vec!["AA"; MAX_DISCLOSURES + 1];
        assert_eq!(
            verify(&present(&jwt, &many)),
            Err(ValidationError::TooManyDisclosures)
        );
        let long = "A".repeat(MAX_DISCLOSURE_LEN + 1);
        assert_eq!(
            verify(&present(&jwt, &[&long])),
            Err(ValidationError::DisclosureMalformed)
        );
        assert_eq!(
            verify(&present(&jwt, &[""])),
            Err(ValidationError::DisclosureMalformed)
        );
        assert_eq!(verify("no-separator"), Err(ValidationError::SdJwtMalformed));
        assert_eq!(
            verify(&present(&"A".repeat(MAX_ISSUER_JWT_LEN + 1), &[])),
            Err(ValidationError::IssuerJwtMalformed)
        );
    }

    #[test]
    fn sd_jwt_vc_profile_enforces_vct_and_exactly_the_requested_claims() {
        let given = name_disclosure("given_name", json!("Alex"));
        let birth = name_disclosure("birthdate", json!("2000-01-01"));
        let vct = name_disclosure("vct", json!(TEST_VCT));
        let big = name_disclosure("family_name", json!("x".repeat(MAX_COMMITTED_CLAIM_BYTES)));
        let digests: Vec<String> = [&given, &birth, &big]
            .iter()
            .map(|d| disclosure_digest(d))
            .collect();
        let jwt = issuer_jwt(&payload(json!({ "_sd": digests })));
        let query = CredentialQuery {
            vct: TEST_VCT,
            claims: &["given_name"],
        };
        let check =
            |p: &str, q: &CredentialQuery<'_>| verify_sd_jwt_vc(p, &trusted(), q, &context());
        let ok = check(&present(&jwt, &[&given]), &query).expect("requested claim only");
        assert_eq!(ok.claims, [("given_name".to_owned(), json!("Alex"))]);
        assert_eq!(ok.disclosed_claim_names, ["given_name"]);
        assert_eq!(ok.vct, TEST_VCT);
        assert_eq!(
            check(&present(&jwt, &[&given, &birth]), &query),
            Err(ValidationError::UnrequestedClaimDisclosed)
        );
        assert_eq!(
            check(&present(&jwt, &[]), &query),
            Err(ValidationError::RequestedClaimMissing)
        );
        let other = CredentialQuery {
            vct: "https://credentials.lab.invalid/other",
            claims: &["given_name"],
        };
        assert_eq!(
            check(&present(&jwt, &[&given]), &other),
            Err(ValidationError::VctMismatch)
        );
        let family = CredentialQuery {
            vct: TEST_VCT,
            claims: &["family_name"],
        };
        assert_eq!(
            check(&present(&jwt, &[&big]), &family),
            Err(ValidationError::ClaimValueTooLarge)
        );
        // `vct` must never come from a Disclosure (SD-JWT VC §2.2.2.3).
        let mut p = payload(json!({ "_sd": [disclosure_digest(&vct)] }));
        if let Some(object) = p.as_object_mut() {
            object.remove(VCT);
        }
        let jwt = issuer_jwt(&p);
        assert_eq!(
            check(&present(&jwt, &[&vct]), &query),
            Err(ValidationError::NonDisclosableClaimDisclosed)
        );
        // A non-SD-JWT-VC `typ` is refused by the profile.
        let plain = jws(
            &key(ISSUER_SCALAR),
            r#"{"alg":"ES256","typ":"example+sd-jwt"}"#,
            &payload(json!({})).to_string(),
        );
        assert_eq!(
            check(&present(&plain, &[]), &query),
            Err(ValidationError::IssuerTyp)
        );
    }
}
