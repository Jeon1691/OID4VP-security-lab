//! JWE Protected Header parsing and the HPKE-0 Integrated Encryption header policy.
//!
//! Checks run in this order, independent of member order in the JSON. Which of them the specs
//! mandate and which are lab v1 policy is tabulated in the crate docs ("Rejection rules").
//! 1. UTF-8, a single JSON object (RFC 8259), unique member names.
//! 2. `alg` present, a string, and exactly `HPKE-0`.
//! 3. `crit` absent.
//! 4. `enc`, `ek`, `psk_id`, `zip` absent.
//! 5. No other members than `alg`, `kid`, `typ`, `cty`.
//! 6. `kid`, `typ`, `cty`, when present, are strings; `kid` satisfies `protocol_model::KeyId`
//!    and `typ`/`cty` are non-empty visible ASCII (`%x21-7E`).
//!
//! The decoded header is capped at [`crate::MAX_PROTECTED_HEADER_LEN`] before JSON parsing.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde_json::Value;

use protocol_model::KeyId;

use crate::error::Error;
use crate::{ALG_HPKE_0, MAX_PROTECTED_HEADER_LEN};

/// RFC 7516 §4.1.1.
const ALG: &str = "alg";
/// RFC 7516 §4.1.6.
const KID: &str = "kid";
/// RFC 7516 §4.1.11.
const TYP: &str = "typ";
/// RFC 7516 §4.1.12.
const CTY: &str = "cty";
/// RFC 7516 §4.1.13.
const CRIT: &str = "crit";
/// Members accepted in an HPKE-0 protected header.
const ACCEPTED: [&str; 4] = [ALG, KID, TYP, CTY];
/// Members rejected with a named error: `enc` (RFC 7516 §4.1.2; MUST NOT, draft-22 §5),
/// `ek` (draft-22 §11.2.1; MUST NOT, §5), `psk_id` (draft-22 §11.2.2), `zip` (RFC 7516 §4.1.3).
const FORBIDDEN: [&str; 4] = ["enc", "ek", "psk_id", "zip"];

/// The accepted HPKE-0 protected header. `alg` is always `HPKE-0` and therefore not stored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectedHeader {
    kid: Option<KeyId>,
    typ: Option<String>,
    cty: Option<String>,
}

impl ProtectedHeader {
    /// `kid`: OpenID4VP 1.1 §8.3 requires it to equal the `kid` of the chosen Verifier JWK when
    /// that JWK has one; use it to select the decryption key, then still authenticate by
    /// decrypting. Validated as a `protocol_model::KeyId` (non-empty visible ASCII, so no
    /// NUL, bidi or zero-width characters reach key lookup or evidence logs).
    pub fn kid(&self) -> Option<&KeyId> {
        self.kid.as_ref()
    }

    /// `typ` (informational only).
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// `cty` (informational only).
    pub fn cty(&self) -> Option<&str> {
        self.cty.as_deref()
    }
}

/// Applies the policy above to the decoded protected header bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<ProtectedHeader, Error> {
    if bytes.len() > MAX_PROTECTED_HEADER_LEN {
        return Err(Error::HeaderTooLong {
            max: MAX_PROTECTED_HEADER_LEN,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::HeaderJson)?;
    let UniqueMembers(members) = serde_json::from_str(text).map_err(|_| Error::HeaderJson)?;
    let get = |name: &str| members.iter().find(|(k, _)| k == name).map(|(_, v)| v);

    match get(ALG) {
        None => return Err(Error::MissingAlg),
        Some(Value::String(alg)) if alg == ALG_HPKE_0 => {}
        Some(Value::String(_)) => return Err(Error::UnsupportedAlg),
        Some(_) => return Err(Error::HeaderParameterType(ALG)),
    }
    if get(CRIT).is_some() {
        return Err(Error::UnsupportedCrit);
    }
    if let Some(name) = FORBIDDEN.into_iter().find(|name| get(name).is_some()) {
        return Err(Error::ForbiddenHeaderParameter(name));
    }
    if members.iter().any(|(k, _)| !ACCEPTED.contains(&k.as_str())) {
        return Err(Error::UnknownHeaderParameter);
    }

    let string = |name: &'static str| match get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(Error::HeaderParameterType(name)),
    };
    let kid = string(KID)?
        .map(|kid| KeyId::new(kid).map_err(|_| Error::HeaderParameterValue(KID)))
        .transpose()?;
    let token = |name: &'static str| -> Result<Option<String>, Error> {
        match string(name)? {
            Some(v) if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic()) => {
                Err(Error::HeaderParameterValue(name))
            }
            v => Ok(v.map(str::to_owned)),
        }
    };
    Ok(ProtectedHeader {
        kid,
        typ: token(TYP)?,
        cty: token(CTY)?,
    })
}

/// A JSON object's members in document order. Deserialisation fails on a repeated member name,
/// which `serde_json::Map` would silently resolve as last-wins.
struct UniqueMembers(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for UniqueMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(UniqueMembersVisitor)
    }
}

struct UniqueMembersVisitor;

impl<'de> Visitor<'de> for UniqueMembersVisitor {
    type Value = UniqueMembers;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object with unique member names")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        let mut members = Vec::new();
        while let Some(name) = map.next_key::<String>()? {
            if !seen.insert(name.clone()) {
                return Err(A::Error::custom("duplicate member name"));
            }
            members.push((name, map.next_value::<Value>()?));
        }
        Ok(UniqueMembers(members))
    }
}
