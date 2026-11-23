//! JWE Protected Header parsing and the HPKE-0 Integrated Encryption header policy.
//!
//! Policy (checked in this order, independent of member order in the JSON):
//! 1. UTF-8, a single JSON object (RFC 8259), unique member names (draft-22 §7.2 steps 3-4).
//! 2. `alg` present, a string, and exactly `HPKE-0` (draft-22 §5, §7.2 step 6, and the closing
//!    note of §7.2 that the application decides which algorithms are acceptable).
//! 3. `crit` absent: this implementation understands no extension (RFC 7516 §4.1.13).
//! 4. `enc` absent (draft-22 §5, §7.2 step 18), `ek` absent (draft-22 §5), `psk_id` absent
//!    (lab policy: OpenID4VP defines no PSK; draft-22 §5 would allow mode_psk), `zip` absent
//!    (lab policy: no decompression of attacker-controlled data).
//! 5. No other members than `alg`, `kid`, `typ`, `cty` (lab policy, fail closed; RFC 7516 §4
//!    would let a recipient ignore unknown non-critical parameters).
//! 6. `kid`, `typ`, `cty`, when present, are strings.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde_json::Value;

use crate::ALG_HPKE_0;
use crate::error::Error;

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
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
}

impl ProtectedHeader {
    /// `kid`: OpenID4VP 1.1 §8.3 requires it to equal the `kid` of the chosen Verifier JWK when
    /// that JWK has one; use it to select the decryption key, then still authenticate by
    /// decrypting.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
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
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::HeaderParameterType(name)),
    };
    Ok(ProtectedHeader {
        kid: string(KID)?,
        typ: string(TYP)?,
        cty: string(CTY)?,
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
