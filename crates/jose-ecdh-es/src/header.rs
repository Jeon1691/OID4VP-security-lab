//! JWE Protected Header parsing and the `ECDH-ES` header policy.
//!
//! Checks run in this order, independent of member order in the JSON. Which of them the RFCs
//! mandate and which are lab policy is tabulated in the crate docs ("Rejection rules").
//! 1. UTF-8, a single JSON object (RFC 8259), unique member names in every object at any depth
//!    (so `epk` cannot carry two `x` either).
//! 2. `alg` present, a string, and exactly `ECDH-ES`.
//! 3. `crit` absent; `zip` absent.
//! 4. No other members than `alg`, `enc`, `epk`, `apu`, `apv`, `kid`, `typ`, `cty`.
//! 5. `enc` present, a string, `A128GCM` or `A256GCM`.
//! 6. `epk` present: an object with exactly `kty` = `EC`, `crv` = `P-256`, `x`, `y` (32-byte
//!    canonical base64url each) forming a point on P-256; `d` is refused first.
//! 7. `apu` / `apv`, when present, canonical base64url strings, and not equal to each other.
//! 8. `kid`, `typ`, `cty`, when present, strings; `kid` satisfies `protocol_model::KeyId` and
//!    `typ`/`cty` are non-empty visible ASCII (`%x21-7E`).
//!
//! The decoded header is capped at [`crate::MAX_PROTECTED_HEADER_LEN`] before JSON parsing.

use std::collections::BTreeSet;
use std::fmt;

use p256::PublicKey;
use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use protocol_model::KeyId;

use crate::content::ContentEncryption;
use crate::error::Error;
use crate::keys::{JWK_CRV_P256, JWK_KTY_EC, P256_FIELD_BYTES, point_from_coordinates};
use crate::{ALG_ECDH_ES, MAX_PROTECTED_HEADER_LEN, b64};

/// RFC 7516 §4.1.1.
const ALG: &str = "alg";
/// RFC 7516 §4.1.2.
const ENC: &str = "enc";
/// RFC 7518 §4.6.1.1.
const EPK: &str = "epk";
/// RFC 7518 §4.6.1.2.
const APU: &str = "apu";
/// RFC 7518 §4.6.1.3.
const APV: &str = "apv";
/// RFC 7516 §4.1.6.
const KID: &str = "kid";
/// RFC 7516 §4.1.11.
const TYP: &str = "typ";
/// RFC 7516 §4.1.12.
const CTY: &str = "cty";
/// RFC 7516 §4.1.13.
const CRIT: &str = "crit";
/// RFC 7516 §4.1.3; refused (lab policy: no decompression of untrusted data).
const ZIP: &str = "zip";
/// Members accepted in an `ECDH-ES` protected header.
const ACCEPTED: [&str; 8] = [ALG, ENC, EPK, APU, APV, KID, TYP, CTY];

/// JWK members of an EC public key (RFC 7518 §6.2.1) and the private scalar (§6.2.2.1).
const JWK_KTY: &str = "kty";
const JWK_CRV: &str = "crv";
const JWK_X: &str = "x";
const JWK_Y: &str = "y";
const JWK_D: &str = "d";
/// The only members accepted in `epk` (lab policy, see the crate docs).
const EPK_ACCEPTED: [&str; 4] = [JWK_KTY, JWK_CRV, JWK_X, JWK_Y];
/// [`Error::EphemeralKeyParameter`] value for an `epk` member outside [`EPK_ACCEPTED`].
pub(crate) const EPK_UNKNOWN_MEMBER: &str = "(unknown member)";

/// The accepted `ECDH-ES` protected header. `alg` is always `ECDH-ES` and therefore not stored.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedHeader {
    enc: ContentEncryption,
    pub(crate) epk: PublicKey,
    apu: Option<Vec<u8>>,
    apv: Option<Vec<u8>>,
    kid: Option<KeyId>,
    typ: Option<String>,
    cty: Option<String>,
}

impl ProtectedHeader {
    /// `enc`: the content encryption algorithm, and the Concat KDF AlgorithmID.
    pub fn enc(&self) -> ContentEncryption {
        self.enc
    }

    /// Decoded `apu` (Agreement PartyUInfo), if present.
    pub fn apu(&self) -> Option<&[u8]> {
        self.apu.as_deref()
    }

    /// Decoded `apv` (Agreement PartyVInfo), if present.
    pub fn apv(&self) -> Option<&[u8]> {
        self.apv.as_deref()
    }

    /// `kid`, for selecting the decryption key (OpenID4VP 1.0 §8.3: it equals the `kid` of the
    /// chosen Verifier JWK when that JWK has one). Selecting by `kid` is routing, not
    /// authentication; decrypting is. Validated as a `protocol_model::KeyId`.
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

impl fmt::Debug for ProtectedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedHeader")
            .field("enc", &self.enc)
            .field("apu_len", &self.apu.as_ref().map(Vec::len))
            .field("apv_len", &self.apv.as_ref().map(Vec::len))
            .field("kid", &self.kid)
            .field("typ", &self.typ)
            .field("cty", &self.cty)
            .finish_non_exhaustive()
    }
}

/// Applies the policy above to the decoded protected header bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<ProtectedHeader, Error> {
    if bytes.len() > MAX_PROTECTED_HEADER_LEN {
        return Err(Error::HeaderTooLong {
            max: MAX_PROTECTED_HEADER_LEN,
        });
    }
    let members = parse_strict_object(bytes).ok_or(Error::HeaderJson)?;

    match members.get(ALG) {
        None => return Err(Error::MissingAlg),
        Some(Value::String(alg)) if alg == ALG_ECDH_ES => {}
        Some(Value::String(_)) => return Err(Error::UnsupportedAlg),
        Some(_) => return Err(Error::HeaderParameterType(ALG)),
    }
    if members.contains_key(CRIT) {
        return Err(Error::UnsupportedCrit);
    }
    if members.contains_key(ZIP) {
        return Err(Error::ForbiddenHeaderParameter(ZIP));
    }
    if members.keys().any(|k| !ACCEPTED.contains(&k.as_str())) {
        return Err(Error::UnknownHeaderParameter);
    }

    let enc = match members.get(ENC) {
        None => return Err(Error::MissingEnc),
        Some(Value::String(enc)) => {
            ContentEncryption::from_header(enc).ok_or(Error::UnsupportedEnc)?
        }
        Some(_) => return Err(Error::HeaderParameterType(ENC)),
    };
    let epk = match members.get(EPK) {
        None => return Err(Error::MissingEpk),
        Some(Value::Object(epk)) => parse_epk(epk)?,
        Some(_) => return Err(Error::HeaderParameterType(EPK)),
    };

    let string = |name: &'static str| match members.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(Error::HeaderParameterType(name)),
    };
    // RFC 7518 §4.6.1.2-3: "represented as a base64url-encoded string".
    let party_info = |name: &'static str| {
        string(name)?
            .map(|v| b64::decode(v).ok_or(Error::HeaderParameterValue(name)))
            .transpose()
    };
    let apu = party_info(APU)?;
    let apv = party_info(APV)?;
    // RFC 7518 §4.6.2: "The "apu" and "apv" values MUST be distinct, when used."
    if apu.is_some() && apu == apv {
        return Err(Error::HeaderParameterValue(APV));
    }
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
        enc,
        epk,
        apu,
        apv,
        kid,
        typ: token(TYP)?,
        cty: token(CTY)?,
    })
}

/// RFC 7518 §4.6.1.1 / §6.2.1: an EC P-256 public JWK with a point on the curve.
fn parse_epk(epk: &Map<String, Value>) -> Result<PublicKey, Error> {
    // "It MUST contain only public key parameters."
    if epk.contains_key(JWK_D) {
        return Err(Error::EphemeralKeyPrivate);
    }
    // The error names the category, never the attacker-chosen member name.
    if epk.keys().any(|k| !EPK_ACCEPTED.contains(&k.as_str())) {
        return Err(Error::EphemeralKeyParameter(EPK_UNKNOWN_MEMBER));
    }
    let string = |name: &'static str| match epk.get(name) {
        Some(Value::String(s)) => Ok(s.as_str()),
        _ => Err(Error::EphemeralKeyParameter(name)),
    };
    if string(JWK_KTY)? != JWK_KTY_EC {
        return Err(Error::EphemeralKeyParameter(JWK_KTY));
    }
    if string(JWK_CRV)? != JWK_CRV_P256 {
        return Err(Error::EphemeralKeyParameter(JWK_CRV));
    }
    let coordinate = |name: &'static str| {
        b64::decode(string(name)?)
            .filter(|c| c.len() == P256_FIELD_BYTES)
            .ok_or(Error::EphemeralKeyParameter(name))
    };
    let (x, y) = (coordinate(JWK_X)?, coordinate(JWK_Y)?);
    point_from_coordinates(&x, &y).ok_or(Error::EphemeralKeyPoint)
}

/// Parses JSON, refusing a repeated member name in any object at any depth (RFC 7516 §5.2
/// step 4; RFC 8259 §4 leaves duplicates undefined and `serde_json::Map` silently keeps the last
/// one). Same two-pass approach as lab-server's `jose::parse_strict_json`. Nesting is bounded by
/// serde_json's recursion limit.
fn parse_strict_object(bytes: &[u8]) -> Option<Map<String, Value>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut check = serde_json::Deserializer::from_str(text);
    UniqueMembers.deserialize(&mut check).ok()?;
    check.end().ok()?;
    match serde_json::from_str(text).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// Walks a JSON document and fails on the first object with a repeated member name. Values are
/// only visited, never kept.
#[derive(Clone, Copy)]
struct UniqueMembers;

impl<'de> DeserializeSeed<'de> for UniqueMembers {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueMembers {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique member names")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !seen.insert(name) {
                return Err(A::Error::custom("duplicate member name"));
            }
            map.next_value_seed(self)?;
        }
        Ok(())
    }
}
