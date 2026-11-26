//! Strict JOSE primitives for the Verifier side of holder binding: canonical base64url, JSON
//! with unique member names at every depth, compact JWS parsing, ES256 verification and EC
//! P-256 public JWKs.
//!
//! Same policy as jose-hpke's JWE codec and [`crate::jar`]: one spelling per octet string, no
//! last-wins duplicate members, `crit` refused, `alg` compared exactly. Every size is bounded by
//! the caller before anything here runs.

use std::collections::BTreeSet;
use std::fmt;

use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use crate::server::{JWK_CRV_P256, JWK_KTY_EC, P256_COORDINATE_BYTES, SEC1_UNCOMPRESSED_TAG};

/// Canonical base64url (RFC 7515 §2): URL-safe alphabet, no padding, no non-zero trailing bits.
/// RFC 9901 §4 (ABNF `BASE64URL`) uses the same alphabet for every SD-JWT component.
pub(crate) const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

/// JWS algorithm the lab accepts for issuer and Key Binding JWTs (RFC 7518 §3.4; RFC 9901
/// §7.1 step 2a and §7.3 step 5b: the algorithm must be deemed secure, never `none`).
pub(crate) const ALG_ES256: &str = "ES256";
/// JOSE header parameters (RFC 7515 §4.1.1, §4.1.9, §4.1.11).
pub(crate) const HEADER_ALG: &str = "alg";
pub(crate) const HEADER_TYP: &str = "typ";
const HEADER_CRIT: &str = "crit";
/// Segments of a compact JWS (RFC 7515 §7.1).
const JWS_SEGMENTS: usize = 3;
/// Bytes of an ES256 signature: `R || S`, 32 bytes each (RFC 7518 §3.4).
const ES256_SIGNATURE_BYTES: usize = 2 * P256_COORDINATE_BYTES;
/// JWK members of an EC public key (RFC 7518 §6.2.1) and the private scalar (§6.2.2.1).
const JWK_KTY: &str = "kty";
const JWK_CRV: &str = "crv";
const JWK_X: &str = "x";
const JWK_Y: &str = "y";
const JWK_D: &str = "d";

/// Decodes canonical base64url; `None` for any other spelling.
pub(crate) fn b64_decode(encoded: &str) -> Option<Vec<u8>> {
    BASE64URL.decode(encoded).ok()
}

/// base64url of SHA-256 over `bytes` (RFC 9901 §4.2.3, §4.3.1; RFC 7638 §3).
pub(crate) fn sha256_b64(bytes: &[u8]) -> String {
    BASE64URL.encode(Sha256::digest(bytes))
}

/// Parses JSON, refusing a repeated member name in any object at any depth (RFC 8259 §4 leaves
/// duplicates undefined; `serde_json::Map` silently keeps the last one, which lets two parsers
/// see different claims). Nesting is bounded by serde_json's recursion limit.
pub(crate) fn parse_strict_json(bytes: &[u8]) -> Option<Value> {
    let mut check = serde_json::Deserializer::from_slice(bytes);
    UniqueMembers.deserialize(&mut check).ok()?;
    check.end().ok()?;
    serde_json::from_slice(bytes).ok()
}

/// [`parse_strict_json`] of a JSON object.
pub(crate) fn parse_strict_object(bytes: &[u8]) -> Option<Map<String, Value>> {
    match parse_strict_json(bytes)? {
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

/// A compact JWS split and decoded, not yet verified.
pub(crate) struct CompactJws<'a> {
    /// The protected header (unique members).
    pub(crate) header: Map<String, Value>,
    /// The payload (a JSON object with unique members).
    pub(crate) payload: Map<String, Value>,
    /// `BASE64URL(header) || '.' || BASE64URL(payload)` (RFC 7515 §5.2 step 8).
    signing_input: &'a str,
    /// The decoded signature (any length; checked in [`CompactJws::verify_es256`]).
    signature: Vec<u8>,
}

impl<'a> CompactJws<'a> {
    /// Splits `token` into exactly three canonical base64url segments whose header and payload
    /// are JSON objects with unique member names. The signature segment may be empty
    /// (`alg: none`): the caller rejects that by its `alg` policy, before verification.
    pub(crate) fn parse(token: &'a str) -> Option<Self> {
        let mut segments = token.split('.');
        let parts: [&str; JWS_SEGMENTS] = [segments.next()?, segments.next()?, segments.next()?];
        if segments.next().is_some() {
            return None;
        }
        let [header_b64, payload_b64, signature_b64] = parts;
        let header = parse_strict_object(&b64_decode(header_b64)?)?;
        let payload = parse_strict_object(&b64_decode(payload_b64)?)?;
        let signature = b64_decode(signature_b64)?;
        let signing_input = token.get(..header_b64.len() + 1 + payload_b64.len())?;
        Some(Self {
            header,
            payload,
            signing_input,
            signature,
        })
    }

    /// Header policy shared by every JWT the lab verifies: no `crit` (the lab understands no
    /// extension, RFC 7515 §4.1.11), `alg` exactly ES256, and `typ` exactly `typ`
    /// (RFC 8725 §3.11 explicit typing).
    pub(crate) fn check_header(&self, typ: &str) -> Result<(), HeaderError> {
        if self.header.contains_key(HEADER_CRIT) {
            return Err(HeaderError::Malformed);
        }
        if self.header.get(HEADER_TYP).and_then(Value::as_str) != Some(typ) {
            return Err(HeaderError::Typ);
        }
        if self.header.get(HEADER_ALG).and_then(Value::as_str) != Some(ALG_ES256) {
            return Err(HeaderError::Alg);
        }
        Ok(())
    }

    /// `BASE64URL(header) '.' BASE64URL(payload)`, as received.
    #[cfg(feature = "conformance")]
    pub(crate) const fn signing_input(&self) -> &str {
        self.signing_input
    }

    /// The decoded signature, any length.
    #[cfg(feature = "conformance")]
    pub(crate) fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// ES256 signature check over the signing input (RFC 7515 §5.2 step 8, RFC 7518 §3.4).
    pub(crate) fn verify_es256(&self, key: &VerifyingKey) -> bool {
        self.signature.len() == ES256_SIGNATURE_BYTES
            && Signature::from_slice(&self.signature)
                .is_ok_and(|sig| key.verify(self.signing_input.as_bytes(), &sig).is_ok())
    }
}

/// Why a JWS header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderError {
    /// `crit` present.
    Malformed,
    /// `typ` missing or wrong.
    Typ,
    /// `alg` missing or not ES256 (including `none`).
    Alg,
}

/// An EC P-256 public JWK (RFC 7518 §6.2.1): `kty` `EC`, `crv` `P-256`, canonical base64url
/// 32-byte `x` / `y` on the curve. A private scalar `d` is refused: a public key slot that
/// carries a private key is a configuration or issuance error. Other members (`kid`, `use`,
/// `alg`) are ignored.
pub(crate) fn p256_public_jwk(jwk: &Map<String, Value>) -> Option<VerifyingKey> {
    let member = |name| jwk.get(name).and_then(Value::as_str);
    if member(JWK_KTY) != Some(JWK_KTY_EC)
        || member(JWK_CRV) != Some(JWK_CRV_P256)
        || jwk.contains_key(JWK_D)
    {
        return None;
    }
    let coordinate =
        |name| b64_decode(member(name)?).filter(|bytes| bytes.len() == P256_COORDINATE_BYTES);
    let mut point = vec![SEC1_UNCOMPRESSED_TAG];
    point.extend(coordinate(JWK_X)?);
    point.extend(coordinate(JWK_Y)?);
    VerifyingKey::from_sec1_bytes(&point).ok()
}

/// The public JWK of `key` as a JSON object (RFC 7518 §6.2.1).
#[cfg(any(test, feature = "wallet-sim"))]
pub(crate) fn p256_jwk_value(key: &VerifyingKey) -> Map<String, Value> {
    let (x, y) = p256_coordinates(key);
    let mut jwk = Map::new();
    jwk.insert(JWK_KTY.into(), JWK_KTY_EC.into());
    jwk.insert(JWK_CRV.into(), JWK_CRV_P256.into());
    jwk.insert(JWK_X.into(), x.into());
    jwk.insert(JWK_Y.into(), y.into());
    jwk
}

/// RFC 7638 JWK Thumbprint (SHA-256, base64url) of an EC public key: the hash of the required
/// members `crv`, `kty`, `x`, `y` in lexicographic order, without whitespace (§3.2, §3.3).
pub(crate) fn p256_thumbprint(key: &VerifyingKey) -> String {
    let (x, y) = p256_coordinates(key);
    sha256_b64(
        format!(r#"{{"{JWK_CRV}":"{JWK_CRV_P256}","{JWK_KTY}":"{JWK_KTY_EC}","{JWK_X}":"{x}","{JWK_Y}":"{y}"}}"#)
            .as_bytes(),
    )
}

/// base64url `x` and `y` of `key`.
fn p256_coordinates(key: &VerifyingKey) -> (String, String) {
    let point = key.to_sec1_point(false);
    let (x, y) = point
        .as_bytes()
        .strip_prefix(&[SEC1_UNCOMPRESSED_TAG])
        .map(|xy| xy.split_at(P256_COORDINATE_BYTES))
        .unwrap_or_default();
    (BASE64URL.encode(x), BASE64URL.encode(y))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JSON `\u00XX` escape as raw bytes (backslash, `u`, `0`, `0`).
    const ESCAPE_PREFIX: &[u8] = b"\\u00";

    #[test]
    fn strict_json_refuses_duplicate_members_at_any_depth() {
        assert!(parse_strict_json(br#"{"a":1,"b":{"c":[{"d":1}]}}"#).is_some());
        assert!(parse_strict_json(br#"{"a":1,"a":2}"#).is_none());
        assert!(parse_strict_json(br#"{"a":{"b":1,"b":1}}"#).is_none());
        assert!(parse_strict_json(br#"[{"x":1},{"y":[{"z":1,"z":2}]}]"#).is_none());
        // An escaped spelling of the same name is the same name (RFC 8259 §7), at the top level
        // and nested.
        let escaped = b"{\"alg\":\"ES256\",\"\\u0061lg\":\"none\"}";
        let nested = b"{\"cnf\":{\"jwk\":{\"x\":\"a\",\"\\u0078\":\"b\"}}}";
        for json in [escaped.as_slice(), nested.as_slice()] {
            assert!(
                json.windows(ESCAPE_PREFIX.len())
                    .any(|w| w == ESCAPE_PREFIX),
                "the test input keeps its \\u escape"
            );
            assert!(parse_strict_json(json).is_none());
        }
        assert!(parse_strict_json(br#"{"a":1} x"#).is_none());
    }

    #[test]
    fn base64url_accepts_one_spelling_only() {
        assert_eq!(b64_decode("AQ"), Some(vec![1]));
        assert_eq!(b64_decode("AQ=="), None);
        assert_eq!(b64_decode("AR"), None);
        assert_eq!(b64_decode("A+"), None);
    }

    /// The thumbprint input is the required members in lexicographic order without whitespace
    /// (RFC 7638 §3.2, §3.3), here for the RFC 9901 Appendix A.5 issuer key.
    #[test]
    fn thumbprint_hashes_the_rfc7638_member_order() {
        let jwk = parse_strict_object(
            br#"{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}"#,
        )
        .expect("jwk");
        let key = p256_public_jwk(&jwk).expect("on-curve key");
        let canonical = r#"{"crv":"P-256","kty":"EC","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}"#;
        assert_eq!(p256_thumbprint(&key), sha256_b64(canonical.as_bytes()));
        let mut private = jwk.clone();
        private.insert(JWK_D.into(), "AA".into());
        assert!(
            p256_public_jwk(&private).is_none(),
            "a private member is refused"
        );
    }
}
