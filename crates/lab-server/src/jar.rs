//! Signed Request Objects (JAR, RFC 9101) as OpenID4VP 1.1 §5 profiles them.
//!
//! The Verifier signs each request object once, when the session is issued, over the JSON
//! built from the session's `RequestBinding` (the same value then moved into the registry), and
//! serves the compact JWS unchanged at its `request_uri`. Nothing re-signs or edits it later.
//!
//! Signing is ES256 with RustCrypto `p256` 0.14 (`ecdsa`, RFC 6979 deterministic nonces), not
//! SpruceID's `P256Signer`: that signer would pull `openid4vp` (with reqwest, ssi and the
//! advisory baseline) into the default Verifier build, which the `verifier_without_sealing`
//! gate step forbids, and its p256 0.13 line signs over crypto-bigint 0.5 (RUSTSEC-2026-0387).
//! `tests/signed_request_object_e2e.rs` pins the lab signature byte-identical to `P256Signer`
//! over the same signing input.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use protocol_model::ClientIdWire;
use serde_json::{Value, json};

use crate::server::{JWK_CRV_P256, JWK_KTY_EC, P256_COORDINATE_BYTES, SEC1_UNCOMPRESSED_TAG};

/// JOSE `typ` of a Request Object (OpenID4VP 1.1 §5: Verifiers MUST include it, Wallets MUST
/// NOT process a Request Object without it; RFC 9101 §10.8 explicit typing).
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
/// Content type of the Request URI response (OpenID4VP 1.1 §5.10.1; RFC 9101 §5.2.3, media
/// type registered in §9.4.1).
pub const REQUEST_OBJECT_MEDIA_TYPE: &str = "application/oauth-authz-req+jwt";
/// Request Object `aud` under Static Discovery (OpenID4VP 1.1 §5.8). The lab has no Wallet
/// metadata (no `request_uri_method=post`, §5.10), so Dynamic Discovery's `issuer` never applies.
pub const REQUEST_OBJECT_AUD: &str = "https://self-issued.me/v2";
/// JWS algorithm of a P-256 signing key (RFC 7518 §3.4).
pub const REQUEST_OBJECT_ALG: &str = "ES256";
/// Client Identifier Prefix of a DID `client_id` (OpenID4VP 1.1 §5.9.3).
pub(crate) const DECENTRALIZED_IDENTIFIER_PREFIX: &str = "decentralized_identifier:";
/// did:key DIDs; their single verification method is `<did>#<method-specific id>` (did:key
/// Method v0.7 §3.1).
const DID_KEY_PREFIX: &str = "did:key:";
/// Separates a DID from its fragment in a DID URL (DID Core §3.2).
pub(crate) const DID_URL_FRAGMENT: char = '#';

/// The Verifier's Request Object signing key: an EC P-256 private JWK from configuration.
///
/// The lab ships no key. Tests load the synthetic SpruceID fixture
/// (`tests/fixtures/spruce_verifier.jwk`) through [`RequestSigningKey::from_jwk`]; the binary
/// reads a JWK file named by `--signing-key`. `Debug` never shows the private scalar.
#[derive(Clone)]
pub struct RequestSigningKey {
    key: SigningKey,
}

impl fmt::Debug for RequestSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSigningKey").finish_non_exhaustive()
    }
}

/// Why a signing key JWK was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigningKeyError {
    /// Not a JSON object, or a member is not canonical base64url of the right length.
    #[error("signing key JWK is malformed")]
    Malformed,
    /// Not an EC P-256 key with a private scalar `d`.
    #[error("signing key must be an EC P-256 private JWK")]
    Unsupported,
    /// `x` / `y` are not the public key of `d`.
    #[error("signing key JWK public coordinates do not match d")]
    PublicKeyMismatch,
}

impl RequestSigningKey {
    /// Parses an EC P-256 private JWK (RFC 7518 §6.2: `kty`, `crv`, `x`, `y`, `d`; each
    /// coordinate and `d` exactly 32 bytes) and checks that `x` / `y` belong to `d`.
    ///
    /// # Errors
    /// [`SigningKeyError`].
    pub fn from_jwk(jwk: &str) -> Result<Self, SigningKeyError> {
        let jwk: Value = serde_json::from_str(jwk).map_err(|_| SigningKeyError::Malformed)?;
        let member = |name| jwk.get(name).and_then(Value::as_str);
        if member("kty") != Some(JWK_KTY_EC)
            || member("crv") != Some(JWK_CRV_P256)
            || member("d").is_none()
        {
            return Err(SigningKeyError::Unsupported);
        }
        let field = |name| {
            member(name)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .filter(|bytes| bytes.len() == P256_COORDINATE_BYTES)
                .ok_or(SigningKeyError::Malformed)
        };
        let key = SigningKey::from_slice(&field("d")?).map_err(|_| SigningKeyError::Malformed)?;
        let mut expected = vec![SEC1_UNCOMPRESSED_TAG];
        expected.extend(field("x")?);
        expected.extend(field("y")?);
        if key.verifying_key().to_sec1_point(false).as_bytes() != expected.as_slice() {
            return Err(SigningKeyError::PublicKeyMismatch);
        }
        Ok(Self { key })
    }
}

/// Signs request objects for one `client_id`: the protected header is fixed at start.
pub(crate) struct RequestSigner {
    key: SigningKey,
    /// base64url of `{"alg":"ES256","typ":"oauth-authz-req+jwt"[,"kid":...]}`.
    header_b64: String,
}

impl RequestSigner {
    /// The header names the did:key verification method as `kid` when `client_id` is a
    /// `decentralized_identifier:did:key:` identifier (OpenID4VP 1.1 §5.9.3: the `kid`
    /// identifies the DID Document key that signed). Other client ids (lab experiments) get no
    /// `kid`; a wallet must then already know the Verifier's key.
    pub(crate) fn new(key: RequestSigningKey, client_id: &ClientIdWire) -> Self {
        let mut header = json!({ "alg": REQUEST_OBJECT_ALG, "typ": REQUEST_OBJECT_TYP });
        if let Some(kid) = did_key_verification_method(client_id.as_str()) {
            header["kid"] = kid.into();
        }
        Self {
            key: key.key,
            header_b64: URL_SAFE_NO_PAD.encode(header.to_string()),
        }
    }

    /// Compact JWS (RFC 7515 §7.1) over exactly `payload`; the signature is the 64-byte
    /// `R || S` of RFC 7518 §3.4.
    pub(crate) fn sign(&self, payload: &[u8]) -> String {
        let input = format!("{}.{}", self.header_b64, URL_SAFE_NO_PAD.encode(payload));
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

/// `did:key:<id>#<id>` for `decentralized_identifier:did:key:<id>`, else `None`.
fn did_key_verification_method(client_id: &str) -> Option<String> {
    let did = client_id.strip_prefix(DECENTRALIZED_IDENTIFIER_PREFIX)?;
    let id = did.strip_prefix(DID_KEY_PREFIX)?;
    (!id.is_empty() && !id.contains(DID_URL_FRAGMENT))
        .then(|| format!("{did}{DID_URL_FRAGMENT}{id}"))
}
