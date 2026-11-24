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
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::StartError;
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
/// Client Identifier Prefixes (OpenID4VP 1.1 §5.9.3) the lab cannot sign for correctly:
/// `redirect_uri` requests cannot be signed at all; `openid_federation`, `verifier_attestation`,
/// `x509_san_dns` and `x509_hash` need trust material (entity statements, an attestation JWT,
/// an `x5c` chain) the lab does not have; `origin` is reserved for the DC API (Appendix A).
const UNSIGNABLE_CLIENT_ID_PREFIXES: [&str; 6] = [
    "redirect_uri:",
    "openid_federation:",
    "verifier_attestation:",
    "x509_san_dns:",
    "x509_hash:",
    "origin:",
];
/// did:key DIDs; their single verification method is `<did>#<method-specific id>` (did:key
/// Method v0.7 §3.1).
const DID_KEY_PREFIX: &str = "did:key:";
/// Multibase prefix of base58btc, the encoding of a did:key method-specific id (did:key Method
/// v0.7 §3.1.1; multibase table).
const MULTIBASE_BASE58BTC: char = 'z';
/// Multicodec `p256-pub` (0x1200) as an unsigned varint, followed in a did:key by the
/// compressed SEC1 point (multicodec table; did:key Method v0.7 §2 "P-256").
const P256_PUB_MULTICODEC_VARINT: [u8; 2] = [0x80, 0x24];
/// Separates a DID from its fragment in a DID URL (DID Core §3.2).
pub(crate) const DID_URL_FRAGMENT: char = '#';
/// JWK member holding the private scalar (RFC 7518 §6.2.2.1).
const JWK_D: &str = "d";

/// The Verifier's Request Object signing key: an EC P-256 private JWK from configuration.
///
/// The lab ships no key. Tests load the synthetic SpruceID fixture
/// (`tests/fixtures/spruce_verifier.jwk`) through [`RequestSigningKey::from_jwk`]; the binary
/// reads a JWK file named by `--signing-key`. Not `Clone`, so the scalar is not copied around;
/// `SigningKey` zeroizes it on drop, and `Debug` never shows it.
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
    /// `d` is moved out of the parsed JSON and, like its decoded bytes, zeroized when dropped.
    /// The caller owns (and should zeroize) `jwk` itself.
    ///
    /// # Errors
    /// [`SigningKeyError`].
    pub fn from_jwk(jwk: &str) -> Result<Self, SigningKeyError> {
        let mut jwk: Value = serde_json::from_str(jwk).map_err(|_| SigningKeyError::Malformed)?;
        let d = match jwk.as_object_mut().and_then(|o| o.remove(JWK_D)) {
            Some(Value::String(d)) => Zeroizing::new(d),
            _ => return Err(SigningKeyError::Unsupported),
        };
        let member = |name| jwk.get(name).and_then(Value::as_str);
        if member("kty") != Some(JWK_KTY_EC) || member("crv") != Some(JWK_CRV_P256) {
            return Err(SigningKeyError::Unsupported);
        }
        // Each decoded buffer is moved (not copied) into `Zeroizing`.
        let decode = |value: Option<&str>| {
            let bytes = Zeroizing::new(
                value
                    .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                    .ok_or(SigningKeyError::Malformed)?,
            );
            if bytes.len() == P256_COORDINATE_BYTES {
                Ok(bytes)
            } else {
                Err(SigningKeyError::Malformed)
            }
        };
        let key = SigningKey::from_slice(&decode(Some(d.as_str()))?)
            .map_err(|_| SigningKeyError::Malformed)?;
        let mut expected = vec![SEC1_UNCOMPRESSED_TAG];
        expected.extend_from_slice(&decode(member("x"))?);
        expected.extend_from_slice(&decode(member("y"))?);
        if key.verifying_key().to_sec1_point(false).as_bytes() != expected.as_slice() {
            return Err(SigningKeyError::PublicKeyMismatch);
        }
        Ok(Self { key })
    }

    /// The parsed key, for the wallet simulator's synthetic issuer.
    #[cfg(feature = "wallet-sim")]
    pub(crate) fn into_signing_key(self) -> SigningKey {
        self.key
    }

    /// `did:key:z…` of the public key: base58btc of the `p256-pub` multicodec varint and the
    /// compressed point (did:key Method v0.7).
    fn did_key(&self) -> String {
        let mut bytes = P256_PUB_MULTICODEC_VARINT.to_vec();
        bytes.extend_from_slice(self.key.verifying_key().to_sec1_point(true).as_bytes());
        format!(
            "{DID_KEY_PREFIX}{MULTIBASE_BASE58BTC}{}",
            bs58::encode(bytes).into_string()
        )
    }
}

/// The JWS `kid` for `client_id`, refusing client ids the lab cannot sign for correctly.
///
/// * `decentralized_identifier:did:key:<id>`: `<id>` must be the did:key of `key` (derived
///   here, so a mismatch is caught at start, not by wallets); `kid` = `did:key:<id>#<id>`
///   (OpenID4VP 1.1 §5.9.3: `kid` identifies the DID Document key). Other DID methods need a
///   `kid` the lab cannot derive.
/// * A prefix in `UNSIGNABLE_CLIENT_ID_PREFIXES` is refused.
/// * Anything else is a pre-registered client (§5.9.2): no `kid`, the wallet knows the key.
///
/// # Errors
/// [`StartError::ClientIdKeyMismatch`] or [`StartError::UnsupportedClientIdPrefix`].
pub(crate) fn request_kid(
    client_id: &str,
    key: &RequestSigningKey,
) -> Result<Option<String>, StartError> {
    if let Some(did) = client_id.strip_prefix(DECENTRALIZED_IDENTIFIER_PREFIX) {
        let Some(id) = did.strip_prefix(DID_KEY_PREFIX) else {
            return Err(StartError::UnsupportedClientIdPrefix);
        };
        if did != key.did_key() {
            return Err(StartError::ClientIdKeyMismatch);
        }
        return Ok(Some(format!("{did}{DID_URL_FRAGMENT}{id}")));
    }
    if UNSIGNABLE_CLIENT_ID_PREFIXES
        .iter()
        .any(|prefix| client_id.starts_with(prefix))
    {
        return Err(StartError::UnsupportedClientIdPrefix);
    }
    Ok(None)
}

/// Signs request objects for one `client_id`: the protected header is fixed at start.
pub(crate) struct RequestSigner {
    key: SigningKey,
    /// base64url of `{"alg":"ES256","typ":"oauth-authz-req+jwt"[,"kid":...]}`.
    header_b64: String,
}

impl RequestSigner {
    /// `kid` from [`request_kid`] (checked before the server binds).
    pub(crate) fn new(key: RequestSigningKey, kid: Option<String>) -> Self {
        let mut header = json!({ "alg": REQUEST_OBJECT_ALG, "typ": REQUEST_OBJECT_TYP });
        if let Some(kid) = kid {
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
