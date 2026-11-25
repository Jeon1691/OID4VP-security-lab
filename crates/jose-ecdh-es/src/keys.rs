//! P-256 recipient keys and the ECDH primitive (RFC 7518 §4.6, §6.2). This and `content` are
//! the only modules that call RustCrypto.

use std::fmt;

use p256::elliptic_curve::Generate as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::{PublicKey, SecretKey};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::b64;
use crate::error::Error;
use crate::rand_core::CryptoRng;

/// Octets of a P-256 coordinate or private scalar: RFC 7518 §6.2.1.2-3 ("the full size of a
/// coordinate for the curve") and §6.2.2.1 (ceiling(log2(n)/8) for the 256-bit order n).
pub(crate) const P256_FIELD_BYTES: usize = 32;
/// SEC1 §2.3.3 uncompressed point prefix (`0x04 || x || y`).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
/// JWK `kty` for elliptic-curve keys (RFC 7518 §6.1).
pub(crate) const JWK_KTY_EC: &str = "EC";
/// JWK `crv` for P-256 (RFC 7518 §6.2.1.1).
pub(crate) const JWK_CRV_P256: &str = "P-256";

/// A recipient (Verifier) private key: a P-256 scalar in `[1, n)`.
///
/// `Debug` never prints key material, and there is deliberately no accessor for the scalar
/// bytes. The underlying `p256::SecretKey` zeroizes on drop.
pub struct RecipientPrivateKey(SecretKey);

impl fmt::Debug for RecipientPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientPrivateKey(<redacted>)")
    }
}

impl RecipientPrivateKey {
    /// Parses the 32-byte big-endian scalar, e.g. the decoded JWK `d` member (RFC 7518
    /// §6.2.2.1). Shorter or longer inputs, zero and values `>= n` are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P256_FIELD_BYTES {
            return Err(Error::InvalidKey);
        }
        SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// A fresh random key.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        Self(SecretKey::generate_from_rng(rng))
    }

    /// The matching public key.
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey(self.0.public_key())
    }

    /// ECDH shared secret `Z` with `peer` (RFC 7518 §4.6.2): the x-coordinate of the shared
    /// point as a 32-byte octet string (NIST SP 800-56A §5.7.1.2).
    pub(crate) fn agree(&self, peer: &PublicKey) -> Zeroizing<[u8; P256_FIELD_BYTES]> {
        shared_secret(&self.0, peer)
    }
}

/// `Z` for a scalar and a validated public point. `p256::ecdh::SharedSecret` zeroizes itself;
/// the copy returned here does too. Best effort only: the `NonZeroScalar` copy made by
/// `to_nonzero_scalar`, the projective point inside `diffie_hellman` and the by-value `FieldBytes`
/// moved into the `Zeroizing` are stack temporaries that Rust can copy or leave behind, and
/// nothing guarantees they are wiped.
pub(crate) fn shared_secret(sk: &SecretKey, peer: &PublicKey) -> Zeroizing<[u8; P256_FIELD_BYTES]> {
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    Zeroizing::new((*shared.raw_secret_bytes()).into())
}

/// A recipient public key: a P-256 point other than the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPublicKey(pub(crate) PublicKey);

impl RecipientPublicKey {
    /// Builds the key from the decoded JWK `x` and `y` members (RFC 7518 §6.2.1.2-3), each
    /// exactly 32 bytes. Points that are not on P-256 are rejected.
    pub fn from_coordinates(x: &[u8], y: &[u8]) -> Result<Self, Error> {
        point_from_coordinates(x, y)
            .map(Self)
            .ok_or(Error::InvalidKey)
    }

    /// The public JWK `{"kty":"EC","crv":"P-256","x":...,"y":...}` (RFC 7518 §6.2.1), with no
    /// `kid`, `use` or `alg`; the caller adds those it advertises.
    pub fn to_jwk(&self) -> Value {
        public_jwk(&self.0)
    }
}

/// `x || y` as a validated P-256 point (SEC1 §2.3.4 with the `0x04` prefix): both coordinates
/// must be exactly 32 bytes, canonical (`< p`), and satisfy the curve equation. This is the
/// check that stops invalid-curve attacks on the static recipient key.
pub(crate) fn point_from_coordinates(x: &[u8], y: &[u8]) -> Option<PublicKey> {
    if x.len() != P256_FIELD_BYTES || y.len() != P256_FIELD_BYTES {
        return None;
    }
    let mut sec1 = Vec::with_capacity(1 + 2 * P256_FIELD_BYTES);
    sec1.push(SEC1_UNCOMPRESSED_TAG);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&sec1).ok()
}

pub(crate) fn public_jwk(pk: &PublicKey) -> Value {
    // `0x04 || x || y`; a `PublicKey` is never the identity, so this is always 65 bytes.
    let point = pk.to_uncompressed_point();
    let (x, y) = point[1..].split_at(P256_FIELD_BYTES);
    json!({
        "kty": JWK_KTY_EC,
        "crv": JWK_CRV_P256,
        "x": b64::encode(x),
        "y": b64::encode(y),
    })
}
