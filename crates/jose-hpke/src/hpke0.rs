//! The HPKE-0 ciphersuite and its keys. This is the only module that calls the `hpke` crate.
//!
//! HPKE-0 = DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM (draft-22 §5.1 Table 1),
//! i.e. RFC 9180 kem_id 0x0010, kdf_id 0x0001, aead_id 0x0001, used in mode_base only.

use std::fmt;

use hpke::{Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _};

use crate::error::Error;
use crate::rand_core::CryptoRng;

/// HPKE-0 ciphersuite types from the `hpke` crate (draft-22 §5.1, RFC 9180 §7).
pub mod suite {
    /// DHKEM(P-256, HKDF-SHA256), RFC 9180 kem_id 0x0010.
    pub type Kem = hpke::kem::DhP256HkdfSha256;
    /// HKDF-SHA256, RFC 9180 kdf_id 0x0001.
    pub type Kdf = hpke::kdf::HkdfSha256;
    /// AES-128-GCM, RFC 9180 aead_id 0x0001.
    pub type Aead = hpke::aead::AesGcm128;
}

use suite::{Aead, Kdf, Kem};

type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

/// A recipient (Verifier) HPKE-0 private key: a P-256 scalar in `[1, n)`.
///
/// `Debug` never prints key material, and there is deliberately no accessor for the scalar
/// bytes. The underlying `p256::SecretKey` zeroizes on drop.
pub struct RecipientPrivateKey(<Kem as hpke::Kem>::PrivateKey);

impl fmt::Debug for RecipientPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientPrivateKey(<redacted>)")
    }
}

impl RecipientPrivateKey {
    /// Parses `SerializePrivateKey` output (RFC 9180 §7.1.2): the 32-byte big-endian scalar,
    /// e.g. the decoded JWK `d` member.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        <Kem as hpke::Kem>::PrivateKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)`. `ikm` SHOULD have at least 32 bytes of entropy;
    /// intended for known-answer tests and deterministic lab fixtures.
    pub fn derive_from_ikm(ikm: &[u8]) -> Self {
        Self(Kem::derive_keypair(ikm).0)
    }

    /// A fresh random key pair (`DeriveKeyPair(random(Nsk))`, RFC 9180 §4).
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        Self(Kem::gen_keypair_with_rng(rng).0)
    }

    /// The matching public key.
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey(Kem::sk_to_pk(&self.0))
    }
}

/// A recipient HPKE-0 public key: a P-256 point other than the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPublicKey(<Kem as hpke::Kem>::PublicKey);

impl RecipientPublicKey {
    /// Parses `SerializePublicKey` output (RFC 9180 §7.1.1): the 65-byte SEC1 uncompressed
    /// point `0x04 || x || y`. Compressed points and off-curve points are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// `SerializePublicKey` (RFC 9180 §7.1.1): 65-byte SEC1 uncompressed point.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// A validated encapsulated key (`enc`, RFC 9180 §4.1): a 65-byte uncompressed P-256 point.
#[derive(Clone)]
pub(crate) struct EncapsulatedKey(EncappedKey);

impl EncapsulatedKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        EncappedKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::EncapsulatedKey)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// RFC 9180 §6.1 `OpenBase(enc, skR, info, aad, ct)`.
    pub(crate) fn open(
        &self,
        sk: &RecipientPrivateKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &sk.0,
            &self.0,
            info,
            ciphertext,
            aad,
        )
        .map_err(|_| Error::Decryption)
    }
}

/// RFC 9180 §6.1 single-shot `OpenBase(enc, skR, info, aad, ct)` for the HPKE-0 suite.
///
/// This is the primitive behind [`crate::CompactJwe::open`]; it is public so the RFC 9180
/// known-answer tests exercise the same code path. `ciphertext` is the AEAD output including
/// its 16-byte tag. Every failure after `enc` validation is [`Error::Decryption`].
pub fn open_base(
    sk: &RecipientPrivateKey,
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    EncapsulatedKey::from_bytes(encapsulated_key)?.open(sk, info, aad, ciphertext)
}

/// RFC 9180 §6.1 single-shot `SealBase(pkR, info, aad, pt)`; returns `(enc, ct)`.
pub(crate) fn seal_base(
    pk: &RecipientPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (enc, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk.0,
        info,
        plaintext,
        aad,
        rng,
    )
    .map_err(|_| Error::Encryption)?;
    Ok((enc.to_bytes().to_vec(), ct))
}
