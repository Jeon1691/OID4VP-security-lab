//! JOSE HPKE-0 Integrated Encryption codec and OpenID4VP 1.1 Session Info (IMP-004..006).
//!
//! Skeleton for the RED commit: public API only, every operation fails.

mod error;

pub use error::{Error, Segment};
pub use hpke::rand_core;

/// JWE `alg` value for HPKE-0 Integrated Encryption (draft-ietf-jose-hpke-encrypt-22 §5.1).
pub const ALG_HPKE_0: &str = "HPKE-0";

/// Maximum accepted compact JWE length in bytes.
pub const MAX_COMPACT_JWE_LEN: usize = 1 << 20;

/// HPKE-0 ciphersuite types from the `hpke` crate.
pub mod suite {
    /// DHKEM(P-256, HKDF-SHA256).
    pub type Kem = hpke::kem::DhP256HkdfSha256;
    /// HKDF-SHA256.
    pub type Kdf = hpke::kdf::HkdfSha256;
    /// AES-128-GCM.
    pub type Aead = hpke::aead::AesGcm128;
}

/// HPKE-0 recipient private key.
pub struct RecipientPrivateKey(());

impl std::fmt::Debug for RecipientPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecipientPrivateKey")
    }
}

impl RecipientPrivateKey {
    /// Parses a private key.
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        Err(Error::InvalidKey)
    }
    /// DeriveKeyPair.
    pub fn derive_from_ikm(_ikm: &[u8]) -> Self {
        Self(())
    }
    /// Random key.
    pub fn generate(_rng: &mut impl rand_core::CryptoRng) -> Self {
        Self(())
    }
    /// Public key.
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey(Vec::new())
    }
}

/// HPKE-0 recipient public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPublicKey(Vec<u8>);

impl RecipientPublicKey {
    /// Parses a public key.
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        Err(Error::InvalidKey)
    }
    /// Serialises the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Single-shot HPKE base-mode open.
pub fn open_base(
    _sk: &RecipientPrivateKey,
    _encapsulated_key: &[u8],
    _info: &[u8],
    _aad: &[u8],
    _ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    Err(Error::Decryption)
}

/// Protected header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectedHeader;

impl ProtectedHeader {
    /// `kid`.
    pub fn kid(&self) -> Option<&str> {
        None
    }
    /// `typ`.
    pub fn typ(&self) -> Option<&str> {
        None
    }
    /// `cty`.
    pub fn cty(&self) -> Option<&str> {
        None
    }
}

/// Parsed compact JWE.
#[derive(Debug, PartialEq, Eq)]
pub struct CompactJwe(ProtectedHeader);

impl CompactJwe {
    /// Parses.
    pub fn parse(_input: &str) -> Result<Self, Error> {
        Err(Error::HeaderJson)
    }
    /// Header.
    pub fn header(&self) -> &ProtectedHeader {
        &self.0
    }
    /// Opens.
    pub fn open(&self, _sk: &RecipientPrivateKey, _info: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::Decryption)
    }
}

/// Parse and open.
pub fn open_compact(input: &str, sk: &RecipientPrivateKey, info: &[u8]) -> Result<Vec<u8>, Error> {
    CompactJwe::parse(input)?.open(sk, info)
}

/// Session info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo(Vec<u8>);

impl SessionInfo {
    /// direct_post.jwt.
    pub fn direct_post_jwt(
        _client_id: &str,
        _nonce: &str,
        _response_uri: &str,
    ) -> Result<Self, Error> {
        Ok(Self(Vec::new()))
    }
    /// dc_api.jwt.
    pub fn dc_api_jwt(_origin: &str, _nonce: &str) -> Result<Self, Error> {
        Ok(Self(Vec::new()))
    }
    /// Bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionInfo {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Test support: sealing.
pub mod test_support {
    use crate::{Error, RecipientPublicKey, rand_core::CryptoRng};

    /// Seal.
    pub fn seal_compact(
        _recipient: &RecipientPublicKey,
        _kid: Option<&str>,
        _info: &[u8],
        _plaintext: &[u8],
        _rng: &mut impl CryptoRng,
    ) -> Result<String, Error> {
        Err(Error::Encryption)
    }

    /// Seal with a verbatim header.
    pub fn seal_compact_with_protected_header(
        _recipient: &RecipientPublicKey,
        _protected_header_json: &str,
        _info: &[u8],
        _plaintext: &[u8],
        _rng: &mut impl CryptoRng,
    ) -> Result<String, Error> {
        Err(Error::Encryption)
    }
}
