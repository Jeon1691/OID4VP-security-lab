//! Content encryption with AES GCM (RFC 7518 §5.3): `A128GCM` and `A256GCM`, 96-bit IV,
//! 128-bit tag, detached tag as the JWE Authentication Tag.

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use zeroize::Zeroize as _;

use crate::error::Error;

/// RFC 7518 §5.3: "Use of an IV of size 96 bits is REQUIRED with this algorithm."
pub const IV_LEN: usize = 12;
/// RFC 7518 §5.3: "The requested size of the Authentication Tag output MUST be 128 bits,
/// regardless of the key size."
pub const TAG_LEN: usize = 16;
/// RFC 7518 §5.3 table: "AES GCM using 128-bit key".
const A128GCM_KEY_LEN: usize = 16;
/// RFC 7518 §5.3 table: "AES GCM using 256-bit key".
const A256GCM_KEY_LEN: usize = 32;

/// RFC 7518 §5.3 `enc` value for AES-128-GCM.
pub const ENC_A128GCM: &str = "A128GCM";
/// RFC 7518 §5.3 `enc` value for AES-256-GCM.
pub const ENC_A256GCM: &str = "A256GCM";

/// The accepted `enc` values. `A192GCM` (RFC 7518 §5.3) and the AES-CBC-HMAC family (§5.2) are
/// not: OpenID4VP 1.0 HAIP profiles advertise only these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncryption {
    /// `A128GCM`.
    A128Gcm,
    /// `A256GCM`.
    A256Gcm,
}

impl ContentEncryption {
    /// The `enc` header value; for `ECDH-ES` also the Concat KDF AlgorithmID (RFC 7518 §4.6.2).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => ENC_A128GCM,
            Self::A256Gcm => ENC_A256GCM,
        }
    }

    /// CEK length in bytes; for `ECDH-ES` the Concat KDF keydatalen / 8 (RFC 7518 §4.6.2).
    pub const fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => A128GCM_KEY_LEN,
            Self::A256Gcm => A256GCM_KEY_LEN,
        }
    }

    /// Exact, case-sensitive match (RFC 7516 §4.1.2).
    pub(crate) fn from_header(value: &str) -> Option<Self> {
        match value {
            ENC_A128GCM => Some(Self::A128Gcm),
            ENC_A256GCM => Some(Self::A256Gcm),
            _ => None,
        }
    }
}

/// RFC 7516 §5.2 step 16: authenticated decryption. No plaintext is returned (and the work
/// buffer is wiped) when the tag does not verify.
pub(crate) fn decrypt(
    enc: ContentEncryption,
    cek: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, Error> {
    match enc {
        ContentEncryption::A128Gcm => open_with::<Aes128Gcm>(cek, iv, aad, ciphertext, tag),
        ContentEncryption::A256Gcm => open_with::<Aes256Gcm>(cek, iv, aad, ciphertext, tag),
    }
}

fn open_with<A>(
    cek: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, Error>
where
    A: KeyInit + AeadInOut<NonceSize = U12, TagSize = U16>,
{
    let cipher = A::new_from_slice(cek).map_err(|_| Error::Decryption)?;
    let mut buffer = ciphertext.to_vec();
    match cipher.decrypt_inout_detached(
        &Nonce::from(*iv),
        aad,
        buffer.as_mut_slice().into(),
        &Tag::from(*tag),
    ) {
        Ok(()) => Ok(buffer),
        Err(_) => {
            buffer.zeroize();
            Err(Error::Decryption)
        }
    }
}

/// RFC 7516 §5.1 step 15: encryption; returns `(ciphertext, tag)`.
#[cfg(feature = "test-support")]
pub(crate) fn encrypt(
    enc: ContentEncryption,
    cek: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Error> {
    match enc {
        ContentEncryption::A128Gcm => seal_with::<Aes128Gcm>(cek, iv, aad, plaintext),
        ContentEncryption::A256Gcm => seal_with::<Aes256Gcm>(cek, iv, aad, plaintext),
    }
}

#[cfg(feature = "test-support")]
fn seal_with<A>(
    cek: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Error>
where
    A: KeyInit + AeadInOut<NonceSize = U12, TagSize = U16>,
{
    let cipher = A::new_from_slice(cek).map_err(|_| Error::Encryption)?;
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(*iv), aad, buffer.as_mut_slice().into())
        .map_err(|_| Error::Encryption)?;
    Ok((buffer, tag.into()))
}
