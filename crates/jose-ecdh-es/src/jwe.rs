//! Strict JWE Compact Serialization parser and `ECDH-ES` Direct Key Agreement decryption
//! (RFC 7516 §5.2 with the RFC 7518 §4.6 and §5.3 algorithms).

use std::fmt;

use zeroize::Zeroizing;

use crate::content::{self, IV_LEN, TAG_LEN};
use crate::error::{Error, Segment};
use crate::header::{self, ProtectedHeader};
use crate::keys::RecipientPrivateKey;
use crate::{MAX_COMPACT_JWE_LEN, MAX_PROTECTED_HEADER_LEN, b64, kdf};

/// RFC 7516 §7.1 / §5.2 step 1: five segments, separated by exactly four periods.
const COMPACT_SEGMENTS: usize = 5;
const SEGMENT_SEPARATOR: char = '.';
/// A JWE JSON Serialization (RFC 7516 §7.2) is a JSON object; the compact form never starts
/// with `{` because `{` is not in the base64url alphabet.
const JSON_OBJECT_START: char = '{';
/// Unpadded base64url: at most 4 characters per 3 bytes (RFC 4648 §5, RFC 7515 §2).
const B64_CHARS_PER_GROUP: usize = 4;
const B64_BYTES_PER_GROUP: usize = 3;

/// A parsed and policy-checked `ECDH-ES` compact JWE, ready to be opened.
///
/// Parsing performs every check that does not need the private key: length bound, compact
/// serialization only, five segments, canonical base64url, protected-header policy (including
/// an on-curve `epk`), empty JWE Encrypted Key, 96-bit IV and 128-bit tag. Opening is the only
/// authenticated step.
pub struct CompactJwe {
    /// The encoded protected header exactly as received; ASCII of it is the AES-GCM AAD.
    protected: String,
    header: ProtectedHeader,
    iv: [u8; IV_LEN],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_LEN],
}

impl CompactJwe {
    /// Parses `input` as an `ECDH-ES` (Direct Key Agreement) JWE Compact Serialization.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > MAX_COMPACT_JWE_LEN {
            return Err(Error::TooLong {
                max: MAX_COMPACT_JWE_LEN,
            });
        }
        if input.trim_start().starts_with(JSON_OBJECT_START) {
            return Err(Error::JsonSerialization);
        }
        // Count first so a separator flood never allocates per segment; then split into a
        // fixed-size array.
        let found = input.matches(SEGMENT_SEPARATOR).count() + 1;
        if found != COMPACT_SEGMENTS {
            return Err(Error::SegmentCount { found });
        }
        let mut segments = input.splitn(COMPACT_SEGMENTS, SEGMENT_SEPARATOR);
        let [protected, encrypted_key, iv, ciphertext, tag]: [&str; COMPACT_SEGMENTS] =
            std::array::from_fn(|_| segments.next().unwrap_or_default());

        // Cheap pre-check on the encoded length; header::parse applies the exact decoded bound.
        if protected.len()
            > MAX_PROTECTED_HEADER_LEN.div_ceil(B64_BYTES_PER_GROUP) * B64_CHARS_PER_GROUP
        {
            return Err(Error::HeaderTooLong {
                max: MAX_PROTECTED_HEADER_LEN,
            });
        }
        let header =
            header::parse(&b64::decode(protected).ok_or(Error::Base64(Segment::ProtectedHeader))?)?;
        // RFC 7518 §4.6: "the empty octet sequence is used as the JWE Encrypted Key value";
        // RFC 7516 §5.2 step 10: verify it. Its only spelling is the empty segment.
        if !encrypted_key.is_empty() {
            return Err(Error::NonEmptyEncryptedKey);
        }
        let iv = decode_fixed::<IV_LEN>(iv, Segment::InitializationVector, |found| {
            Error::IvLength { found }
        })?;
        let ciphertext = b64::decode(ciphertext).ok_or(Error::Base64(Segment::Ciphertext))?;
        let tag = decode_fixed::<TAG_LEN>(tag, Segment::AuthenticationTag, |found| {
            Error::TagLength { found }
        })?;

        Ok(Self {
            protected: protected.to_owned(),
            header,
            iv,
            ciphertext,
            tag,
        })
    }

    /// The accepted protected header (e.g. `kid` for key selection).
    pub fn header(&self) -> &ProtectedHeader {
        &self.header
    }

    /// RFC 7516 §5.2 steps 8 and 14-16: `Z = ECDH(sk, epk)`, CEK = Concat KDF (RFC 7518
    /// §4.6.2), then AES-GCM decryption with AAD = ASCII(Encoded Protected Header).
    ///
    /// Nothing but the private key goes into the key derivation: no `session_info`, no
    /// transaction binding. Any failure is [`Error::Decryption`] and no partial plaintext is
    /// returned.
    pub fn open(&self, sk: &RecipientPrivateKey) -> Result<Vec<u8>, Error> {
        let cek = derive_cek(sk, &self.header);
        content::decrypt(
            self.header.enc(),
            &cek,
            &self.iv,
            self.protected.as_bytes(),
            &self.ciphertext,
            &self.tag,
        )
    }
}

impl fmt::Debug for CompactJwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactJwe")
            .field("header", &self.header)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// [`CompactJwe::parse`] followed by [`CompactJwe::open`].
pub fn open_compact(input: &str, sk: &RecipientPrivateKey) -> Result<Vec<u8>, Error> {
    CompactJwe::parse(input)?.open(sk)
}

/// RFC 7516 §5.2 step 8 for Direct Key Agreement: the agreed-upon key is the CEK.
pub(crate) fn derive_cek(sk: &RecipientPrivateKey, header: &ProtectedHeader) -> Zeroizing<Vec<u8>> {
    let z = sk.agree(&header.epk);
    let enc = header.enc();
    kdf::concat_kdf(
        z.as_slice(),
        enc.as_str().as_bytes(),
        header.apu().unwrap_or_default(),
        header.apv().unwrap_or_default(),
        enc.key_len(),
    )
}

/// Decodes a segment that must be exactly `N` bytes; `length_error` gets the decoded length.
fn decode_fixed<const N: usize>(
    encoded: &str,
    segment: Segment,
    length_error: fn(usize) -> Error,
) -> Result<[u8; N], Error> {
    let bytes = b64::decode(encoded).ok_or(Error::Base64(segment))?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| length_error(bytes.len()))
}
