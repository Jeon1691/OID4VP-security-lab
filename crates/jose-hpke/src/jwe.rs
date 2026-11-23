//! Strict JWE Compact Serialization parser and HPKE-0 Integrated Encryption open
//! (draft-ietf-jose-hpke-encrypt-22 §5 and §7.2).

use std::fmt;

use crate::error::{Error, Segment};
use crate::hpke0::{EncapsulatedKey, RecipientPrivateKey};
use crate::{MAX_COMPACT_JWE_LEN, MAX_PROTECTED_HEADER_LEN, b64, header, header::ProtectedHeader};

/// RFC 7516 §7.1 / draft-22 §7.2 step 1: five segments, separated by exactly four periods.
const COMPACT_SEGMENTS: usize = 5;
const SEGMENT_SEPARATOR: char = '.';
/// A JWE JSON Serialization (RFC 7516 §7.2) is a JSON object; the compact form never starts
/// with `{` because `{` is not in the base64url alphabet.
const JSON_OBJECT_START: char = '{';

/// A parsed and policy-checked HPKE-0 compact JWE, ready to be opened.
///
/// Parsing performs every check that does not need the private key: length bound, compact
/// serialization only, five segments, canonical base64url, protected-header policy, empty IV and
/// Tag, and a valid P-256 encapsulated key. Opening is the only authenticated step.
pub struct CompactJwe {
    /// The encoded protected header exactly as received; ASCII of it is the HPKE `aad`.
    protected: String,
    header: ProtectedHeader,
    encapsulated_key: EncapsulatedKey,
    ciphertext: Vec<u8>,
}

impl CompactJwe {
    /// Parses `input` as an HPKE-0 Integrated Encryption JWE Compact Serialization.
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

        // Cheap pre-check on the encoded length (unpadded base64url needs at most 4 chars per
        // 3 bytes); header::parse applies the exact decoded bound.
        if protected.len() > MAX_PROTECTED_HEADER_LEN.div_ceil(3) * 4 {
            return Err(Error::HeaderTooLong {
                max: MAX_PROTECTED_HEADER_LEN,
            });
        }
        let header = header::parse(&b64::decode(protected, Segment::ProtectedHeader)?)?;
        // draft-22 §5: IV and Tag MUST be the empty octet sequence, i.e. empty segments.
        if !iv.is_empty() {
            return Err(Error::NonEmptyIv);
        }
        if !tag.is_empty() {
            return Err(Error::NonEmptyTag);
        }
        // draft-22 §4.1, §5: the JWE Encrypted Key is the HPKE encapsulated secret.
        let encapsulated_key =
            EncapsulatedKey::from_bytes(&b64::decode(encrypted_key, Segment::EncryptedKey)?)?;
        let ciphertext = b64::decode(ciphertext, Segment::Ciphertext)?;

        Ok(Self {
            protected: protected.to_owned(),
            header,
            encapsulated_key,
            ciphertext,
        })
    }

    /// The accepted protected header (e.g. `kid` for key selection).
    pub fn header(&self) -> &ProtectedHeader {
        &self.header
    }

    /// HPKE-0 Integrated Encryption decryption (draft-22 §7.2 steps 15-19): `OpenBase` with
    /// `aad = ASCII(Encoded Protected Header)` and the application-supplied `info`.
    ///
    /// For OpenID4VP pass [`crate::SessionInfo::as_bytes`] as `info` (OpenID4VP 1.1 §8.3.1);
    /// the draft-22 default is the empty string. Any failure is [`Error::Decryption`] and no
    /// partial plaintext is returned.
    pub fn open(&self, sk: &RecipientPrivateKey, info: &[u8]) -> Result<Vec<u8>, Error> {
        self.encapsulated_key
            .open(sk, info, self.protected.as_bytes(), &self.ciphertext)
    }
}

impl PartialEq for CompactJwe {
    /// Equal when the serialized JWEs are equal (the header is derived from `protected`).
    fn eq(&self, other: &Self) -> bool {
        self.protected == other.protected
            && self.encapsulated_key.to_bytes() == other.encapsulated_key.to_bytes()
            && self.ciphertext == other.ciphertext
    }
}

impl Eq for CompactJwe {}

impl fmt::Debug for CompactJwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactJwe")
            .field("header", &self.header)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// [`CompactJwe::parse`] followed by [`CompactJwe::open`].
pub fn open_compact(input: &str, sk: &RecipientPrivateKey, info: &[u8]) -> Result<Vec<u8>, Error> {
    CompactJwe::parse(input)?.open(sk, info)
}
