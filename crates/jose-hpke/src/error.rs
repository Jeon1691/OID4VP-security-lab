//! Error type shared by the codec and the Session Info encoders.
//!
//! Variants carry only static strings and lengths: never key material, plaintext, decoded
//! segment bytes or attacker-supplied header values (which could be large or contain control
//! characters destined for logs).

use std::fmt;

/// A compact JWE segment, for base64url decoding errors (RFC 7516 §7.1 order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// BASE64URL(UTF8(JWE Protected Header)).
    ProtectedHeader,
    /// BASE64URL(JWE Encrypted Key), the HPKE encapsulated key for Integrated Encryption.
    EncryptedKey,
    /// BASE64URL(JWE Ciphertext), the HPKE ciphertext (AEAD output including its tag).
    Ciphertext,
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProtectedHeader => "protected header",
            Self::EncryptedKey => "encrypted key",
            Self::Ciphertext => "ciphertext",
        })
    }
}

/// Everything that can go wrong while parsing, opening or sealing an HPKE-0 compact JWE.
/// (Session Info encoding is infallible: its inputs are validated `protocol-model` types.)
///
/// All authenticated-decryption failures (wrong key, wrong `info`, modified header, modified
/// ciphertext, invalid encapsulated key on decap) collapse into [`Error::Decryption`], so the
/// error does not act as an oracle for which input was wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input is longer than [`crate::MAX_COMPACT_JWE_LEN`].
    #[error("compact JWE exceeds the maximum length of {max} bytes")]
    TooLong {
        /// The enforced limit.
        max: usize,
    },
    /// Input looks like a JWE JSON Serialization (general or flattened, RFC 7516 §7.2).
    #[error("JWE JSON Serialization is not accepted; only the Compact Serialization is")]
    JsonSerialization,
    /// Compact serialization must have exactly five segments (draft-22 §7.2 step 1).
    #[error("compact JWE must have 5 segments, found {found}")]
    SegmentCount {
        /// Number of `.`-separated segments found.
        found: usize,
    },
    /// A segment is not canonical unpadded base64url (draft-22 §7.2 step 2, RFC 7515 §2).
    #[error("{0} segment is not canonical unpadded base64url")]
    Base64(Segment),
    /// The protected header is not UTF-8 JSON, not an object, or has duplicate members
    /// (draft-22 §7.2 steps 3-4).
    #[error("protected header is not a UTF-8 JSON object with unique member names")]
    HeaderJson,
    /// The protected header has no `alg` member.
    #[error("protected header has no \"alg\" member")]
    MissingAlg,
    /// `alg` is not `HPKE-0`.
    #[error("unsupported \"alg\"; only HPKE-0 is accepted")]
    UnsupportedAlg,
    /// A header parameter that is forbidden or not supported for HPKE-0 Integrated Encryption.
    #[error("header parameter \"{0}\" is not permitted for HPKE-0 integrated encryption")]
    ForbiddenHeaderParameter(&'static str),
    /// `crit` is present; no extension is understood (RFC 7516 §4.1.13, RFC 7515 §4.1.11).
    #[error("\"crit\" header parameter is not supported")]
    UnsupportedCrit,
    /// A header member outside the accepted set (`alg`, `kid`, `typ`, `cty`).
    #[error("unknown protected header parameter")]
    UnknownHeaderParameter,
    /// A known header parameter has the wrong JSON type.
    #[error("header parameter \"{0}\" must be a JSON string")]
    HeaderParameterType(&'static str),
    /// JWE Initialization Vector must be empty for Integrated Encryption (draft-22 §5).
    #[error("JWE Initialization Vector must be empty")]
    NonEmptyIv,
    /// JWE Authentication Tag must be empty for Integrated Encryption (draft-22 §5).
    #[error("JWE Authentication Tag must be empty")]
    NonEmptyTag,
    /// The JWE Encrypted Key is not a valid DHKEM(P-256) encapsulated key (RFC 9180 §7.1.1).
    #[error("JWE Encrypted Key is not a valid HPKE-0 encapsulated key")]
    EncapsulatedKey,
    /// Key bytes are not a valid P-256 private scalar or uncompressed public point.
    #[error("invalid HPKE-0 key encoding")]
    InvalidKey,
    /// HPKE decapsulation or AEAD open failed.
    #[error("decryption failed")]
    Decryption,
    /// HPKE encapsulation or AEAD seal failed.
    #[error("encryption failed")]
    Encryption,
}
