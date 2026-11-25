//! Error type of the codec.
//!
//! Variants carry only static strings and lengths: never key material, plaintext, decoded
//! segment bytes or attacker-supplied header values (which could be large or contain control
//! characters destined for logs).

use std::fmt;

/// A compact JWE segment, for base64url decoding errors (RFC 7516 §7.1 order). The JWE Encrypted
/// Key has no variant: for `ECDH-ES` it must be the empty segment and is never decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// BASE64URL(UTF8(JWE Protected Header)).
    ProtectedHeader,
    /// BASE64URL(JWE Initialization Vector).
    InitializationVector,
    /// BASE64URL(JWE Ciphertext).
    Ciphertext,
    /// BASE64URL(JWE Authentication Tag).
    AuthenticationTag,
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProtectedHeader => "protected header",
            Self::InitializationVector => "initialization vector",
            Self::Ciphertext => "ciphertext",
            Self::AuthenticationTag => "authentication tag",
        })
    }
}

/// Everything that can go wrong while parsing, opening or sealing an `ECDH-ES` compact JWE.
///
/// Every check that does not need the private key happens in [`crate::CompactJwe::parse`]. After
/// that, every failure (wrong key, modified header, IV, ciphertext or tag) is
/// [`Error::Decryption`], so the error does not act as an oracle for which input was wrong.
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
    /// Compact serialization must have exactly five segments (RFC 7516 §5.2 step 1, §7.1).
    #[error("compact JWE must have 5 segments, found {found}")]
    SegmentCount {
        /// Number of `.`-separated segments found.
        found: usize,
    },
    /// A segment is not canonical unpadded base64url (RFC 7516 §5.2 step 2, RFC 7515 §2).
    #[error("{0} segment is not canonical unpadded base64url")]
    Base64(Segment),
    /// The protected header is not UTF-8 JSON, not an object, or has a duplicate member name at
    /// any depth (RFC 7516 §5.2 steps 3-4).
    #[error("protected header is not a UTF-8 JSON object with unique member names")]
    HeaderJson,
    /// The decoded protected header exceeds [`crate::MAX_PROTECTED_HEADER_LEN`] (lab policy).
    #[error("protected header exceeds the maximum length of {max} bytes")]
    HeaderTooLong {
        /// The enforced limit.
        max: usize,
    },
    /// The protected header has no `alg` member (RFC 7516 §4.1.1: MUST be present).
    #[error("protected header has no \"alg\" member")]
    MissingAlg,
    /// `alg` is not exactly `ECDH-ES` (key wrapping, HPKE, `dir` and everything else).
    #[error("unsupported \"alg\"; only ECDH-ES is accepted")]
    UnsupportedAlg,
    /// The protected header has no `enc` member (RFC 7516 §4.1.2: MUST be present).
    #[error("protected header has no \"enc\" member")]
    MissingEnc,
    /// `enc` is not `A128GCM` or `A256GCM`.
    #[error("unsupported \"enc\"; only A128GCM and A256GCM are accepted")]
    UnsupportedEnc,
    /// The protected header has no `epk` member (RFC 7518 §4.6.1.1: MUST be present).
    #[error("protected header has no \"epk\" member")]
    MissingEpk,
    /// A header parameter the lab refuses even though RFC 7516 defines it (`zip`).
    #[error("header parameter \"{0}\" is not permitted")]
    ForbiddenHeaderParameter(&'static str),
    /// `crit` is present; no extension is understood (RFC 7516 §4.1.13, RFC 7515 §4.1.11).
    #[error("\"crit\" header parameter is not supported")]
    UnsupportedCrit,
    /// A header member outside the accepted set (`alg`, `enc`, `epk`, `apu`, `apv`, `kid`, `typ`,
    /// `cty`).
    #[error("unknown protected header parameter")]
    UnknownHeaderParameter,
    /// A known header parameter has the wrong JSON type.
    #[error("header parameter \"{0}\" has the wrong JSON type")]
    HeaderParameterType(&'static str),
    /// A header parameter has a value outside the accepted set (`apu`/`apv`: not canonical
    /// base64url, or equal; `kid`: not a `protocol_model::KeyId`; `typ`/`cty`: not non-empty
    /// visible ASCII).
    #[error("header parameter \"{0}\" has an invalid value")]
    HeaderParameterValue(&'static str),
    /// `epk` carries a private key (`d`); RFC 7518 §4.6.1.1: "MUST contain only public key
    /// parameters".
    #[error("\"epk\" must not contain a private key")]
    EphemeralKeyPrivate,
    /// An `epk` member is missing, has the wrong type or value (`kty` not `EC`, `crv` not
    /// `P-256`, `x`/`y` not canonical base64url of 32 bytes), or is not one of those four.
    #[error("\"epk\" member \"{0}\" is missing or invalid")]
    EphemeralKeyParameter(&'static str),
    /// `epk` `x`/`y` are well-formed but not the coordinates of a point on P-256.
    #[error("\"epk\" is not a point on P-256")]
    EphemeralKeyPoint,
    /// The JWE Encrypted Key must be empty for Direct Key Agreement (RFC 7518 §4.6, RFC 7516
    /// §5.2 step 10).
    #[error("JWE Encrypted Key must be empty for ECDH-ES")]
    NonEmptyEncryptedKey,
    /// The JWE Initialization Vector is not 96 bits (RFC 7518 §5.3).
    #[error("JWE Initialization Vector must be 12 bytes, found {found}")]
    IvLength {
        /// Decoded length in bytes.
        found: usize,
    },
    /// The JWE Authentication Tag is not 128 bits (RFC 7518 §5.3).
    #[error("JWE Authentication Tag must be 16 bytes, found {found}")]
    TagLength {
        /// Decoded length in bytes.
        found: usize,
    },
    /// Key bytes are not a valid P-256 private scalar or public point.
    #[error("invalid P-256 key encoding")]
    InvalidKey,
    /// AES-GCM authenticated decryption failed.
    #[error("decryption failed")]
    Decryption,
    /// AES-GCM encryption failed.
    #[error("encryption failed")]
    Encryption,
}
