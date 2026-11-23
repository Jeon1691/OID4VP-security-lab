//! JOSE HPKE-0 Integrated Encryption codec and OpenID4VP 1.1 Session Info (IMP-004..006).
//!
//! Normative basis (verified against the texts, see `tests/fixtures/MANIFEST.md`):
//!
//! * draft-ietf-jose-hpke-encrypt-22 §5.1: `HPKE-0` = DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
//!   AES-128-GCM. The draft cites draft-ietf-hpke-hpke-03, which is backwards compatible with
//!   RFC 9180 for this suite in mode_base; primitives come from the `hpke` crate (RFC 9180).
//! * draft-22 §5: no `enc`, no `ek`; JWE Encrypted Key = HPKE encapsulated secret; IV and Tag
//!   empty; JWE Ciphertext = HPKE ciphertext; HPKE `aad` = ASCII(Encoded Protected Header)
//!   (§7.1 step 15); HPKE `info` defaults to empty.
//! * OpenID4VP 1.1 §8.3.1: for Integrated Encryption, HPKE `info` = `session_info`.
//!
//! Verifier flow: [`CompactJwe::parse`] (all key-independent checks), select the key by
//! [`ProtectedHeader::kid`], compute [`SessionInfo`] from the stored request, then
//! [`CompactJwe::open`]. Sender-side sealing lives in [`test_support`] only.

mod b64;
mod error;
mod header;
mod hpke0;
mod jwe;
mod session_info;
pub mod test_support;

pub use error::{Error, Segment};
pub use header::ProtectedHeader;
pub use hpke::rand_core;
pub use hpke0::{RecipientPrivateKey, RecipientPublicKey, open_base, suite};
pub use jwe::{CompactJwe, open_compact};
pub use session_info::SessionInfo;

/// JWE `alg` value for HPKE-0 Integrated Encryption (draft-ietf-jose-hpke-encrypt-22 §5.1).
pub const ALG_HPKE_0: &str = "HPKE-0";

/// Maximum accepted compact JWE length in bytes (1 MiB).
///
/// No specification sets a limit (RFC 7516, draft-22 and OpenID4VP 1.1 are silent). The bound
/// caps the work done on unauthenticated input (base64url decoding, JSON parsing, ECDH, AEAD)
/// before anything is authenticated, while staying far above realistic `direct_post.jwt` /
/// `dc_api.jwt` responses: SD-JWT VC or mdoc VP tokens are typically a few KiB to tens of KiB,
/// around 100 KiB with an embedded portrait. The HTTP layer should enforce its own body limit
/// of at least this size.
pub const MAX_COMPACT_JWE_LEN: usize = 1 << 20;
