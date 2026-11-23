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
//! # Rejection rules
//!
//! *Spec* rows are required by the cited text. *Lab policy* rows are lab v1 choices (Notion 02
//! §7.1) that are stricter than the specs; they fail closed and are not interoperability
//! requirements.
//!
//! | Rejected input | Basis |
//! | --- | --- |
//! | `enc` present (any value, incl. `null`) | Spec: draft-22 §5 "MUST NOT be present", §7.2 step 18 |
//! | `ek` present | Spec: draft-22 §5 "MUST NOT be present" |
//! | JWE Initialization Vector or Authentication Tag not empty | Spec: draft-22 §5 "MUST be the empty octet sequence" |
//! | JWE Encrypted Key not a valid encapsulated key | Spec: draft-22 §5 (encapsulated secret), RFC 9180 §7.1.1 |
//! | Header not UTF-8 JSON object, or duplicate member names | Spec: draft-22 §7.2 steps 3-4 (RFC 7516 §5.2) |
//! | `crit` present | Spec: no extension is understood, so any `crit` either lists an unknown extension (RFC 7516 §4.1.13 / RFC 7515 §4.1.11: MUST reject), is empty or lists a registered parameter (both invalid there) |
//! | Padding, whitespace, line breaks, wrong alphabet | Spec: RFC 7515 §2 base64url, draft-22 §7.2 step 2 |
//! | JWE JSON Serialization (incl. multi-recipient) | Spec: OpenID4VP 1.1 §8.3 requires an encrypted JWT, and JWTs use the Compact Serialization (RFC 7519 §1); draft-22 §5 "exactly one recipient" |
//! | `alg` other than `HPKE-0` | Application choice allowed by draft-22 §7.2 (final paragraph) and OpenID4VP 1.1 §8.3 (`alg` equals the chosen JWK's `alg`); the lab Verifier advertises only HPKE-0 |
//! | Non-zero trailing bits in the last base64url character | Lab policy: canonical encoding only, so the encoded header used as HPKE `aad` has one spelling |
//! | `psk_id` present | Lab policy: draft-22 §4/§5 allow mode_psk ("MAY be present"); OpenID4VP defines no PSK |
//! | `zip` present | Lab policy: RFC 7516 §4.1.3 allows it; no decompression of untrusted data |
//! | Any member other than `alg`, `kid`, `typ`, `cty` | Lab policy: deviates from RFC 7515 §4 / RFC 7516 §4, under which unknown non-critical parameters are ignored |
//! | Input longer than [`MAX_COMPACT_JWE_LEN`] | Lab policy: no spec limit exists |
//! | Decoded protected header longer than [`MAX_PROTECTED_HEADER_LEN`] | Lab policy: no spec limit exists |
//! | `kid` not a `protocol_model::KeyId` (empty, non-ASCII, control, space) | Lab policy: RFC 7516 §4.1.6 allows any string |
//! | `typ` / `cty` not non-empty visible ASCII | Lab policy: RFC 7516 §4.1.11-12 allow any string |
//!
//! Verifier flow: [`CompactJwe::parse`] (all key-independent checks), select the key by
//! [`ProtectedHeader::kid`], compute [`SessionInfo::from_binding`] from the stored
//! `protocol_model::RequestBinding`, then [`CompactJwe::open`].
//!
//! # `test-support` feature
//!
//! Off by default. It enables `test_support` (sender-side sealing for fixtures and the wallet
//! simulator), `open_base` (raw RFC 9180 single-shot open, used by the known-answer tests) and
//! `RecipientPrivateKey::derive_from_ikm` (deterministic keys from `ikm`). A Verifier build
//! must not enable it; this crate's own tests enable it through a self dev-dependency.

mod b64;
mod error;
mod header;
mod hpke0;
mod jwe;
mod session_info;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use error::{Error, Segment};
pub use header::ProtectedHeader;
pub use hpke::rand_core;
#[cfg(feature = "test-support")]
pub use hpke0::open_base;
pub use hpke0::{RecipientPrivateKey, RecipientPublicKey, suite};
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

/// Maximum decoded JWE Protected Header length in bytes (lab policy; no spec sets one).
///
/// An HPKE-0 header carries at most `alg`, `kid`, `typ` and `cty`, typically well under
/// 200 bytes; 4 KiB leaves room for long key identifiers (e.g. a JWK thumbprint URI) while
/// bounding the JSON parser's work and the size of any accepted `kid`.
pub const MAX_PROTECTED_HEADER_LEN: usize = 4096;
