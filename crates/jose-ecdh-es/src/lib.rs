//! JWE `alg` = `ECDH-ES` (Direct Key Agreement) on P-256 with `enc` `A128GCM` / `A256GCM`, in
//! the JWE Compact Serialization: the response encryption of OpenID4VP 1.0 `direct_post.jwt`.
//!
//! # Scope
//!
//! This crate exists so the lab can run a 1.0-style ECDH-ES Verifier next to the HPKE-0 one and
//! *observe* the difference (docs/interop/issue-792-reproduction.md, C3 and C9, §4 item 1): under
//! ECDH-ES, decryption needs only the recipient's private key. There is no `session_info` or any
//! other transaction binding in the key schedule, so one shared key opens the response of every
//! session it was advertised for, and correlating a response with its session has to rely on
//! something inside the plaintext (`state`, `nonce`). That missing binding is the property under
//! study, not a defect to be fixed here. It is a separate codec on purpose: the HPKE-0 route
//! never falls back to it (a fallback would be the downgrade #792 C9 describes), and jose-hpke
//! keeps refusing every `alg` but `HPKE-0`.
//!
//! Normative basis (verified against the RFC texts):
//!
//! * RFC 7516 §5.2: decryption steps; step 10 (empty JWE Encrypted Key for Direct Key
//!   Agreement), steps 14-15 (AAD = ASCII(Encoded Protected Header)), step 16 (no output
//!   unless the tag verifies).
//! * RFC 7518 §4.6: `ECDH-ES` Direct Key Agreement, `epk` (§4.6.1.1), `apu`/`apv`
//!   (§4.6.1.2-3), Concat KDF with SHA-256 and AlgorithmID = `enc` (§4.6.2).
//! * RFC 7518 §5.3: AES GCM, 96-bit IV, 128-bit tag; §6.2.1: EC public JWK members.
//! * RFC 8725 §3.4: `epk` validation (partial public-key validation for P-256).
//!
//! # Rejection rules
//!
//! *Spec* rows are required by the cited text. *Lab policy* rows are stricter than the specs;
//! they fail closed and are not interoperability requirements.
//!
//! | Rejected input | Basis |
//! | --- | --- |
//! | `alg` other than exactly `ECDH-ES` (`ECDH-ES+A128KW`/`+A192KW`/`+A256KW`, `HPKE-*`, `dir`, ...) | Lab policy, allowed by RFC 7516 §5.2 (final paragraph: the application decides which algorithms are acceptable). No key wrapping: the lab studies Direct Key Agreement only, and no other mode is ever tried as a fallback |
//! | `enc` absent | Spec: RFC 7516 §4.1.2 "MUST be present" |
//! | `enc` other than `A128GCM` / `A256GCM` | Lab policy: the two values HAIP-style Verifiers advertise; `A192GCM` and AES-CBC-HMAC are not implemented |
//! | `epk` absent | Spec: RFC 7518 §4.6.1.1 "MUST be present" |
//! | `epk` with `d` | Spec: RFC 7518 §4.6.1.1 "MUST contain only public key parameters" |
//! | `epk` `kty` not `EC`, `crv` not `P-256`, `x`/`y` not 32 bytes | Spec: RFC 7518 §6.2.1.1-3 (coordinates are "the full size of a coordinate"); P-256 only is lab policy |
//! | `epk` not a point on P-256 (coordinates `>= p`, off the curve) | Spec: RFC 8725 §3.4 (MUST, NIST SP 800-56A r3 §5.6.2.3.4 partial public-key validation); §2.5: without it invalid-curve points recover the static key |
//! | `epk` members other than `kty`, `crv`, `x`, `y` | Lab policy: RFC 7518 §4.6.1.1 lets them be ignored |
//! | JWE Encrypted Key not empty | Spec: RFC 7518 §4.6, RFC 7516 §5.2 step 10 |
//! | IV not 96 bits, tag not 128 bits | Spec: RFC 7518 §5.3 |
//! | `apu`/`apv` not base64url strings | Spec: RFC 7518 §4.6.1.2-3 |
//! | `apu` and `apv` with equal decoded bytes | Lab enforcement of a producer requirement: RFC 7518 §4.6.2 "MUST be distinct, when used" binds the sender; a recipient may refuse |
//! | `apu` or `apv` decoding to the empty octet sequence | Lab policy: the KDF input is the same as when absent (§4.6.2 Datalen 0), so it would be a second spelling of "absent" |
//! | Header not UTF-8 JSON object, or a duplicate member name in any object | Spec: RFC 7516 §5.2 steps 3-4 (duplicates inside `epk` are lab policy) |
//! | `crit` present | Spec: no extension is understood (RFC 7516 §4.1.13 / RFC 7515 §4.1.11) |
//! | Padding, whitespace, line breaks, wrong alphabet | Spec: RFC 7516 §5.2 step 2, RFC 7515 §2 |
//! | JWE JSON Serialization | Spec: OpenID4VP `direct_post.jwt` carries a JWT, and JWTs use the Compact Serialization (RFC 7519 §1) |
//! | Non-zero trailing bits in the last base64url character | Lab policy: canonical encoding only, so the encoded header used as AAD has one spelling |
//! | `zip` present | Lab policy: RFC 7516 §4.1.3 allows it; RFC 8725 §3.6 "SHOULD NOT" compress before encryption, and no decompression of untrusted data |
//! | Any member other than `alg`, `enc`, `epk`, `apu`, `apv`, `kid`, `typ`, `cty` | Lab policy: deviates from RFC 7516 §4, under which unknown non-critical parameters are ignored |
//! | Input longer than [`MAX_COMPACT_JWE_LEN`], decoded header longer than [`MAX_PROTECTED_HEADER_LEN`] | Lab policy: no spec limit exists |
//! | `kid` not a `protocol_model::KeyId`; `typ` / `cty` not non-empty visible ASCII | Lab policy: RFC 7516 §4.1.6, §4.1.11-12 allow any string |
//!
//! Verifier flow: [`CompactJwe::parse`] (all key-independent checks), select the key by
//! [`ProtectedHeader::kid`], then [`CompactJwe::open`]. Every failure after parsing is
//! [`Error::Decryption`].
//!
//! # `test-support` feature
//!
//! Off by default. It enables `test_support`: sender-side sealing for fixtures and the wallet
//! simulator, and the Concat KDF / CEK derivation hooks of the RFC 7518 Appendix C known-answer
//! tests. A Verifier build must not enable it (`scripts/ci_local.sh` checks this); this crate's
//! own tests enable it through a self dev-dependency.

mod b64;
mod content;
mod error;
mod header;
mod jwe;
mod kdf;
mod keys;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use content::{ContentEncryption, ENC_A128GCM, ENC_A256GCM, IV_LEN, TAG_LEN};
pub use error::{Error, Segment};
pub use header::ProtectedHeader;
pub use jwe::{CompactJwe, open_compact};
pub use keys::{RecipientPrivateKey, RecipientPublicKey};
pub use p256::elliptic_curve::rand_core;

/// JWE `alg` value for ECDH-ES Direct Key Agreement (RFC 7518 §4.6).
pub const ALG_ECDH_ES: &str = "ECDH-ES";

/// Maximum accepted compact JWE length in bytes (1 MiB).
///
/// No specification sets a limit (RFC 7516 and OpenID4VP are silent). Same bound and rationale
/// as jose-hpke's `MAX_COMPACT_JWE_LEN`: it caps the work done on unauthenticated input
/// (base64url decoding, JSON parsing, point validation, ECDH, AEAD) while staying far above
/// realistic `direct_post.jwt` responses (a few KiB to about 100 KiB).
pub const MAX_COMPACT_JWE_LEN: usize = 1 << 20;

/// Maximum decoded JWE Protected Header length in bytes (lab policy; no spec sets one).
///
/// An `ECDH-ES` header with its `epk` (two 43-character coordinates) and a `kid` is typically
/// about 250 bytes; 4 KiB leaves room for long key identifiers and `apu`/`apv` while bounding
/// the JSON parser's work and the Concat KDF inputs.
pub const MAX_PROTECTED_HEADER_LEN: usize = 4096;
