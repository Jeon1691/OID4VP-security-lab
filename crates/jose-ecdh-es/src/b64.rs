//! Strict base64url (RFC 7515 §2 "Base64url Encoding", referenced by RFC 7516 §2).
//!
//! Decoding accepts exactly one spelling per octet string: URL-safe alphabet only, no `=`
//! padding, no whitespace or line breaks (RFC 7516 §5.2 step 2), no `len % 4 == 1`, and the
//! unused low bits of the final character must be zero. The encoded protected header is the
//! AES-GCM additional authenticated data, so it must have one spelling.

use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

/// Canonical base64url decode; `None` for any other spelling.
pub(crate) fn decode(encoded: &str) -> Option<Vec<u8>> {
    BASE64URL.decode(encoded).ok()
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    BASE64URL.encode(bytes)
}
