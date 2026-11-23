//! Strict base64url (RFC 7515 §2 "Base64url Encoding", referenced by RFC 7516 §2).
//!
//! Decoding accepts exactly one spelling per octet string: URL-safe alphabet only, no `=`
//! padding, no whitespace or line breaks (draft-22 §7.2 step 2), no `len % 4 == 1`, and the
//! unused low bits of the final character must be zero. A lax decoder would accept several
//! encodings of the same bytes, which matters here because the encoded protected header is
//! the HPKE `aad` and must be compared byte-for-byte.

use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::error::{Error, Segment};

const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

pub(crate) fn decode(encoded: &str, segment: Segment) -> Result<Vec<u8>, Error> {
    BASE64URL
        .decode(encoded)
        .map_err(|_| Error::Base64(segment))
}

#[cfg(feature = "test-support")]
pub(crate) fn encode(bytes: &[u8]) -> String {
    BASE64URL.encode(bytes)
}
