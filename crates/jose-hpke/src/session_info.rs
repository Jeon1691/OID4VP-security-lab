//! OpenID4VP 1.1 §8.3.1 `session_info` encodings.
//!
//! The bytes are the HPKE `info` parameter of Integrated Encryption (§8.3.1, last paragraph:
//! "The session_info structure's bytes are used as the value of the info parameter when using
//! Integrated Encryption as the Key Management Mode"). Wallet and Verifier compute them
//! independently, so a response sealed for another session fails to decrypt.
//!
//! Inputs are the wire strings exactly as sent in the request; no normalisation is applied.
//! `0xFF` cannot occur in ASCII (nor in UTF-8), so the encoding is unambiguous without length
//! prefixes; non-ASCII input is rejected because the spec encodes each field as `ASCII(...)`.

use crate::error::Error;

/// §8.3.1 `ASCII("OpenID4VP-si")`: redirect-based response modes such as `direct_post.jwt`.
const DIRECT_POST_LABEL: &str = "OpenID4VP-si";
/// §8.3.1 `ASCII("OpenID4VPDCAPI-si")`: response mode `dc_api.jwt`.
const DC_API_LABEL: &str = "OpenID4VPDCAPI-si";
/// §8.3.1 `BYTE(255)` field separator.
const SEPARATOR: u8 = 0xFF;
/// §8.3.1: the origin "MUST NOT be prefixed with origin:" (the DC API client_id prefix).
const ORIGIN_PREFIX: &str = "origin:";

/// An encoded `session_info` value, to be passed as HPKE `info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo(Vec<u8>);

impl SessionInfo {
    /// `ASCII("OpenID4VP-si") || 0xFF || client_id || 0xFF || nonce || 0xFF || response_uri`.
    ///
    /// `client_id` is the request parameter including any Client Identifier Prefix;
    /// `response_uri` is the `response_uri` (or `redirect_uri`, per Response Mode) parameter.
    pub fn direct_post_jwt(
        client_id: &str,
        nonce: &str,
        response_uri: &str,
    ) -> Result<Self, Error> {
        encode(
            DIRECT_POST_LABEL,
            &[
                ("client_id", client_id),
                ("nonce", nonce),
                ("response_uri", response_uri),
            ],
        )
    }

    /// `ASCII("OpenID4VPDCAPI-si") || 0xFF || origin || 0xFF || nonce`.
    ///
    /// `origin` is the platform-provided Origin (Appendix A.2), without the `origin:` prefix.
    pub fn dc_api_jwt(origin: &str, nonce: &str) -> Result<Self, Error> {
        if origin.starts_with(ORIGIN_PREFIX) {
            return Err(Error::OriginPrefixed);
        }
        encode(DC_API_LABEL, &[("origin", origin), ("nonce", nonce)])
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionInfo {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn encode(label: &str, fields: &[(&'static str, &str)]) -> Result<SessionInfo, Error> {
    let len = label.len() + fields.iter().map(|(_, v)| 1 + v.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(label.as_bytes());
    for &(field, value) in fields {
        if !value.is_ascii() {
            return Err(Error::SessionInfoNotAscii { field });
        }
        out.push(SEPARATOR);
        out.extend_from_slice(value.as_bytes());
    }
    Ok(SessionInfo(out))
}
