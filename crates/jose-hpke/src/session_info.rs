//! OpenID4VP 1.1 §8.3.1 `session_info` encodings.
//!
//! The bytes are the HPKE `info` parameter of Integrated Encryption (§8.3.1, last paragraph:
//! "The session_info structure's bytes are used as the value of the info parameter when using
//! Integrated Encryption as the Key Management Mode"). Wallet and Verifier compute them
//! independently, so a response sealed for another session fails to decrypt.
//!
//! Inputs are `protocol-model` wire types, which hold the exact request strings and enforce the
//! field rules (non-empty, ASCII, no control characters, §5.2 nonce alphabet, no `origin:`
//! prefix) at construction. This module does no validation of its own, so there is a single
//! source of truth. Because every field is ASCII, no field contains `0xFF` and the encoding is
//! unambiguous without length prefixes.

use protocol_model::{ClientIdWire, NonceWire, OriginWire, RequestBinding, ResponseUriWire};

/// §8.3.1 `ASCII("OpenID4VP-si")`: redirect-based response modes such as `direct_post.jwt`.
const DIRECT_POST_LABEL: &str = "OpenID4VP-si";
/// §8.3.1 `ASCII("OpenID4VPDCAPI-si")`: response mode `dc_api.jwt`.
const DC_API_LABEL: &str = "OpenID4VPDCAPI-si";
/// §8.3.1 `BYTE(255)` field separator.
const SEPARATOR: u8 = 0xFF;

/// An encoded `session_info` value, to be passed as HPKE `info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo(Vec<u8>);

impl SessionInfo {
    /// `ASCII("OpenID4VP-si") || 0xFF || client_id || 0xFF || nonce || 0xFF || response_uri`.
    pub fn direct_post_jwt(
        client_id: &ClientIdWire,
        nonce: &NonceWire,
        response_uri: &ResponseUriWire,
    ) -> Self {
        encode(
            DIRECT_POST_LABEL,
            &[
                client_id.as_bytes(),
                nonce.as_bytes(),
                response_uri.as_bytes(),
            ],
        )
    }

    /// `ASCII("OpenID4VPDCAPI-si") || 0xFF || origin || 0xFF || nonce`.
    pub fn dc_api_jwt(origin: &OriginWire, nonce: &NonceWire) -> Self {
        encode(DC_API_LABEL, &[origin.as_bytes(), nonce.as_bytes()])
    }

    /// The `session_info` for a stored request binding, using the formula of its mode.
    pub fn from_binding(binding: &RequestBinding) -> Self {
        match binding {
            RequestBinding::DirectPostJwt {
                client_id,
                nonce,
                response_uri,
            } => Self::direct_post_jwt(client_id, nonce, response_uri),
            RequestBinding::DcApiJwt { origin, nonce } => Self::dc_api_jwt(origin, nonce),
        }
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

fn encode(label: &str, fields: &[&[u8]]) -> SessionInfo {
    let len = label.len() + fields.iter().map(|v| 1 + v.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(label.as_bytes());
    for value in fields {
        out.push(SEPARATOR);
        out.extend_from_slice(value);
    }
    SessionInfo(out)
}
