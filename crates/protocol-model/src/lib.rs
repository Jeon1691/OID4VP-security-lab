//! Versioned OpenID4VP wire model (IMP-003).
//!
//! The types here keep the exact wire strings captured when a request is signed, because the
//! OpenID4VP 1.1 HPKE `session_info` is built from those exact bytes (see Notion 02 ·
//! Architecture §5 and §7.2). Nothing is ever normalised: no case folding, percent-decoding,
//! trailing-slash handling or URL re-serialisation.
//!
//! # Spec decisions
//!
//! OpenID4VP 1.1 editor's draft §8.3.1 ("Encryption using HPKE") defines
//!
//! ```text
//! direct_post.jwt: ASCII("OpenID4VP-si")      || BYTE(255) || ASCII(clientId) || BYTE(255)
//!                  || ASCII(nonce) || BYTE(255) || ASCII(responseUri)
//! dc_api.jwt:      ASCII("OpenID4VPDCAPI-si") || BYTE(255) || ASCII(origin) || BYTE(255)
//!                  || ASCII(nonce)
//! ```
//!
//! * **ASCII.** The formulas apply `ASCII(...)` to every field. The draft does not say how
//!   non-ASCII input is handled, so this crate rejects it at construction instead of guessing an
//!   encoding. `client_id` (including its client identifier prefix), `response_uri`, `origin`
//!   and `nonce` are therefore ASCII-only.
//! * **Delimiter.** `BYTE(255)` is `0xFF`. Valid UTF-8 never contains `0xFF`, but that alone
//!   would not matter if a field were not UTF-8. Unambiguity is guaranteed because every field
//!   is ASCII (all bytes below `0x80`), so no field can contain `0xFF`, and splitting the
//!   concatenation on `0xFF` recovers the fields exactly.
//! * **Control characters.** ASCII control characters (`0x00..=0x1F`, `0x7F`) and spaces are not
//!   legal in any of these values (URLs, origins, URL-safe tokens), so they are rejected too.
//! * **Nonce.** §5.2 requires "ASCII URL safe characters (uppercase and lowercase letters,
//!   decimal digits, hyphen, period, underscore, and tilde)"; [`NonceWire`] enforces that set.
//! * **Origin.** §8.3.1: the origin "MUST NOT be prefixed with `origin:`" (that prefix belongs to
//!   the audience in §5.9.3, not to `session_info`); [`OriginWire`] rejects it.
//! * **Binding shape.** `dc_api.jwt` has no `client_id` or `response_uri` input and
//!   `direct_post.jwt` has no `origin`, so [`RequestBinding`] is an enum whose variants carry
//!   exactly the fields each mode's formula uses.

use std::fmt;
use std::str::FromStr;

/// Wire string of [`EncryptedResponseMode::DirectPostJwt`] (OpenID4VP 1.1 §8.3.2).
const DIRECT_POST_JWT: &str = "direct_post.jwt";
/// Wire string of [`EncryptedResponseMode::DcApiJwt`] (OpenID4VP 1.1 §8.3).
const DC_API_JWT: &str = "dc_api.jwt";
/// Prefix that §8.3.1 forbids on the `origin` used in `session_info`.
const ORIGIN_AUDIENCE_PREFIX: &str = "origin:";

/// Errors from parsing or validating wire values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// The value was the empty string.
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    /// The value contained a non-ASCII character (§8.3.1 applies `ASCII(...)`).
    #[error("{field} must be ASCII")]
    NotAscii { field: &'static str },
    /// The value contained an ASCII control character or a space.
    #[error("{field} must not contain control characters or spaces")]
    ControlCharacter { field: &'static str },
    /// The value contained a character outside the set the spec allows for it.
    #[error("{field} contains a character outside the allowed set")]
    DisallowedCharacter { field: &'static str },
    /// The origin carried the `origin:` prefix, which §8.3.1 forbids.
    #[error("origin must not be prefixed with \"origin:\"")]
    OriginPrefix,
    /// The `response_mode` string is not one this model supports.
    #[error("unknown response_mode")]
    UnknownResponseMode,
}

/// Rejects empty strings; shared by every newtype.
fn check_non_empty(field: &'static str, s: &str) -> Result<(), ModelError> {
    if s.is_empty() {
        Err(ModelError::Empty { field })
    } else {
        Ok(())
    }
}

/// Rejects control characters (and, when `allow_space` is false, spaces).
fn check_no_control(field: &'static str, s: &str, allow_space: bool) -> Result<(), ModelError> {
    if s.chars()
        .any(|c| c.is_control() || (c == ' ' && !allow_space))
    {
        Err(ModelError::ControlCharacter { field })
    } else {
        Ok(())
    }
}

/// Validation for fields fed to `ASCII(...)` in §8.3.1: non-empty, ASCII, no controls/spaces.
fn check_session_info_field(field: &'static str, s: &str) -> Result<(), ModelError> {
    check_ascii_visible(field, s, false)
}

/// Non-empty, ASCII-only, no control characters, and spaces only when `allow_space`.
fn check_ascii_visible(field: &'static str, s: &str, allow_space: bool) -> Result<(), ModelError> {
    check_non_empty(field, s)?;
    if !s.is_ascii() {
        return Err(ModelError::NotAscii { field });
    }
    check_no_control(field, s, allow_space)
}

/// Defines a wire-string newtype with `as_str`, `as_bytes`, `Display` and `AsRef<str>`.
macro_rules! wire_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// The exact wire string, unmodified.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The exact wire bytes, unmodified.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

wire_newtype!(
    /// `client_id` exactly as passed in the Authorization Request, including any client
    /// identifier prefix (§8.3.1). Visible ASCII (`%x20-7E`, RFC 6749 App. A.1
    /// `client-id = *VSCHAR`), so a space is allowed here but control characters are not.
    ///
    /// Non-ASCII client IDs (possible in principle, e.g. from a JWT `sub`) are rejected as a
    /// deliberate deviation: §8.3.1 defines the encoding only as `ASCII(...)`.
    ClientIdWire
);
impl ClientIdWire {
    /// # Errors
    /// Empty, non-ASCII, or containing control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        check_ascii_visible("client_id", &value, true)?;
        Ok(Self(value))
    }
}

wire_newtype!(
    /// `nonce` exactly as sent. §5.2: ASCII URL-safe characters (`A-Za-z0-9-._~`).
    NonceWire
);
impl NonceWire {
    /// # Errors
    /// Empty, non-ASCII, or containing a character outside `A-Za-z0-9-._~`.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        check_non_empty("nonce", &value)?;
        if !value.is_ascii() {
            return Err(ModelError::NotAscii { field: "nonce" });
        }
        let url_safe = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if !value.bytes().all(url_safe) {
            return Err(ModelError::DisallowedCharacter { field: "nonce" });
        }
        Ok(Self(value))
    }
}

wire_newtype!(
    /// `response_uri` exactly as signed (no trailing-slash, case or percent-encoding changes).
    /// Not parsed as a URL; only the `ASCII(...)` constraints of §8.3.1 are enforced.
    ///
    /// §8.3.1 also allows the `redirect_uri` request parameter for other response modes; this
    /// type is for the `response_uri` of `direct_post.jwt`.
    ResponseUriWire
);
impl ResponseUriWire {
    /// # Errors
    /// Empty, non-ASCII, or containing control characters/spaces.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        check_session_info_field("response_uri", &value)?;
        Ok(Self(value))
    }
}

wire_newtype!(
    /// Origin string of the Digital Credentials API caller (§8.3.1, Appendix A.2), opaque and
    /// never prefixed with `origin:`.
    OriginWire
);
impl OriginWire {
    /// # Errors
    /// Empty, non-ASCII, control characters/spaces, or an `origin:` prefix.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        check_session_info_field("origin", &value)?;
        if value.starts_with(ORIGIN_AUDIENCE_PREFIX) {
            return Err(ModelError::OriginPrefix);
        }
        Ok(Self(value))
    }
}

wire_newtype!(
    /// Lab-internal session identifier. Not part of `session_info`; non-empty visible ASCII
    /// (`%x21-7E`) so bidi or zero-width characters cannot spoof evidence logs.
    SessionId
);
impl SessionId {
    /// # Errors
    /// Empty, non-ASCII, or containing control characters/spaces.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        check_ascii_visible("session_id", &value, false)?;
        Ok(Self(value))
    }
}

wire_newtype!(
    /// Key identifier (`kid`). Not part of `session_info`; non-empty visible ASCII (`%x21-7E`)
    /// so bidi or zero-width characters cannot spoof evidence logs.
    KeyId
);
impl KeyId {
    /// # Errors
    /// Empty, non-ASCII, or containing control characters/spaces.
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        check_ascii_visible("key_id", &value, false)?;
        Ok(Self(value))
    }
}

/// OpenID4VP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    /// OpenID4VP 1.0.
    Vp10,
    /// OpenID4VP 1.1.
    Vp11,
}

/// The encrypted response modes that use HPKE `session_info` (§8.3.1). Plain `direct_post` and
/// `dc_api` are valid OpenID4VP modes but intentionally not representable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptedResponseMode {
    /// `direct_post.jwt`.
    DirectPostJwt,
    /// `dc_api.jwt`.
    DcApiJwt,
}

impl EncryptedResponseMode {
    /// The wire string of this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectPostJwt => DIRECT_POST_JWT,
            Self::DcApiJwt => DC_API_JWT,
        }
    }
}

impl FromStr for EncryptedResponseMode {
    type Err = ModelError;

    /// Exact, case-sensitive match; anything else is an error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            DIRECT_POST_JWT => Ok(Self::DirectPostJwt),
            DC_API_JWT => Ok(Self::DcApiJwt),
            _ => Err(ModelError::UnknownResponseMode),
        }
    }
}

impl fmt::Display for EncryptedResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The signed-request values that feed HPKE `session_info`, per response mode. Each variant
/// holds exactly the fields its §8.3.1 formula uses, so a mode/field mismatch cannot be built.
///
/// `session_info` exists only in OpenID4VP 1.1, so this type is 1.1-only and carries no
/// [`ProtocolVersion`]; that type is for reporting 1.0 (ECDH-ES) versus 1.1 (HPKE) elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBinding {
    /// `direct_post.jwt`: `client_id`, `nonce`, `response_uri`.
    DirectPostJwt {
        client_id: ClientIdWire,
        nonce: NonceWire,
        response_uri: ResponseUriWire,
    },
    /// `dc_api.jwt`: `origin`, `nonce`.
    DcApiJwt {
        origin: OriginWire,
        nonce: NonceWire,
    },
}

impl RequestBinding {
    /// The response mode implied by the variant.
    #[must_use]
    pub const fn mode(&self) -> EncryptedResponseMode {
        match self {
            Self::DirectPostJwt { .. } => EncryptedResponseMode::DirectPostJwt,
            Self::DcApiJwt { .. } => EncryptedResponseMode::DcApiJwt,
        }
    }

    /// The nonce, present in both modes.
    #[must_use]
    pub const fn nonce(&self) -> &NonceWire {
        match self {
            Self::DirectPostJwt { nonce, .. } | Self::DcApiJwt { nonce, .. } => nonce,
        }
    }
}
