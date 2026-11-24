//! Field encoding between session-core values and Redis strings.
//!
//! Everything read back is validated again (wire newtypes, route token, numbers). A value that
//! does not decode means the store is corrupt or was tampered with, and is reported as
//! [`StoreUnavailable`]: fail closed, never a best-effort guess.

use std::str::FromStr;

use protocol_model::{
    ClientIdWire, EncryptedResponseMode, KeyId, NonceWire, OriginWire, RequestBinding,
    ResponseUriWire, SessionId,
};
use session_core::{
    RESPONSE_DIGEST_BYTES, ResponseDigest, Revision, RouteToken, StoreUnavailable, Timestamp,
};

use crate::scripts::MAX_EXACT_MILLIS;

/// A script or command reply: a flat array of bulk strings and nils.
pub(crate) type Reply = Vec<Option<Vec<u8>>>;

/// Sequential reader over a [`Reply`].
pub(crate) struct Fields(std::vec::IntoIter<Option<Vec<u8>>>);

impl Fields {
    pub(crate) fn new(reply: Reply) -> Self {
        Self(reply.into_iter())
    }

    /// `true` once every field was read.
    pub(crate) fn is_done(&self) -> bool {
        self.0.len() == 0
    }

    /// The next field, which may be nil.
    pub(crate) fn raw(&mut self) -> Result<Option<Vec<u8>>, StoreUnavailable> {
        self.0.next().ok_or(StoreUnavailable)
    }

    /// The next field as UTF-8, or `None` for nil.
    pub(crate) fn opt_text(&mut self) -> Result<Option<String>, StoreUnavailable> {
        self.raw()?
            .map(|b| String::from_utf8(b).map_err(|_| StoreUnavailable))
            .transpose()
    }

    /// The next field as non-nil UTF-8.
    pub(crate) fn text(&mut self) -> Result<String, StoreUnavailable> {
        self.opt_text()?.ok_or(StoreUnavailable)
    }

    /// The next field as a decimal `u64`.
    pub(crate) fn number(&mut self) -> Result<u64, StoreUnavailable> {
        self.text()?.parse().map_err(|_| StoreUnavailable)
    }

    /// The remaining fields, as text (key references).
    pub(crate) fn rest(&mut self) -> Result<Vec<String>, StoreUnavailable> {
        let mut out = Vec::new();
        while !self.is_done() {
            out.push(self.text()?);
        }
        Ok(out)
    }
}

/// A timestamp as written to Redis, clamped to [`MAX_EXACT_MILLIS`].
pub(crate) fn clamp(t: Timestamp) -> Timestamp {
    Timestamp::from_unix_millis(t.as_unix_millis().min(MAX_EXACT_MILLIS))
}

pub(crate) fn session_id(s: String) -> Result<SessionId, StoreUnavailable> {
    SessionId::new(s).map_err(|_| StoreUnavailable)
}

pub(crate) fn key_id(s: String) -> Result<KeyId, StoreUnavailable> {
    KeyId::new(s).map_err(|_| StoreUnavailable)
}

pub(crate) fn route(s: &str) -> Result<RouteToken, StoreUnavailable> {
    RouteToken::parse(s).map_err(|_| StoreUnavailable)
}

pub(crate) fn digest(bytes: Vec<u8>) -> Result<ResponseDigest, StoreUnavailable> {
    <[u8; RESPONSE_DIGEST_BYTES]>::try_from(bytes.as_slice())
        .map(ResponseDigest::new)
        .map_err(|_| StoreUnavailable)
}

/// `(mode, b1, b2, b3)`: the response mode's wire string and the binding fields in the order
/// its `session_info` formula uses them; `b3` is empty for `dc_api.jwt`.
pub(crate) fn encode_binding(binding: &RequestBinding) -> [&str; 4] {
    match binding {
        RequestBinding::DirectPostJwt {
            client_id,
            nonce,
            response_uri,
        } => [
            binding.mode().as_str(),
            client_id.as_str(),
            nonce.as_str(),
            response_uri.as_str(),
        ],
        RequestBinding::DcApiJwt { origin, nonce } => {
            [binding.mode().as_str(), origin.as_str(), nonce.as_str(), ""]
        }
    }
}

/// Inverse of [`encode_binding`]; every field is re-validated by its wire constructor.
pub(crate) fn decode_binding(f: &mut Fields) -> Result<RequestBinding, StoreUnavailable> {
    let bad = |_| StoreUnavailable;
    let mode = EncryptedResponseMode::from_str(&f.text()?).map_err(bad)?;
    let (b1, b2, b3) = (f.text()?, f.text()?, f.text()?);
    Ok(match mode {
        EncryptedResponseMode::DirectPostJwt => RequestBinding::DirectPostJwt {
            client_id: ClientIdWire::new(b1).map_err(bad)?,
            nonce: NonceWire::new(b2).map_err(bad)?,
            response_uri: ResponseUriWire::new(b3).map_err(bad)?,
        },
        EncryptedResponseMode::DcApiJwt => {
            if !b3.is_empty() {
                return Err(StoreUnavailable);
            }
            RequestBinding::DcApiJwt {
                origin: OriginWire::new(b1).map_err(bad)?,
                nonce: NonceWire::new(b2).map_err(bad)?,
            }
        }
    })
}

/// A session record in [`RECORD_FIELDS`](crate::scripts::RECORD_FIELDS) order.
pub(crate) struct Record {
    pub(crate) incarnation: u64,
    pub(crate) revision: Revision,
    pub(crate) expires_at: Timestamp,
    pub(crate) state: String,
    pub(crate) route: RouteToken,
    pub(crate) kid: Option<KeyId>,
    pub(crate) key_ref: String,
    pub(crate) binding: RequestBinding,
}

impl Record {
    /// Reads one record; `None` if the hash does not exist (every field nil).
    pub(crate) fn read(f: &mut Fields) -> Result<Option<Self>, StoreUnavailable> {
        let Some(inc) = f.opt_text()? else {
            // Skip the remaining fields of a missing record; all of them must be nil too.
            for _ in 1..crate::scripts::RECORD_FIELDS.len() {
                if f.raw()?.is_some() {
                    return Err(StoreUnavailable);
                }
            }
            return Ok(None);
        };
        Ok(Some(Self {
            incarnation: inc.parse().map_err(|_| StoreUnavailable)?,
            revision: Revision::new(f.number()?),
            expires_at: Timestamp::from_unix_millis(f.number()?),
            state: f.text()?,
            route: route(&f.text()?)?,
            kid: f.opt_text()?.map(key_id).transpose()?,
            key_ref: f.text()?,
            binding: decode_binding(f)?,
        }))
    }

    /// Expired at `now`: the TTL is half-open, `[inserted, expires_at)`.
    pub(crate) fn is_due(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }
}
