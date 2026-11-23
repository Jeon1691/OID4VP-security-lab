//! **Test support only.** Sender-side sealing for fixtures and the future wallet simulator.
//!
//! Verifier code must never call these: the lab Verifier only parses and opens. They perform
//! no header policy (so tests can build correctly encrypted JWEs with forbidden headers) and
//! take the RNG explicitly; pass an OS-backed CSPRNG such as
//! `rand_core::UnwrapErr(getrandom::SysRng)`.

use crate::hpke0::{RecipientPublicKey, seal_base};
use crate::rand_core::CryptoRng;
use crate::{ALG_HPKE_0, b64, error::Error};

/// Seals `plaintext` to `recipient` as an HPKE-0 compact JWE with protected header
/// `{"alg":"HPKE-0"}` or `{"alg":"HPKE-0","kid":...}` (draft-22 §7.1).
pub fn seal_compact(
    recipient: &RecipientPublicKey,
    kid: Option<&str>,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<String, Error> {
    let mut header = serde_json::Map::new();
    header.insert("alg".to_owned(), ALG_HPKE_0.into());
    if let Some(kid) = kid {
        header.insert("kid".to_owned(), kid.into());
    }
    let header = serde_json::Value::Object(header).to_string();
    seal_compact_with_protected_header(recipient, &header, info, plaintext, rng)
}

/// Like [`seal_compact`], but encodes `protected_header_json` verbatim (no validation), for
/// negative tests and attack scenarios.
pub fn seal_compact_with_protected_header(
    recipient: &RecipientPublicKey,
    protected_header_json: &str,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<String, Error> {
    let protected = b64::encode(protected_header_json.as_bytes());
    // draft-22 §5 / §7.1 step 15: HPKE aad = ASCII(Encoded Protected Header).
    let (enc, ct) = seal_base(recipient, info, protected.as_bytes(), plaintext, rng)?;
    // §7.1 step 21 with empty IV and Tag segments.
    Ok(format!(
        "{protected}.{}..{}.",
        b64::encode(&enc),
        b64::encode(&ct)
    ))
}
