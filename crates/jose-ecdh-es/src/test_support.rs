//! **Test support only.** Sender-side sealing for fixtures and the wallet simulator, and the
//! key-derivation hooks of the RFC 7518 Appendix C known-answer tests.
//!
//! Verifier code must never call these: the lab Verifier only parses and opens. The sealing
//! functions perform no header policy (so tests can build correctly encrypted JWEs with refused
//! headers) and take the RNG explicitly; pass an OS-backed CSPRNG such as
//! `rand_core::UnwrapErr(getrandom::SysRng)`.

use p256::SecretKey;
use p256::elliptic_curve::Generate as _;
use serde_json::{Value, json};

use crate::content::{self, ContentEncryption, IV_LEN};
use crate::error::Error;
use crate::keys::{RecipientPrivateKey, RecipientPublicKey, public_jwk, shared_secret};
use crate::rand_core::CryptoRng;
use crate::{ALG_ECDH_ES, b64, header, jwe, kdf};

/// Seals `plaintext` to `recipient` as an `ECDH-ES` compact JWE with protected header
/// `{"alg":"ECDH-ES","enc":...,"epk":{...}}` plus `kid` when given, and no `apu`/`apv`
/// (RFC 7516 §5.1, RFC 7518 §4.6).
pub fn seal_compact(
    recipient: &RecipientPublicKey,
    enc: ContentEncryption,
    kid: Option<&str>,
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<String, Error> {
    let header = |epk: &Value| {
        let mut header = json!({ "alg": ALG_ECDH_ES, "enc": enc.as_str(), "epk": epk });
        if let (Some(kid), Some(object)) = (kid, header.as_object_mut()) {
            object.insert("kid".to_owned(), kid.into());
        }
        header.to_string()
    };
    seal_compact_with_protected_header(recipient, enc, b"", b"", header, plaintext, rng)
}

/// Seals with a fresh ephemeral key (RFC 7518 §4.6: "A new ephemeral public key value MUST be
/// generated for each key agreement operation"). The CEK is derived for `enc`, `apu` and `apv`
/// as given (empty means absent); the protected header is whatever `protected_header_json`
/// returns for the ephemeral public JWK, encoded verbatim with no validation, so negative tests
/// can pair a correct encryption with a refused or inconsistent header.
pub fn seal_compact_with_protected_header(
    recipient: &RecipientPublicKey,
    enc: ContentEncryption,
    apu: &[u8],
    apv: &[u8],
    protected_header_json: impl FnOnce(&Value) -> String,
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<String, Error> {
    let ephemeral = SecretKey::generate_from_rng(rng);
    let epk = public_jwk(&ephemeral.public_key());
    let z = shared_secret(&ephemeral, &recipient.0);
    let cek = kdf::concat_kdf(
        z.as_slice(),
        enc.as_str().as_bytes(),
        apu,
        apv,
        enc.key_len(),
    );

    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut iv);
    // RFC 7516 §5.1 steps 13-14: AAD = ASCII(BASE64URL(UTF8(JWE Protected Header))).
    let protected = b64::encode(protected_header_json(&epk).as_bytes());
    let (ciphertext, tag) = content::encrypt(enc, &cek, &iv, protected.as_bytes(), plaintext)?;
    // §5.1 step 19 / §7.1, with the empty JWE Encrypted Key of Direct Key Agreement.
    Ok(format!(
        "{protected}..{}.{}.{}",
        b64::encode(&iv),
        b64::encode(&ciphertext),
        b64::encode(&tag)
    ))
}

/// The Concat KDF of RFC 7518 §4.6.2 for Direct Key Agreement (AlgorithmID = `enc`), on a raw
/// shared secret `z`. The primitive behind [`crate::CompactJwe::open`], exposed for the
/// Appendix C known-answer test.
pub fn concat_kdf(z: &[u8], enc: ContentEncryption, apu: &[u8], apv: &[u8]) -> Vec<u8> {
    kdf::concat_kdf(z, enc.as_str().as_bytes(), apu, apv, enc.key_len()).to_vec()
}

/// Runs the header policy on `protected_header_json`, then the same ECDH and Concat KDF steps
/// as [`crate::CompactJwe::open`], and returns the CEK. Exposed for the Appendix C test, whose
/// printed protected header and keys must yield the printed key.
pub fn derive_content_key(
    recipient: &RecipientPrivateKey,
    protected_header_json: &str,
) -> Result<Vec<u8>, Error> {
    let header = header::parse(protected_header_json.as_bytes())?;
    Ok(jwe::derive_cek(recipient, &header).to_vec())
}
