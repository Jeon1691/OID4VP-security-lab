//! Shared test helpers. Fixtures are read from `tests/fixtures/` (see MANIFEST.md); nothing here
//! touches the network. All keys are synthetic (generated per run) or RFC example keys.
#![allow(dead_code)] // each integration-test binary uses a different subset

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_ecdh_es::rand_core::UnwrapErr;
use jose_ecdh_es::{RecipientPrivateKey, RecipientPublicKey};
use serde_json::Value;

pub const RFC7518_APPENDIX_C: &str = include_str!("../fixtures/rfc7518_appendix_c.json");
/// Segments of a compact JWE (RFC 7516 §7.1).
pub const SEGMENTS: usize = 5;

pub fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

pub fn b64e(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

pub fn fresh_key() -> (RecipientPrivateKey, RecipientPublicKey) {
    let sk = RecipientPrivateKey::generate(&mut rng());
    let pk = sk.public_key();
    (sk, pk)
}

pub fn appendix_c() -> Value {
    serde_json::from_str(RFC7518_APPENDIX_C).expect("fixture json")
}

pub fn octets(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("octet array")
        .iter()
        .map(|n| u8::try_from(n.as_u64().expect("number")).expect("octet"))
        .collect()
}

pub fn split(compact: &str) -> [String; SEGMENTS] {
    let parts: Vec<String> = compact.split('.').map(str::to_owned).collect();
    parts.try_into().expect("five segments")
}

pub fn join(parts: [&str; SEGMENTS]) -> String {
    parts.join(".")
}

/// The decoded protected header of `compact` as a JSON object.
pub fn header_of(compact: &str) -> serde_json::Map<String, Value> {
    let [protected, ..] = split(compact);
    match serde_json::from_slice(&b64(&protected)).expect("header json") {
        Value::Object(map) => map,
        _ => panic!("header is an object"),
    }
}

/// `compact` with its protected header segment replaced by BASE64URL(`header_json`).
pub fn with_header(compact: &str, header_json: &str) -> String {
    let [_, ek, iv, ct, tag] = split(compact);
    join([&b64e(header_json.as_bytes()), &ek, &iv, &ct, &tag])
}
