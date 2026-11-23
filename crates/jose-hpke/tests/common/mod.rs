//! Shared test helpers. Fixtures are read from `tests/fixtures/` (see MANIFEST.md); nothing here
//! touches the network.
#![allow(dead_code)] // each integration-test binary uses a different subset

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::{RecipientPrivateKey, RecipientPublicKey};
use serde_json::Value;

/// SEC1 §2.3.3 uncompressed point prefix, as used by RFC 9180 §7.1.1 SerializePublicKey.
pub const SEC1_UNCOMPRESSED: u8 = 0x04;

pub const RFC9180_FIXTURE: &str =
    include_str!("../fixtures/rfc9180_base_p256_sha256_aes128gcm.json");
pub const JOSE_FIXTURE: &str = include_str!("../fixtures/jose_hpke_22_vectors.json");

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    hex(v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing hex field {key}")))
}

pub fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

pub fn b64e(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

/// The single RFC 9180 A.3.1 vector (mode_base, DHKEM(P-256), HKDF-SHA256, AES-128-GCM).
pub fn rfc9180_vector() -> Value {
    let all: Value = serde_json::from_str(RFC9180_FIXTURE).expect("fixture json");
    let all = all.as_array().expect("fixture is a list");
    assert_eq!(
        all.len(),
        1,
        "fixture must hold exactly the HPKE-0 base vector"
    );
    all[0].clone()
}

pub fn jose_fixture() -> Value {
    serde_json::from_str(JOSE_FIXTURE).expect("fixture json")
}

/// The draft-22 Appendix A entry for `alg` (HPKE-0, HPKE-0-KE or HPKE-7).
pub fn jose_vector(alg: &str) -> Value {
    jose_fixture()["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["alg"] == alg)
        .unwrap_or_else(|| panic!("no {alg} vector"))
        .clone()
}

pub fn jose_plaintext() -> String {
    jose_fixture()["plaintext"]
        .as_str()
        .expect("plaintext")
        .to_owned()
}

pub fn jwk_private_key(jwk: &Value) -> RecipientPrivateKey {
    RecipientPrivateKey::from_bytes(&b64(jwk["d"].as_str().expect("d"))).expect("valid d")
}

pub fn jwk_public_point(jwk: &Value) -> Vec<u8> {
    let mut point = vec![SEC1_UNCOMPRESSED];
    point.extend(b64(jwk["x"].as_str().expect("x")));
    point.extend(b64(jwk["y"].as_str().expect("y")));
    point
}

pub fn fresh_key() -> (RecipientPrivateKey, RecipientPublicKey) {
    let sk = RecipientPrivateKey::generate(&mut rng());
    let pk = sk.public_key();
    (sk, pk)
}

/// Joins five raw segment strings with `.`.
pub fn join(segments: [&str; 5]) -> String {
    segments.join(".")
}

/// Splits a compact JWE into its five raw segment strings.
pub fn split(compact: &str) -> [String; 5] {
    let parts: Vec<String> = compact.split('.').map(str::to_owned).collect();
    parts.try_into().expect("five segments")
}
