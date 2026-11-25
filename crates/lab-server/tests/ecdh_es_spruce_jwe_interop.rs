//! jose-ecdh-es opens the `direct_post.jwt` responses the pinned SpruceID openid4vp produces.
//!
//! openid4vp@c57a8958 `build_encrypted_response` selects the Verifier key with
//! `find_encryption_jwk` (OpenID4VP 1.0 §8.3: `alg` required in the JWK) and encrypts with
//! `JweBuilder` (josekit ECDH-ES on P-256, `typ` = `JWT`, `kid` copied from the JWK). This test
//! drives those two public functions directly with the same inputs `build_encrypted_response`
//! derives from `client_metadata`, so no Authorization Request is needed. It lives in lab-server
//! only because the openid4vp dependency is confined here (deny.toml `[bans]`); the Verifier
//! build does not contain jose-ecdh-es. Keys are synthetic, generated per run.

use jose_ecdh_es::rand_core::UnwrapErr;
use jose_ecdh_es::{ALG_ECDH_ES, CompactJwe, ContentEncryption, ENC_A128GCM, RecipientPrivateKey};
use openid4vp::core::jwe::{DEFAULT_ENC, JweBuilder, find_encryption_jwk};
use serde_json::{Map, Value, json};

const KID: &str = "lab-ecdh-es-1";
/// JWK `use` for an encryption key (RFC 7517 §4.2).
const KEY_USE_ENC: &str = "enc";

/// The Verifier JWKS entry as the lab would advertise it in `client_metadata.jwks`.
fn advertised_jwk(sk: &RecipientPrivateKey) -> Map<String, Value> {
    let mut jwk = sk.public_key().to_jwk();
    let object = jwk.as_object_mut().expect("JWK object");
    object.insert("alg".into(), ALG_ECDH_ES.into());
    object.insert("use".into(), KEY_USE_ENC.into());
    object.insert("kid".into(), KID.into());
    object.clone()
}

fn spruce_encrypt(jwk: &Map<String, Value>, enc: ContentEncryption, payload: &Value) -> String {
    let info = find_encryption_jwk(std::iter::once(jwk)).expect("SpruceID selects the key");
    assert_eq!(info.alg, ALG_ECDH_ES);
    let jwk_json = serde_json::to_value(&info.jwk).expect("JWK serializes");
    let mut builder = JweBuilder::new()
        .payload(payload.clone())
        .recipient_key_json(&jwk_json)
        .expect("recipient JWK")
        .alg(info.alg)
        .enc(enc.as_str());
    if let Some(kid) = info.kid {
        builder = builder.kid(kid);
    }
    builder.build().expect("SpruceID builds the ECDH-ES JWE")
}

#[test]
fn spruce_ecdh_es_direct_post_jwt_response_opens_with_jose_ecdh_es() {
    // SpruceID's default `enc` is the one jose-ecdh-es calls A128GCM.
    assert_eq!(DEFAULT_ENC, ENC_A128GCM);
    let sk = RecipientPrivateKey::generate(&mut UnwrapErr(getrandom::SysRng));
    let jwk = advertised_jwk(&sk);
    for enc in [ContentEncryption::A128Gcm, ContentEncryption::A256Gcm] {
        let payload = json!({ "vp_token": { "cred": ["synthetic"] }, "state": "s-1" });
        let compact = spruce_encrypt(&jwk, enc, &payload);
        let jwe = CompactJwe::parse(&compact).expect("SpruceID JWE passes the policy");
        assert_eq!(jwe.header().enc(), enc);
        assert_eq!(jwe.header().kid().map(|k| k.as_str()), Some(KID));
        assert_eq!(jwe.header().typ(), Some("JWT"));
        let plaintext = jwe.open(&sk).expect("opens");
        let opened: Value = serde_json::from_slice(&plaintext).expect("JSON payload");
        assert_eq!(opened, payload, "{enc:?}");
    }
}
