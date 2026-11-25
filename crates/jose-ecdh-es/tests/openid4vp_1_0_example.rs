//! End-to-end known-answer test: the encrypted Authorization Response example of OpenID4VP 1.0
//! §8.3 (ECDH-ES + A128GCM to the `kid` "ac" P-256 key, whose `d` the spec prints) opens to the
//! printed payload. Fixture provenance: `tests/fixtures/MANIFEST.md`.

mod common;

use common::{b64, fresh_key};
use jose_ecdh_es::{
    CompactJwe, ContentEncryption, Error, RecipientPrivateKey, RecipientPublicKey, open_compact,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/openid4vp_1_0_section_8_3_example.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture json")
}

fn member(jwk: &Value, name: &str) -> Vec<u8> {
    b64(jwk[name].as_str().expect(name))
}

#[test]
fn openid4vp_1_0_section_8_3_example_opens_to_the_printed_payload() {
    let v = fixture();
    let jwk = &v["recipient_jwk"];
    let sk = RecipientPrivateKey::from_bytes(&member(jwk, "d")).expect("spec d");
    let pk = RecipientPublicKey::from_coordinates(&member(jwk, "x"), &member(jwk, "y"))
        .expect("spec point");
    assert_eq!(sk.public_key(), pk, "printed d matches the advertised x/y");

    let compact = v["jwe_compact"].as_str().expect("compact");
    let jwe = CompactJwe::parse(compact).expect("the spec example passes the policy");
    let header = jwe.header();
    assert_eq!(header.enc(), ContentEncryption::A128Gcm);
    assert_eq!(header.kid().map(|k| k.as_str()), jwk["kid"].as_str());
    assert_eq!(
        (header.apu(), header.apv(), header.typ()),
        (None, None, None)
    );

    let plaintext = jwe.open(&sk).expect("opens with the printed d");
    let payload: Value = serde_json::from_slice(&plaintext).expect("JSON payload");
    assert_eq!(payload, v["payload"]);

    // Only the printed key opens it.
    let (other, _) = fresh_key();
    assert_eq!(open_compact(compact, &other), Err(Error::Decryption));
}
