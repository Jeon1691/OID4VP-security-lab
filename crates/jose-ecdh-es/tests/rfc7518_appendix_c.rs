//! RFC 7518 Appendix C known-answer tests: the Concat KDF (§4.6.2) and the ECDH step, against
//! the exact bytes printed in the RFC (fixture provenance: `tests/fixtures/MANIFEST.md`).

mod common;

use common::{appendix_c, b64, octets};
use jose_ecdh_es::test_support::{concat_kdf, derive_content_key};
use jose_ecdh_es::{ContentEncryption, RecipientPrivateKey, RecipientPublicKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn private_key(jwk: &Value) -> RecipientPrivateKey {
    RecipientPrivateKey::from_bytes(&b64(jwk["d"].as_str().expect("d"))).expect("RFC key")
}

fn public_key(jwk: &Value) -> RecipientPublicKey {
    RecipientPublicKey::from_coordinates(
        &b64(jwk["x"].as_str().expect("x")),
        &b64(jwk["y"].as_str().expect("y")),
    )
    .expect("RFC point")
}

#[test]
fn rfc7518_appendix_c_concat_kdf_matches_vector() {
    let v = appendix_c();
    let header = &v["protected_header"];
    // The printed `apu` / `apv` are base64url of "Alice" / "Bob" (Appendix C prose).
    let apu = b64(header["apu"].as_str().expect("apu"));
    let apv = b64(header["apv"].as_str().expect("apv"));
    assert_eq!(apu, v["apu_utf8"].as_str().expect("apu text").as_bytes());
    assert_eq!(apv, v["apv_utf8"].as_str().expect("apv text").as_bytes());
    assert_eq!(header["enc"], ContentEncryption::A128Gcm.as_str());

    let key = concat_kdf(&octets(&v["z"]), ContentEncryption::A128Gcm, &apu, &apv);
    assert_eq!(
        key,
        octets(&v["derived_key"]),
        "exact RFC 7518 Appendix C key bytes"
    );
    assert_eq!(key.len(), ContentEncryption::A128Gcm.key_len());
    assert_eq!(
        common::b64e(&key),
        v["derived_key_base64url"].as_str().expect("b64 key")
    );

    // The printed intermediate values are consistent with the printed key (fixture check).
    let round1 = octets(&v["round1_hash_input"]);
    assert_eq!(Sha256::digest(&round1)[..key.len()], key[..]);
}

#[test]
fn rfc7518_appendix_c_key_agreement_yields_the_printed_key() {
    let v = appendix_c();
    let bob = private_key(&v["bob_jwk"]);
    let header_json = v["protected_header"].to_string();
    let key = derive_content_key(&bob, &header_json).expect("RFC header passes the policy");
    assert_eq!(key, octets(&v["derived_key"]));
}

#[test]
fn rfc7518_appendix_c_keys_round_trip_through_the_key_types() {
    let v = appendix_c();
    for name in ["alice_ephemeral_jwk", "bob_jwk"] {
        let jwk = &v[name];
        let sk = private_key(jwk);
        assert_eq!(sk.public_key(), public_key(jwk), "{name}: d matches x/y");
        let public = sk.public_key().to_jwk();
        for member in ["kty", "crv", "x", "y"] {
            assert_eq!(public[member], jwk[member], "{name}.{member}");
        }
        assert!(public.get("d").is_none(), "{name}: public JWK has no d");
        assert_eq!(public.as_object().expect("object").len(), 4);
    }
}

#[test]
fn rfc7518_appendix_c_kdf_binds_every_input() {
    let v = appendix_c();
    let z = octets(&v["z"]);
    let want = octets(&v["derived_key"]);
    let (apu, apv) = (b"Alice".as_slice(), b"Bob".as_slice());
    let mut other_z = z.clone();
    other_z[0] ^= 1;
    for (label, key) in [
        (
            "Z",
            concat_kdf(&other_z, ContentEncryption::A128Gcm, apu, apv),
        ),
        ("apu", concat_kdf(&z, ContentEncryption::A128Gcm, b"", apv)),
        ("apv", concat_kdf(&z, ContentEncryption::A128Gcm, apu, b"")),
        (
            "swapped apu/apv",
            concat_kdf(&z, ContentEncryption::A128Gcm, apv, apu),
        ),
    ] {
        assert_ne!(key, want, "{label} must change the key");
    }
    // AlgorithmID and keydatalen: A256GCM yields a different 32-byte key, not an extension.
    let a256 = concat_kdf(&z, ContentEncryption::A256Gcm, apu, apv);
    assert_eq!(a256.len(), ContentEncryption::A256Gcm.key_len());
    assert_ne!(a256[..want.len()], want[..]);
}
