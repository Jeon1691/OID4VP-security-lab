//! Interoperability with josekit, at the git rev SpruceID openid4vp encrypts its
//! `direct_post.jwt` responses with (`JweBuilder`: josekit `ECDH_ES` + P-256). Both directions,
//! both `enc` values, with and without `apu`/`apv`. Keys are synthetic, generated per run.

mod common;

use common::{b64, fresh_key, header_of, rng};
use jose_ecdh_es::test_support::{seal_compact, seal_compact_with_protected_header};
use jose_ecdh_es::{
    ALG_ECDH_ES, CompactJwe, ContentEncryption, RecipientPrivateKey, RecipientPublicKey,
    open_compact,
};
use josekit::jwe::{ECDH_ES, JweHeader};
use josekit::jwk::{Jwk, KeyPair as _};
use p256_spruce::NistP256;
use serde_json::{Value, json};

const PLAINTEXT: &[u8] = br#"{"vp_token":{"cred":["synthetic"]},"state":"s-1"}"#;
const KID: &str = "verifier-ecdh-es-1";
const ENCS: [ContentEncryption; 2] = [ContentEncryption::A128Gcm, ContentEncryption::A256Gcm];
const APU: &[u8] = b"synthetic wallet";
const APV: &[u8] = b"synthetic verifier";

/// josekit encrypts `PLAINTEXT` to our public key; `party_info` sets `apu`/`apv`.
fn josekit_encrypt(pk: &RecipientPublicKey, enc: ContentEncryption, party_info: bool) -> String {
    let jwk = Jwk::from_bytes(pk.to_jwk().to_string()).expect("our public JWK parses in josekit");
    let mut encrypter = ECDH_ES
        .encrypter_from_jwk::<NistP256>(&jwk)
        .expect("josekit ECDH-ES encrypter");
    if party_info {
        encrypter.set_agreement_partyuinfo(APU);
        encrypter.set_agreement_partyvinfo(APV);
    }
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(ALG_ECDH_ES);
    header.set_content_encryption(enc.as_str());
    header.set_key_id(KID);
    josekit::jwe::serialize_compact(PLAINTEXT, &header, &encrypter).expect("josekit encrypts")
}

/// A josekit-generated key pair as (our private key, our public key, josekit private JWK).
fn josekit_key_pair() -> (RecipientPrivateKey, RecipientPublicKey, Jwk) {
    let pair = ECDH_ES
        .generate_ec_key_pair::<NistP256>()
        .expect("josekit P-256 key pair");
    let private = pair.to_jwk_key_pair();
    let member = |name: &str| b64(private.parameter(name).and_then(Value::as_str).expect(name));
    let sk = RecipientPrivateKey::from_bytes(&member("d")).expect("josekit d is a P-256 scalar");
    let pk = RecipientPublicKey::from_coordinates(&member("x"), &member("y")).expect("point");
    assert_eq!(sk.public_key(), pk, "josekit d matches its x/y");
    (sk, pk, private)
}

fn josekit_decrypt(private: &Jwk, compact: &str) -> (Vec<u8>, JweHeader) {
    let decrypter = ECDH_ES
        .decrypter_from_jwk::<NistP256>(private)
        .expect("josekit ECDH-ES decrypter");
    josekit::jwe::deserialize_compact(compact, &decrypter).expect("josekit decrypts")
}

#[test]
fn josekit_ecdh_es_a128gcm_and_a256gcm_jwes_open() {
    let (sk, pk) = fresh_key();
    for enc in ENCS {
        let compact = josekit_encrypt(&pk, enc, false);
        let jwe = CompactJwe::parse(&compact).expect("josekit JWE passes the policy");
        assert_eq!(jwe.header().enc(), enc);
        assert_eq!(jwe.header().kid().map(|k| k.as_str()), Some(KID));
        assert_eq!(jwe.header().typ(), Some("JWT"));
        assert_eq!(jwe.open(&sk).expect("opens"), PLAINTEXT, "{enc:?}");
        // josekit's epk carries exactly kty, crv, x, y (the members this crate accepts).
        let epk = &header_of(&compact)["epk"];
        assert_eq!(epk.as_object().expect("epk object").len(), 4);
    }
}

#[test]
fn josekit_jwes_with_apu_and_apv_open() {
    let (sk, pk) = fresh_key();
    for enc in ENCS {
        let compact = josekit_encrypt(&pk, enc, true);
        let jwe = CompactJwe::parse(&compact).expect("parse");
        assert_eq!(jwe.header().apu(), Some(APU));
        assert_eq!(jwe.header().apv(), Some(APV));
        assert_eq!(jwe.open(&sk).expect("opens"), PLAINTEXT, "{enc:?}");
    }
}

#[test]
fn josekit_jwe_does_not_open_with_another_key() {
    let (_, pk) = fresh_key();
    let (other, _) = fresh_key();
    for enc in ENCS {
        let compact = josekit_encrypt(&pk, enc, false);
        assert_eq!(
            open_compact(&compact, &other),
            Err(jose_ecdh_es::Error::Decryption)
        );
    }
}

#[test]
fn sealed_jwes_decrypt_with_josekit() {
    let (_, pk, private) = josekit_key_pair();
    for enc in ENCS {
        for kid in [None, Some(KID)] {
            let compact = seal_compact(&pk, enc, kid, PLAINTEXT, &mut rng()).expect("seal");
            let (plaintext, header) = josekit_decrypt(&private, &compact);
            assert_eq!(plaintext, PLAINTEXT, "{enc:?} {kid:?}");
            assert_eq!(header.algorithm(), Some(ALG_ECDH_ES));
            assert_eq!(header.content_encryption(), Some(enc.as_str()));
            assert_eq!(header.key_id(), kid);
        }
    }
}

#[test]
fn sealed_jwes_with_apu_and_apv_decrypt_with_josekit() {
    let (sk, pk, private) = josekit_key_pair();
    for enc in ENCS {
        let header = |epk: &Value| {
            json!({
                "alg": ALG_ECDH_ES,
                "enc": enc.as_str(),
                "epk": epk,
                "apu": common::b64e(APU),
                "apv": common::b64e(APV),
            })
            .to_string()
        };
        let compact =
            seal_compact_with_protected_header(&pk, enc, APU, APV, header, PLAINTEXT, &mut rng())
                .expect("seal");
        assert_eq!(josekit_decrypt(&private, &compact).0, PLAINTEXT, "{enc:?}");
        assert_eq!(open_compact(&compact, &sk).expect("opens"), PLAINTEXT);
    }
}
