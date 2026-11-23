//! IMP-005: draft-ietf-jose-hpke-encrypt-22 Appendix A vectors (see fixtures/MANIFEST.md).
//!
//! A.1 HPKE-0 is the official decryptable vector for Integrated Encryption with a recipient
//! private JWK. Its expected plaintext comes from the generator script at the -22 tag (the I-D
//! text does not print it); its HPKE `info` is the empty default of draft-22 §5. A.2 HPKE-0-KE
//! and A.13 HPKE-7 are used as official inputs that the HPKE-0 verifier must reject.

mod common;

use common::{b64, b64e, fresh_key, join, jose_plaintext, jose_vector, jwk_private_key, split};
use jose_hpke::{CompactJwe, Error, SessionInfo, open_compact};

#[test]
fn draft22_hpke0_jwk_private_key_matches_public_coordinates() {
    let v = jose_vector("HPKE-0");
    let sk = jwk_private_key(&v["jwk"]);
    assert_eq!(
        sk.public_key().to_bytes(),
        common::jwk_public_point(&v["jwk"])
    );
}

#[test]
fn draft22_hpke0_compact_vector_decrypts_to_generator_plaintext() {
    let v = jose_vector("HPKE-0");
    let sk = jwk_private_key(&v["jwk"]);
    let jwe = CompactJwe::parse(v["compact"].as_str().expect("compact")).expect("parse");
    assert_eq!(jwe.header().kid(), v["jwk"]["kid"].as_str());
    let pt = jwe.open(&sk, b"").expect("open");
    assert_eq!(String::from_utf8(pt).expect("utf-8"), jose_plaintext());
}

#[test]
fn draft22_hpke0_compact_vector_fails_with_session_info_as_info() {
    let v = jose_vector("HPKE-0");
    let sk = jwk_private_key(&v["jwk"]);
    let si = SessionInfo::direct_post_jwt("x509_san_dns:example.com", "n", "https://example.com/r")
        .expect("session info");
    assert_eq!(
        open_compact(v["compact"].as_str().expect("compact"), &sk, si.as_bytes()),
        Err(Error::Decryption)
    );
}

#[test]
fn draft22_hpke0_compact_vector_fails_with_wrong_key() {
    let v = jose_vector("HPKE-0");
    let (other, _) = fresh_key();
    assert_eq!(
        open_compact(v["compact"].as_str().expect("compact"), &other, b""),
        Err(Error::Decryption)
    );
}

#[test]
fn draft22_hpke0_tampered_ciphertext_or_encapsulated_key_is_rejected() {
    let v = jose_vector("HPKE-0");
    let sk = jwk_private_key(&v["jwk"]);
    let [h, ek, iv, ct, tag] = split(v["compact"].as_str().expect("compact"));

    let mut ct_bytes = b64(&ct);
    let last = ct_bytes.len() - 1;
    ct_bytes[last] ^= 1; // inside the AEAD tag
    let bad_ct = b64e(&ct_bytes);
    assert_eq!(
        open_compact(&join([&h, &ek, &iv, &bad_ct, &tag]), &sk, b""),
        Err(Error::Decryption)
    );

    let mut ct_bytes = b64(&ct);
    ct_bytes[0] ^= 1; // inside the encrypted body
    let bad_ct = b64e(&ct_bytes);
    assert_eq!(
        open_compact(&join([&h, &ek, &iv, &bad_ct, &tag]), &sk, b""),
        Err(Error::Decryption)
    );

    // A different, valid P-256 point as encapsulated key: decap succeeds, AEAD open fails.
    let (_, other_pk) = fresh_key();
    let bad_ek = b64e(&other_pk.to_bytes());
    assert_eq!(
        open_compact(&join([&h, &bad_ek, &iv, &ct, &tag]), &sk, b""),
        Err(Error::Decryption)
    );
}

/// The HPKE aad is ASCII(Encoded Protected Header) (draft-22 §5, §7.2 steps 15-16): any change
/// to the encoded header, even a semantically equivalent one, must break decryption.
#[test]
fn draft22_hpke0_protected_header_is_bound_as_aad() {
    let v = jose_vector("HPKE-0");
    let sk = jwk_private_key(&v["jwk"]);
    let [_, ek, iv, ct, tag] = split(v["compact"].as_str().expect("compact"));
    let kid = v["jwk"]["kid"].as_str().expect("kid");

    for header in [
        format!(r#"{{"alg":"HPKE-0","kid":"{kid}x"}}"#),
        format!(r#"{{"kid":"{kid}","alg":"HPKE-0"}}"#),
        format!(r#"{{"alg":"HPKE-0", "kid":"{kid}"}}"#),
        r#"{"alg":"HPKE-0"}"#.to_owned(),
    ] {
        let h = b64e(header.as_bytes());
        assert_eq!(
            open_compact(&join([&h, &ek, &iv, &ct, &tag]), &sk, b""),
            Err(Error::Decryption),
            "{header}"
        );
    }
}

#[test]
fn draft22_hpke0_flattened_json_serialization_is_rejected() {
    let v = jose_vector("HPKE-0");
    let flattened = serde_json::to_string(&v["flattened"]).expect("json");
    assert_eq!(CompactJwe::parse(&flattened), Err(Error::JsonSerialization));
    let pretty = serde_json::to_string_pretty(&v["flattened"]).expect("json");
    assert_eq!(
        CompactJwe::parse(&format!("\n {pretty}")),
        Err(Error::JsonSerialization)
    );
}

#[test]
fn draft22_hpke0_ke_compact_vector_is_rejected() {
    let v = jose_vector("HPKE-0-KE");
    let compact = v["compact"].as_str().expect("compact");
    assert_eq!(CompactJwe::parse(compact), Err(Error::UnsupportedAlg));
    let flattened = serde_json::to_string(&v["flattened"]).expect("json");
    assert_eq!(CompactJwe::parse(&flattened), Err(Error::JsonSerialization));
}

#[test]
fn draft22_hpke7_compact_vector_is_rejected_as_unsupported_alg() {
    // Same KEM/KDF and key type as HPKE-0 but AES-256-GCM: must not be accepted as HPKE-0.
    let v = jose_vector("HPKE-7");
    assert_eq!(
        CompactJwe::parse(v["compact"].as_str().expect("compact")),
        Err(Error::UnsupportedAlg)
    );
}
