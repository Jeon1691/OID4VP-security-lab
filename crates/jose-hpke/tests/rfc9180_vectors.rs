//! IMP-004: RFC 9180 Appendix A.3.1 known-answer tests for the HPKE-0 suite, receiver side.
//!
//! Source: CFRG draft-irtf-cfrg-hpke test-vectors.json (see fixtures/MANIFEST.md), subset
//! mode_base / kem_id 0x0010 / kdf_id 0x0001 / aead_id 0x0001. The receiver is driven only from
//! `ikmR`, `enc`, `info` and the per-message `aad`/`ct`; the sender-side values (`ikmE`, `skEm`,
//! `shared_secret`, `key`, ...) are never fed into the code under test.

mod common;

use common::{hex, hex_field, rfc9180_vector};
use hpke::{Deserializable as _, Kem as _, OpModeR, Serializable as _};
use jose_hpke::RecipientPrivateKey;
use jose_hpke::suite::{Aead, Kdf, Kem};

/// RFC 9180 §5 Table 1: mode_base.
const MODE_BASE: u64 = 0;
/// RFC 9180 §5.2: Nn, the AEAD nonce length of AES-128-GCM (Table 5).
const AES_128_GCM_NN: usize = 12;
/// The vector file lists every sequence number from 0 to 256 inclusive.
const VECTOR_ENCRYPTIONS: usize = 257;

#[test]
fn rfc9180_vector_suite_ids_match_hpke0_types() {
    let v = rfc9180_vector();
    assert_eq!(v["mode"].as_u64(), Some(MODE_BASE));
    assert_eq!(
        v["kem_id"].as_u64(),
        Some(u64::from(<Kem as hpke::Kem>::KEM_ID))
    );
    assert_eq!(
        v["kdf_id"].as_u64(),
        Some(u64::from(<Kdf as hpke::kdf::Kdf>::KDF_ID))
    );
    assert_eq!(
        v["aead_id"].as_u64(),
        Some(u64::from(<Aead as hpke::aead::Aead>::AEAD_ID))
    );
}

#[test]
fn rfc9180_derive_key_pair_matches_vector() {
    let v = rfc9180_vector();
    let pk_rm = hex_field(&v, "pkRm");

    // Codec key type: DeriveKeyPair(ikmR) yields pkRm, and skRm parses to the same key.
    let derived = RecipientPrivateKey::derive_from_ikm(&hex_field(&v, "ikmR"));
    assert_eq!(derived.public_key().to_bytes(), pk_rm);
    let parsed = RecipientPrivateKey::from_bytes(&hex_field(&v, "skRm")).expect("skRm");
    assert_eq!(parsed.public_key(), derived.public_key());

    // Underlying primitive: SerializePrivateKey(DeriveKeyPair(ikmR).sk) == skRm.
    let (sk, pk) = Kem::derive_keypair(&hex_field(&v, "ikmR"));
    assert_eq!(sk.to_bytes().as_slice(), hex_field(&v, "skRm").as_slice());
    assert_eq!(pk.to_bytes().as_slice(), pk_rm.as_slice());
}

/// Fixture self-check: nonce_i = base_nonce XOR I2OSP(i, Nn) (RFC 9180 §5.2 ComputeNonce), and
/// the list is ordered by sequence number, so opening in list order uses the vector's nonces.
#[test]
fn rfc9180_vector_nonces_follow_base_nonce_xor_sequence() {
    let v = rfc9180_vector();
    let base_nonce = hex_field(&v, "base_nonce");
    assert_eq!(base_nonce.len(), AES_128_GCM_NN);
    let encryptions = v["encryptions"].as_array().expect("encryptions");
    assert_eq!(encryptions.len(), VECTOR_ENCRYPTIONS);
    for (seq, e) in encryptions.iter().enumerate() {
        let seq_bytes = (seq as u128).to_be_bytes();
        let seq_bytes = &seq_bytes[seq_bytes.len() - AES_128_GCM_NN..];
        let expected: Vec<u8> = base_nonce
            .iter()
            .zip(seq_bytes)
            .map(|(b, s)| b ^ s)
            .collect();
        assert_eq!(hex_field(e, "nonce"), expected, "nonce for sequence {seq}");
    }
}

#[test]
fn rfc9180_base_p256_opens_all_vector_encryptions_in_sequence() {
    let v = rfc9180_vector();
    let (sk, _) = Kem::derive_keypair(&hex_field(&v, "ikmR"));
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex_field(&v, "enc")).expect("enc");
    let mut ctx =
        hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &hex_field(&v, "info"))
            .expect("SetupBaseR");

    let encryptions = v["encryptions"].as_array().expect("encryptions");
    assert_eq!(encryptions.len(), VECTOR_ENCRYPTIONS);
    for (seq, e) in encryptions.iter().enumerate() {
        let pt = ctx
            .open(&hex_field(e, "ct"), &hex_field(e, "aad"))
            .unwrap_or_else(|err| panic!("open sequence {seq}: {err}"));
        assert_eq!(pt, hex_field(e, "pt"), "plaintext for sequence {seq}");
    }
}

#[test]
fn rfc9180_base_p256_exporter_values_match() {
    let v = rfc9180_vector();
    let (sk, _) = Kem::derive_keypair(&hex_field(&v, "ikmR"));
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex_field(&v, "enc")).expect("enc");
    let ctx =
        hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &hex_field(&v, "info"))
            .expect("SetupBaseR");

    let exports = v["exports"].as_array().expect("exports");
    assert!(!exports.is_empty());
    for x in exports {
        let len = usize::try_from(x["L"].as_u64().expect("L")).expect("L fits");
        let mut out = vec![0u8; len];
        ctx.export(&hex_field(x, "exporter_context"), &mut out)
            .expect("export");
        assert_eq!(out, hex_field(x, "exported_value"));
    }
}

/// The codec's own single-shot open (the path `CompactJwe::open` uses) reproduces sequence 0.
#[test]
fn rfc9180_first_encryption_opens_via_codec_open_base() {
    let v = rfc9180_vector();
    let sk = RecipientPrivateKey::derive_from_ikm(&hex_field(&v, "ikmR"));
    let e0 = &v["encryptions"][0];
    let pt = jose_hpke::open_base(
        &sk,
        &hex_field(&v, "enc"),
        &hex_field(&v, "info"),
        &hex_field(e0, "aad"),
        &hex_field(e0, "ct"),
    )
    .expect("OpenBase");
    assert_eq!(pt, hex_field(e0, "pt"));
}

#[test]
fn rfc9180_first_encryption_rejects_wrong_info_aad_or_ciphertext() {
    let v = rfc9180_vector();
    let sk = RecipientPrivateKey::derive_from_ikm(&hex_field(&v, "ikmR"));
    let e0 = &v["encryptions"][0];
    let (enc, info, aad, ct) = (
        hex_field(&v, "enc"),
        hex_field(&v, "info"),
        hex_field(e0, "aad"),
        hex_field(e0, "ct"),
    );

    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 1;
    let cases: [(&[u8], &[u8], &[u8]); 4] = [
        (b"", &aad, &ct),
        (&info, b"", &ct),
        (&info, &aad, &bad_ct),
        (&info, &hex("436f756e742d31"), &ct), // aad of sequence 1 ("Count-1")
    ];
    for (info, aad, ct) in cases {
        assert_eq!(
            jose_hpke::open_base(&sk, &enc, info, aad, ct),
            Err(jose_hpke::Error::Decryption)
        );
    }
}
