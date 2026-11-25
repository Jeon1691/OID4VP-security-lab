//! Strict compact JWE parsing, the `ECDH-ES` protected-header policy, and authenticated
//! decryption failures.
//!
//! Where possible the rejected input is a *correctly encrypted* JWE (sealed with the offending
//! header via `test_support`), so each test shows that policy, not a decryption failure, is
//! what rejects it. Test names carry an `ecdh_es_` prefix so the gate's REQUIRED_TESTS cannot
//! confuse them with jose-hpke's.

mod common;

use common::{b64, b64e, fresh_key, header_of, rng, split, with_header};
use jose_ecdh_es::test_support::{seal_compact, seal_compact_with_protected_header};
use jose_ecdh_es::{
    ALG_ECDH_ES, CompactJwe, ContentEncryption, Error, IV_LEN, MAX_COMPACT_JWE_LEN,
    MAX_PROTECTED_HEADER_LEN, RecipientPrivateKey, Segment, TAG_LEN, open_compact,
};
use serde_json::{Value, json};

const PLAINTEXT: &[u8] = br#"{"vp_token":{"cred":["synthetic"]},"state":"s-1"}"#;
const KID: &str = "verifier-ecdh-es-1";
const ENC: ContentEncryption = ContentEncryption::A128Gcm;
/// `Error::EphemeralKeyParameter` value for an `epk` member outside kty/crv/x/y.
const EPK_UNKNOWN_MEMBER: &str = "(unknown member)";
/// The member name `kid` with its `i` written as the JSON escape backslash-u-0069 (RFC 8259
/// §7). Built from `\u{5c}` (a backslash) so the source holds no ambiguous escape sequence.
const ESCAPED_KID: &str = "k\u{5c}u0069d";
/// The P-256 field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (SEC 2 §2.4.2 / FIPS 186-5
/// curve P-256), big-endian.
const P256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// Segment indices (RFC 7516 §7.1 order).
const PROTECTED: usize = 0;
const ENCRYPTED_KEY: usize = 1;
const IV: usize = 2;
const CIPHERTEXT: usize = 3;
const TAG: usize = 4;

/// The default header for `epk`: `{"alg":"ECDH-ES","enc":"A128GCM","epk":...}`.
fn header_with_epk(epk: &Value) -> Value {
    json!({ "alg": ALG_ECDH_ES, "enc": ENC.as_str(), "epk": epk })
}

/// Seals `PLAINTEXT` (A128GCM, no apu/apv) under the header `header` builds; returns
/// (key, compact).
fn sealed(header: impl FnOnce(&Value) -> String) -> (RecipientPrivateKey, String) {
    let (sk, pk) = fresh_key();
    let compact =
        seal_compact_with_protected_header(&pk, ENC, b"", b"", header, PLAINTEXT, &mut rng())
            .expect("seal");
    (sk, compact)
}

/// Like [`sealed`], with `edit` applied to the default header object.
fn sealed_edited(
    edit: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> (RecipientPrivateKey, String) {
    sealed(|epk| {
        let mut header = header_with_epk(epk);
        edit(header.as_object_mut().expect("object"));
        header.to_string()
    })
}

/// Parsing fails, and the one-shot API fails identically (before any decryption).
fn parse_err_of(sk: &RecipientPrivateKey, compact: &str) -> Error {
    let err = CompactJwe::parse(compact).expect_err(compact);
    assert_eq!(open_compact(compact, sk), Err(err.clone()));
    err
}

fn edited_err(edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Error {
    let (sk, compact) = sealed_edited(edit);
    parse_err_of(&sk, &compact)
}

fn epk_edited_err(edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Error {
    edited_err(|header| edit(header["epk"].as_object_mut().expect("epk object")))
}

fn raw_err(header: impl FnOnce(&Value) -> String) -> Error {
    let (sk, compact) = sealed(header);
    parse_err_of(&sk, &compact)
}

/// A valid A128GCM JWE with `kid`; returns (key, compact).
fn valid() -> (RecipientPrivateKey, String) {
    let (sk, pk) = fresh_key();
    let compact = seal_compact(&pk, ENC, Some(KID), PLAINTEXT, &mut rng()).expect("seal");
    (sk, compact)
}

/// `compact` with segment `index` replaced by base64url of its decoded bytes after `edit`.
fn with_segment_bytes(compact: &str, index: usize, edit: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut parts = split(compact);
    let mut bytes = b64(&parts[index]);
    edit(&mut bytes);
    parts[index] = b64e(&bytes);
    parts.join(".")
}

fn with_segment(compact: &str, index: usize, segment: &str) -> String {
    let mut parts = split(compact);
    parts[index] = segment.to_owned();
    parts.join(".")
}

#[test]
fn ecdh_es_seal_then_open_round_trip_for_both_enc_values() {
    // Supplementary only: interoperability is josekit_interop.rs and the Appendix C vector.
    let (sk, pk) = fresh_key();
    for enc in [ContentEncryption::A128Gcm, ContentEncryption::A256Gcm] {
        for kid in [None, Some(KID)] {
            let compact = seal_compact(&pk, enc, kid, PLAINTEXT, &mut rng()).expect("seal");
            let jwe = CompactJwe::parse(&compact).expect("parse");
            assert_eq!(jwe.header().enc(), enc);
            assert_eq!(jwe.header().kid().map(|k| k.as_str()), kid);
            assert_eq!(jwe.open(&sk).expect("open"), PLAINTEXT);
            let parts = split(&compact);
            assert!(parts[ENCRYPTED_KEY].is_empty(), "direct key agreement");
            assert_eq!(b64(&parts[IV]).len(), IV_LEN);
            assert_eq!(b64(&parts[TAG]).len(), TAG_LEN);
        }
    }
}

#[test]
fn ecdh_es_accepts_apu_apv_typ_and_cty() {
    let (sk, pk) = fresh_key();
    let header = |epk: &Value| {
        json!({
            "alg": ALG_ECDH_ES, "enc": ENC.as_str(), "epk": epk, "apu": b64e(b"u"),
            "apv": b64e(b"v"), "kid": KID, "typ": "JWT", "cty": "json",
        })
        .to_string()
    };
    let compact =
        seal_compact_with_protected_header(&pk, ENC, b"u", b"v", header, PLAINTEXT, &mut rng())
            .expect("seal");
    let jwe = CompactJwe::parse(&compact).expect("parse");
    let h = jwe.header();
    assert_eq!(
        (h.apu(), h.apv()),
        (Some(b"u".as_slice()), Some(b"v".as_slice()))
    );
    assert_eq!((h.typ(), h.cty()), (Some("JWT"), Some("json")));
    assert_eq!(jwe.open(&sk).expect("open"), PLAINTEXT);
}

/// The property the lab wants to observe (#792 C3/C9, §4 item 1): the key schedule takes
/// nothing but the recipient key, so every response sealed to a shared key opens with it, and
/// only the plaintext (`state`) says which session it belongs to.
#[test]
fn ecdh_es_shared_key_opens_every_candidate_response() {
    let (sk, pk) = fresh_key();
    let responses: Vec<(String, String)> = ["session-a", "session-b", "session-c"]
        .into_iter()
        .map(|state| {
            let plaintext = json!({ "vp_token": {}, "state": state }).to_string();
            let compact =
                seal_compact(&pk, ENC, Some(KID), plaintext.as_bytes(), &mut rng()).expect("seal");
            (plaintext, compact)
        })
        .collect();
    for (plaintext, compact) in &responses {
        let jwe = CompactJwe::parse(compact).expect("parse");
        // Same `kid` for every session: the header cannot route to one of them.
        assert_eq!(jwe.header().kid().map(|k| k.as_str()), Some(KID));
        assert_eq!(
            jwe.open(&sk).expect("every candidate opens"),
            plaintext.as_bytes()
        );
    }
    let headers: Vec<_> = responses
        .iter()
        .map(|(_, c)| {
            let mut h = header_of(c);
            h.remove("epk"); // fresh per message, carries no session information
            h
        })
        .collect();
    assert!(
        headers.windows(2).all(|w| w[0] == w[1]),
        "headers are identical across sessions"
    );
}

#[test]
fn ecdh_es_tampered_ciphertext_tag_or_iv_fails_decryption() {
    let (sk, compact) = valid();
    let flip_first = |b: &mut Vec<u8>| b[0] ^= 1;
    let flip_last = |b: &mut Vec<u8>| *b.last_mut().expect("non-empty") ^= 0x80;
    let truncate = |b: &mut Vec<u8>| {
        b.pop();
    };
    let tampered = [
        with_segment_bytes(&compact, CIPHERTEXT, flip_first),
        with_segment_bytes(&compact, CIPHERTEXT, flip_last),
        with_segment_bytes(&compact, CIPHERTEXT, truncate),
        with_segment_bytes(&compact, CIPHERTEXT, |b| b.push(0)),
        with_segment_bytes(&compact, TAG, flip_first),
        with_segment_bytes(&compact, TAG, flip_last),
        with_segment_bytes(&compact, IV, flip_first),
        with_segment_bytes(&compact, IV, flip_last),
    ];
    for t in tampered {
        let jwe = CompactJwe::parse(&t).expect("still well-formed");
        assert_eq!(jwe.open(&sk), Err(Error::Decryption), "{t}");
    }
    assert_eq!(
        open_compact(&compact, &sk).expect("original opens"),
        PLAINTEXT
    );
}

#[test]
fn ecdh_es_tampered_protected_header_fails_decryption() {
    let (sk, compact) = valid();
    let original = header_of(&compact);
    let (_, other_pk) = fresh_key();
    let edits: [(&str, &str, Value); 5] = [
        ("kid changed", "kid", "other-kid".into()),
        ("typ added", "typ", "JWT".into()),
        // AlgorithmID and keydatalen are bound into the key.
        ("enc swapped", "enc", "A256GCM".into()),
        // PartyUInfo is bound into the key.
        ("apu added", "apu", b64e(b"x").into()),
        // A different (valid) ephemeral key gives a different Z.
        ("epk replaced", "epk", other_pk.to_jwk()),
    ];
    for (label, name, value) in edits {
        let mut header = original.clone();
        header.insert(name.into(), value);
        let t = with_header(&compact, &Value::Object(header).to_string());
        let jwe = CompactJwe::parse(&t).expect(label);
        assert_eq!(jwe.open(&sk), Err(Error::Decryption), "{label}");
    }
    // The same JSON with different whitespace is a different AAD.
    let protected = String::from_utf8(b64(&split(&compact)[PROTECTED])).expect("utf8");
    for respelled in [format!(" {protected}"), format!("{protected}\n")] {
        let t = with_header(&compact, &respelled);
        assert_eq!(open_compact(&t, &sk), Err(Error::Decryption));
    }
}

#[test]
fn ecdh_es_wrong_recipient_key_fails_decryption() {
    let (_, compact) = valid();
    for _ in 0..3 {
        let (other, _) = fresh_key();
        assert_eq!(open_compact(&compact, &other), Err(Error::Decryption));
    }
}

#[test]
fn ecdh_es_rejects_key_wrapping_hpke_dir_and_every_other_alg() {
    for alg in [
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
        "HPKE-0",
        "HPKE-0-KE",
        "HPKE-7",
        "dir",
        "A128KW",
        "RSA-OAEP-256",
        "none",
        "ecdh-es",
        "ECDH-ES ",
        "",
    ] {
        assert_eq!(
            edited_err(|h| _ = h.insert("alg".into(), alg.into())),
            Error::UnsupportedAlg,
            "{alg}"
        );
    }
    assert_eq!(edited_err(|h| _ = h.remove("alg")), Error::MissingAlg);
    for bad in [Value::Null, json!(1), json!(["ECDH-ES"])] {
        assert_eq!(
            edited_err(|h| _ = h.insert("alg".into(), bad)),
            Error::HeaderParameterType("alg")
        );
    }
}

#[test]
fn ecdh_es_rejects_unsupported_enc() {
    for enc in [
        "A192GCM",
        "A128CBC-HS256",
        "A256CBC-HS512",
        "a128gcm",
        "A128GCM ",
        "",
    ] {
        assert_eq!(
            edited_err(|h| _ = h.insert("enc".into(), enc.into())),
            Error::UnsupportedEnc,
            "{enc}"
        );
    }
    assert_eq!(edited_err(|h| _ = h.remove("enc")), Error::MissingEnc);
    assert_eq!(
        edited_err(|h| _ = h.insert("enc".into(), Value::Null)),
        Error::HeaderParameterType("enc")
    );
}

#[test]
fn ecdh_es_rejects_zip_header_parameter() {
    for zip in [json!("DEF"), json!(""), Value::Null] {
        assert_eq!(
            edited_err(|h| _ = h.insert("zip".into(), zip)),
            Error::ForbiddenHeaderParameter("zip")
        );
    }
}

#[test]
fn ecdh_es_rejects_crit_header_parameter() {
    for crit in [json!(["exp"]), json!([]), json!(["zip"]), json!(["epk"])] {
        assert_eq!(
            edited_err(|h| _ = h.insert("crit".into(), crit)),
            Error::UnsupportedCrit
        );
    }
}

#[test]
fn ecdh_es_rejects_unknown_header_parameter() {
    for name in [
        "jwk", "jku", "x5u", "x5c", "iv", "tag", "p2s", "ek", "psk_id", "foo",
    ] {
        assert_eq!(
            edited_err(|h| _ = h.insert(name.into(), "x".into())),
            Error::UnknownHeaderParameter,
            "{name}"
        );
    }
}

#[test]
fn ecdh_es_rejects_duplicate_header_parameter() {
    let cases: [fn(&Value) -> String; 4] = [
        |epk| format!(r#"{{"alg":"ECDH-ES","enc":"A128GCM","enc":"A256GCM","epk":{epk}}}"#),
        |epk| format!(r#"{{"alg":"ECDH-ES","alg":"ECDH-ES","enc":"A128GCM","epk":{epk}}}"#),
        |epk| format!(r#"{{"alg":"ECDH-ES","enc":"A128GCM","epk":{epk},"epk":{epk}}}"#),
        // The same member spelled with a JSON escape is still the same name.
        |epk| {
            format!(
                r#"{{"alg":"ECDH-ES","enc":"A128GCM","epk":{epk},"kid":"a","{ESCAPED_KID}":"b"}}"#
            )
        },
    ];
    for case in cases {
        assert_eq!(raw_err(case), Error::HeaderJson);
    }
    // The escaped spelling really is an escape (a backslash, not the letters `kid`) ...
    assert!(ESCAPED_KID.starts_with("k\\") && ESCAPED_KID != "kid");
    // ... and on its own decodes to `kid`, so the last case above is a real duplicate.
    let (sk, compact) = sealed(|epk| {
        format!(r#"{{"alg":"ECDH-ES","enc":"A128GCM","epk":{epk},"{ESCAPED_KID}":"b"}}"#)
    });
    assert!(
        String::from_utf8(b64(&split(&compact)[PROTECTED]))
            .expect("utf8")
            .contains(ESCAPED_KID)
    );
    let jwe = CompactJwe::parse(&compact).expect("escaped member name parses");
    assert_eq!(jwe.header().kid().map(|k| k.as_str()), Some("b"));
    assert_eq!(jwe.open(&sk).expect("opens"), PLAINTEXT);
}

#[test]
fn ecdh_es_rejects_duplicate_epk_member() {
    for member in ["x", "y", "kty", "crv"] {
        let err = raw_err(|epk| {
            let text = epk.to_string();
            let value = epk[member].to_string();
            // Insert a second copy of `member` right after `{`.
            let text = text.replacen('{', &format!(r#"{{"{member}":{value},"#), 1);
            format!(r#"{{"alg":"ECDH-ES","enc":"A128GCM","epk":{text}}}"#)
        });
        assert_eq!(err, Error::HeaderJson, "{member}");
    }
}

#[test]
fn ecdh_es_rejects_missing_or_non_object_epk() {
    assert_eq!(edited_err(|h| _ = h.remove("epk")), Error::MissingEpk);
    for bad in [json!("epk"), Value::Null, json!([])] {
        assert_eq!(
            edited_err(|h| _ = h.insert("epk".into(), bad)),
            Error::HeaderParameterType("epk")
        );
    }
}

#[test]
fn ecdh_es_rejects_epk_with_private_key() {
    // Any `d`, even a well-formed scalar next to a valid point.
    for d in [json!(b64e(&[1; 32])), json!(""), Value::Null] {
        assert_eq!(
            epk_edited_err(|e| _ = e.insert("d".into(), d)),
            Error::EphemeralKeyPrivate
        );
    }
}

#[test]
fn ecdh_es_rejects_off_curve_epk() {
    // y of a valid point with one bit flipped: (x, y') does not satisfy the curve equation.
    let err = epk_edited_err(|e| {
        let mut y = b64(e["y"].as_str().expect("y"));
        *y.last_mut().expect("32 bytes") ^= 1;
        e.insert("y".into(), b64e(&y).into());
    });
    assert_eq!(err, Error::EphemeralKeyPoint);
    // Classic invalid-curve points (RFC 8725 §2.5): points of order 2 (y = 0) on curves
    // y^2 = x^3 - 3x + b' that share P-256's a = -3 but not its b. ECDH with them would leak the
    // static key modulo 2 if the point were not validated.
    //   (0, 0)   lies on b' = 0;
    //   (1, 0)   lies on b' = 2   (1 - 3 + 2 = 0);
    //   (p-1, 0) lies on b' = -2  (-1 + 3 - 2 = 0).
    let p_minus_1 = {
        let mut v = P256_P;
        v[31] -= 1;
        v
    };
    let mut one = [0u8; 32];
    one[31] = 1;
    // Coordinates equal to p, or all ones (> p), are not field elements at all.
    for (x, y) in [
        ([0u8; 32], [0u8; 32]),
        (one, [0u8; 32]),
        (p_minus_1, [0u8; 32]),
        (P256_P, [0u8; 32]),
        ([0xff; 32], [0xff; 32]),
    ] {
        let err = epk_edited_err(|e| {
            e.insert("x".into(), b64e(&x).into());
            e.insert("y".into(), b64e(&y).into());
        });
        assert_eq!(err, Error::EphemeralKeyPoint);
    }
}

#[test]
fn ecdh_es_rejects_wrong_curve_or_key_type_epk() {
    for crv in ["P-384", "P-521", "secp256k1", "X25519", "p-256", ""] {
        assert_eq!(
            epk_edited_err(|e| _ = e.insert("crv".into(), crv.into())),
            Error::EphemeralKeyParameter("crv"),
            "{crv}"
        );
    }
    for kty in ["OKP", "RSA", "oct", "ec", ""] {
        assert_eq!(
            epk_edited_err(|e| _ = e.insert("kty".into(), kty.into())),
            Error::EphemeralKeyParameter("kty"),
            "{kty}"
        );
    }
    // A genuine P-384 epk (48-byte coordinates) fails on `crv` before any point decoding.
    let err = epk_edited_err(|e| {
        e.insert("crv".into(), "P-384".into());
        e.insert("x".into(), b64e(&[1; 48]).into());
        e.insert("y".into(), b64e(&[2; 48]).into());
    });
    assert_eq!(err, Error::EphemeralKeyParameter("crv"));
}

#[test]
fn ecdh_es_rejects_malformed_epk_coordinates() {
    for name in ["x", "y"] {
        let cases: [fn(&str) -> Value; 6] = [
            |_| b64e(&[1; 31]).into(),
            |_| b64e(&[1; 33]).into(),
            |c| format!("{c}=").into(),
            |c| format!("{c}!").into(),
            |_| json!(1),
            |_| Value::Null,
        ];
        for case in cases {
            let err = epk_edited_err(|e| {
                let v = case(e[name].as_str().expect("coordinate"));
                e.insert(name.into(), v);
            });
            assert_eq!(err, Error::EphemeralKeyParameter(name));
        }
        assert_eq!(
            epk_edited_err(|e| _ = e.remove(name)),
            Error::EphemeralKeyParameter(name)
        );
    }
}

#[test]
fn ecdh_es_rejects_unknown_epk_member() {
    for name in ["alg", "kid", "use", "key_ops", "ext"] {
        assert_eq!(
            epk_edited_err(|e| _ = e.insert(name.into(), "x".into())),
            Error::EphemeralKeyParameter(EPK_UNKNOWN_MEMBER),
            "{name}"
        );
    }
}

#[test]
fn ecdh_es_rejects_non_empty_encrypted_key() {
    let (sk, compact) = valid();
    for ek in ["A", "AA", "AAAA", "AAAAAAAAAAAAAAAAAAAAAA", "="] {
        let t = with_segment(&compact, ENCRYPTED_KEY, ek);
        assert_eq!(parse_err_of(&sk, &t), Error::NonEmptyEncryptedKey, "{ek}");
    }
}

#[test]
fn ecdh_es_rejects_wrong_iv_length() {
    let (sk, compact) = valid();
    for len in [0, 1, IV_LEN - 1, IV_LEN + 1, 16] {
        let t = with_segment(&compact, IV, &b64e(&vec![7; len]));
        assert_eq!(parse_err_of(&sk, &t), Error::IvLength { found: len });
    }
}

#[test]
fn ecdh_es_rejects_wrong_tag_length() {
    let (sk, compact) = valid();
    for len in [0, 1, 12, TAG_LEN - 1, TAG_LEN + 1, 32] {
        let t = with_segment(&compact, TAG, &b64e(&vec![7; len]));
        assert_eq!(parse_err_of(&sk, &t), Error::TagLength { found: len });
    }
}

#[test]
fn ecdh_es_rejects_bad_base64url_segments() {
    let (sk, compact) = valid();
    let parts = split(&compact);
    let cases = [
        (PROTECTED, Segment::ProtectedHeader),
        (IV, Segment::InitializationVector),
        (CIPHERTEXT, Segment::Ciphertext),
        (TAG, Segment::AuthenticationTag),
    ];
    for (index, segment) in cases {
        let original = &parts[index];
        let mut bad = vec![
            format!("{original}="),
            format!("{original}=="),
            format!(" {original}"),
            format!("{original}\n"),
            format!("{}+{}", &original[..1], &original[2..]),
            format!("{}/{}", &original[..1], &original[2..]),
            format!("{original}!"),
        ];
        // The tag (16 bytes = 22 chars) leaves the 4 low bits of its last character unused, so
        // the canonical last character is a multiple of 16 in the alphabet; setting a low bit
        // gives a second spelling of the same bytes.
        if index == TAG {
            const ALPHABET: &str =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            const UNUSED_BITS_MASK: usize = 0b1111;
            let last = original.chars().last().expect("non-empty");
            let pos = ALPHABET.find(last).expect("alphabet");
            assert_eq!(pos & UNUSED_BITS_MASK, 0, "canonical tag encoding");
            let respelled = &ALPHABET[pos | 1..=pos | 1];
            bad.push(format!("{}{respelled}", &original[..original.len() - 1]));
        }
        for b in bad {
            let t = with_segment(&compact, index, &b);
            assert_eq!(
                parse_err_of(&sk, &t),
                Error::Base64(segment),
                "{segment:?}: {b:?}"
            );
        }
    }
}

#[test]
fn ecdh_es_rejects_equal_or_malformed_apu_apv() {
    // RFC 7518 §4.6.2: "The "apu" and "apv" values MUST be distinct, when used." Compared on
    // the decoded bytes that enter the KDF.
    for v in [b64e(b"same"), b64e(&[0]), b64e(&[0xff; 64])] {
        assert_eq!(
            edited_err(|h| {
                h.insert("apu".into(), v.clone().into());
                h.insert("apv".into(), v.into());
            }),
            Error::HeaderParameterValue("apv")
        );
    }
    // Empty is refused on its own, alone or next to a non-empty partner (lab policy: it would
    // be a second spelling of "absent").
    for (apu, apv) in [("", None), ("", Some(b64e(b"v")))] {
        assert_eq!(
            edited_err(|h| {
                h.insert("apu".into(), apu.into());
                if let Some(apv) = apv {
                    h.insert("apv".into(), apv.into());
                }
            }),
            Error::HeaderParameterValue("apu")
        );
    }
    assert_eq!(
        edited_err(|h| _ = h.insert("apv".into(), "".into())),
        Error::HeaderParameterValue("apv")
    );
    for name in ["apu", "apv"] {
        for bad in ["", "QWxpY2U=", "QWxp Y2U", "QWxpY2U+", "QWxpY2V"] {
            assert_eq!(
                edited_err(|h| _ = h.insert(name.into(), bad.into())),
                Error::HeaderParameterValue(name),
                "{name}={bad}"
            );
        }
        assert_eq!(
            edited_err(|h| _ = h.insert(name.into(), json!(1))),
            Error::HeaderParameterType(name)
        );
    }
}

#[test]
fn ecdh_es_rejects_kid_typ_cty_with_control_bidi_or_empty_values() {
    for name in ["kid", "typ", "cty"] {
        for bad in ["", "a b", "\u{0}", "\u{202e}x", "\u{200b}", "x\n"] {
            assert_eq!(
                edited_err(|h| _ = h.insert(name.into(), bad.into())),
                Error::HeaderParameterValue(name),
                "{name}={bad:?}"
            );
        }
        assert_eq!(
            edited_err(|h| _ = h.insert(name.into(), json!(true))),
            Error::HeaderParameterType(name)
        );
    }
}

#[test]
fn ecdh_es_rejects_non_object_or_non_utf8_header() {
    let (sk, compact) = valid();
    for header in [&b"[]"[..], b"\"x\"", b"{", b"{}x", b"\xff\xfe{}", b"null"] {
        let t = with_segment(&compact, PROTECTED, &b64e(header));
        assert_eq!(parse_err_of(&sk, &t), Error::HeaderJson, "{header:?}");
    }
}

#[test]
fn ecdh_es_rejects_wrong_segment_count_and_json_serialization() {
    let (sk, compact) = valid();
    let parts = split(&compact);
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    assert_eq!(
        parse_err_of(&sk, &refs[..4].join(".")),
        Error::SegmentCount { found: 4 }
    );
    assert_eq!(
        parse_err_of(&sk, &format!("{compact}.")),
        Error::SegmentCount { found: 6 }
    );
    assert_eq!(parse_err_of(&sk, ""), Error::SegmentCount { found: 1 });
    let json_serialization = json!({
        "protected": parts[PROTECTED], "iv": parts[IV], "ciphertext": parts[CIPHERTEXT],
        "tag": parts[TAG],
    })
    .to_string();
    assert_eq!(
        parse_err_of(&sk, &json_serialization),
        Error::JsonSerialization
    );
    assert_eq!(
        parse_err_of(&sk, &format!(" \n{json_serialization}")),
        Error::JsonSerialization
    );
}

#[test]
fn ecdh_es_rejects_oversized_input_and_header() {
    let (sk, compact) = valid();
    let too_long = format!("{compact}{}", "A".repeat(MAX_COMPACT_JWE_LEN));
    assert_eq!(
        parse_err_of(&sk, &too_long),
        Error::TooLong {
            max: MAX_COMPACT_JWE_LEN
        }
    );
    // A separator flood at the maximum length is refused without per-segment work.
    assert_eq!(
        parse_err_of(&sk, &".".repeat(MAX_COMPACT_JWE_LEN)),
        Error::SegmentCount {
            found: MAX_COMPACT_JWE_LEN + 1
        }
    );
    let big_kid = "k".repeat(MAX_PROTECTED_HEADER_LEN);
    assert_eq!(
        edited_err(|h| _ = h.insert("kid".into(), big_kid.into())),
        Error::HeaderTooLong {
            max: MAX_PROTECTED_HEADER_LEN
        }
    );
}

#[test]
fn ecdh_es_errors_and_debug_never_echo_header_values() {
    let secret_looking = "attacker-chosen-value-0123456789";
    let err = edited_err(|h| _ = h.insert("alg".into(), secret_looking.into()));
    assert!(!err.to_string().contains(secret_looking));
    assert!(!format!("{err:?}").contains(secret_looking));
    let (sk, compact) = valid();
    let jwe = CompactJwe::parse(&compact).expect("parse");
    let debug = format!("{jwe:?} {sk:?}");
    assert!(!debug.contains(&split(&compact)[CIPHERTEXT]));
    assert!(debug.contains("<redacted>"));
}
