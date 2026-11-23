//! IMP-005: strict compact JWE parsing and HPKE-0 protected-header policy.
//!
//! Where possible the rejected input is a *correctly encrypted* JWE (sealed with the offending
//! header via `test_support`), so each test shows that policy, not a decryption failure, is
//! what rejects it.

mod common;

use common::{b64e, fresh_key, join, jose_vector, rng, split};
use jose_hpke::test_support::{seal_compact, seal_compact_with_protected_header};
use jose_hpke::{
    CompactJwe, Error, MAX_COMPACT_JWE_LEN, RecipientPrivateKey, Segment, open_compact,
};

const PLAINTEXT: &[u8] = br#"{"vp_token":{"cred":["synthetic"]}}"#;
const INFO: &[u8] = b"synthetic session info";

/// Seals `PLAINTEXT` under a verbatim protected header; returns (key, compact).
fn sealed_with_header(header_json: &str) -> (RecipientPrivateKey, String) {
    let (sk, pk) = fresh_key();
    let compact = seal_compact_with_protected_header(&pk, header_json, INFO, PLAINTEXT, &mut rng())
        .expect("seal");
    (sk, compact)
}

fn parse_err(header_json: &str) -> Error {
    let (sk, compact) = sealed_with_header(header_json);
    let err = CompactJwe::parse(&compact).expect_err(header_json);
    // The same input through the one-shot API fails identically, before any decryption.
    assert_eq!(open_compact(&compact, &sk, INFO), Err(err.clone()));
    err
}

/// Valid segments (from the official HPKE-0 vector) around a custom raw header segment.
fn with_raw_header_segment(header_segment: &str) -> String {
    let [_, ek, iv, ct, tag] = split(jose_vector("HPKE-0")["compact"].as_str().expect("compact"));
    join([header_segment, &ek, &iv, &ct, &tag])
}

#[test]
fn seal_then_open_round_trip_with_and_without_kid() {
    // Supplementary only: a self-generated round trip is not an interoperability vector.
    let (sk, pk) = fresh_key();
    for kid in [None, Some("verifier-key-1")] {
        let compact = seal_compact(&pk, kid, INFO, PLAINTEXT, &mut rng()).expect("seal");
        let jwe = CompactJwe::parse(&compact).expect("parse");
        assert_eq!(jwe.header().kid(), kid);
        assert_eq!(jwe.open(&sk, INFO).expect("open"), PLAINTEXT);
        let [_, _, iv, _, tag] = split(&compact);
        assert!(iv.is_empty() && tag.is_empty());
    }
}

#[test]
fn accepts_typ_and_cty_header_parameters() {
    let (sk, compact) =
        sealed_with_header(r#"{"alg":"HPKE-0","kid":"k","typ":"JWT","cty":"json"}"#);
    let jwe = CompactJwe::parse(&compact).expect("parse");
    assert_eq!(
        (jwe.header().typ(), jwe.header().cty()),
        (Some("JWT"), Some("json"))
    );
    assert_eq!(jwe.open(&sk, INFO).expect("open"), PLAINTEXT);
}

#[test]
fn rejects_enc_header_parameter() {
    for header in [
        r#"{"alg":"HPKE-0","enc":"A128GCM"}"#,
        r#"{"alg":"HPKE-0","enc":null}"#,
        r#"{"alg":"HPKE-0","enc":""}"#,
    ] {
        assert_eq!(
            parse_err(header),
            Error::ForbiddenHeaderParameter("enc"),
            "{header}"
        );
    }
}

#[test]
fn rejects_ek_header_parameter() {
    let header = r#"{"alg":"HPKE-0","ek":"BKqUaiyoPbH1jnjApcpjGqswg7npGSSXFcFv1nGaL6YY"}"#;
    assert_eq!(parse_err(header), Error::ForbiddenHeaderParameter("ek"));
}

#[test]
fn rejects_psk_id_header_parameter() {
    assert_eq!(
        parse_err(r#"{"alg":"HPKE-0","psk_id":"cHNrLWlk"}"#),
        Error::ForbiddenHeaderParameter("psk_id")
    );
}

#[test]
fn rejects_zip_header_parameter() {
    assert_eq!(
        parse_err(r#"{"alg":"HPKE-0","zip":"DEF"}"#),
        Error::ForbiddenHeaderParameter("zip")
    );
}

#[test]
fn rejects_crit_header_parameter() {
    for header in [
        r#"{"alg":"HPKE-0","crit":["exp"],"exp":1}"#,
        r#"{"alg":"HPKE-0","crit":[]}"#,
        r#"{"alg":"HPKE-0","crit":["kid"],"kid":"k"}"#,
        r#"{"alg":"HPKE-0","crit":"x"}"#,
    ] {
        assert_eq!(parse_err(header), Error::UnsupportedCrit, "{header}");
    }
}

#[test]
fn rejects_unknown_header_parameter() {
    for header in [
        r#"{"alg":"HPKE-0","epk":{"kty":"EC"}}"#,
        r#"{"alg":"HPKE-0","apu":"YQ"}"#,
        r#"{"alg":"HPKE-0","jwk":{}}"#,
        r#"{"alg":"HPKE-0","x-custom":1}"#,
        r#"{"alg":"HPKE-0","Alg":"HPKE-0"}"#,
    ] {
        assert_eq!(parse_err(header), Error::UnknownHeaderParameter, "{header}");
    }
}

#[test]
fn rejects_duplicate_header_parameter() {
    for header in [
        r#"{"alg":"HPKE-0","alg":"HPKE-0"}"#,
        r#"{"alg":"HPKE-0","kid":"a","kid":"b"}"#,
        r#"{"alg":"HPKE-7","alg":"HPKE-0"}"#,
        r#"{"alg":"HPKE-0","enc":"A128GCM","enc":"A128GCM"}"#,
    ] {
        assert_eq!(parse_err(header), Error::HeaderJson, "{header}");
    }
}

#[test]
fn rejects_missing_alg() {
    assert_eq!(parse_err(r#"{"kid":"k"}"#), Error::MissingAlg);
    assert_eq!(parse_err("{}"), Error::MissingAlg);
}

#[test]
fn rejects_unsupported_alg() {
    for alg in [
        "HPKE-0-KE",
        "HPKE-7",
        "HPKE-1",
        "HPKE-3",
        "hpke-0",
        "HPKE-0 ",
        " HPKE-0",
        "HPKE-00",
        "HPKE-0\\u0000",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "RSA-OAEP-256",
        "dir",
        "none",
        "",
    ] {
        let header = format!(r#"{{"alg":"{alg}"}}"#);
        assert_eq!(parse_err(&header), Error::UnsupportedAlg, "{header}");
    }
}

#[test]
fn rejects_non_string_alg_or_kid() {
    for header in [
        r#"{"alg":null}"#,
        r#"{"alg":0}"#,
        r#"{"alg":["HPKE-0"]}"#,
        r#"{"alg":{}}"#,
    ] {
        assert_eq!(
            parse_err(header),
            Error::HeaderParameterType("alg"),
            "{header}"
        );
    }
    for header in [
        r#"{"alg":"HPKE-0","kid":null}"#,
        r#"{"alg":"HPKE-0","kid":7}"#,
    ] {
        assert_eq!(
            parse_err(header),
            Error::HeaderParameterType("kid"),
            "{header}"
        );
    }
    assert_eq!(
        parse_err(r#"{"alg":"HPKE-0","typ":1}"#),
        Error::HeaderParameterType("typ")
    );
    assert_eq!(
        parse_err(r#"{"alg":"HPKE-0","cty":false}"#),
        Error::HeaderParameterType("cty")
    );
}

#[test]
fn rejects_header_that_is_not_a_json_object() {
    for header in [
        "[]",
        r#""HPKE-0""#,
        "null",
        "1",
        "{",
        r#"{"alg":"HPKE-0"}x"#,
        r#"{"alg":"HPKE-0"} {}"#,
        r#"{"alg":"HPKE-0",}"#,
        r#"{'alg':'HPKE-0'}"#,
        "",
        r#"{"alg":"\ud800"}"#,
    ] {
        assert_eq!(parse_err(header), Error::HeaderJson, "{header}");
    }
}

#[test]
fn rejects_header_with_invalid_utf8() {
    let mut header = br#"{"alg":"HPKE-0","kid":"#.to_vec();
    header.extend([b'"', 0xC3, 0x28, b'"', b'}']);
    let compact = with_raw_header_segment(&b64e(&header));
    assert_eq!(CompactJwe::parse(&compact), Err(Error::HeaderJson));
}

#[test]
fn rejects_wrong_segment_count() {
    let compact = jose_vector("HPKE-0")["compact"]
        .as_str()
        .expect("compact")
        .to_owned();
    let [h, ek, iv, ct, tag] = split(&compact);
    let cases = [
        (h.clone(), 1),
        (format!("{h}.{ek}.{ct}"), 3),
        (format!("{h}.{ek}.{iv}.{ct}"), 4),
        (format!("{compact}."), 6),
        (
            format!("{h}.{ek}.{iv}.{ct}.{tag}.{h}.{ek}.{iv}.{ct}.{tag}"),
            10,
        ),
    ];
    for (input, found) in cases {
        assert_eq!(
            CompactJwe::parse(&input),
            Err(Error::SegmentCount { found }),
            "{found}"
        );
    }
    assert_eq!(CompactJwe::parse(""), Err(Error::SegmentCount { found: 1 }));
}

/// A maximum-length input made only of separators is rejected by counting, without splitting
/// it into ~1 Mi segments (review L2).
#[test]
fn rejects_separator_flood_at_maximum_length() {
    let flood = ".".repeat(MAX_COMPACT_JWE_LEN);
    assert_eq!(
        CompactJwe::parse(&flood),
        Err(Error::SegmentCount {
            found: MAX_COMPACT_JWE_LEN + 1
        })
    );
    let [h, ek, iv, ct, tag] = split(jose_vector("HPKE-0")["compact"].as_str().expect("compact"));
    let padded = format!("{h}.{ek}.{iv}.{ct}.{tag}{}", ".".repeat(1000));
    assert_eq!(
        CompactJwe::parse(&padded),
        Err(Error::SegmentCount { found: 1005 })
    );
}

#[test]
fn rejects_json_serialization_with_multiple_recipients() {
    let general = r#"{"protected":"eyJhbGciOiJIUEtFLTAifQ","recipients":[{"encrypted_key":"AA"},{"encrypted_key":"AQ"}],"ciphertext":"AA"}"#;
    assert_eq!(CompactJwe::parse(general), Err(Error::JsonSerialization));
}

#[test]
fn rejects_non_empty_iv_or_tag() {
    let (_, compact) = sealed_with_header(r#"{"alg":"HPKE-0"}"#);
    let [h, ek, _, ct, _] = split(&compact);
    let twelve_zero_bytes = b64e(&[0; 12]);
    let sixteen_zero_bytes = b64e(&[0; 16]);
    assert_eq!(
        CompactJwe::parse(&join([&h, &ek, &twelve_zero_bytes, &ct, ""])),
        Err(Error::NonEmptyIv)
    );
    assert_eq!(
        CompactJwe::parse(&join([&h, &ek, "", &ct, &sixteen_zero_bytes])),
        Err(Error::NonEmptyTag)
    );
    // Even a segment that would decode to zero octets in a lax decoder ("=") is non-empty.
    assert_eq!(
        CompactJwe::parse(&join([&h, &ek, "=", &ct, ""])),
        Err(Error::NonEmptyIv)
    );
}

#[test]
fn rejects_padded_base64url() {
    let (_, compact) = sealed_with_header(r#"{"alg":"HPKE-0"}"#);
    let [h, ek, iv, ct, tag] = split(&compact);
    // Encoded header {"alg":"HPKE-0"} is 22 chars (16 bytes); a padded encoder would add "==".
    let padded_h = format!("{h}==");
    assert_eq!(
        CompactJwe::parse(&join([&padded_h, &ek, &iv, &ct, &tag])),
        Err(Error::Base64(Segment::ProtectedHeader))
    );
    // P-256 encapsulated key is 65 bytes -> 87 chars unpadded, "=" when padded.
    let padded_ek = format!("{ek}=");
    assert_eq!(
        CompactJwe::parse(&join([&h, &padded_ek, &iv, &ct, &tag])),
        Err(Error::Base64(Segment::EncryptedKey))
    );
    for pad in ["=", "==", "==="] {
        let padded_ct = format!("{ct}{pad}");
        assert_eq!(
            CompactJwe::parse(&join([&h, &ek, &iv, &padded_ct, &tag])),
            Err(Error::Base64(Segment::Ciphertext)),
            "{pad}"
        );
    }
}

#[test]
fn rejects_non_canonical_trailing_bits() {
    let (_, compact) = sealed_with_header(r#"{"alg":"HPKE-0"}"#);
    let [h, ek, iv, ct, tag] = split(&compact);
    // 65 bytes leave 2 spare bits in the last of 87 chars; canonical encoders set them to zero.
    let mut last = ek.as_bytes()[ek.len() - 1];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let idx = alphabet.iter().position(|&c| c == last).expect("alphabet");
    assert_eq!(idx & 0b11, 0, "canonical encoder left trailing bits clear");
    last = alphabet[idx | 0b01];
    let bad_ek = format!("{}{}", &ek[..ek.len() - 1], last as char);
    assert_eq!(
        CompactJwe::parse(&join([&h, &bad_ek, &iv, &ct, &tag])),
        Err(Error::Base64(Segment::EncryptedKey))
    );
    // A single leftover char (length % 4 == 1) can never be canonical.
    assert_eq!(
        CompactJwe::parse(&join([&h, &ek, &iv, "AAAAA", &tag])),
        Err(Error::Base64(Segment::Ciphertext))
    );
    // Protected header with non-zero trailing bits: "eyJhbGciOiJIUEtFLTAifQ" ends in 'Q'
    // (index 16, low 4 bits clear); 'R' (17) decodes to the same bytes in a lax decoder.
    assert_eq!(h, "eyJhbGciOiJIUEtFLTAifQ");
    assert_eq!(
        CompactJwe::parse(&join(["eyJhbGciOiJIUEtFLTAifR", &ek, &iv, &ct, &tag])),
        Err(Error::Base64(Segment::ProtectedHeader))
    );
}

#[test]
fn rejects_standard_alphabet_whitespace_and_line_breaks() {
    let (_, compact) = sealed_with_header(r#"{"alg":"HPKE-0","kid":"??>>"}"#);
    let [h, ek, iv, ct, tag] = split(&compact);
    // The kid was chosen so the encoded header contains '_' / '-'; swap in the standard
    // alphabet's '/' / '+'.
    assert!(h.contains('_') || h.contains('-'), "{h}");
    let std_h = h.replace('_', "/").replace('-', "+");
    assert_eq!(
        CompactJwe::parse(&join([&std_h, &ek, &iv, &ct, &tag])),
        Err(Error::Base64(Segment::ProtectedHeader))
    );
    for ws in [" ", "\n", "\r\n", "\t"] {
        let mid = ct.len() / 2;
        let spaced_ct = format!("{}{ws}{}", &ct[..mid], &ct[mid..]);
        assert_eq!(
            CompactJwe::parse(&join([&h, &ek, &iv, &spaced_ct, &tag])),
            Err(Error::Base64(Segment::Ciphertext)),
            "{ws:?}"
        );
    }
    assert_eq!(
        CompactJwe::parse(&format!("{compact}\n")),
        Err(Error::NonEmptyTag),
        "trailing newline lands in the tag segment"
    );
    assert_eq!(
        CompactJwe::parse(&format!(" {compact}")),
        Err(Error::Base64(Segment::ProtectedHeader))
    );
}

#[test]
fn rejects_oversize_input() {
    let too_long = "A".repeat(MAX_COMPACT_JWE_LEN + 1);
    assert_eq!(
        CompactJwe::parse(&too_long),
        Err(Error::TooLong {
            max: MAX_COMPACT_JWE_LEN
        })
    );
    // Exactly at the limit, the length check passes and a later check rejects it.
    let at_limit = "A".repeat(MAX_COMPACT_JWE_LEN);
    assert_eq!(
        CompactJwe::parse(&at_limit),
        Err(Error::SegmentCount { found: 1 })
    );
    // Multi-byte input is measured in bytes, not chars.
    let wide = "\u{00e9}".repeat(MAX_COMPACT_JWE_LEN / 2 + 1);
    assert_eq!(
        CompactJwe::parse(&wide),
        Err(Error::TooLong {
            max: MAX_COMPACT_JWE_LEN
        })
    );
}

#[test]
fn rejects_invalid_encapsulated_key() {
    let (_, compact) = sealed_with_header(r#"{"alg":"HPKE-0"}"#);
    let [h, ek, iv, ct, tag] = split(&compact);
    let ek_bytes = common::b64(&ek);
    let mut off_curve = ek_bytes.clone();
    off_curve[64] ^= 1; // flip a bit of y: no longer on P-256
    let mut compressed = vec![0x02 | (ek_bytes[64] & 1)];
    compressed.extend(&ek_bytes[1..33]);
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        ek_bytes[..64].to_vec(),
        [ek_bytes.as_slice(), &[0]].concat(),
        off_curve,
        compressed,
        [vec![0x04], vec![0; 64]].concat(),
        vec![0x00],
    ];
    for bad in cases {
        let bad_ek = b64e(&bad);
        assert_eq!(
            CompactJwe::parse(&join([&h, &bad_ek, &iv, &ct, &tag])),
            Err(Error::EncapsulatedKey),
            "{} bytes",
            bad.len()
        );
    }
}

#[test]
fn decryption_errors_are_indistinguishable() {
    let (sk, pk) = fresh_key();
    let (other_sk, _) = fresh_key();
    let compact = seal_compact(&pk, Some("k"), INFO, PLAINTEXT, &mut rng()).expect("seal");
    let [h, ek, iv, ct, tag] = split(&compact);
    let mut ct_bytes = common::b64(&ct);
    ct_bytes[0] ^= 1;
    let bad_ct = b64e(&ct_bytes);
    let other_h = b64e(br#"{"alg":"HPKE-0","kid":"j"}"#);

    let failures = [
        open_compact(&compact, &other_sk, INFO),
        open_compact(&compact, &sk, b"other info"),
        open_compact(&join([&h, &ek, &iv, &bad_ct, &tag]), &sk, INFO),
        open_compact(&join([&other_h, &ek, &iv, &ct, &tag]), &sk, INFO),
    ];
    for f in failures {
        assert_eq!(f, Err(Error::Decryption));
    }
    // Truncated ciphertext shorter than the AES-GCM tag.
    let short_ct = b64e(&ct_bytes[..8]);
    assert_eq!(
        open_compact(&join([&h, &ek, &iv, &short_ct, &tag]), &sk, INFO),
        Err(Error::Decryption)
    );
}

#[test]
fn private_key_debug_does_not_print_key_bytes() {
    let v = jose_vector("HPKE-0");
    let d = v["jwk"]["d"].as_str().expect("d");
    let sk = common::jwk_private_key(&v["jwk"]);
    let debug = format!("{sk:?} {sk:#?}");
    let d_bytes = common::b64(d);
    let hex_lower: String = d_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex_lower.to_uppercase();
    let decimal_first = d_bytes[0].to_string();
    assert!(!debug.contains(d) && !debug.contains(&hex_lower) && !debug.contains(&hex_upper));
    assert!(!debug.contains(&format!("[{decimal_first},")), "{debug}");
    assert!(debug.contains("RecipientPrivateKey"), "{debug}");
}

#[test]
fn errors_do_not_echo_plaintext_or_header_values() {
    let (sk, pk) = fresh_key();
    let compact = seal_compact(&pk, Some("k"), INFO, PLAINTEXT, &mut rng()).expect("seal");
    let err = open_compact(&compact, &sk, b"wrong").expect_err("wrong info");
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains("synthetic") && !rendered.contains("vp_token"),
        "{rendered}"
    );

    let marker = "MARKER-VALUE-1234";
    let header = format!(r#"{{"alg":"{marker}","{marker}":1}}"#);
    let err = parse_err(&header);
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains(marker), "{rendered}");
}
