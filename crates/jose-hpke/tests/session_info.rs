//! IMP-006: OpenID4VP 1.1 §8.3.1 Session Info encodings and their binding into HPKE `info`.
//!
//! The expected byte strings are the non-normative examples printed in §8.3.1 of the
//! OpenID4VP 1.1 editor's draft (see fixtures/MANIFEST.md for the retrieved revision).

mod common;

use common::{fresh_key, hex, rng};
use jose_hpke::test_support::seal_compact;
use jose_hpke::{Error, RecipientPrivateKey, SessionInfo, open_compact};

const EXAMPLE_CLIENT_ID: &str = "x509_san_dns:example.com";
const EXAMPLE_NONCE: &str = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
const EXAMPLE_RESPONSE_URI: &str = "https://example.com/response";
const EXAMPLE_ORIGIN: &str = "https://example.com";

/// OpenID4VP 1.1 §8.3.1, direct_post.jwt example, hexadecimal representation.
const DIRECT_POST_EXAMPLE_HEX: &str = "4f70656e49443456502d7369ff783530395f73616e5f646e733a6578616d706c652e636f6dff6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c48684777717441ff68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365";
/// OpenID4VP 1.1 §8.3.1, dc_api.jwt example, hexadecimal representation.
const DC_API_EXAMPLE_HEX: &str = "4f70656e494434565044434150492d7369ff68747470733a2f2f6578616d706c652e636f6dff6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c48684777717441";

const PLAINTEXT: &[u8] = br#"{"vp_token":{"cred":["synthetic"]}}"#;

fn direct_post(client_id: &str, nonce: &str, response_uri: &str) -> SessionInfo {
    SessionInfo::direct_post_jwt(client_id, nonce, response_uri).expect("direct_post.jwt info")
}

fn dc_api(origin: &str, nonce: &str) -> SessionInfo {
    SessionInfo::dc_api_jwt(origin, nonce).expect("dc_api.jwt info")
}

fn sealed_for(info: &SessionInfo) -> (RecipientPrivateKey, String) {
    let (sk, pk) = fresh_key();
    let compact =
        seal_compact(&pk, Some("k"), info.as_bytes(), PLAINTEXT, &mut rng()).expect("seal");
    (sk, compact)
}

#[test]
fn direct_post_session_info_matches_openid4vp_example() {
    let si = direct_post(EXAMPLE_CLIENT_ID, EXAMPLE_NONCE, EXAMPLE_RESPONSE_URI);
    assert_eq!(si.as_bytes(), hex(DIRECT_POST_EXAMPLE_HEX).as_slice());
    let mut expected = b"OpenID4VP-si\xff".to_vec();
    expected.extend(b"x509_san_dns:example.com\xff");
    expected.extend(b"exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA\xff");
    expected.extend(b"https://example.com/response");
    assert_eq!(si.as_ref(), expected.as_slice());
}

#[test]
fn dc_api_session_info_matches_openid4vp_example() {
    let si = dc_api(EXAMPLE_ORIGIN, EXAMPLE_NONCE);
    assert_eq!(si.as_bytes(), hex(DC_API_EXAMPLE_HEX).as_slice());
    let mut expected = b"OpenID4VPDCAPI-si\xffhttps://example.com\xff".to_vec();
    expected.extend(b"exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA");
    assert_eq!(si.as_ref(), expected.as_slice());
}

#[test]
fn session_info_encodes_empty_fields_without_dropping_separators() {
    assert_eq!(
        direct_post("", "", "").as_bytes(),
        b"OpenID4VP-si\xff\xff\xff"
    );
    assert_eq!(dc_api("", "").as_bytes(), b"OpenID4VPDCAPI-si\xff\xff");
}

#[test]
fn session_info_rejects_non_ascii_fields() {
    let bad = "caf\u{00e9}";
    assert_eq!(
        SessionInfo::direct_post_jwt(bad, "n", "https://v"),
        Err(Error::SessionInfoNotAscii { field: "client_id" })
    );
    assert_eq!(
        SessionInfo::direct_post_jwt("c", bad, "https://v"),
        Err(Error::SessionInfoNotAscii { field: "nonce" })
    );
    assert_eq!(
        SessionInfo::direct_post_jwt("c", "n", "https://v/\u{2603}"),
        Err(Error::SessionInfoNotAscii {
            field: "response_uri"
        })
    );
    assert_eq!(
        SessionInfo::dc_api_jwt("https://b\u{00fc}cher.example", "n"),
        Err(Error::SessionInfoNotAscii { field: "origin" })
    );
    assert_eq!(
        SessionInfo::dc_api_jwt("o", bad),
        Err(Error::SessionInfoNotAscii { field: "nonce" })
    );
}

#[test]
fn dc_api_session_info_rejects_origin_prefix() {
    assert_eq!(
        SessionInfo::dc_api_jwt("origin:https://example.com", EXAMPLE_NONCE),
        Err(Error::OriginPrefixed)
    );
}

#[test]
fn direct_post_bound_jwe_opens_only_with_identical_session() {
    let si = direct_post(EXAMPLE_CLIENT_ID, EXAMPLE_NONCE, EXAMPLE_RESPONSE_URI);
    let (sk, compact) = sealed_for(&si);
    assert_eq!(
        open_compact(&compact, &sk, si.as_bytes()).expect("open"),
        PLAINTEXT
    );
}

#[test]
fn direct_post_bound_jwe_fails_with_any_single_field_changed() {
    let si = direct_post(EXAMPLE_CLIENT_ID, EXAMPLE_NONCE, EXAMPLE_RESPONSE_URI);
    let (sk, compact) = sealed_for(&si);
    let variants = [
        // client_id: other verifier, other prefix, prefix dropped, case, trailing char
        direct_post(
            "x509_san_dns:attacker.example",
            EXAMPLE_NONCE,
            EXAMPLE_RESPONSE_URI,
        ),
        direct_post(
            "redirect_uri:https://example.com/response",
            EXAMPLE_NONCE,
            EXAMPLE_RESPONSE_URI,
        ),
        direct_post("example.com", EXAMPLE_NONCE, EXAMPLE_RESPONSE_URI),
        direct_post(
            "X509_san_dns:example.com",
            EXAMPLE_NONCE,
            EXAMPLE_RESPONSE_URI,
        ),
        direct_post(
            "x509_san_dns:example.com ",
            EXAMPLE_NONCE,
            EXAMPLE_RESPONSE_URI,
        ),
        // nonce: another session's nonce, one char changed, truncated, empty
        direct_post(
            EXAMPLE_CLIENT_ID,
            "fresh-nonce-of-another-session",
            EXAMPLE_RESPONSE_URI,
        ),
        direct_post(
            EXAMPLE_CLIENT_ID,
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtB",
            EXAMPLE_RESPONSE_URI,
        ),
        direct_post(EXAMPLE_CLIENT_ID, &EXAMPLE_NONCE[1..], EXAMPLE_RESPONSE_URI),
        direct_post(EXAMPLE_CLIENT_ID, "", EXAMPLE_RESPONSE_URI),
        // response_uri: per-session path, trailing slash, scheme, query
        direct_post(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_NONCE,
            "https://example.com/response/2",
        ),
        direct_post(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_NONCE,
            "https://example.com/response/",
        ),
        direct_post(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_NONCE,
            "http://example.com/response",
        ),
        direct_post(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_NONCE,
            "https://example.com/response?s=1",
        ),
        // field boundaries shifted: same concatenated text, different split
        direct_post(
            "x509_san_dns:example.co",
            "mexc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            EXAMPLE_RESPONSE_URI,
        ),
    ];
    for variant in &variants {
        assert_ne!(variant, &si);
        assert_eq!(
            open_compact(&compact, &sk, variant.as_bytes()),
            Err(Error::Decryption),
            "{:?}",
            String::from_utf8_lossy(variant.as_bytes())
        );
    }
    assert_eq!(open_compact(&compact, &sk, b""), Err(Error::Decryption));
}

#[test]
fn dc_api_bound_jwe_fails_with_any_single_field_changed() {
    let si = dc_api(EXAMPLE_ORIGIN, EXAMPLE_NONCE);
    let (sk, compact) = sealed_for(&si);
    assert_eq!(
        open_compact(&compact, &sk, si.as_bytes()).expect("open"),
        PLAINTEXT
    );
    let variants = [
        dc_api("https://attacker.example", EXAMPLE_NONCE),
        dc_api("https://example.com/", EXAMPLE_NONCE),
        dc_api("https://example.com:443", EXAMPLE_NONCE),
        dc_api("http://example.com", EXAMPLE_NONCE),
        dc_api(EXAMPLE_ORIGIN, "fresh-nonce-of-another-session"),
        dc_api(EXAMPLE_ORIGIN, &EXAMPLE_NONCE[1..]),
        dc_api(EXAMPLE_ORIGIN, ""),
    ];
    for variant in &variants {
        assert_eq!(
            open_compact(&compact, &sk, variant.as_bytes()),
            Err(Error::Decryption),
            "{:?}",
            String::from_utf8_lossy(variant.as_bytes())
        );
    }
}

#[test]
fn direct_post_and_dc_api_session_info_never_cross_open() {
    // Same nonce, and the dc_api origin equal to the direct_post client_id / response_uri, so
    // only the label and field layout differ.
    let pairs = [
        (
            direct_post(EXAMPLE_ORIGIN, EXAMPLE_NONCE, EXAMPLE_RESPONSE_URI),
            dc_api(EXAMPLE_ORIGIN, EXAMPLE_NONCE),
        ),
        (
            direct_post(EXAMPLE_CLIENT_ID, EXAMPLE_NONCE, EXAMPLE_ORIGIN),
            dc_api(EXAMPLE_ORIGIN, EXAMPLE_NONCE),
        ),
        (direct_post("", "", ""), dc_api("", "")),
    ];
    for (dp, dc) in &pairs {
        assert_ne!(dp.as_bytes(), dc.as_bytes());
        let (sk_dp, jwe_dp) = sealed_for(dp);
        let (sk_dc, jwe_dc) = sealed_for(dc);
        assert_eq!(
            open_compact(&jwe_dp, &sk_dp, dc.as_bytes()),
            Err(Error::Decryption)
        );
        assert_eq!(
            open_compact(&jwe_dc, &sk_dc, dp.as_bytes()),
            Err(Error::Decryption)
        );
        assert_eq!(
            open_compact(&jwe_dp, &sk_dp, dp.as_bytes()).expect("dp"),
            PLAINTEXT
        );
        assert_eq!(
            open_compact(&jwe_dc, &sk_dc, dc.as_bytes()).expect("dc"),
            PLAINTEXT
        );
    }
}
