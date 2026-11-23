//! Route token generation, parsing and redaction (IMP-007 unique-uri).

use std::collections::HashSet;

use session_core::{ROUTE_TOKEN_BYTES, RouteToken, RouteTokenError};

/// Tokens generated for the uniqueness check; any collision at 128 bits would mean a broken RNG.
const SAMPLE: usize = 4096;
/// Unpadded base64url length of `ROUTE_TOKEN_BYTES` bytes: ceil(16 * 4 / 3) = 22.
const ENCODED_LEN: usize = 22;

#[test]
fn route_tokens_are_distinct_and_round_trip() {
    let mut seen = HashSet::new();
    for _ in 0..SAMPLE {
        let token = RouteToken::generate().expect("OS CSPRNG available");
        let segment = token.to_url_segment();
        assert_eq!(segment.len(), ENCODED_LEN);
        assert!(
            segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "URL-safe alphabet, no padding: {segment}"
        );
        assert_eq!(RouteToken::parse(&segment), Ok(token.clone()));
        assert!(seen.insert(segment), "duplicate route token");
    }
    const {
        assert!(
            ROUTE_TOKEN_BYTES * 8 >= 128,
            "task floor: at least 128 bits"
        )
    };
}

/// RFC 4648 §5 base64url alphabet, in value order.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/// 128 bits in 22 six-bit characters leave the low 4 bits of the last character unused; a
/// canonical encoding has them zero.
const UNUSED_TRAILING_BITS: u8 = 0b1111;

fn same_length_with(valid: &str, at: usize, c: char) -> String {
    let mut s = valid.to_owned();
    s.replace_range(at..=at, c.encode_utf8(&mut [0; 4]));
    s
}

fn with_trailing_bits(valid: &str) -> String {
    let last = valid.as_bytes()[ENCODED_LEN - 1];
    let value = BASE64URL
        .iter()
        .position(|&b| b == last)
        .expect("alphabet char");
    let value = u8::try_from(value).expect("six bits");
    assert_eq!(
        value & UNUSED_TRAILING_BITS,
        0,
        "generated token is canonical"
    );
    let tampered = char::from(BASE64URL[usize::from(value | 1)]);
    same_length_with(valid, ENCODED_LEN - 1, tampered)
}

#[test]
fn route_token_parse_rejects_malformed_input() {
    let valid = RouteToken::generate().expect("rng").to_url_segment();
    let cases = [
        String::new(),
        valid[..ENCODED_LEN - 1].to_owned(),
        format!("{valid}A"),
        format!("{valid}=="),
        valid.replacen(|c: char| c.is_ascii_alphanumeric(), "+", 1),
        valid.replacen(|c: char| c.is_ascii_alphanumeric(), "/", 1),
        valid.replacen(|c: char| c.is_ascii_alphanumeric(), "é", 1),
        format!(" {}", &valid[1..]),
        // Same length, one character outside the base64url alphabet.
        same_length_with(&valid, ENCODED_LEN / 2, '.'),
        same_length_with(&valid, ENCODED_LEN / 2, '='),
        same_length_with(&valid, ENCODED_LEN / 2, '*'),
        // Same length, valid alphabet, but the unused low bits of the last character set.
        with_trailing_bits(&valid),
    ];
    for case in cases {
        assert_eq!(
            RouteToken::parse(&case),
            Err(RouteTokenError::Malformed),
            "{case:?}"
        );
    }
}

#[test]
fn route_token_debug_does_not_reveal_the_token() {
    let token = RouteToken::generate().expect("rng");
    let segment = token.to_url_segment();
    let debug = format!("{token:?}");
    assert!(!debug.contains(&segment), "{debug}");
    // Only a short prefix may appear, for correlating log lines.
    assert!(!debug.contains(&segment[..ENCODED_LEN / 2]), "{debug}");
}
