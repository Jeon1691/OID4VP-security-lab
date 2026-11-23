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
