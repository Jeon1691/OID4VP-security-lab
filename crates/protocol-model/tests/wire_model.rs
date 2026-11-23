//! Behavioural tests for the public wire model.

use protocol_model::*;

#[test]
fn wire_strings_round_trip_byte_exact() {
    let uris = [
        "https://Verifier.Example.COM/cb/%7Esess%2F1/?q=a%20b&Z=1#",
        "https://v.example/path/",
        "HTTPS://V.example:443/x",
    ];
    for u in uris {
        let r = ResponseUriWire::new(u).unwrap();
        assert_eq!(r.as_str(), u);
        assert_eq!(r.as_bytes(), u.as_bytes());
    }
    let c = ClientIdWire::new("x509_san_dns:Verifier.Example.COM").unwrap();
    assert_eq!(c.as_str(), "x509_san_dns:Verifier.Example.COM");
    let o = OriginWire::new("https://Example.COM:8443").unwrap();
    assert_eq!(o.as_str(), "https://Example.COM:8443");
    let n = NonceWire::new("aB-._~09").unwrap();
    assert_eq!(n.as_str(), "aB-._~09");
}

#[test]
fn non_ascii_values_are_rejected() {
    let bad = "https://exämple.test/cb";
    assert_eq!(
        ClientIdWire::new(bad),
        Err(ModelError::NotAscii { field: "client_id" })
    );
    assert_eq!(
        ResponseUriWire::new(bad),
        Err(ModelError::NotAscii {
            field: "response_uri"
        })
    );
    assert_eq!(
        OriginWire::new(bad),
        Err(ModelError::NotAscii { field: "origin" })
    );
    assert_eq!(
        NonceWire::new("nönce"),
        Err(ModelError::NotAscii { field: "nonce" })
    );
}

#[test]
fn delimiter_lookalikes_are_rejected() {
    // U+00FF encodes as 0xC3 0xBF in UTF-8; it is non-ASCII and therefore refused.
    assert!(ClientIdWire::new("a\u{ff}b").is_err());
    assert!(NonceWire::new("a\u{ff}").is_err());
    assert!(ResponseUriWire::new("https://v.example/\u{ff}").is_err());
    assert!(OriginWire::new("https://\u{ff}.example").is_err());
}

#[test]
fn accepted_session_info_values_are_all_below_0x80() {
    // Every ASCII char, plus samples across the rest of Unicode (incl. U+00FF, bidi, zero-width).
    let beyond_ascii = (0x80u32..=0x10_FFFF)
        .step_by(0x101)
        .chain([0xFF, 0x200B, 0x202E]);
    let chars = (0u32..0x80).chain(beyond_ascii).filter_map(char::from_u32);
    for c in chars {
        let v = format!("a{c}");
        let accepted = [
            ClientIdWire::new(v.clone()).map(|x| x.as_bytes().to_vec()),
            NonceWire::new(v.clone()).map(|x| x.as_bytes().to_vec()),
            ResponseUriWire::new(v.clone()).map(|x| x.as_bytes().to_vec()),
            OriginWire::new(v.clone()).map(|x| x.as_bytes().to_vec()),
            SessionId::new(v.clone()).map(|x| x.as_bytes().to_vec()),
            KeyId::new(v).map(|x| x.as_bytes().to_vec()),
        ];
        for bytes in accepted.into_iter().flatten() {
            assert!(
                bytes.iter().all(|b| *b < 0x80),
                "accepted U+{:04X}",
                c as u32
            );
            assert!(!bytes.contains(&0xFF));
        }
    }
}

#[test]
fn only_client_id_allows_space() {
    assert!(ClientIdWire::new("a b").is_ok());
    assert!(ResponseUriWire::new("https://v.example/a b").is_err());
    assert!(OriginWire::new("https://v.example b").is_err());
    assert!(NonceWire::new("a b").is_err());
    assert!(SessionId::new("a b").is_err());
    assert!(KeyId::new("a b").is_err());
}

#[test]
fn bidi_and_zero_width_in_identifiers_are_rejected() {
    for bad in ["a\u{202E}b", "a\u{200B}b"] {
        assert!(SessionId::new(bad).is_err());
        assert!(KeyId::new(bad).is_err());
    }
}

#[test]
fn empty_values_are_rejected() {
    assert_eq!(
        ClientIdWire::new(""),
        Err(ModelError::Empty { field: "client_id" })
    );
    assert_eq!(
        NonceWire::new(""),
        Err(ModelError::Empty { field: "nonce" })
    );
    assert_eq!(
        ResponseUriWire::new(""),
        Err(ModelError::Empty {
            field: "response_uri"
        })
    );
    assert_eq!(
        OriginWire::new(""),
        Err(ModelError::Empty { field: "origin" })
    );
    assert_eq!(
        SessionId::new(""),
        Err(ModelError::Empty {
            field: "session_id"
        })
    );
    assert_eq!(KeyId::new(""), Err(ModelError::Empty { field: "key_id" }));
}

#[test]
fn control_characters_and_spaces_are_rejected() {
    for bad in ["a\nb", "a\0b", "a\x7fb", "a\tb"] {
        assert!(matches!(
            ClientIdWire::new(bad),
            Err(ModelError::ControlCharacter { .. })
        ));
        assert!(ResponseUriWire::new(bad).is_err());
        assert!(OriginWire::new(bad).is_err());
    }
    assert!(SessionId::new("a\nb").is_err());
    assert!(KeyId::new("a\0b").is_err());
}

#[test]
fn nonce_outside_url_safe_set_is_rejected() {
    for bad in ["a/b", "a+b", "a=b", "a%20b", "a&b", "a b"] {
        assert!(NonceWire::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn origin_prefix_is_rejected() {
    assert_eq!(
        OriginWire::new("origin:https://example.com"),
        Err(ModelError::OriginPrefix)
    );
    assert!(OriginWire::new("https://origin.example").is_ok());
}

#[test]
fn unknown_response_mode_is_rejected() {
    for bad in [
        "",
        "direct_post",
        "DIRECT_POST.JWT",
        "dc_api",
        "query.jwt",
        " dc_api.jwt",
    ] {
        assert_eq!(
            bad.parse::<EncryptedResponseMode>(),
            Err(ModelError::UnknownResponseMode),
            "{bad}"
        );
    }
    assert_eq!(
        "direct_post.jwt".parse(),
        Ok(EncryptedResponseMode::DirectPostJwt)
    );
    assert_eq!("dc_api.jwt".parse(), Ok(EncryptedResponseMode::DcApiJwt));
    assert_eq!(
        EncryptedResponseMode::DirectPostJwt.as_str(),
        "direct_post.jwt"
    );
    assert_eq!(EncryptedResponseMode::DcApiJwt.to_string(), "dc_api.jwt");
}

#[test]
fn binding_variants_report_their_mode_and_nonce() {
    let nonce = NonceWire::new("n1").unwrap();
    let dp = RequestBinding::DirectPostJwt {
        client_id: ClientIdWire::new("redirect_uri:https://v.example/cb").unwrap(),
        nonce: nonce.clone(),
        response_uri: ResponseUriWire::new("https://v.example/cb/").unwrap(),
    };
    assert_eq!(dp.mode(), EncryptedResponseMode::DirectPostJwt);
    assert_eq!(dp.nonce(), &nonce);

    let dc = RequestBinding::DcApiJwt {
        origin: OriginWire::new("https://origin.example").unwrap(),
        nonce: nonce.clone(),
    };
    assert_eq!(dc.mode(), EncryptedResponseMode::DcApiJwt);
    assert_eq!(dc.nonce(), &nonce);
}
