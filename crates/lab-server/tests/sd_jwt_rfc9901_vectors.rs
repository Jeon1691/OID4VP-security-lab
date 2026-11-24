//! Official RFC 9901 (SD-JWT, November 2025) examples as fixtures for the lab Verifier's
//! SD-JWT+KB code: an independent encoder (the RFC authors') against the lab's decoder.
//!
//! `fixtures/rfc9901_examples.json` carries the provenance (URL, SHA-256 of the RFC text,
//! retrieval date); only line breaks inside the printed base64url strings were removed. The
//! examples are verifiable: Appendix A.5 prints the issuer public key, and each issuer-signed
//! JWT carries the holder key in `cnf.jwk`.

use lab_server::{
    CredentialQuery, KB_JWT_MAX_AGE_SECS, KeyBindingContext, TrustedIssuerKey, ValidationError,
    disclosure_digest, verify_sd_jwt_kb, verify_sd_jwt_vc,
};
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("fixtures/rfc9901_examples.json");
/// The lab's own synthetic issuer, which did not sign the RFC examples.
const LAB_ISSUER_PUBLIC_JWK: &str = include_str!("fixtures/lab_issuer.pub.jwk");
/// SHA-256 of `https://www.rfc-editor.org/rfc/rfc9901.txt` as retrieved for the fixture.
const RFC9901_TXT_SHA256: &str = "fd4cb79184162fa7ef95f4f63abab8ee6d03c9a04c19b8f83758946464b284eb";
/// RFC 9901 §5.1 lists ten Disclosures (eight claims, two array entries).
const SECTION_5_1_DISCLOSURES: usize = 10;

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture JSON")
}

fn rfc_issuer(fixture: &Value) -> TrustedIssuerKey {
    TrustedIssuerKey::from_jwk(&fixture["appendix_a_5_issuer_key"].to_string())
        .expect("RFC 9901 A.5 key")
}

fn str_of<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().expect("string member")
}

fn context(example: &Value) -> KeyBindingContext<'_> {
    KeyBindingContext {
        audience: str_of(example, "kb_aud"),
        nonce: str_of(example, "kb_nonce"),
        now: example["kb_iat"].as_u64().expect("kb_iat"),
    }
}

#[test]
fn rfc9901_fixture_provenance_is_pinned() {
    let fixture = fixture();
    let provenance = &fixture["provenance"];
    assert_eq!(
        provenance["url"],
        "https://www.rfc-editor.org/rfc/rfc9901.txt"
    );
    assert_eq!(provenance["sha256_of_document"], RFC9901_TXT_SHA256);
    assert_eq!(provenance["retrieved"], "2026-11-24");
}

/// RFC 9901 §4.2.3: the digest is base64url(SHA-256(US-ASCII of the encoded Disclosure)), for
/// the §4.2.3 example and every §5.1 Disclosure with its printed hash.
#[test]
fn rfc9901_disclosure_digests_match_the_printed_hashes() {
    let fixture = fixture();
    let example = &fixture["section_4_2_3"];
    assert_eq!(
        disclosure_digest(str_of(example, "disclosure")),
        str_of(example, "sha256")
    );
    let listed = fixture["section_5_1_disclosures"]
        .as_array()
        .expect("disclosure list");
    assert_eq!(listed.len(), SECTION_5_1_DISCLOSURES);
    for entry in listed {
        assert_eq!(
            disclosure_digest(str_of(entry, "disclosure")),
            str_of(entry, "sha256"),
            "{entry}"
        );
    }
}

/// RFC 9901 §5.2: the SD-JWT+KB verifies (A.5 issuer key, `cnf` holder key, `nonce`, `aud`,
/// `sd_hash`) and yields exactly the printed Processed SD-JWT Payload, including the array
/// element Disclosure (`nationalities`) and the dropped undisclosed digests.
#[test]
fn rfc9901_section_5_2_presentation_verifies_and_yields_the_printed_payload() {
    let fixture = fixture();
    let example = &fixture["section_5_2"];
    let processed = verify_sd_jwt_kb(
        str_of(example, "presentation"),
        &rfc_issuer(&fixture),
        str_of(example, "issuer_typ"),
        &context(example),
    )
    .expect("RFC 9901 §5.2 verifies");
    assert_eq!(
        Value::Object(processed.payload),
        json!({
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "user_42",
            "nationalities": ["US"],
            "cnf": { "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
            }},
            "family_name": "Doe",
            "address": {
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US",
            },
            "given_name": "John",
        })
    );
    let mut names = processed.disclosed_claim_names;
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "/address",
            "/family_name",
            "/given_name",
            "/nationalities/0"
        ]
    );
}

/// RFC 9901 Appendix A.3: an SD-JWT VC (`typ` `dc+sd-jwt`, `vct`, recursive Disclosure of
/// `age_equal_or_over`) passes the lab's SD-JWT VC / DCQL profile with exactly the claims
/// the presentation discloses.
#[test]
fn rfc9901_appendix_a3_sd_jwt_vc_passes_the_lab_profile() {
    let fixture = fixture();
    let example = &fixture["appendix_a_3"];
    let query = CredentialQuery {
        vct: str_of(example, "vct"),
        claims: &["nationalities", "age_equal_or_over"],
    };
    let verified = verify_sd_jwt_vc(
        str_of(example, "presentation"),
        &rfc_issuer(&fixture),
        &query,
        &context(example),
    )
    .expect("RFC 9901 A.3 verifies");
    assert_eq!(verified.vct, "urn:eudi:pid:de:1");
    assert_eq!(
        verified.claims,
        [
            ("nationalities".to_owned(), json!(["DE"])),
            ("age_equal_or_over".to_owned(), json!({ "18": true })),
        ]
    );
    assert_eq!(
        verified.disclosed_claim_names,
        [
            "/age_equal_or_over",
            "/age_equal_or_over/18",
            "/nationalities"
        ]
    );
}

/// The same official examples fail closed when the Verifier context differs: another
/// audience, nonce, clock, issuer key or profile.
#[test]
fn rfc9901_examples_fail_closed_on_wrong_binding_issuer_or_profile() {
    let fixture = fixture();
    let example = &fixture["section_5_2"];
    let presentation = str_of(example, "presentation");
    let typ = str_of(example, "issuer_typ");
    let issuer = rfc_issuer(&fixture);
    let base = context(example);
    let check = |issuer: &TrustedIssuerKey, kb: &KeyBindingContext<'_>| {
        verify_sd_jwt_kb(presentation, issuer, typ, kb).map(|_| ())
    };
    let cases = [
        (
            KeyBindingContext {
                audience: "https://other-verifier.example.org",
                ..base
            },
            ValidationError::KbAudienceMismatch,
        ),
        (
            KeyBindingContext {
                nonce: "0987654321",
                ..base
            },
            ValidationError::KbNonceMismatch,
        ),
        (
            KeyBindingContext {
                now: base.now + KB_JWT_MAX_AGE_SECS + 1,
                ..base
            },
            ValidationError::KbIatOutOfWindow,
        ),
    ];
    for (kb, want) in cases {
        assert_eq!(check(&issuer, &kb), Err(want));
    }
    let lab_issuer = TrustedIssuerKey::from_jwk(LAB_ISSUER_PUBLIC_JWK).expect("lab issuer key");
    assert_eq!(
        check(&lab_issuer, &base),
        Err(ValidationError::IssuerSignature)
    );
    // §5.2 is typed `example+sd-jwt`: not an SD-JWT VC.
    let query = CredentialQuery {
        vct: "urn:eudi:pid:de:1",
        claims: &["family_name"],
    };
    assert_eq!(
        verify_sd_jwt_vc(presentation, &issuer, &query, &base).map(|_| ()),
        Err(ValidationError::IssuerTyp)
    );
    // A.3 asked for a claim it does not disclose, or with another vct.
    let a3 = &fixture["appendix_a_3"];
    let verify_a3 = |query: &CredentialQuery<'_>| {
        verify_sd_jwt_vc(str_of(a3, "presentation"), &issuer, query, &context(a3)).map(|_| ())
    };
    assert_eq!(
        verify_a3(&CredentialQuery {
            vct: "urn:eudi:pid:de:1",
            claims: &["nationalities", "age_equal_or_over", "given_name"],
        }),
        Err(ValidationError::RequestedClaimMissing)
    );
    assert_eq!(
        verify_a3(&CredentialQuery {
            vct: "urn:eudi:pid:de:1",
            claims: &["nationalities"],
        }),
        Err(ValidationError::UnrequestedClaimDisclosed)
    );
    assert_eq!(
        verify_a3(&CredentialQuery {
            vct: "urn:eudi:pid:de:2",
            claims: &["nationalities", "age_equal_or_over"],
        }),
        Err(ValidationError::VctMismatch)
    );
}

/// Edits of the official §5.2 presentation (RFC 9901 §4, §7.1 steps 4-5, §7.3): a dropped
/// KB-JWT, a duplicated or fabricated Disclosure, and a genuine Disclosure (`email`, issued in
/// §5.1) added after the holder signed, which only `sd_hash` catches.
#[test]
fn rfc9901_presentation_edits_are_rejected() {
    let fixture = fixture();
    let example = &fixture["section_5_2"];
    let presentation = str_of(example, "presentation");
    let issuer = rfc_issuer(&fixture);
    let verify = |p: &str| {
        verify_sd_jwt_kb(p, &issuer, str_of(example, "issuer_typ"), &context(example)).map(|_| ())
    };
    let (sd_jwt, kb_jwt) = presentation.split_at(presentation.rfind('~').expect("~") + 1);
    let (issuer_jwt, disclosures) = sd_jwt.split_once('~').expect("issuer JWT");
    let email = fixture["section_5_1_disclosures"]
        .as_array()
        .expect("list")
        .iter()
        .find(|d| d["claim"] == "email")
        .map(|d| str_of(d, "disclosure").to_owned())
        .expect("email disclosure");
    let first = disclosures.split('~').next().expect("a disclosure");
    // `["c2FsdA", "nickname", "Lex"]`, referenced by no digest.
    let fabricated = "WyJjMkZzZEEiLCAibmlja25hbWUiLCAiTGV4Il0";

    assert_eq!(verify(sd_jwt), Err(ValidationError::KeyBindingMissing));
    assert_eq!(
        verify(&format!("{issuer_jwt}~{disclosures}{first}~{kb_jwt}")),
        Err(ValidationError::DuplicateDisclosure)
    );
    assert_eq!(
        verify(&format!("{issuer_jwt}~{disclosures}{fabricated}~{kb_jwt}")),
        Err(ValidationError::UnreferencedDisclosure)
    );
    assert_eq!(
        verify(&format!("{issuer_jwt}~{disclosures}{email}~{kb_jwt}")),
        Err(ValidationError::KbSdHashMismatch)
    );
}
