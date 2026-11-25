//! Wallet simulator (IMP-010), `wallet-sim` feature only.
//!
//! Fetches a lab request object over HTTP, verifies it as a signed Request Object (JAR,
//! [`WalletSim::verify_request`]), presents its synthetic SD-JWT VC as an SD-JWT+KB bound to
//! the request's `client_id` / `nonce` ([`WalletSim::present`]), seals the response with HPKE-0
//! using the `session_info` computed from the verified payload's exact wire values, and POSTs
//! it as a `direct_post.jwt` form. The sealed payload carries `vp_token` and, next to it, the
//! Request Object's `state` (OpenID4VP 1.1 §8.3: the response parameters are top-level JSON
//! members; RFC 6749 §4.1.2: `state` is echoed when the request carried one). [`SealOptions`]
//! can tamper with every input the Verifier binds (session_info fields, the presentation via
//! [`PresentationTamper`], `state` via [`StateChoice`], `kid`, ciphertext); a replay is
//! posting the same JWE again. Also carries the lab-driver calls (create session, read
//! result) the scenarios need. Loopback targets only: proxies and redirects are disabled and any
//! other host is refused.
//!
//! [`SyntheticIssuer`] issues the credential (RFC 9901 §4, SD-JWT VC draft-27 §2): `typ`
//! `dc+sd-jwt`, ES256, `vct` [`SYNTHETIC_CREDENTIAL_VCT`], `cnf.jwk` = the wallet's own holder
//! key (a fresh P-256 key per [`WalletSim`]), `given_name`, `family_name`, `birthdate` and
//! `age_over_18` selectively disclosable, one decoy digest. All synthetic.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::test_support::seal_compact;
use jose_hpke::{RecipientPublicKey, SessionInfo};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use protocol_model::{ClientIdWire, NonceWire, ResponseUriWire};
use reqwest::header::CONTENT_TYPE;
use serde_json::{Map, Value, json};
use ssi::JWK;
use ssi::dids::{DIDKey, VerificationMethodDIDResolver};
use ssi::jwk::{Algorithm, JWKResolver as _};
use ssi::verification_methods::AnyJwkMethod;

use crate::config::RouteKind;
use crate::jar::{
    DECENTRALIZED_IDENTIFIER_PREFIX, DID_URL_FRAGMENT, REQUEST_OBJECT_ALG, REQUEST_OBJECT_AUD,
    REQUEST_OBJECT_MEDIA_TYPE, REQUEST_OBJECT_TYP, RequestSigningKey,
};
use crate::jose::{self, ALG_ES256, BASE64URL};
use crate::sd_jwt::{
    KB_JWT_MAX_AGE_SECS, KB_JWT_MAX_FUTURE_SKEW_SECS, KB_JWT_TYP, SD_JWT_VC_TYP, TrustedIssuerKey,
};
use crate::validate::{
    DCQL_CLAIMS, DCQL_CREDENTIALS, DCQL_FORMAT, DCQL_ID, DCQL_META, DCQL_PATH, DCQL_VCT_VALUES,
    RESPONSE_STATE, SYNTHETIC_CREDENTIAL_VCT, VP_TOKEN,
};

/// Upper bound for one loopback request; a wedged server fails the caller instead of hanging.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";
/// HTTP statuses the simulator interprets (RFC 9110 §15).
const STATUS_CREATED: u16 = 201;
const STATUS_OK: u16 = 200;
const STATUS_NOT_FOUND: u16 = 404;
/// SEC1 uncompressed point tag (SEC1 §2.3.3).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
/// Index of the JWE Ciphertext in a compact JWE (RFC 7516 §7.1).
const CIPHERTEXT_SEGMENT: usize = 3;
/// JOSE header parameters the wallet checks (RFC 7515 §4.1).
const HEADER_ALG: &str = "alg";
const HEADER_TYP: &str = "typ";
const HEADER_KID: &str = "kid";
/// Critical-extension header (RFC 7515 §4.1.11): the wallet understands none, so any is refused.
const HEADER_CRIT: &str = "crit";
/// The unsecured JWS algorithm (RFC 7518 §3.6), for the `alg: none` tampers.
const ALG_NONE: &str = "none";
/// `iss` of the synthetic issuer, under the reserved `.invalid` TLD (RFC 2606 §2).
const SYNTHETIC_ISSUER_ID: &str = "https://issuer.lab.invalid";
/// Lifetime of an issued credential (`exp` - `iat`): one day, longer than any test run.
const CREDENTIAL_LIFETIME_SECS: u64 = 86_400;
/// Salt bytes per Disclosure: 128 bits, the minimum RFC 9901 §9.3 recommends.
const SALT_BYTES: usize = 16;
/// Random bytes hashed into a decoy digest (RFC 9901 §4.2.5).
const DECOY_BYTES: usize = 32;
/// Bytes of a P-256 private scalar (SEC1 §2.3.6).
const P256_SCALAR_BYTES: usize = 32;
/// Seconds past the KB-JWT freshness window used by the stale / future `iat` tampers.
const IAT_WINDOW_MARGIN_SECS: u64 = 60;
/// The synthetic subject's claims, all selectively disclosable (RFC 9901 §4.2.1).
const SYNTHETIC_GIVEN_NAME: &str = "Alex";
const SYNTHETIC_FAMILY_NAME: &str = "Sample";
const SYNTHETIC_BIRTHDATE: &str = "2000-01-01";
/// Claim the lab never requests: disclosed only by [`PresentationTamper::DiscloseUnrequestedClaim`].
const UNREQUESTED_CLAIM: &str = "birthdate";
/// Requested claim left out by [`PresentationTamper::WithholdRequestedClaim`].
const WITHHELD_CLAIM: &str = "family_name";
/// Claim name and value of the fabricated Disclosure of
/// [`PresentationTamper::UnreferencedDisclosure`].
const FABRICATED_CLAIM: &str = "nickname";
const FABRICATED_VALUE: &str = "Lex";
/// Value written into a Disclosure by [`PresentationTamper::AlteredDisclosure`].
const ALTERED_CLAIM_VALUE: &str = "Mallory";

/// Errors of the simulator.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// HTTP transport error.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// The target URL is not a loopback IP literal.
    #[error("refusing non-loopback target")]
    NonLoopback,
    /// The server answered with an unexpected status.
    #[error("unexpected status {0}")]
    Status(u16),
    /// A server document or an override is malformed.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// Sealing failed.
    #[error("seal: {0}")]
    Seal(#[from] jose_hpke::Error),
    /// The Request Object did not verify; nothing from it was used.
    #[error("request object rejected: {0:?}")]
    Rejected(RequestRejection),
    /// The OS random number generator failed.
    #[error("OS random number generator unavailable")]
    Rng,
    /// The request's DCQL query asks for a credential this wallet does not hold.
    #[error("no credential matches the DCQL query")]
    NoMatchingCredential,
}

/// Why the wallet refused a Request Object (checked in this order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRejection {
    /// The `request_uri` answer is not `application/oauth-authz-req+jwt` (OpenID4VP 1.1
    /// §5.10.1).
    ContentType,
    /// Not a compact JWS with JSON-object header and payload, or a `crit` header.
    Malformed,
    /// `typ` missing or not `oauth-authz-req+jwt` (OpenID4VP 1.1 §5).
    Typ,
    /// `alg` other than ES256, including `none`.
    Alg,
    /// did:key trust: `kid` missing, not a DID URL, or not resolvable (§5.9.3).
    Kid,
    /// The signature does not verify with the trusted key.
    Signature,
    /// `client_id` differs from the Authorization Request's (§5.10.1), or (did:key trust)
    /// from the DID whose key signed (§5.9.3).
    ClientId,
    /// `aud` is not the Static Discovery value (§5.8).
    Audience,
    /// `exp` missing, not a NumericDate, or not after now (RFC 7519 §4.1.4).
    Expired,
}

/// Which key the wallet accepts Request Object signatures from.
#[derive(Debug, Clone)]
enum VerifierTrust {
    /// Resolve the key from the `kid` did:key DID URL, and require `client_id` to be that DID
    /// (`decentralized_identifier`, OpenID4VP 1.1 §5.9.3).
    DidKey,
    /// A public key known in advance (a pre-registered client, §5.9.2); `kid` is ignored.
    Pinned(Box<JWK>),
}

/// A session created through `POST /lab/v1/sessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSession {
    /// Lab session id.
    pub session_id: String,
    /// The Authorization Request's `client_id`, which the Request Object must repeat.
    pub client_id: String,
    /// `GET` URL of the request object.
    pub request_uri: String,
    /// Where the response goes.
    pub response_uri: String,
    /// Where the outcome is read; carries the result token (only returned here).
    pub result_uri: String,
}

/// The values of a fetched request object the wallet uses.
#[derive(Debug, Clone)]
pub struct RequestObject {
    /// `client_id`, exact.
    pub client_id: String,
    /// `nonce`, exact.
    pub nonce: String,
    /// `response_uri`, exact.
    pub response_uri: String,
    /// `response_mode`.
    pub response_mode: String,
    /// `state`, exact, if the request carries one.
    pub state: Option<String>,
    /// `alg` of the advertised encryption JWK.
    pub jwk_alg: String,
    /// `kid` of the advertised encryption JWK.
    pub kid: Option<String>,
    /// The advertised HPKE-0 public key.
    pub public_key: RecipientPublicKey,
    /// `id` of the (single) DCQL Credential Query: the `vp_token` key (OpenID4VP 1.1 §8.1).
    pub credential_query_id: String,
    /// Its `meta.vct_values` (B.3.5).
    pub vct_values: Vec<String>,
    /// Its requested claims (one-element claims paths, §7.1).
    pub requested_claims: Vec<String>,
}

/// Which `kid` the JWE protected header carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum KidChoice {
    /// The advertised JWK's `kid` (OpenID4VP 1.1 §8.3), if any.
    #[default]
    Advertised,
    /// No `kid`.
    Omit,
    /// This `kid`.
    Other(String),
}

/// Which `state` the sealed payload carries next to `vp_token`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StateChoice {
    /// The Request Object's `state` (RFC 6749 §4.1.2), or none if it has none.
    #[default]
    Request,
    /// No `state` member.
    Omit,
    /// This JSON value as `state` (another session's `state`, or a non-string).
    Other(Value),
}

/// Sealing knobs. `Default` is an honest wallet.
#[derive(Debug, Clone, Default)]
pub struct SealOptions {
    /// `session_info` client_id instead of the request's.
    pub session_info_client_id: Option<String>,
    /// `session_info` nonce instead of the request's.
    pub session_info_nonce: Option<String>,
    /// `session_info` response_uri instead of the request's.
    pub session_info_response_uri: Option<String>,
    /// How the SD-JWT+KB presentation deviates from an honest one.
    pub presentation: PresentationTamper,
    /// Seal this `vp_token` verbatim instead of building one (replays, shape tests,
    /// presentations from another implementation).
    pub vp_token: Option<Value>,
    /// Payload `state`.
    pub state: StateChoice,
    /// Protected header `kid`.
    pub kid: KidChoice,
    /// Flip one ciphertext character (still canonical base64url).
    pub tamper_ciphertext: bool,
}

/// One deviation from an honest SD-JWT+KB presentation. `Default` is honest: exactly the
/// requested Disclosures, a KB-JWT signed by the `cnf` key over `aud` = `client_id`, `nonce`,
/// `iat` = now and the right `sd_hash`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PresentationTamper {
    /// Honest.
    #[default]
    None,
    /// KB-JWT `aud` instead of the request's `client_id`.
    KbAudience(String),
    /// KB-JWT `nonce` instead of the request's.
    KbNonce(String),
    /// KB-JWT `iat` older than the Verifier's freshness window.
    StaleIat,
    /// KB-JWT `iat` further in the future than the allowed clock skew.
    FutureIat,
    /// KB-JWT `sd_hash` over a different SD-JWT (one Disclosure fewer).
    WrongSdHash,
    /// KB-JWT signed by a fresh key that is not the credential's `cnf` key.
    KbSignedByOtherKey,
    /// KB-JWT with `alg: none` and an empty signature.
    KbAlgNone,
    /// No KB-JWT: an SD-JWT ending in `~`.
    MissingKb,
    /// A presented Disclosure's value changed after the KB-JWT was signed (in transit).
    AlteredDisclosure,
    /// A fabricated Disclosure no digest refers to, signed over by the holder.
    UnreferencedDisclosure,
    /// The same Disclosure sent twice.
    DuplicateDisclosure,
    /// A requested claim (`family_name`) not disclosed.
    WithholdRequestedClaim,
    /// A claim the request did not ask for (`birthdate`) disclosed as well.
    DiscloseUnrequestedClaim,
    /// The same credential, but issued (signed) by a key the Verifier does not trust.
    UntrustedIssuer,
    /// The issuer-signed JWT re-encoded with `alg: none` and an empty signature.
    IssuerAlgNone,
}

/// An HTTP answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    /// Status code.
    pub status: u16,
    /// `Content-Type` header, if any.
    pub content_type: Option<String>,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// A synthetic SD-JWT VC issuer (ES256). Never in the default build.
pub struct SyntheticIssuer {
    key: SigningKey,
}

impl fmt::Debug for SyntheticIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntheticIssuer").finish_non_exhaustive()
    }
}

impl SyntheticIssuer {
    /// An issuer signing with an EC P-256 private JWK (the lab fixture
    /// `tests/fixtures/lab_issuer.jwk`).
    ///
    /// # Errors
    /// [`WalletError::Malformed`] for anything [`RequestSigningKey::from_jwk`] refuses.
    pub fn from_jwk(private_jwk: &str) -> Result<Self, WalletError> {
        let key = RequestSigningKey::from_jwk(private_jwk)
            .map_err(|_| WalletError::Malformed("issuer jwk"))?;
        Ok(Self {
            key: key.into_signing_key(),
        })
    }

    /// An issuer with a fresh random key (one no Verifier trusts).
    ///
    /// # Errors
    /// [`WalletError::Rng`].
    pub fn generate() -> Result<Self, WalletError> {
        Ok(Self {
            key: random_signing_key()?,
        })
    }

    /// The public key a Verifier must be configured with to accept this issuer.
    #[must_use]
    pub fn trusted_key(&self) -> TrustedIssuerKey {
        TrustedIssuerKey::from_verifying_key(*self.key.verifying_key())
    }

    /// Issues the synthetic credential bound to `holder` (`cnf.jwk`), valid from `now` for
    /// [`CREDENTIAL_LIFETIME_SECS`].
    fn issue(&self, holder: &VerifyingKey, now: u64) -> Result<Credential, WalletError> {
        let claims = [
            ("given_name", json!(SYNTHETIC_GIVEN_NAME)),
            ("family_name", json!(SYNTHETIC_FAMILY_NAME)),
            (UNREQUESTED_CLAIM, json!(SYNTHETIC_BIRTHDATE)),
            ("age_over_18", json!(true)),
        ];
        let mut disclosures = Vec::with_capacity(claims.len());
        for (name, value) in claims {
            disclosures.push((name.to_owned(), encode_disclosure(name, &value)?));
        }
        let mut digests: Vec<Value> = disclosures
            .iter()
            .map(|(_, d)| jose::sha256_b64(d.as_bytes()).into())
            .collect();
        digests.push(jose::sha256_b64(&random_bytes(DECOY_BYTES)?).into());
        // RFC 9901 §4.2.4.1: hide the original claim order.
        digests.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        let payload = json!({
            "iss": SYNTHETIC_ISSUER_ID,
            "iat": now,
            "exp": now + CREDENTIAL_LIFETIME_SECS,
            "vct": SYNTHETIC_CREDENTIAL_VCT,
            "cnf": { "jwk": Value::Object(jose::p256_jwk_value(holder)) },
            "_sd_alg": "sha-256",
            "_sd": digests,
        });
        Ok(Credential {
            issuer_jwt: sign_jws(&self.key, SD_JWT_VC_TYP, &payload),
            disclosures,
        })
    }
}

/// An issued SD-JWT: the issuer-signed JWT and every Disclosure, by claim name.
#[derive(Debug, Clone)]
struct Credential {
    issuer_jwt: String,
    disclosures: Vec<(String, String)>,
}

/// The simulator. Cheap to clone (shares one connection pool).
#[derive(Clone)]
pub struct WalletSim {
    http: reqwest::Client,
    trust: VerifierTrust,
    /// This wallet's holder key (the credential's `cnf.jwk`).
    holder: SigningKey,
    credential: Credential,
}

impl fmt::Debug for WalletSim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletSim")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl WalletSim {
    /// A simulator with a loopback-only HTTP client that trusts Request Objects signed by the
    /// key of their `decentralized_identifier:did:key:` client id, resolved from the `kid`
    /// header with ssi's did:key resolver (as G0-C/G0-D do). It holds a fresh holder key and a
    /// credential `issuer` issued for it.
    ///
    /// # Errors
    /// The HTTP client cannot be built, or the RNG fails.
    pub fn new(issuer: &SyntheticIssuer) -> Result<Self, WalletError> {
        Self::with_trust(VerifierTrust::DidKey, issuer)
    }

    /// A simulator that trusts only `public_jwk` (a pre-registered Verifier key), for lab
    /// client ids that are not DIDs.
    ///
    /// # Errors
    /// `public_jwk` is not a JWK, the HTTP client cannot be built, or the RNG fails.
    pub fn with_pinned_verifier_key(
        public_jwk: &str,
        issuer: &SyntheticIssuer,
    ) -> Result<Self, WalletError> {
        let jwk: JWK =
            serde_json::from_str(public_jwk).map_err(|_| WalletError::Malformed("pinned jwk"))?;
        Self::with_trust(VerifierTrust::Pinned(Box::new(jwk.to_public())), issuer)
    }

    fn with_trust(trust: VerifierTrust, issuer: &SyntheticIssuer) -> Result<Self, WalletError> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()?;
        let holder = random_signing_key()?;
        let credential = issuer.issue(holder.verifying_key(), now_secs()?)?;
        Ok(Self {
            http,
            trust,
            holder,
            credential,
        })
    }

    /// RFC 7638 thumbprint of this wallet's holder key, as the Verifier commits it.
    #[must_use]
    pub fn holder_key_thumbprint(&self) -> String {
        jose::p256_thumbprint(self.holder.verifying_key())
    }

    /// The holder's public key as a JWK (the credential's `cnf.jwk`).
    #[must_use]
    pub fn holder_public_jwk(&self) -> Value {
        Value::Object(jose::p256_jwk_value(self.holder.verifying_key()))
    }

    /// Builds the SD-JWT+KB presentation for `request` (OpenID4VP 1.1 B.3.6; RFC 9901 §7.2):
    /// the Disclosures of exactly the requested claims, then a KB-JWT (`typ` `kb+jwt`, ES256 by
    /// the holder key) with `iat` = now, `aud` = `client_id`, `nonce` and `sd_hash` over the
    /// SD-JWT (§4.3.1), except where `tamper` says otherwise.
    ///
    /// # Errors
    /// [`WalletError::NoMatchingCredential`] if the query asks for another `vct` or a claim the
    /// credential lacks; [`WalletError::Rng`].
    pub fn present(
        &self,
        request: &RequestObject,
        tamper: &PresentationTamper,
    ) -> Result<String, WalletError> {
        use PresentationTamper as T;
        if !request
            .vct_values
            .iter()
            .any(|v| v == SYNTHETIC_CREDENTIAL_VCT)
        {
            return Err(WalletError::NoMatchingCredential);
        }
        let now = now_secs()?;
        let reissued;
        let credential = if *tamper == T::UntrustedIssuer {
            reissued = SyntheticIssuer::generate()?.issue(self.holder.verifying_key(), now)?;
            &reissued
        } else {
            &self.credential
        };
        let disclosure = |name: &str| {
            credential
                .disclosures
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, d)| d.clone())
                .ok_or(WalletError::NoMatchingCredential)
        };
        let mut disclosures = Vec::new();
        for name in &request.requested_claims {
            if *tamper == T::WithholdRequestedClaim && name == WITHHELD_CLAIM {
                continue;
            }
            disclosures.push(disclosure(name)?);
        }
        match tamper {
            T::DiscloseUnrequestedClaim => disclosures.push(disclosure(UNREQUESTED_CLAIM)?),
            T::UnreferencedDisclosure => {
                disclosures.push(encode_disclosure(
                    FABRICATED_CLAIM,
                    &json!(FABRICATED_VALUE),
                )?);
            }
            T::DuplicateDisclosure => {
                let first = disclosures
                    .first()
                    .cloned()
                    .ok_or(WalletError::NoMatchingCredential)?;
                disclosures.push(first);
            }
            _ => {}
        }
        let issuer_jwt = if *tamper == T::IssuerAlgNone {
            unsecured(&credential.issuer_jwt, SD_JWT_VC_TYP)?
        } else {
            credential.issuer_jwt.clone()
        };
        let sd_jwt = sd_jwt_string(&issuer_jwt, &disclosures);
        if *tamper == T::MissingKb {
            return Ok(sd_jwt);
        }
        let hashed = if *tamper == T::WrongSdHash {
            sd_jwt_string(
                &issuer_jwt,
                &disclosures[..disclosures.len().saturating_sub(1)],
            )
        } else {
            sd_jwt.clone()
        };
        let iat = match tamper {
            T::StaleIat => now - KB_JWT_MAX_AGE_SECS - IAT_WINDOW_MARGIN_SECS,
            T::FutureIat => now + KB_JWT_MAX_FUTURE_SKEW_SECS + IAT_WINDOW_MARGIN_SECS,
            _ => now,
        };
        let pick =
            |over: Option<&String>, honest: &str| over.map_or(honest, String::as_str).to_owned();
        let kb_payload = json!({
            "iat": iat,
            "aud": pick(
                match tamper { T::KbAudience(a) => Some(a), _ => None },
                &request.client_id,
            ),
            "nonce": pick(
                match tamper { T::KbNonce(n) => Some(n), _ => None },
                &request.nonce,
            ),
            "sd_hash": jose::sha256_b64(hashed.as_bytes()),
        });
        let other;
        let signer = if *tamper == T::KbSignedByOtherKey {
            other = random_signing_key()?;
            &other
        } else {
            &self.holder
        };
        let mut kb_jwt = sign_jws(signer, KB_JWT_TYP, &kb_payload);
        if *tamper == T::KbAlgNone {
            kb_jwt = unsecured(&kb_jwt, KB_JWT_TYP)?;
        }
        if *tamper == T::AlteredDisclosure {
            let altered = sd_jwt_string(&issuer_jwt, &alter_first_disclosure(&disclosures)?);
            return Ok(format!("{altered}{kb_jwt}"));
        }
        Ok(format!("{sd_jwt}{kb_jwt}"))
    }

    /// Lab driver: `POST /lab/v1/sessions` for `route`, optionally with a fixed nonce
    /// (research mode only).
    ///
    /// # Errors
    /// Transport errors, or any status other than 201.
    pub async fn create_session(
        &self,
        base_url: &str,
        route: RouteKind,
        nonce: Option<&str>,
    ) -> Result<CreatedSession, WalletError> {
        let route = match route {
            RouteKind::Unique => "unique",
            RouteKind::Shared => "shared",
        };
        let mut body = json!({ "route": route });
        if let Some(nonce) = nonce {
            body["nonce"] = nonce.into();
        }
        let url = format!("{base_url}/lab/v1/sessions");
        let reply = self
            .send(
                &url,
                Some((JSON_CONTENT_TYPE, body.to_string().into_bytes())),
            )
            .await?;
        if reply.status != STATUS_CREATED {
            return Err(WalletError::Status(reply.status));
        }
        let created = parse_json(&reply.body)?;
        let field = |name| {
            created[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(WalletError::Malformed("session creation response"))
        };
        Ok(CreatedSession {
            session_id: field("session_id")?,
            client_id: field("client_id")?,
            request_uri: field("request_uri")?,
            response_uri: field("response_uri")?,
            result_uri: field("result_uri")?,
        })
    }

    /// Lab driver: the session's `state` from its `result_uri`, or `None` if the lab does not
    /// know it (404).
    ///
    /// # Errors
    /// Transport errors or an unexpected answer.
    pub async fn session_state(&self, result_uri: &str) -> Result<Option<String>, WalletError> {
        let reply = self.get(result_uri).await?;
        match reply.status {
            STATUS_NOT_FOUND => Ok(None),
            STATUS_OK => parse_json(&reply.body)?["state"]
                .as_str()
                .map(|s| Some(s.to_owned()))
                .ok_or(WalletError::Malformed("result")),
            other => Err(WalletError::Status(other)),
        }
    }

    /// Fetches the session's Request Object from its `request_uri` and verifies it
    /// ([`Self::verify_request`]) against the Authorization Request's `client_id`.
    ///
    /// # Errors
    /// Transport errors, a non-200 status, [`WalletError::Rejected`], or a malformed payload.
    pub async fn fetch_request(
        &self,
        session: &CreatedSession,
    ) -> Result<RequestObject, WalletError> {
        let reply = self.get(&session.request_uri).await?;
        if reply.status != STATUS_OK {
            return Err(WalletError::Status(reply.status));
        }
        if reply.content_type.as_deref() != Some(REQUEST_OBJECT_MEDIA_TYPE) {
            return Err(WalletError::Rejected(RequestRejection::ContentType));
        }
        let jwt = std::str::from_utf8(&reply.body)
            .map_err(|_| WalletError::Rejected(RequestRejection::Malformed))?;
        self.verify_request(jwt, &session.client_id).await
    }

    /// Verifies a signed Request Object (RFC 9101; OpenID4VP 1.1 §5) and only then reads the
    /// binding values, from its verified payload. Checks, in order: compact JWS of JSON
    /// objects, no `crit`; `typ` = `oauth-authz-req+jwt` (§5); `alg` = ES256 exactly (so never
    /// `none`); the signature with the trusted key (did:key resolved from `kid`, or the pinned
    /// key); payload `client_id` = `client_id` (§5.10.1) and, with did:key trust, = the signing
    /// DID (§5.9.3); `aud` = `https://self-issued.me/v2` (§5.8); `exp` after now (RFC 7519
    /// §4.1.4). `iss` is ignored (§5).
    ///
    /// # Errors
    /// [`WalletError::Rejected`], or a malformed (but verified) payload.
    pub async fn verify_request(
        &self,
        jwt: &str,
        client_id: &str,
    ) -> Result<RequestObject, WalletError> {
        let reject = WalletError::Rejected;
        let mut segments = jwt.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(reject(RequestRejection::Malformed));
        };
        let header = decode_object(header_b64)?;
        if header.contains_key(HEADER_CRIT) {
            return Err(reject(RequestRejection::Malformed));
        }
        if header.get(HEADER_TYP).and_then(Value::as_str) != Some(REQUEST_OBJECT_TYP) {
            return Err(reject(RequestRejection::Typ));
        }
        if header.get(HEADER_ALG).and_then(Value::as_str) != Some(REQUEST_OBJECT_ALG) {
            return Err(reject(RequestRejection::Alg));
        }
        let (jwk, signer_did) = match &self.trust {
            VerifierTrust::Pinned(jwk) => ((**jwk).clone(), None),
            VerifierTrust::DidKey => {
                let kid = header
                    .get(HEADER_KID)
                    .and_then(Value::as_str)
                    .ok_or(reject(RequestRejection::Kid))?;
                let (did, _) = kid
                    .split_once(DID_URL_FRAGMENT)
                    .ok_or(reject(RequestRejection::Kid))?;
                let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
                    VerificationMethodDIDResolver::new(DIDKey);
                let jwk = resolver
                    .fetch_public_jwk(Some(kid))
                    .await
                    .map_err(|_| reject(RequestRejection::Kid))?
                    .into_owned();
                (jwk, Some(did.to_owned()))
            }
        };
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| reject(RequestRejection::Signature))?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        ssi::claims::jws::verify_bytes(
            Algorithm::ES256,
            signing_input.as_bytes(),
            &jwk,
            &signature,
        )
        .map_err(|_| reject(RequestRejection::Signature))?;

        // Verified: from here on every value comes from the signed payload.
        let object = decode_object(payload_b64)?;
        if object.get("client_id").and_then(Value::as_str) != Some(client_id) {
            return Err(reject(RequestRejection::ClientId));
        }
        if let Some(did) = signer_did
            && client_id.strip_prefix(DECENTRALIZED_IDENTIFIER_PREFIX) != Some(did.as_str())
        {
            return Err(reject(RequestRejection::ClientId));
        }
        if object.get("aud").and_then(Value::as_str) != Some(REQUEST_OBJECT_AUD) {
            return Err(reject(RequestRejection::Audience));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| reject(RequestRejection::Expired))?
            .as_secs();
        if !object
            .get("exp")
            .and_then(Value::as_u64)
            .is_some_and(|exp| now < exp)
        {
            return Err(reject(RequestRejection::Expired));
        }
        request_object(&Value::Object(object))
    }

    /// Builds the presentation ([`Self::present`]) and seals `{"vp_token": {<query id>:
    /// [<presentation>]}, "state": <state>}` for `request` (HPKE-0, `session_info` from the
    /// request's exact wire values unless overridden). [`SealOptions::vp_token`] replaces the
    /// built `vp_token`; [`SealOptions::state`] chooses the `state` member.
    ///
    /// # Errors
    /// An override that is not a valid wire value, a presentation or sealing failure.
    pub fn seal(&self, request: &RequestObject, opts: &SealOptions) -> Result<String, WalletError> {
        let pick = |o: &Option<String>, d: &str| o.clone().unwrap_or_else(|| d.to_owned());
        let malformed = |_| WalletError::Malformed("session_info value");
        let info = SessionInfo::direct_post_jwt(
            &ClientIdWire::new(pick(&opts.session_info_client_id, &request.client_id))
                .map_err(malformed)?,
            &NonceWire::new(pick(&opts.session_info_nonce, &request.nonce)).map_err(malformed)?,
            &ResponseUriWire::new(pick(&opts.session_info_response_uri, &request.response_uri))
                .map_err(malformed)?,
        );
        let vp_token = match &opts.vp_token {
            Some(vp_token) => vp_token.clone(),
            None => {
                let mut answers = Map::new();
                answers.insert(
                    request.credential_query_id.clone(),
                    json!([self.present(request, &opts.presentation)?]),
                );
                Value::Object(answers)
            }
        };
        let mut payload = Map::new();
        payload.insert(VP_TOKEN.to_owned(), vp_token);
        let state = match &opts.state {
            StateChoice::Request => request.state.clone().map(Value::String),
            StateChoice::Omit => None,
            StateChoice::Other(value) => Some(value.clone()),
        };
        if let Some(state) = state {
            payload.insert(RESPONSE_STATE.to_owned(), state);
        }
        let plaintext = Value::Object(payload);
        let kid = match &opts.kid {
            KidChoice::Advertised => request.kid.as_deref(),
            KidChoice::Omit => None,
            KidChoice::Other(kid) => Some(kid.as_str()),
        };
        let jwe = seal_compact(
            &request.public_key,
            kid,
            info.as_bytes(),
            plaintext.to_string().as_bytes(),
            &mut UnwrapErr(getrandom::SysRng),
        )?;
        Ok(if opts.tamper_ciphertext {
            tamper_ciphertext(&jwe)
        } else {
            jwe
        })
    }

    /// POSTs `response=<jwe>` as a form to `response_uri`.
    ///
    /// # Errors
    /// Transport errors (any status is returned as a reply).
    pub async fn post_response(
        &self,
        response_uri: &str,
        jwe: &str,
    ) -> Result<HttpReply, WalletError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("response", jwe)
            .finish();
        self.post_raw(response_uri, FORM_CONTENT_TYPE, body.into_bytes())
            .await
    }

    /// POSTs `body` with `content_type`, for admission tests.
    ///
    /// # Errors
    /// Transport errors.
    pub async fn post_raw(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpReply, WalletError> {
        self.send(url, Some((content_type, body))).await
    }

    /// GETs `url`.
    ///
    /// # Errors
    /// Transport errors.
    pub async fn get(&self, url: &str) -> Result<HttpReply, WalletError> {
        self.send(url, None).await
    }

    async fn send(
        &self,
        url: &str,
        body: Option<(&str, Vec<u8>)>,
    ) -> Result<HttpReply, WalletError> {
        let url = reqwest::Url::parse(url).map_err(|_| WalletError::Malformed("url"))?;
        let loopback = url
            .host_str()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|h| h.parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !loopback {
            return Err(WalletError::NonLoopback);
        }
        let request = match body {
            Some((content_type, body)) => self
                .http
                .post(url)
                .header(CONTENT_TYPE, content_type)
                .body(body),
            None => self.http.get(url),
        };
        let response = request.send().await?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await?.to_vec();
        Ok(HttpReply {
            status,
            content_type,
            body,
        })
    }
}

fn parse_json(body: &[u8]) -> Result<Value, WalletError> {
    serde_json::from_slice(body).map_err(|_| WalletError::Malformed("json"))
}

/// A base64url JWS segment holding a JSON object.
fn decode_object(segment: &str) -> Result<Map<String, Value>, WalletError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(WalletError::Rejected(RequestRejection::Malformed))
}

/// The values the wallet uses, from a verified Request Object payload.
fn request_object(object: &Value) -> Result<RequestObject, WalletError> {
    let string = |v: &Value| {
        v.as_str()
            .map(str::to_owned)
            .ok_or(WalletError::Malformed("request object"))
    };
    let jwk = &object["client_metadata"]["jwks"]["keys"][0];
    let coordinate = |name: &str| {
        jwk[name]
            .as_str()
            .and_then(|c| URL_SAFE_NO_PAD.decode(c).ok())
            .ok_or(WalletError::Malformed("jwk coordinate"))
    };
    let mut point = vec![SEC1_UNCOMPRESSED_TAG];
    point.extend(coordinate("x")?);
    point.extend(coordinate("y")?);
    // The wallet answers exactly one `dc+sd-jwt` Credential Query (OpenID4VP 1.1 §6.1, B.3).
    let query = match object["dcql_query"][DCQL_CREDENTIALS]
        .as_array()
        .map(Vec::as_slice)
    {
        Some([query]) if query[DCQL_FORMAT] == SD_JWT_VC_TYP => query,
        _ => return Err(WalletError::Malformed("dcql_query")),
    };
    let strings = |values: &Value| -> Result<Vec<String>, WalletError> {
        values
            .as_array()
            .ok_or(WalletError::Malformed("dcql_query"))?
            .iter()
            .map(string)
            .collect()
    };
    let requested_claims = query[DCQL_CLAIMS]
        .as_array()
        .ok_or(WalletError::Malformed("dcql_query"))?
        .iter()
        .map(
            |claim| match claim[DCQL_PATH].as_array().map(Vec::as_slice) {
                Some([Value::String(name)]) => Ok(name.clone()),
                _ => Err(WalletError::Malformed("dcql claims path")),
            },
        )
        .collect::<Result<_, _>>()?;
    Ok(RequestObject {
        client_id: string(&object["client_id"])?,
        nonce: string(&object["nonce"])?,
        response_uri: string(&object["response_uri"])?,
        response_mode: string(&object["response_mode"])?,
        state: object.get(RESPONSE_STATE).map(string).transpose()?,
        jwk_alg: string(&jwk["alg"])?,
        kid: jwk["kid"].as_str().map(str::to_owned),
        public_key: RecipientPublicKey::from_bytes(&point)?,
        credential_query_id: string(&query[DCQL_ID])?,
        vct_values: strings(&query[DCQL_META][DCQL_VCT_VALUES])?,
        requested_claims,
    })
}

/// Seconds since the Unix epoch.
fn now_secs() -> Result<u64, WalletError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| WalletError::Malformed("system clock"))
}

fn random_bytes(n: usize) -> Result<Vec<u8>, WalletError> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).map_err(|_| WalletError::Rng)?;
    Ok(bytes)
}

/// A fresh P-256 key from the OS CSPRNG (a random 32-byte string is a valid scalar except with
/// negligible probability; such a draw is retried).
fn random_signing_key() -> Result<SigningKey, WalletError> {
    loop {
        let scalar = zeroize::Zeroizing::new(random_bytes(P256_SCALAR_BYTES)?);
        if let Ok(key) = SigningKey::from_slice(&scalar) {
            return Ok(key);
        }
    }
}

/// `base64url(JSON [salt, name, value])` with a fresh 128-bit salt (RFC 9901 §4.2.1).
fn encode_disclosure(name: &str, value: &Value) -> Result<String, WalletError> {
    let salt = BASE64URL.encode(random_bytes(SALT_BYTES)?);
    Ok(BASE64URL.encode(json!([salt, name, value]).to_string()))
}

/// Compact JWS (RFC 7515 §7.1), ES256 by `key`, header `{"alg":"ES256","typ":typ}`.
fn sign_jws(key: &SigningKey, typ: &str, payload: &Value) -> String {
    let header = json!({ HEADER_ALG: ALG_ES256, HEADER_TYP: typ });
    let input = format!(
        "{}.{}",
        BASE64URL.encode(header.to_string()),
        BASE64URL.encode(payload.to_string())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", BASE64URL.encode(signature.to_bytes()))
}

/// `jws` re-encoded as an unsecured JWS (RFC 7515 Appendix A.5): header `alg` `none`, same
/// payload, empty signature.
fn unsecured(jws: &str, typ: &str) -> Result<String, WalletError> {
    let payload = jws.split('.').nth(1).ok_or(WalletError::Malformed("jws"))?;
    let header = json!({ HEADER_ALG: ALG_NONE, HEADER_TYP: typ });
    Ok(format!(
        "{}.{payload}.",
        BASE64URL.encode(header.to_string())
    ))
}

/// `<JWT>~<D.1>~...~<D.N>~` (RFC 9901 §4).
fn sd_jwt_string(issuer_jwt: &str, disclosures: &[String]) -> String {
    let mut out = format!("{issuer_jwt}~");
    for disclosure in disclosures {
        out.push_str(disclosure);
        out.push('~');
    }
    out
}

/// `disclosures` with the first one's claim value replaced (same salt and name).
fn alter_first_disclosure(disclosures: &[String]) -> Result<Vec<String>, WalletError> {
    let mut out = disclosures.to_vec();
    let first = out.first_mut().ok_or(WalletError::NoMatchingCredential)?;
    let decoded = jose::b64_decode(first)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .ok_or(WalletError::Malformed("disclosure"))?;
    let (Some(salt), Some(name)) = (decoded[0].as_str(), decoded[1].as_str()) else {
        return Err(WalletError::Malformed("disclosure"));
    };
    *first = BASE64URL.encode(json!([salt, name, ALTERED_CLAIM_VALUE]).to_string());
    Ok(out)
}

/// Replaces the first ciphertext character with another base64url character. The first
/// character of a segment carries six full bits, so the result stays canonical and only the
/// AEAD check can catch it.
fn tamper_ciphertext(jwe: &str) -> String {
    let mut segments: Vec<String> = jwe.split('.').map(str::to_owned).collect();
    if let Some(ct) = segments.get_mut(CIPHERTEXT_SEGMENT)
        && let Some(first) = ct.chars().next()
    {
        let replacement = if first == 'A' { "B" } else { "A" };
        ct.replace_range(..first.len_utf8(), replacement);
    }
    segments.join(".")
}
