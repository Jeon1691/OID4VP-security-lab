//! Wallet simulator (IMP-010), `wallet-sim` feature only.
//!
//! Fetches a lab request object over HTTP, verifies it as a signed Request Object (JAR,
//! [`WalletSim::verify_request`]), builds the synthetic presentation, seals it with HPKE-0
//! using the `session_info` computed from the verified payload's exact wire values, and POSTs
//! it as a `direct_post.jwt` form. [`SealOptions`] can tamper with every input the Verifier binds
//! (session_info fields, presentation fields, `kid`, ciphertext); a replay is posting the same
//! JWE again. Also carries the lab-driver calls (create session, read result) the scenarios
//! need. Loopback targets only: proxies and redirects are disabled and any other host is
//! refused.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::test_support::seal_compact;
use jose_hpke::{RecipientPublicKey, SessionInfo};
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
    REQUEST_OBJECT_MEDIA_TYPE, REQUEST_OBJECT_TYP,
};
use crate::validate::{
    PRESENTATION_AUD, PRESENTATION_NONCE, SYNTHETIC_CREDENTIAL_QUERY_ID, VP_TOKEN,
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
    /// `alg` of the advertised encryption JWK.
    pub jwk_alg: String,
    /// `kid` of the advertised encryption JWK.
    pub kid: Option<String>,
    /// The advertised HPKE-0 public key.
    pub public_key: RecipientPublicKey,
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

/// Sealing knobs. `Default` is an honest wallet.
#[derive(Debug, Clone, Default)]
pub struct SealOptions {
    /// `session_info` client_id instead of the request's.
    pub session_info_client_id: Option<String>,
    /// `session_info` nonce instead of the request's.
    pub session_info_nonce: Option<String>,
    /// `session_info` response_uri instead of the request's.
    pub session_info_response_uri: Option<String>,
    /// Presentation `nonce` instead of the request's.
    pub presentation_nonce: Option<String>,
    /// Presentation `aud` instead of the request's client_id.
    pub presentation_aud: Option<String>,
    /// Extra string members added to the presentation (the lab accepts none).
    pub presentation_extra: Vec<(String, String)>,
    /// Protected header `kid`.
    pub kid: KidChoice,
    /// Flip one ciphertext character (still canonical base64url).
    pub tamper_ciphertext: bool,
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

/// The simulator. Cheap to clone (shares one connection pool).
#[derive(Debug, Clone)]
pub struct WalletSim {
    http: reqwest::Client,
    trust: VerifierTrust,
}

impl WalletSim {
    /// A simulator with a loopback-only HTTP client that trusts Request Objects signed by the
    /// key of their `decentralized_identifier:did:key:` client id, resolved from the `kid`
    /// header with ssi's did:key resolver (as G0-C/G0-D do).
    ///
    /// # Errors
    /// The HTTP client cannot be built.
    pub fn new() -> Result<Self, WalletError> {
        Self::with_trust(VerifierTrust::DidKey)
    }

    /// A simulator that trusts only `public_jwk` (a pre-registered Verifier key), for lab
    /// client ids that are not DIDs.
    ///
    /// # Errors
    /// `public_jwk` is not a JWK, or the HTTP client cannot be built.
    pub fn with_pinned_verifier_key(public_jwk: &str) -> Result<Self, WalletError> {
        let jwk: JWK =
            serde_json::from_str(public_jwk).map_err(|_| WalletError::Malformed("pinned jwk"))?;
        Self::with_trust(VerifierTrust::Pinned(Box::new(jwk.to_public())))
    }

    fn with_trust(trust: VerifierTrust) -> Result<Self, WalletError> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()?;
        Ok(Self { http, trust })
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

    /// Builds the synthetic presentation and seals it for `request` (HPKE-0, `session_info`
    /// from the request's exact wire values unless overridden).
    ///
    /// # Errors
    /// An override that is not a valid wire value, or a sealing failure.
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
        let mut presentation = json!({
            PRESENTATION_NONCE: pick(&opts.presentation_nonce, &request.nonce),
            PRESENTATION_AUD: pick(&opts.presentation_aud, &request.client_id),
        });
        for (name, value) in &opts.presentation_extra {
            presentation[name.as_str()] = value.as_str().into();
        }
        let plaintext = json!({ VP_TOKEN: { SYNTHETIC_CREDENTIAL_QUERY_ID: [presentation] } });
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
    Ok(RequestObject {
        client_id: string(&object["client_id"])?,
        nonce: string(&object["nonce"])?,
        response_uri: string(&object["response_uri"])?,
        response_mode: string(&object["response_mode"])?,
        jwk_alg: string(&jwk["alg"])?,
        kid: jwk["kid"].as_str().map(str::to_owned),
        public_key: RecipientPublicKey::from_bytes(&point)?,
    })
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
