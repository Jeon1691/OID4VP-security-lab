//! Wallet simulator (IMP-010), `wallet-sim` feature only.
//!
//! Fetches a lab request object over HTTP, builds the synthetic presentation, seals it with
//! HPKE-0 using the `session_info` computed from the request's exact wire values, and POSTs it
//! as a `direct_post.jwt` form. [`SealOptions`] can tamper with every input the Verifier binds
//! (session_info fields, presentation fields, `kid`, ciphertext); a replay is posting the same
//! JWE again. Also carries the lab-driver calls (create session, read result) the scenarios
//! need. Loopback targets only: proxies and redirects are disabled and any other host is
//! refused.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::test_support::seal_compact;
use jose_hpke::{RecipientPublicKey, SessionInfo};
use protocol_model::{ClientIdWire, NonceWire, ResponseUriWire};
use reqwest::header::CONTENT_TYPE;
use serde_json::{Value, json};

use crate::config::RouteKind;
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
}

/// A session created through `POST /lab/v1/sessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSession {
    /// Lab session id.
    pub session_id: String,
    /// `GET` URL of the request object.
    pub request_uri: String,
    /// Where the response goes.
    pub response_uri: String,
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
    /// Body bytes.
    pub body: Vec<u8>,
}

/// The simulator. Cheap to clone (shares one connection pool).
#[derive(Debug, Clone)]
pub struct WalletSim {
    http: reqwest::Client,
}

impl WalletSim {
    /// A simulator with a loopback-only HTTP client.
    ///
    /// # Errors
    /// The HTTP client cannot be built.
    pub fn new() -> Result<Self, WalletError> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()?;
        Ok(Self { http })
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
            request_uri: field("request_uri")?,
            response_uri: field("response_uri")?,
        })
    }

    /// Lab driver: the session's `state`, or `None` if the lab does not know it (404).
    ///
    /// # Errors
    /// Transport errors or an unexpected answer.
    pub async fn session_state(
        &self,
        base_url: &str,
        session_id: &str,
    ) -> Result<Option<String>, WalletError> {
        let reply = self
            .get(&format!("{base_url}/lab/v1/sessions/{session_id}/result"))
            .await?;
        match reply.status {
            STATUS_NOT_FOUND => Ok(None),
            STATUS_OK => parse_json(&reply.body)?["state"]
                .as_str()
                .map(|s| Some(s.to_owned()))
                .ok_or(WalletError::Malformed("result")),
            other => Err(WalletError::Status(other)),
        }
    }

    /// Fetches and parses the request object at `request_uri`.
    ///
    /// # Errors
    /// Transport errors, a non-200 status, or a malformed request object.
    pub async fn fetch_request(&self, request_uri: &str) -> Result<RequestObject, WalletError> {
        let reply = self.get(request_uri).await?;
        if reply.status != STATUS_OK {
            return Err(WalletError::Status(reply.status));
        }
        let object = parse_json(&reply.body)?;
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
        let presentation = json!({
            PRESENTATION_NONCE: pick(&opts.presentation_nonce, &request.nonce),
            PRESENTATION_AUD: pick(&opts.presentation_aud, &request.client_id),
        });
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
        let body = response.bytes().await?.to_vec();
        Ok(HttpReply { status, body })
    }
}

fn parse_json(body: &[u8]) -> Result<Value, WalletError> {
    serde_json::from_slice(body).map_err(|_| WalletError::Malformed("json"))
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
