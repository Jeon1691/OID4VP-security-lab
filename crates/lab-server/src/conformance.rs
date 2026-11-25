//! Time-boxed OIDF conformance mode (`conformance` feature, [`crate::Mode::Conformance`];
//! docs/adr/0002-conformance-mode.md).
//!
//! It exists so the OIDF conformance suite's OpenID4VP **1.0 Final** Verifier plans (plain and
//! HAIP) can run against the lab. Those plans cannot test the lab's primary path (HPKE-0,
//! `session_info`, OpenID4VP 1.1): the suite has no such plan. What this mode serves instead,
//! and only while it runs:
//!
//! * **HTTPS on the loopback bind.** The lab terminates TLS itself (rustls, ring provider, TLS
//!   1.3, HTTP/1.1 via ALPN) with the leaf certificate of a synthetic CA. The bind address stays
//!   loopback; the suite container reaches it through the host's loopback forwarding, under a
//!   configured public origin (e.g. `https://host.docker.internal:<port>`) that every
//!   `request_uri` / `response_uri` / `result_uri` uses ([`PublicOrigin`]).
//! * **x509 client identifiers** (OpenID4VP 1.0 §5.9.3), checked at start against the same
//!   certificate ([`check`]):
//!   - `x509_san_dns:<dns>`: `<dns>` "MUST be a DNS name and match a dNSName Subject
//!     Alternative Name (SAN)" of the leaf, and the lab requires it to be the public origin's
//!     host, so the `response_uri` FQDN matches the client id (the §5.9.3 rule for Wallets that
//!     do not otherwise trust the client id);
//!   - `x509_hash:<hash>`: base64url of the SHA-256 of the leaf's DER;
//!   - for both: the Request Object "MUST be signed with the private key corresponding to the
//!     public key in the leaf X.509 certificate", which travels in the `x5c` JWS header (leaf
//!     first, no trust anchor: HAIP 1.0 §5), and the leaf must chain to the configured trust
//!     anchor now and must not be self-signed (HAIP 1.0 §5). The same trust anchor PEM is what
//!     the HAIP plan is configured with (`client.request_object_trust_anchor_pem`).
//! * **ECDH-ES response encryption on the unique route.** Each session gets a fresh ECDH-ES
//!   P-256 key and `kid` ("ephemeral encryption public keys specific to each Authorization
//!   Request", HAIP 1.0 §5), advertised in `client_metadata.jwks` with `alg` `ECDH-ES` and `use`
//!   `enc`, next to `encrypted_response_enc_values_supported` `["A128GCM","A256GCM"]` (both
//!   required by HAIP 1.0 §5; 1.0 §5.1) and `vp_formats_supported` for `dc+sd-jwt` (1.0 §5.1,
//!   §11.1, B.3.4). The response is correlated by its unique `response_uri` (route token), then
//!   the JWE `kid`, exactly as the HPKE-0 unique route does; `state`, holder binding and the
//!   Verifier-wide replay guard run as on every route.
//!
//! # Pipeline of `POST /lab/v1/response/{token}` in this mode
//!
//! Steps 0-3 as on the HPKE-0 routes (route token, body limit, media type, exactly one
//! `response`); `jose_ecdh_es::CompactJwe::parse` (every `alg` but `ECDH-ES`, `HPKE-0`
//! included, is `Rejection::EcdhEsJweParse`); `kid` required; unique-uri resolve (at most one
//! candidate); open with that session's ECDH-ES key; `state`, then holder binding against the
//! session's `client_id` (the full prefixed client id is the KB-JWT `aud`, 1.0 B.3.6) and
//! `nonce`; replay guard; claim. A session key of the other kind never opens, so neither
//! algorithm can stand in for the other.
//!
//! # Kill switch
//!
//! The mode exists only in builds with the `conformance` feature (the default build and
//! binary have no TLS, X.509 or ECDH-ES code), the binary enters it only on an explicit
//! `--mode conformance` flag (never from the environment), it refuses to start without its
//! complete configuration, and the server stops accepting after
//! [`ConformanceConfig::max_runtime`] (default [`DEFAULT_CONFORMANCE_MAX_RUNTIME`], at most
//! [`MAX_CONFORMANCE_MAX_RUNTIME`]; measured with `Instant`, so on macOS time asleep does not
//! count). It is never
//! entered as a fallback: Hardened and Research servers refuse a [`ConformanceConfig`] and the
//! x509 client id prefixes.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::http::HeaderMap;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jose_ecdh_es::CompactJwe;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{
    AlgorithmIdentifier, CertificateDer, DnsName, InvalidSignature, PrivateKeyDer, ServerName,
    SignatureVerificationAlgorithm, UnixTime, alg_id,
};
use serde_json::{Value, json};
use session_core::{
    Clock as _, IngressHint, ResolutionStrategy, RouteToken, SessionStore, SystemClock,
};
use sha2::{Digest as _, Sha256};
use tokio_rustls::TlsAcceptor;
use webpki::{EndEntityCert, KeyUsage};

use crate::config::{LabConfig, RouteKind, StartError};
use crate::evidence::{EvidenceRecord, Rejection};
use crate::jose::ALG_ES256;
use crate::sd_jwt::SD_JWT_VC_TYP;
use crate::server::{self, AppState, MILLIS_PER_SECOND};
use crate::status_list::StatusListPolicy;

/// Client Identifier Prefix: a DNS name in the leaf certificate's SAN (OpenID4VP 1.0 §5.9.3).
pub const X509_SAN_DNS_PREFIX: &str = "x509_san_dns:";
/// Client Identifier Prefix: base64url SHA-256 of the leaf certificate's DER (OpenID4VP 1.0
/// §5.9.3; the only prefix HAIP 1.0 §5 lets Verifiers use for signed requests).
pub const X509_HASH_PREFIX: &str = "x509_hash:";
/// Default maximum runtime of a conformance server (lab policy, the time box of ADR 0002): long
/// enough for one plan run of the OIDF suite, whose modules each finish in minutes with a
/// tester in the loop, short enough that a forgotten server does not keep serving.
pub const DEFAULT_CONFORMANCE_MAX_RUNTIME: Duration = Duration::from_secs(2 * 60 * 60);
/// Longest maximum runtime a conformance server accepts (lab policy, ADR 0002): one working
/// day. A plan run takes well under an hour, so a longer time box only means a server that was
/// forgotten; above it the server refuses to start (`StartError::MaxRuntimeTooLong`).
pub const MAX_CONFORMANCE_MAX_RUNTIME: Duration = Duration::from_secs(8 * 60 * 60);
/// Most certificates in the configured chain, leaf first (lab policy): the synthetic CA issues
/// the leaf directly, so one is normal; a few intermediates leave room for experiments.
pub const MAX_CHAIN_CERTIFICATES: usize = 4;

/// The only scheme of the public origin: the suite requires `https` for both `request_uri`
/// (`EnsureRequestUriIsHttps`) and `response_uri` (`EnsureValidResponseUriForAuthorizationEndpointRequest`).
const HTTPS_PREFIX: &str = "https://";
/// The only application protocol the lab serves (RFC 7301 ALPN identifier for HTTP/1.1).
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
/// `client_metadata` members (OpenID4VP 1.0 §5.1, §11.1; B.3.4 for `dc+sd-jwt`).
const VP_FORMATS_SUPPORTED: &str = "vp_formats_supported";
const SD_JWT_ALG_VALUES: &str = "sd-jwt_alg_values";
const KB_JWT_ALG_VALUES: &str = "kb-jwt_alg_values";
/// Bytes signed by the start check that proves the Request Object key is the leaf's key.
const KEY_MATCH_PROBE: &[u8] = b"lab-server conformance: request signing key matches the leaf";

/// Why the conformance X.509 configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum X509Error {
    /// A PEM input holds no certificate or key of the expected kind.
    #[error("PEM input unreadable or of the wrong kind")]
    Pem,
    /// The chain is empty or longer than [`MAX_CHAIN_CERTIFICATES`].
    #[error("certificate chain must hold 1 to {MAX_CHAIN_CERTIFICATES} certificates, leaf first")]
    ChainLength,
    /// The chain contains the trust anchor (HAIP 1.0 §5: it "MUST NOT be included in the x5c").
    #[error("the trust anchor must not be part of the chain (x5c)")]
    AnchorInChain,
    /// The leaf is not a parseable end-entity certificate.
    #[error("leaf is not a valid end-entity certificate")]
    Leaf,
    /// The leaf is self-signed (HAIP 1.0 §5: "MUST NOT be self-signed").
    #[error("leaf certificate is self-signed")]
    SelfSigned,
    /// The leaf does not chain to the trust anchor now (signature, validity, CA constraints,
    /// `serverAuth` extended key usage).
    #[error("leaf does not chain to the trust anchor now")]
    Chain,
    /// The Request Object signing key is not the leaf's key (OpenID4VP 1.0 §5.9.3).
    #[error("request signing key is not the leaf certificate's key")]
    KeyMismatch,
    /// The `client_id` is neither `x509_san_dns:` nor `x509_hash:`.
    #[error("conformance mode needs an x509_san_dns: or x509_hash: client_id")]
    ClientIdPrefix,
    /// `x509_san_dns:<dns>`: `<dns>` is not the public origin's host, or not a dNSName SAN of
    /// the leaf (OpenID4VP 1.0 §5.9.3).
    #[error("x509_san_dns value must be the public host and a dNSName SAN of the leaf")]
    SanMismatch,
    /// `x509_hash:<hash>`: not the base64url SHA-256 of the leaf DER (OpenID4VP 1.0 §5.9.3).
    #[error("x509_hash value is not the hash of the leaf certificate")]
    HashMismatch,
    /// The public origin is not `https://<lowercase DNS name>[:<port>]`.
    #[error("public origin must be https://<lowercase dns name>[:<port>]")]
    Origin,
    /// The leaf certificate is not valid for the public origin's host (TLS server name).
    #[error("leaf certificate is not valid for the public host")]
    OriginNotInCertificate,
    /// The response `redirect_uri` is not an absolute `https://` URL with a host (no user
    /// info, no fragment: the lab appends a `response_code` query parameter).
    #[error("response redirect_uri must be an absolute https URL with a host and no fragment")]
    RedirectUri,
}

/// The public origin of a conformance server: what every URL it hands out starts with. The
/// bind address stays loopback; this is the name under which the suite container reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicOrigin {
    host: String,
    port: Option<u16>,
}

impl PublicOrigin {
    /// `https://<host>[:<port>]`, nothing after it. `host` is a lowercase DNS name (no IP
    /// literal: x509_san_dns needs a dNSName). Without a port the bound port is used.
    ///
    /// # Errors
    /// [`X509Error::Origin`].
    pub fn parse(origin: &str) -> Result<Self, X509Error> {
        let rest = origin.strip_prefix(HTTPS_PREFIX).ok_or(X509Error::Origin)?;
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => (
                host,
                Some(port.parse::<u16>().map_err(|_| X509Error::Origin)?),
            ),
            None => (rest, None),
        };
        let is_dns_name = DnsName::try_from(host).is_ok()
            && host.parse::<std::net::IpAddr>().is_err()
            && !host.bytes().any(|b| b.is_ascii_uppercase());
        if !is_dns_name || port == Some(0) {
            return Err(X509Error::Origin);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The DNS name.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// `https://<host>:<port>`, with the configured port or else `bound_port`.
    pub(crate) fn base_url(&self, bound_port: u16) -> String {
        format!(
            "{HTTPS_PREFIX}{}:{}",
            self.host,
            self.port.unwrap_or(bound_port)
        )
    }
}

/// The synthetic X.509 material of a conformance server: the chain (leaf first, without the
/// trust anchor), the leaf's private key (TLS) and the trust anchor the chain must lead to.
/// Not `Clone`; `Debug` never shows the key.
pub struct X509Credentials {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    trust_anchor: CertificateDer<'static>,
}

impl fmt::Debug for X509Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Credentials")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl X509Credentials {
    /// Parses the chain (one or more `CERTIFICATE` blocks, leaf first), the leaf's private key
    /// (`PRIVATE KEY` / `EC PRIVATE KEY`) and the trust anchor (`CERTIFICATE`). How they fit
    /// together is checked when the server starts.
    ///
    /// # Errors
    /// [`X509Error::Pem`], [`X509Error::ChainLength`], [`X509Error::AnchorInChain`].
    pub fn from_pem(
        chain_pem: &[u8],
        key_pem: &[u8],
        trust_anchor_pem: &[u8],
    ) -> Result<Self, X509Error> {
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| X509Error::Pem)?;
        if chain.is_empty() || chain.len() > MAX_CHAIN_CERTIFICATES {
            return Err(X509Error::ChainLength);
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| X509Error::Pem)?;
        let trust_anchor =
            CertificateDer::from_pem_slice(trust_anchor_pem).map_err(|_| X509Error::Pem)?;
        if chain.contains(&trust_anchor) {
            return Err(X509Error::AnchorInChain);
        }
        Ok(Self {
            chain,
            key,
            trust_anchor,
        })
    }

    /// `x509_hash:<base64url(SHA-256(leaf DER))>` (OpenID4VP 1.0 §5.9.3).
    #[must_use]
    pub fn x509_hash_client_id(&self) -> String {
        format!("{X509_HASH_PREFIX}{}", self.leaf_hash())
    }

    fn leaf(&self) -> &CertificateDer<'static> {
        // `from_pem` refuses an empty chain.
        &self.chain[0]
    }

    fn leaf_hash(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.leaf().as_ref()))
    }
}

/// Configuration of [`crate::Mode::Conformance`].
#[derive(Debug)]
pub struct ConformanceConfig {
    /// TLS certificate chain and key, and the Request Object `x5c` chain.
    pub credentials: X509Credentials,
    /// The origin every handed-out URL uses.
    pub public_origin: PublicOrigin,
    /// The server stops accepting connections this long after start (kill switch); at most
    /// [`MAX_CONFORMANCE_MAX_RUNTIME`], never zero.
    pub max_runtime: Duration,
    /// `redirect_uri` the `response_uri` answers a committed response with (OpenID4VP 1.0
    /// §8.2: OPTIONAL; with it present the Wallet MUST redirect there), extended per response
    /// with a fresh `response_code` (`server::RESPONSE_CODE_BYTES`). `None` (default) answers
    /// `200 {}` like every other mode.
    pub response_redirect_uri: Option<String>,
    /// The issuer's Token Status List policy (`crate::status_list`;
    /// docs/adr/0003-status-list-checking.md): which list URIs to fetch, how their tokens are
    /// trusted, and the Status Provider's pinned TLS certificate. `None` (default): every
    /// credential that references a status list is refused (`StatusError::NoPolicy`).
    pub status_list: Option<StatusListPolicy>,
}

impl ConformanceConfig {
    /// `credentials` served under `public_origin`, with [`DEFAULT_CONFORMANCE_MAX_RUNTIME`], no
    /// response `redirect_uri` and no status policy.
    #[must_use]
    pub const fn new(credentials: X509Credentials, public_origin: PublicOrigin) -> Self {
        Self {
            credentials,
            public_origin,
            max_runtime: DEFAULT_CONFORMANCE_MAX_RUNTIME,
            response_redirect_uri: None,
            status_list: None,
        }
    }
}

/// ES256 over a certificate's P-256 key with a JWS signature (`R || S`, RFC 7518 §3.4) rather
/// than the DER signature X.509 itself uses, so webpki can check a JWS against the leaf's key.
#[derive(Debug)]
pub(crate) struct JwsEs256;

impl SignatureVerificationAlgorithm for JwsEs256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let signature = Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

/// Start checks of a conformance server (module docs); returns the `x5c` header value: the
/// chain, leaf first, as standard base64 DER (RFC 7515 §4.1.6).
pub(crate) fn check(
    config: &LabConfig,
    conformance: &ConformanceConfig,
) -> Result<Vec<String>, StartError> {
    if conformance.max_runtime.is_zero() {
        return Err(StartError::ZeroLimit);
    }
    if conformance.max_runtime > MAX_CONFORMANCE_MAX_RUNTIME {
        return Err(StartError::MaxRuntimeTooLong);
    }
    if let Some(uri) = &conformance.response_redirect_uri
        && !crate::config::is_https_url(uri)
    {
        return Err(X509Error::RedirectUri.into());
    }
    let credentials = &conformance.credentials;
    let leaf = EndEntityCert::try_from(credentials.leaf()).map_err(|_| X509Error::Leaf)?;
    if leaf.issuer() == leaf.subject() {
        return Err(X509Error::SelfSigned.into());
    }
    let anchor =
        webpki::anchor_from_trusted_cert(&credentials.trust_anchor).map_err(|_| X509Error::Pem)?;
    leaf.verify_for_usage(
        &[webpki::ring::ECDSA_P256_SHA256],
        &[anchor],
        &credentials.chain[1..],
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|_| X509Error::Chain)?;
    let probe = config.request_signing_key.sign_probe(KEY_MATCH_PROBE);
    leaf.verify_signature(&JwsEs256, KEY_MATCH_PROBE, &probe)
        .map_err(|_| X509Error::KeyMismatch)?;
    let host = conformance.public_origin.host();
    let valid_for = |name: &str| {
        DnsName::try_from(name).is_ok_and(|dns| {
            leaf.verify_is_valid_for_subject_name(&ServerName::DnsName(dns))
                .is_ok()
        })
    };
    if !valid_for(host) {
        return Err(X509Error::OriginNotInCertificate.into());
    }
    let client_id = config.client_id.as_str();
    if let Some(dns) = client_id.strip_prefix(X509_SAN_DNS_PREFIX) {
        // §5.9.3: the value must "match a dNSName Subject Alternative Name (SAN)" entry, so an
        // exact entry, not TLS wildcard matching (which `valid_for` uses for the origin host).
        if dns != host || !has_dns_san(&leaf, dns) {
            return Err(X509Error::SanMismatch.into());
        }
    } else if let Some(hash) = client_id.strip_prefix(X509_HASH_PREFIX) {
        if hash != credentials.leaf_hash() {
            return Err(X509Error::HashMismatch.into());
        }
    } else {
        return Err(X509Error::ClientIdPrefix.into());
    }
    Ok(credentials
        .chain
        .iter()
        .map(|cert| STANDARD.encode(cert))
        .collect())
}

/// Whether `leaf` has a dNSName SAN entry equal to `dns` (ASCII case-insensitive, as DNS
/// names compare; RFC 5280 §4.2.1.6). A wildcard entry such as `*.example` does not match.
pub(crate) fn has_dns_san(leaf: &EndEntityCert<'_>, dns: &str) -> bool {
    leaf.valid_dns_names()
        .any(|name| name.eq_ignore_ascii_case(dns))
}

/// The TLS server of a conformance server: TLS 1.3 only, the ring provider passed explicitly
/// (a workspace build may also compile aws-lc-rs, so no process default is relied on), the
/// configured chain and key (rustls checks that the key is the leaf's), HTTP/1.1 via ALPN.
pub(crate) fn tls_acceptor(credentials: &X509Credentials) -> Result<TlsAcceptor, StartError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(StartError::Tls)?
        .with_no_client_auth()
        .with_single_cert(credentials.chain.clone(), credentials.key.clone_key())
        .map_err(StartError::Tls)?;
    tls.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

/// `client_metadata` of a conformance session: the ECDH-ES `jwks` and both `enc` values
/// (`server::ecdh_es_client_metadata`), plus `vp_formats_supported` for `dc+sd-jwt` with the
/// one algorithm the lab verifies, ES256, for the issuer JWT and the KB-JWT (1.0 B.3.4).
pub(crate) fn client_metadata(
    key: &jose_ecdh_es::RecipientPrivateKey,
    kid: &protocol_model::KeyId,
) -> Value {
    let mut metadata = server::ecdh_es_client_metadata(key, kid);
    if let Some(members) = metadata.as_object_mut() {
        members.insert(
            VP_FORMATS_SUPPORTED.into(),
            json!({ SD_JWT_VC_TYP: { SD_JWT_ALG_VALUES: [ALG_ES256], KB_JWT_ALG_VALUES: [ALG_ES256] } }),
        );
    }
    metadata
}

/// `POST /lab/v1/response/{token}` in conformance mode (module docs).
pub(crate) async fn post_unique(
    state: &AppState,
    token: RouteToken,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let mut record = EvidenceRecord::new(RouteKind::Unique, ResolutionStrategy::UniqueUri);
    record.rejection = pipeline(&mut record, state, token, headers, body)
        .await
        .err();
    server::answer(state, record)
}

async fn pipeline(
    record: &mut EvidenceRecord,
    state: &AppState,
    token: RouteToken,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(), Rejection> {
    let response = server::admit(headers, body)?;
    let jwe = CompactJwe::parse(&response).map_err(Rejection::EcdhEsJweParse)?;
    // OpenID4VP 1.0 §8.3: the JWE carries the chosen JWK's `kid`.
    let kid = jwe.header().kid().cloned().ok_or(Rejection::MissingKid)?;
    let hint = IngressHint::new(token, Some(kid));
    let candidates = SessionStore::resolve(&state.unique, &hint, ResolutionStrategy::UniqueUri)
        .await
        .map_err(Rejection::Resolve)?;
    record.candidate_count = candidates.len();

    let slot = server::decryption_slot(state).await?;
    let acceptance = Arc::clone(&state.acceptance);
    // KB-JWT freshness is judged on this clock, in NumericDate seconds (RFC 7519 §2).
    let now = SystemClock.now().as_unix_millis() / MILLIS_PER_SECOND;
    let (trial, trial_time, candidates) = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let started = Instant::now();
        let trial = server::open_and_validate(&candidates, &acceptance, now, |candidate| {
            jwe.open(candidate.key().ecdh_es()?).ok()
        });
        (trial, started.elapsed(), candidates)
    })
    .await
    .map_err(|_| Rejection::TrialAborted)?;
    record.trial_time = trial_time;
    let (index, validated) = server::select(record, trial)?;
    let candidate = candidates.get(index).ok_or(Rejection::TrialAborted)?;
    server::commit(
        record,
        state,
        &state.unique,
        candidate,
        &response,
        validated,
    )
    .await
}
