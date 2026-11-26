//! Token Status List checking (draft-ietf-oauth-status-list-14, "TSL" below;
//! docs/adr/0003-status-list-checking.md). Verifier side.
//!
//! A presentation that passed holder binding is checked here, after validation and before its
//! session is committed (`server::commit`): RFC 9901 / SD-JWT VC processing comes first
//! (TSL §8.3: "The processing rules for Referenced Tokens ... MUST precede any evaluation of a
//! Referenced Token's status"), so an invalid credential never causes a fetch.
//!
//! | Credential | Verifier | Outcome |
//! | --- | --- | --- |
//! | no `status` claim | any | [`StatusResult::NotReferenced`]: accepted, nothing fetched |
//! | `status.status_list` | no [`StatusListPolicy`] (every build without `conformance`, and a conformance server without one) | refused, [`StatusError::NoPolicy`]: a Verifier that cannot check a referenced status does not accept the credential |
//! | `status.status_list` | a policy | the list is fetched and checked (below); only `0x00` VALID is accepted |
//! | `status` without a well-formed `status_list` | any | refused as `ValidationError::StatusClaimMalformed` (TSL §6.2, §8.3 step 1) |
//!
//! With a policy (`conformance` feature), in this order; the first failure refuses the response
//! with that [`StatusError`], recorded as evidence and never shown on the wire (generic 400):
//!
//! | Step | Check | Source | Failure |
//! | --- | --- | --- | --- |
//! | 1 | `uri` is `https`, under the policy's URI prefix, no query, fragment, user info or dot segment, at most [`MAX_STATUS_URI_LEN`] | TSL §6.2 (RFC 3986 URI); issuer policy (lab) | [`StatusError::UriNotAllowed`] |
//! | 2 | every address of its host is loopback | lab policy (loopback endpoints only) | [`FetchFailure::NotLoopback`] |
//! | 3 | `GET` with `Accept: application/statuslist+jwt`, TLS 1.3 to the pinned server certificate, within [`STATUS_LIST_FETCH_TIMEOUT`] | TSL §8.1; lab policy | [`StatusError::Fetch`] |
//! | 4 | `200`, `Content-Type` `application/statuslist+jwt`, no `Content-Encoding`, body at most [`MAX_STATUS_LIST_TOKEN_BYTES`]; a `3xx` is not followed | TSL §8.2 (lab: stricter than "SHOULD follow", §11.4) | [`StatusError::Fetch`] |
//! | 5 | compact JWS, no `crit`, `typ` `statuslist+jwt`, `alg` ES256 | TSL §5.1; RFC 7515; RFC 8725 §3.1, §3.11 | [`StatusError::TokenMalformed`] / [`StatusError::TokenTyp`] / [`StatusError::TokenAlg`] |
//! | 6 | signature: the pinned key, or an `x5c` chain to the configured status trust anchor (every entry a DER certificate) | TSL §5.1 rule 2, §8.3 step 3a, §11.3 | [`StatusError::UntrustedSigner`] / [`StatusError::TokenSignature`] |
//! | 7 | `sub` = the reference's `uri`, exactly | TSL §5.1, §8.3 step 4a | [`StatusError::SubjectMismatch`] |
//! | 8 | `iat` required, `exp` / `nbf` / `ttl` optional, integer NumericDates (`ttl` positive); no `aud` (the lab has no audience identifier, and RFC 7519 §4.1.3 rejects a JWT whose `aud` does not name its processor) | TSL §5.1, §8.3 step 3b; RFC 7519 §4.1 | [`StatusError::TokenMalformed`] / [`StatusError::TokenAudience`] |
//! | 9 | `exp` not reached; `iat` / `nbf` not more than [`STATUS_LIST_MAX_FUTURE_SKEW_SECS`] ahead, judged on the clock read after the fetch | TSL §8.3 steps 4b-4c; RFC 7519 §4.1.4-§4.1.6 | [`StatusError::TokenExpired`] / [`StatusError::TokenNotYetValid`] |
//! | 10 | `status_list.bits` in {1, 2, 4, 8}, `lst` canonical base64url of exactly one ZLIB stream (no trailing bytes), inflated at most [`MAX_STATUS_LIST_BYTES`] | TSL §4.1, §4.2, §8.3 step 5; RFC 1950 §2.2 | [`StatusError::ListMalformed`] |
//! | 11 | `idx` inside the list | TSL §4.1 step 3, §8.3 step 6 | [`StatusError::IndexOutOfRange`] |
//! | 12 | the value: `0x00` accepted; `0x01` [`StatusError::Revoked`], `0x02` [`StatusError::Suspended`], anything else [`StatusError::NotValid`] | TSL §7.1, §8.3 step 7 | as listed |
//!
//! Only step 12 makes a statement about the credential; every earlier failure, step 11's
//! out-of-range index included, means "no statement can be made" (TSL §8.3) and is recorded as
//! its own variant, never as a revocation.
//! All of them refuse the response: a credential whose status was asked to be checked and could
//! not be is not accepted.
//!
//! Not done (lab scope, ADR 0003): caching (`ttl` is checked for shape only; every check fetches),
//! historical resolution (§8.4), Status List Aggregation (§9), CWT lists (§5.2), redirects, any
//! key resolution other than the configured pin or trust anchor (header `jwk`, `kid` and `x5u`
//! are never used to find a key), and an extended key usage OID for status signers (TSL §10
//! leaves `id-kp-oauthStatusSigning` as TBD through draft-19, so the lab requires a signer
//! certificate with no EKU at all: a TLS server certificate, `serverAuth`, cannot sign a list).

use serde_json::{Map, Value};

use crate::validate::ValidationError;

/// The Referenced Token's status claim and its Status List reference (TSL §6.1, §6.2).
pub(crate) const STATUS: &str = "status";
const STATUS_LIST: &str = "status_list";
const STATUS_LIST_IDX: &str = "idx";
const STATUS_LIST_URI: &str = "uri";
/// Longest Status List `uri` the lab follows (lab policy): URLs in the wild stay far below it,
/// and the value is compared against the token's `sub` and used as the request target.
pub const MAX_STATUS_URI_LEN: usize = 2048;

/// The Status List reference of a credential: `status.status_list` (TSL §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusReference {
    /// `uri`: where the Status List Token is fetched, and what its `sub` must be.
    pub(crate) uri: String,
    /// `idx`: the credential's index in that list.
    pub(crate) idx: u64,
}

/// The status reference of a processed SD-JWT VC payload (TSL §8.3 step 1): `None` without a
/// `status` claim; otherwise `status` must be an object carrying a `status_list` object with a
/// non-negative integer `idx` and a non-empty string `uri` of at most [`MAX_STATUS_URI_LEN`]
/// bytes. Other members (other status mechanisms, TSL §14.2) are ignored next to it; a `status`
/// claim without `status_list` names only mechanisms the lab cannot check, and is refused.
///
/// # Errors
/// [`ValidationError::StatusClaimMalformed`].
pub(crate) fn reference(
    payload: &Map<String, Value>,
) -> Result<Option<StatusReference>, ValidationError> {
    let Some(status) = payload.get(STATUS) else {
        return Ok(None);
    };
    let list = status
        .as_object()
        .and_then(|status| status.get(STATUS_LIST))
        .and_then(Value::as_object)
        .ok_or(ValidationError::StatusClaimMalformed)?;
    let idx = list
        .get(STATUS_LIST_IDX)
        .and_then(Value::as_u64)
        .ok_or(ValidationError::StatusClaimMalformed)?;
    let uri = list
        .get(STATUS_LIST_URI)
        .and_then(Value::as_str)
        .filter(|uri| !uri.is_empty() && uri.len() <= MAX_STATUS_URI_LEN)
        .ok_or(ValidationError::StatusClaimMalformed)?;
    Ok(Some(StatusReference {
        uri: uri.to_owned(),
        idx,
    }))
}

/// Why a fetch of the Status List Token failed (TSL §8.1, §8.2; lab policy). Internal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchFailure {
    /// The host resolved to no address, or to one that is not loopback.
    NotLoopback,
    /// No resolved address accepted the TCP connection.
    Connect,
    /// The TLS handshake failed (including a server certificate other than the pinned one).
    Tls,
    /// The HTTP exchange failed (handshake, request or response head).
    Http,
    /// The answer was not `200` (a `3xx` is not followed).
    Status(u16),
    /// The `Content-Type` is not `application/statuslist+jwt` (TSL §8.2: "MUST use").
    ContentType,
    /// A `Content-Encoding` was applied (the lab asks for none).
    ContentEncoding,
    /// The body could not be read, or exceeds [`MAX_STATUS_LIST_TOKEN_BYTES`].
    Body,
    /// The whole fetch took longer than [`STATUS_LIST_FETCH_TIMEOUT`].
    Timeout,
}

/// Why a referenced status was not accepted. Internal evidence only: every variant answers the
/// same generic HTTP error. Only [`StatusError::Revoked`], [`StatusError::Suspended`] and
/// [`StatusError::NotValid`] are statements about the credential (TSL §7.1); every other
/// variant means its status could not be established (TSL §8.3: "no statement about the
/// status of the Referenced Token can be made").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StatusError {
    /// The credential references a status list, but the Verifier has no status policy, so it
    /// cannot check it (every build without the `conformance` feature, and conformance servers
    /// configured without one).
    #[error("credential references a status list, and no status policy is configured")]
    NoPolicy,
    /// The reference's `uri` is not an `https` URL the issuer policy allows.
    #[error("status list uri is not allowed by the issuer policy")]
    UriNotAllowed,
    /// The Status List Token could not be fetched.
    #[error("status list token could not be fetched: {0:?}")]
    Fetch(FetchFailure),
    /// Not a compact JWS of JSON objects with unique members, a `crit` header, or a required
    /// claim (`sub`, `iat`, `status_list`) missing or of the wrong type.
    #[error("status list token is malformed")]
    TokenMalformed,
    /// `typ` is not `statuslist+jwt` (TSL §5.1).
    #[error("status list token has the wrong typ")]
    TokenTyp,
    /// `alg` is not ES256, including `none`.
    #[error("status list token alg is not accepted")]
    TokenAlg,
    /// Trust anchor policy: no usable `x5c`, or its leaf does not chain to the configured status
    /// trust anchor now (self-signed, anchor inside `x5c`, an EKU present, expired, ...).
    #[error("status list token signer is not trusted")]
    UntrustedSigner,
    /// The signature does not verify with the trusted key (the pinned key, or the `x5c` leaf).
    #[error("status list token signature does not verify")]
    TokenSignature,
    /// `sub` is not the reference's `uri` (TSL §5.1, §8.3 step 4a).
    #[error("status list token sub does not match the reference uri")]
    SubjectMismatch,
    /// `exp` has passed (TSL §8.3 step 4c; RFC 7519 §4.1.4).
    #[error("status list token is expired")]
    TokenExpired,
    /// `iat` or `nbf` lies further in the future than the allowed skew.
    #[error("status list token is not yet valid")]
    TokenNotYetValid,
    /// The token carries `aud`: the lab identifies itself by no audience value, so under RFC
    /// 7519 §4.1.3 ("MUST be rejected") it is meant for someone else.
    #[error("status list token is addressed to an audience")]
    TokenAudience,
    /// `status_list` with `bits` outside {1, 2, 4, 8}, `lst` not canonical base64url of exactly
    /// one ZLIB stream (trailing bytes refused), or the inflated list over
    /// [`MAX_STATUS_LIST_BYTES`] (TSL §4.1, §4.2).
    #[error("status list is malformed")]
    ListMalformed,
    /// `idx` lies outside the list (TSL §8.3 step 6).
    #[error("status list index is out of range")]
    IndexOutOfRange,
    /// Status `0x01` INVALID: revoked (TSL §7.1).
    #[error("credential is revoked")]
    Revoked,
    /// Status `0x02` SUSPENDED (TSL §7.1).
    #[error("credential is suspended")]
    Suspended,
    /// Any other non-zero status value (application specific or reserved, TSL §7.1).
    #[error("credential status {0:#04x} is not VALID")]
    NotValid(u8),
}

/// Status outcome of a response that reached the status check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusResult {
    /// Not reached: the response was refused earlier.
    NotRun,
    /// The credential has no `status` claim; nothing was fetched.
    NotReferenced,
    /// The Status List Token was fetched and verified, and the credential's status is `0x00`
    /// VALID.
    Valid,
    /// The check failed; the response was refused.
    Failed(StatusError),
}

/// A conformance server's status checker; uninhabited in builds without `conformance`, which
/// can therefore never check a referenced status.
#[cfg(not(feature = "conformance"))]
pub(crate) enum StatusChecker {}

#[cfg(feature = "conformance")]
pub(crate) use policy::StatusChecker;
#[cfg(feature = "conformance")]
pub use policy::{
    MAX_STATUS_LIST_BYTES, MAX_STATUS_LIST_TOKEN_BYTES, STATUS_CHECK_TIMEOUT_MARGIN,
    STATUS_LIST_FETCH_TIMEOUT, STATUS_LIST_JWT_MEDIA_TYPE, STATUS_LIST_JWT_TYP,
    STATUS_LIST_MAX_FUTURE_SKEW_SECS, StatusListConfigError, StatusListPolicy, StatusListTrust,
};

/// The status step of the pipeline: [`StatusResult::NotReferenced`] without a reference;
/// with one, [`StatusError::NoPolicy`] without a checker, else the checker's verdict. The
/// checker reads the Verifier's clock itself, after the fetch, so a token that expired while it
/// was being fetched is not accepted.
///
/// # Errors
/// The first failing [`StatusError`].
pub(crate) async fn check(
    checker: Option<&StatusChecker>,
    reference: Option<&StatusReference>,
) -> Result<StatusResult, StatusError> {
    let Some(reference) = reference else {
        return Ok(StatusResult::NotReferenced);
    };
    let Some(checker) = checker else {
        return Err(StatusError::NoPolicy);
    };
    #[cfg(feature = "conformance")]
    {
        checker.check(reference).await
    }
    #[cfg(not(feature = "conformance"))]
    {
        let _ = reference;
        match *checker {}
    }
}

/// Status `0x00` VALID; every other value refuses (TSL §7.1).
#[cfg(any(test, feature = "conformance"))]
const STATUS_VALID: u8 = 0x00;
/// Status `0x01` INVALID (revoked).
#[cfg(any(test, feature = "conformance"))]
const STATUS_INVALID: u8 = 0x01;
/// Status `0x02` SUSPENDED.
#[cfg(any(test, feature = "conformance"))]
const STATUS_SUSPENDED: u8 = 0x02;

/// [`StatusResult::Valid`] for `0x00`, the matching refusal for every other value.
#[cfg(any(test, feature = "conformance"))]
fn verdict(value: u8) -> Result<StatusResult, StatusError> {
    match value {
        STATUS_VALID => Ok(StatusResult::Valid),
        STATUS_INVALID => Err(StatusError::Revoked),
        STATUS_SUSPENDED => Err(StatusError::Suspended),
        other => Err(StatusError::NotValid(other)),
    }
}

/// Bits per byte (the unit TSL §4.1 packs statuses into).
#[cfg(any(test, feature = "conformance"))]
const BITS_PER_BYTE: u64 = 8;

/// The status at `idx` of an inflated list with `bits` bits per entry (TSL §4.1 step 3: blocks
/// packed from the least significant bit of each byte). `None` when `idx` is outside the list.
/// `bits` must be 1, 2, 4 or 8 (checked by the caller).
#[cfg(any(test, feature = "conformance"))]
fn status_at(list: &[u8], bits: u8, idx: u64) -> Option<u8> {
    let bits = u64::from(bits);
    let first_bit = idx.checked_mul(bits)?;
    let byte = usize::try_from(first_bit / BITS_PER_BYTE).ok()?;
    let shift = first_bit % BITS_PER_BYTE;
    let mask = (1u64 << bits) - 1;
    let value = (u64::from(*list.get(byte)?) >> shift) & mask;
    u8::try_from(value).ok()
}

#[cfg(feature = "conformance")]
mod policy {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE, HOST};
    use axum::http::{Request, StatusCode};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hyper_util::rt::TokioIo;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{
        WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
    };
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use serde_json::{Map, Value};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};

    use super::{
        FetchFailure, MAX_STATUS_URI_LEN, STATUS_LIST, StatusError, StatusReference, StatusResult,
        status_at, verdict,
    };
    use session_core::{Clock as _, SystemClock};

    use crate::conformance::{JwsEs256, MAX_CHAIN_CERTIFICATES};
    use crate::jose::{self, CompactJws, HeaderError};
    use crate::sd_jwt::TrustedIssuerKey;
    use crate::server::MILLIS_PER_SECOND;

    /// `typ` of a Status List Token in JWT format (TSL §5.1).
    pub const STATUS_LIST_JWT_TYP: &str = "statuslist+jwt";
    /// Media type of a Status List Token in JWT format: the `Accept` the lab sends (TSL §8.1)
    /// and the only `Content-Type` it accepts (§8.2).
    pub const STATUS_LIST_JWT_MEDIA_TYPE: &str = "application/statuslist+jwt";
    /// Whole-fetch deadline (lab policy): connect, TLS, request and body. A fixed half of the
    /// *default* request timeout (`DEFAULT_REQUEST_TIMEOUT`, 10 s), whatever timeout a server is
    /// configured with, so a stalled Status Provider fails the status check, which is recorded,
    /// before the response POST itself times out.
    pub const STATUS_LIST_FETCH_TIMEOUT: Duration = crate::DEFAULT_REQUEST_TIMEOUT
        .checked_div(2)
        .expect("non-zero divisor");
    /// Headroom a server with a status policy needs on top of [`STATUS_LIST_FETCH_TIMEOUT`] in
    /// its `request_timeout` (lab policy), for the work before the fetch (admission, decryption
    /// slot, trial); below the sum it refuses to start (`StartError::StatusFetchTimeout`). The
    /// default request timeout leaves 5 s.
    pub const STATUS_CHECK_TIMEOUT_MARGIN: Duration = Duration::from_secs(2);
    /// Largest Status List Token body the lab reads, in bytes (lab policy). The OIDF suite's
    /// token is about 2 KiB (its header carries the signer's `x5c` twice); a list of a million
    /// 1-bit entries compresses to well under this.
    pub const MAX_STATUS_LIST_TOKEN_BYTES: usize = 64 * 1024;
    /// Largest inflated Status List, in bytes (lab policy): 8 Mi entries at one bit each. Bounds
    /// the output of ZLIB inflation, so a small token cannot expand into a large allocation
    /// (TSL §11.1).
    pub const MAX_STATUS_LIST_BYTES: usize = 1024 * 1024;
    /// Largest accepted `iat` / `nbf` in the future, in seconds (clock skew between Status
    /// Issuer and Verifier; lab policy, the same skew the KB-JWT gets).
    pub const STATUS_LIST_MAX_FUTURE_SKEW_SECS: u64 = crate::KB_JWT_MAX_FUTURE_SKEW_SECS;

    /// Status List Token claims (TSL §5.1; RFC 7519 §4.1.2, §4.1.4-§4.1.6).
    const SUB: &str = "sub";
    const IAT: &str = "iat";
    const EXP: &str = "exp";
    const NBF: &str = "nbf";
    const TTL: &str = "ttl";
    const AUD: &str = "aud";
    /// `status_list` members (TSL §4.2).
    const BITS: &str = "bits";
    const LST: &str = "lst";
    /// The `bits` values TSL §4.1 step 1 allows.
    const ALLOWED_BITS: [u8; 4] = [1, 2, 4, 8];
    /// The `x5c` header parameter (RFC 7515 §4.1.6: standard base64 DER, leaf first).
    const HEADER_X5C: &str = "x5c";
    /// The only scheme of a Status List `uri` (lab policy) and the default HTTPS port.
    const HTTPS_SCHEME: &str = "https://";
    const HTTPS_DEFAULT_PORT: u16 = 443;
    /// Application protocol of the fetch (RFC 7301 ALPN identifier for HTTP/1.1).
    const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
    /// Characters allowed in the part of a `uri` after the policy prefix (lab policy: RFC 3986
    /// unreserved characters and `/`; no percent-encoding, so no dot segment can hide in one).
    const URI_SUFFIX_EXTRA: &[u8] = b"-._~/";
    /// RFC 3986 §3.3 dot segments, refused anywhere in the path.
    const DOT_SEGMENTS: [&str; 2] = [".", ".."];

    /// How the signature of a Status List Token is trusted (TSL §11.3).
    #[derive(Debug, Clone)]
    pub enum StatusListTrust {
        /// One explicitly configured EC P-256 public key, ES256. Whatever key material the
        /// token's header carries (`jwk`, `x5c`, `kid`) is ignored. For the OIDF suite, which
        /// signs its lists with the configured credential issuer key (`credential.signing_jwk`)
        /// and only a throwaway self-signed `x5c` (README §5a).
        PinnedKey(TrustedIssuerKey),
        /// The token's `x5c` chain (leaf first, at most `MAX_CHAIN_CERTIFICATES`, without the
        /// anchor) must lead to this trust anchor now, with a leaf that is not self-signed and
        /// no certificate on the path (leaf or intermediate) carrying an extended key usage; the leaf's P-256 key must verify the ES256 signature
        /// (TSL §11.3: a Status Issuer certificate issued by a Certificate Authority).
        X509 {
            /// The status trust anchor (DER).
            trust_anchor: CertificateDer<'static>,
        },
    }

    impl StatusListTrust {
        /// [`StatusListTrust::PinnedKey`] from an EC P-256 public JWK (no `d`).
        ///
        /// # Errors
        /// [`StatusListConfigError::Key`].
        pub fn pinned_key(public_jwk: &str) -> Result<Self, StatusListConfigError> {
            TrustedIssuerKey::from_jwk(public_jwk)
                .map(Self::PinnedKey)
                .map_err(|_| StatusListConfigError::Key)
        }

        /// [`StatusListTrust::X509`] from a PEM `CERTIFICATE`, checked to be usable as a
        /// trust anchor.
        ///
        /// # Errors
        /// [`StatusListConfigError::TrustAnchor`].
        pub fn x509_from_pem(trust_anchor_pem: &[u8]) -> Result<Self, StatusListConfigError> {
            let trust_anchor = CertificateDer::from_pem_slice(trust_anchor_pem)
                .map_err(|_| StatusListConfigError::TrustAnchor)?;
            webpki::anchor_from_trusted_cert(&trust_anchor)
                .map_err(|_| StatusListConfigError::TrustAnchor)?;
            Ok(Self::X509 { trust_anchor })
        }
    }

    /// Why a status policy was refused.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[non_exhaustive]
    pub enum StatusListConfigError {
        /// The URI prefix is not an `https://<host>[:<port>]/<path>/` URL ending in `/` (no
        /// query, fragment, user info or dot segment), or over [`MAX_STATUS_URI_LEN`].
        #[error(
            "status list uri prefix must be an https URL ending in /, without query or fragment"
        )]
        UriPrefix,
        /// The pinned key is not an EC P-256 public JWK.
        #[error("status list key must be an EC P-256 public JWK without d")]
        Key,
        /// The trust anchor is not a usable PEM certificate.
        #[error("status list trust anchor must be a PEM certificate")]
        TrustAnchor,
        /// The pinned TLS server certificate is not a PEM certificate.
        #[error("status list TLS certificate must be a PEM certificate")]
        TlsCertificate,
    }

    /// The issuer's status policy (`ConformanceConfig::status_list`): which Status List URIs the
    /// Verifier follows, how it trusts their tokens, and the one TLS server certificate it
    /// accepts from their Status Provider.
    #[derive(Debug, Clone)]
    pub struct StatusListPolicy {
        uri_prefix: String,
        trust: StatusListTrust,
        tls_server_certificate: CertificateDer<'static>,
    }

    impl StatusListPolicy {
        /// A policy that follows only `uri` values starting with `uri_prefix` (an `https` URL
        /// ending in `/`, e.g. `https://localhost:8443/test/a/<alias>/statuslists/`), trusts
        /// tokens by `trust`, and pins `tls_server_certificate_pem`: the Status Provider's TLS
        /// end-entity certificate, compared byte for byte (its name, issuer and validity are
        /// not checked; the handshake signature must still verify with its key).
        ///
        /// # Errors
        /// [`StatusListConfigError::UriPrefix`], [`StatusListConfigError::TlsCertificate`].
        pub fn new(
            uri_prefix: impl Into<String>,
            trust: StatusListTrust,
            tls_server_certificate_pem: &[u8],
        ) -> Result<Self, StatusListConfigError> {
            let uri_prefix = uri_prefix.into();
            let path_ok = split_https(&uri_prefix).is_some_and(|(_, path)| path_is_plain(path));
            if uri_prefix.len() > MAX_STATUS_URI_LEN
                || !uri_prefix.ends_with('/')
                || !crate::config::is_https_url(&uri_prefix)
                || uri_prefix.contains('?')
                || !path_ok
            {
                return Err(StatusListConfigError::UriPrefix);
            }
            let tls_server_certificate = CertificateDer::from_pem_slice(tls_server_certificate_pem)
                .map_err(|_| StatusListConfigError::TlsCertificate)?;
            Ok(Self {
                uri_prefix,
                trust,
                tls_server_certificate,
            })
        }

        /// The URI prefix.
        #[must_use]
        pub fn uri_prefix(&self) -> &str {
            &self.uri_prefix
        }

        /// How tokens are trusted, for logs: the pinned key's RFC 7638 thumbprint, or the
        /// trust anchor's SHA-256; and the pinned TLS certificate's SHA-256.
        #[must_use]
        pub fn trust_description(&self) -> String {
            let sha256 = |der: &[u8]| jose::sha256_b64(der);
            let trust = match &self.trust {
                StatusListTrust::PinnedKey(key) => {
                    format!("pinned key (thumbprint {})", key.thumbprint())
                }
                StatusListTrust::X509 { trust_anchor } => {
                    format!("x5c to trust anchor (sha-256 {})", sha256(trust_anchor))
                }
            };
            format!(
                "{trust}, TLS certificate pinned (sha-256 {})",
                sha256(&self.tls_server_certificate)
            )
        }

        /// Whether `uri` is one the policy follows (module table, step 1).
        fn allows(&self, uri: &str) -> bool {
            let Some(suffix) = uri.strip_prefix(self.uri_prefix.as_str()) else {
                return false;
            };
            uri.len() <= MAX_STATUS_URI_LEN
                && !suffix.is_empty()
                && crate::config::is_https_url(uri)
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || URI_SUFFIX_EXTRA.contains(&b))
                // Every segment after the prefix is non-empty and no dot segment, whatever the
                // prefix's own path (also `/`): no `//`, no trailing `/`.
                && suffix
                    .split('/')
                    .all(|segment| !segment.is_empty() && !DOT_SEGMENTS.contains(&segment))
                && split_https(uri).is_some_and(|(_, path)| path_is_plain(path))
        }
    }

    /// `https://<authority><path>` split into authority and path (`/` when absent).
    fn split_https(url: &str) -> Option<(&str, &str)> {
        let rest = url.strip_prefix(HTTPS_SCHEME)?;
        Some(match rest.find('/') {
            Some(slash) => rest.split_at(slash),
            None => (rest, "/"),
        })
    }

    /// No RFC 3986 dot segment, no empty segment (`//`) and no percent-encoding in `path`
    /// (the leading and one trailing `/`, as every prefix has, are not segments).
    fn path_is_plain(path: &str) -> bool {
        let inner = path.strip_prefix('/').unwrap_or(path);
        let inner = inner.strip_suffix('/').unwrap_or(inner);
        !path.contains('%')
            && (inner.is_empty()
                || !inner
                    .split('/')
                    .any(|segment| segment.is_empty() || DOT_SEGMENTS.contains(&segment)))
    }

    /// Host (brackets removed for an IPv6 literal) and port of an authority without user info.
    fn host_port(authority: &str) -> Option<(&str, u16)> {
        if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, rest) = bracketed.split_once(']')?;
            let port = match rest.strip_prefix(':') {
                Some(port) => port.parse().ok()?,
                None if rest.is_empty() => HTTPS_DEFAULT_PORT,
                None => return None,
            };
            return Some((host, port));
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => Some((host, port.parse().ok()?)),
            None => Some((authority, HTTPS_DEFAULT_PORT)),
        }
    }

    /// A [`StatusListPolicy`] ready to run: the policy and its TLS client.
    pub(crate) struct StatusChecker {
        policy: StatusListPolicy,
        tls: TlsConnector,
    }

    impl StatusChecker {
        /// The TLS client of `policy`: TLS 1.3 only, the ring provider passed explicitly (as for
        /// the server side, no process default is relied on), HTTP/1.1 via ALPN, and the server
        /// certificate pinned ([`PinnedServerCertificate`]).
        ///
        /// # Errors
        /// rustls refused the configuration.
        pub(crate) fn new(policy: StatusListPolicy) -> Result<Self, rustls::Error> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = PinnedServerCertificate {
                pinned: policy.tls_server_certificate.clone(),
                algorithms: provider.signature_verification_algorithms,
            };
            let mut tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            tls.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
            Ok(Self {
                policy,
                tls: TlsConnector::from(Arc::new(tls)),
            })
        }

        /// Module table, steps 1-12, for `reference`. Time checks (token and signer
        /// certificate) use the clock read after the fetch completed.
        pub(crate) async fn check(
            &self,
            reference: &StatusReference,
        ) -> Result<StatusResult, StatusError> {
            if !self.policy.allows(&reference.uri) {
                return Err(StatusError::UriNotAllowed);
            }
            let token = tokio::time::timeout(STATUS_LIST_FETCH_TIMEOUT, self.fetch(&reference.uri))
                .await
                .map_err(|_| StatusError::Fetch(FetchFailure::Timeout))?
                .map_err(StatusError::Fetch)?;
            let token = std::str::from_utf8(&token).map_err(|_| StatusError::TokenMalformed)?;
            let now = SystemClock.now().as_unix_millis() / MILLIS_PER_SECOND;
            verdict(token_status(token, reference, &self.policy.trust, now)?)
        }

        /// Steps 2-4: one `GET` of `uri` over TLS to a loopback address; the body.
        async fn fetch(&self, uri: &str) -> Result<Vec<u8>, FetchFailure> {
            // `allows` checked the shape; these cannot fail for an allowed `uri`.
            let (authority, path) = split_https(uri).ok_or(FetchFailure::Http)?;
            let (host, port) = host_port(authority).ok_or(FetchFailure::Http)?;
            let addresses: Vec<_> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| FetchFailure::NotLoopback)?
                .collect();
            if addresses.is_empty() || !addresses.iter().all(|a| a.ip().is_loopback()) {
                return Err(FetchFailure::NotLoopback);
            }
            let mut tcp = None;
            for address in addresses {
                if let Ok(stream) = TcpStream::connect(address).await {
                    tcp = Some(stream);
                    break;
                }
            }
            let tcp = tcp.ok_or(FetchFailure::Connect)?;
            let name = ServerName::try_from(host.to_owned()).map_err(|_| FetchFailure::Tls)?;
            let tls = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|_| FetchFailure::Tls)?;
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|_| FetchFailure::Http)?;
            // Aborted when this future ends or is dropped (fetch deadline, request timeout),
            // so a stalled connection never outlives the check.
            let _driver = AbortOnDrop(tokio::spawn(connection));
            async {
                let request = Request::get(path)
                    .header(HOST, authority)
                    .header(ACCEPT, STATUS_LIST_JWT_MEDIA_TYPE)
                    .body(Body::empty())
                    .map_err(|_| FetchFailure::Http)?;
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(|_| FetchFailure::Http)?;
                if response.status() != StatusCode::OK {
                    return Err(FetchFailure::Status(response.status().as_u16()));
                }
                let headers = response.headers();
                let essence = headers
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.split(';').next())
                    .map(str::trim);
                if !essence.is_some_and(|e| e.eq_ignore_ascii_case(STATUS_LIST_JWT_MEDIA_TYPE)) {
                    return Err(FetchFailure::ContentType);
                }
                if headers.contains_key(CONTENT_ENCODING) {
                    return Err(FetchFailure::ContentEncoding);
                }
                let body = axum::body::to_bytes(
                    Body::new(response.into_body()),
                    MAX_STATUS_LIST_TOKEN_BYTES,
                )
                .await
                .map_err(|_| FetchFailure::Body)?;
                Ok(body.to_vec())
            }
            .await
        }
    }

    /// Aborts the task when dropped.
    struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Steps 5-11 over a fetched token: the status value at the reference's index.
    fn token_status(
        token: &str,
        reference: &StatusReference,
        trust: &StatusListTrust,
        now: u64,
    ) -> Result<u8, StatusError> {
        let jws = CompactJws::parse(token).ok_or(StatusError::TokenMalformed)?;
        jws.check_header(STATUS_LIST_JWT_TYP).map_err(|e| match e {
            HeaderError::Malformed => StatusError::TokenMalformed,
            HeaderError::Typ => StatusError::TokenTyp,
            HeaderError::Alg => StatusError::TokenAlg,
        })?;
        verify_signature(&jws, trust, now)?;
        let claims = &jws.payload;
        if claims
            .get(SUB)
            .and_then(Value::as_str)
            .ok_or(StatusError::TokenMalformed)?
            != reference.uri
        {
            return Err(StatusError::SubjectMismatch);
        }
        let iat = numeric_date(claims, IAT)?.ok_or(StatusError::TokenMalformed)?;
        let nbf = numeric_date(claims, NBF)?;
        let exp = numeric_date(claims, EXP)?;
        if numeric_date(claims, TTL)? == Some(0) {
            return Err(StatusError::TokenMalformed);
        }
        if claims.contains_key(AUD) {
            return Err(StatusError::TokenAudience);
        }
        if exp.is_some_and(|exp| now >= exp) {
            return Err(StatusError::TokenExpired);
        }
        let latest = now.saturating_add(STATUS_LIST_MAX_FUTURE_SKEW_SECS);
        if iat > latest || nbf.is_some_and(|nbf| nbf > latest) {
            return Err(StatusError::TokenNotYetValid);
        }
        let list = claims
            .get(STATUS_LIST)
            .and_then(Value::as_object)
            .ok_or(StatusError::TokenMalformed)?;
        let bits = list
            .get(BITS)
            .and_then(Value::as_u64)
            .and_then(|b| u8::try_from(b).ok())
            .filter(|b| ALLOWED_BITS.contains(b))
            .ok_or(StatusError::ListMalformed)?;
        let compressed = list
            .get(LST)
            .and_then(Value::as_str)
            .and_then(jose::b64_decode)
            .ok_or(StatusError::ListMalformed)?;
        let inflated = inflate_one_zlib_stream(&compressed).ok_or(StatusError::ListMalformed)?;
        status_at(&inflated, bits, reference.idx).ok_or(StatusError::IndexOutOfRange)
    }

    /// Inflates `compressed` as exactly one ZLIB stream (RFC 1950: header, DEFLATE data, Adler-32
    /// checked) into at most [`MAX_STATUS_LIST_BYTES`]; `None` for a malformed stream, a larger
    /// output, or any byte after the stream's end (a second stream could say something else).
    fn inflate_one_zlib_stream(compressed: &[u8]) -> Option<Vec<u8>> {
        use miniz_oxide::inflate::stream::{InflateState, inflate};
        use miniz_oxide::{DataFormat, MZFlush, MZStatus};
        let mut state = InflateState::new_boxed(DataFormat::Zlib);
        // One byte of headroom: a list that fills it is over the bound.
        let mut out = vec![0u8; MAX_STATUS_LIST_BYTES + 1];
        let result = inflate(&mut state, compressed, &mut out, MZFlush::Finish);
        let complete = result.status == Ok(MZStatus::StreamEnd)
            && result.bytes_consumed == compressed.len()
            && result.bytes_written <= MAX_STATUS_LIST_BYTES;
        complete.then(|| {
            out.truncate(result.bytes_written);
            out
        })
    }

    /// An optional NumericDate claim, as an integer (RFC 7519 §2; lab policy: no fractions, as
    /// for every other JWT the lab verifies).
    fn numeric_date(claims: &Map<String, Value>, name: &str) -> Result<Option<u64>, StatusError> {
        match claims.get(name) {
            None => Ok(None),
            Some(value) => value.as_u64().map(Some).ok_or(StatusError::TokenMalformed),
        }
    }

    /// Step 6 for either trust mode.
    fn verify_signature(
        jws: &CompactJws<'_>,
        trust: &StatusListTrust,
        now: u64,
    ) -> Result<(), StatusError> {
        match trust {
            StatusListTrust::PinnedKey(key) => {
                if jws.verify_es256(key.verifying_key()) {
                    Ok(())
                } else {
                    Err(StatusError::TokenSignature)
                }
            }
            StatusListTrust::X509 { trust_anchor } => {
                let chain = x5c_chain(&jws.header).ok_or(StatusError::UntrustedSigner)?;
                if chain.contains(trust_anchor) {
                    return Err(StatusError::UntrustedSigner);
                }
                let leaf =
                    EndEntityCert::try_from(&chain[0]).map_err(|_| StatusError::UntrustedSigner)?;
                if leaf.issuer() == leaf.subject() {
                    return Err(StatusError::UntrustedSigner);
                }
                let anchor = webpki::anchor_from_trusted_cert(trust_anchor)
                    .map_err(|_| StatusError::UntrustedSigner)?;
                leaf.verify_for_usage(
                    &[webpki::ring::ECDSA_P256_SHA256],
                    &[anchor],
                    &chain[1..],
                    UnixTime::since_unix_epoch(Duration::from_secs(now)),
                    NoExtendedKeyUsage,
                    None,
                    None,
                )
                .map_err(|_| StatusError::UntrustedSigner)?;
                // ES256 needs a P-256 leaf key; the JWS signature is `R || S` (RFC 7518 §3.4).
                leaf.verify_signature(&JwsEs256, jws.signing_input().as_bytes(), jws.signature())
                    .map_err(|_| StatusError::TokenSignature)
            }
        }
    }

    /// The `x5c` header: 1 to `MAX_CHAIN_CERTIFICATES` standard base64 DER certificates.
    fn x5c_chain(header: &Map<String, Value>) -> Option<Vec<CertificateDer<'static>>> {
        let entries = header.get(HEADER_X5C)?.as_array()?;
        if entries.is_empty() || entries.len() > MAX_CHAIN_CERTIFICATES {
            return None;
        }
        // Every entry must parse as a certificate, used on the path or not (RFC 7515 §4.1.6).
        entries
            .iter()
            .map(|entry| {
                let der = CertificateDer::from(STANDARD.decode(entry.as_str()?).ok()?);
                EndEntityCert::try_from(&der).ok()?;
                Some(der)
            })
            .collect()
    }

    /// Extended key usage policy for status signers: none at all. TSL §10 defines
    /// `id-kp-oauthStatusSigning` but leaves its OID TBD (through draft-19), so no certificate
    /// can carry it yet; requiring the extension to be absent keeps certificates issued for
    /// another purpose (a TLS server's `serverAuth`) from signing status lists. webpki applies
    /// it to every certificate on the path, so an intermediate with an EKU is refused too.
    struct NoExtendedKeyUsage;

    impl ExtendedKeyUsageValidator for NoExtendedKeyUsage {
        fn validate(&self, mut iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
            match iter.next() {
                None => Ok(()),
                // The context variant has no public constructor; the error is only mapped to
                // `StatusError::UntrustedSigner` anyway.
                #[allow(deprecated)]
                Some(_) => Err(webpki::Error::RequiredEkuNotFound),
            }
        }
    }

    /// Accepts exactly one TLS server certificate, byte for byte, and verifies the TLS 1.3
    /// handshake signature with its key (rustls `verify_tls13_signature`, ring algorithms). The
    /// certificate's name, issuer and validity are not evaluated: the pin replaces path
    /// validation (the OIDF suite's nginx certificate is a self-signed `CN=localhost` with no
    /// SAN, which no WebPKI path validation accepts).
    #[derive(Debug)]
    struct PinnedServerCertificate {
        pinned: CertificateDer<'static>,
        algorithms: WebPkiSupportedAlgorithms,
    }

    impl ServerCertVerifier for PinnedServerCertificate {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if end_entity.as_ref() == self.pinned.as_ref() {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            // Unreachable: the client offers TLS 1.3 only.
            verify_tls12_signature(message, cert, dss, &self.algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(message, cert, dss, &self.algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.algorithms.supported_schemes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn uri_prefix_and_uri_policy_are_strict() {
            let pem = include_bytes!("../tests/fixtures/conformance_leaf.pem");
            let trust =
                StatusListTrust::pinned_key(include_str!("../tests/fixtures/lab_issuer.pub.jwk"))
                    .expect("pinned key");
            for bad in [
                "http://localhost:8443/lists/",
                "https://localhost:8443/lists",
                "https://localhost:8443/lists/?x=1/",
                "https://localhost:8443/lists/#/",
                "https://user@localhost:8443/lists/",
                "https://localhost:8443/a/../lists/",
                "https://localhost:8443/a/%2e%2e/",
            ] {
                assert_eq!(
                    StatusListPolicy::new(bad, trust.clone(), pem).err(),
                    Some(StatusListConfigError::UriPrefix),
                    "{bad}"
                );
            }
            let policy =
                StatusListPolicy::new("https://localhost:8443/lists/", trust, pem).expect("policy");
            assert!(policy.allows("https://localhost:8443/lists/abc-1_2.3~"));
            assert!(policy.allows("https://localhost:8443/lists/a/b"));
            // A root prefix: `//` and a trailing `/` after it are refused too.
            let root = StatusListPolicy::new(
                "https://localhost:8443/",
                StatusListTrust::pinned_key(include_str!("../tests/fixtures/lab_issuer.pub.jwk"))
                    .expect("pinned key"),
                pem,
            )
            .expect("root policy");
            assert!(root.allows("https://localhost:8443/lists/1"));
            for refused in [
                "https://localhost:8443//",
                "https://localhost:8443//1",
                "https://localhost:8443/lists/",
                "https://localhost:8443/lists//1",
            ] {
                assert!(!root.allows(refused), "{refused}");
            }
            for refused in [
                "https://localhost:8443/lists/",
                "https://localhost:8443/lists",
                "https://localhost:8443/listsX/1",
                "https://localhost:8443/lists/../admin",
                "https://localhost:8443/lists/./1",
                "https://localhost:8443/lists//1",
                "https://localhost:8443/lists/%2e%2e/1",
                "https://localhost:8443/lists/1?time=1",
                "https://localhost:8443/lists/1#x",
                "https://localhost:8444/lists/1",
                "https://localhost:8443.evil.example/lists/1",
            ] {
                assert!(!policy.allows(refused), "{refused}");
            }
        }

        /// The status signer policy refuses any extended key usage: the conformance leaf
        /// (`serverAuth`) chains to its CA for TLS, but not as a status signer; the status
        /// signer fixture (no EKU) chains to the status CA.
        #[test]
        fn status_signer_certificates_must_carry_no_extended_key_usage() {
            // 2027-01-15T08:00:00Z, inside every fixture's validity (the generator's check time).
            const FIXTURE_CHECK_TIME_SECS: u64 = 1_800_000_000;
            let chains = |leaf_pem: &[u8], ca_pem: &[u8], status_signer: bool| {
                let leaf = CertificateDer::from_pem_slice(leaf_pem).expect("leaf");
                let ca = CertificateDer::from_pem_slice(ca_pem).expect("ca");
                let anchor = webpki::anchor_from_trusted_cert(&ca).expect("anchor");
                let leaf = EndEntityCert::try_from(&leaf).expect("end entity");
                let at = UnixTime::since_unix_epoch(Duration::from_secs(FIXTURE_CHECK_TIME_SECS));
                let algs = [webpki::ring::ECDSA_P256_SHA256];
                let anchors = [anchor];
                if status_signer {
                    leaf.verify_for_usage(&algs, &anchors, &[], at, NoExtendedKeyUsage, None, None)
                        .is_ok()
                } else {
                    leaf.verify_for_usage(
                        &algs,
                        &anchors,
                        &[],
                        at,
                        webpki::KeyUsage::server_auth(),
                        None,
                        None,
                    )
                    .is_ok()
                }
            };
            let leaf = include_bytes!("../tests/fixtures/conformance_leaf.pem");
            let ca = include_bytes!("../tests/fixtures/conformance_ca.pem");
            let signer = include_bytes!("../tests/fixtures/status_signer.pem");
            let status_ca = include_bytes!("../tests/fixtures/status_ca.pem");
            assert!(
                chains(leaf, ca, false),
                "the leaf is a valid TLS server certificate"
            );
            assert!(!chains(leaf, ca, true), "but not a status signer");
            assert!(chains(signer, status_ca, true));
            assert!(
                !chains(signer, ca, true),
                "the status CA alone certifies it"
            );
        }

        #[test]
        fn host_and_port_are_split_from_the_authority() {
            assert_eq!(host_port("localhost:8443"), Some(("localhost", 8443)));
            assert_eq!(
                host_port("localhost"),
                Some(("localhost", HTTPS_DEFAULT_PORT))
            );
            assert_eq!(host_port("[::1]:8443"), Some(("::1", 8443)));
            assert_eq!(host_port("[::1]"), Some(("::1", HTTPS_DEFAULT_PORT)));
            assert_eq!(host_port("[::1]x"), None);
            assert_eq!(host_port("localhost:x"), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// TSL §4.1: the 1-bit example (16 entries, bytes `0xB9 0xA3`) and the 2-bit example
    /// (12 entries, bytes `0xC9 0x44 0xF9`), entry by entry as printed.
    #[test]
    fn status_values_are_read_as_tsl_section_4_1_packs_them() {
        let one_bit = [0xB9, 0xA3];
        let expected_one = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        for (idx, want) in expected_one.iter().enumerate() {
            assert_eq!(
                status_at(&one_bit, 1, idx as u64),
                Some(*want),
                "1-bit idx {idx}"
            );
        }
        assert_eq!(status_at(&one_bit, 1, 16), None);
        let two_bit = [0xC9, 0x44, 0xF9];
        let expected_two = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
        for (idx, want) in expected_two.iter().enumerate() {
            assert_eq!(
                status_at(&two_bit, 2, idx as u64),
                Some(*want),
                "2-bit idx {idx}"
            );
        }
        assert_eq!(status_at(&two_bit, 2, 12), None);
        assert_eq!(status_at(&[0xAB], 8, 0), Some(0xAB));
        assert_eq!(status_at(&[0xAB], 8, 1), None);
        assert_eq!(status_at(&[0x0F], 4, 0), Some(0x0F));
        assert_eq!(status_at(&[0x0F], 4, 1), Some(0));
        assert_eq!(status_at(&one_bit, 1, u64::MAX), None);
    }

    #[test]
    fn only_valid_is_accepted_and_every_other_value_has_its_own_refusal() {
        assert_eq!(verdict(0x00), Ok(StatusResult::Valid));
        assert_eq!(verdict(0x01), Err(StatusError::Revoked));
        assert_eq!(verdict(0x02), Err(StatusError::Suspended));
        assert_eq!(verdict(0x03), Err(StatusError::NotValid(0x03)));
        assert_eq!(verdict(0xFF), Err(StatusError::NotValid(0xFF)));
    }

    #[test]
    fn status_reference_is_parsed_strictly() {
        let payload = |status: Value| {
            json!({ "vct": "x", "status": status })
                .as_object()
                .cloned()
                .expect("object")
        };
        assert_eq!(reference(&Map::new()), Ok(None));
        assert_eq!(
            reference(&payload(
                json!({ "status_list": { "idx": 7, "uri": "https://s.example/1" } })
            )),
            Ok(Some(StatusReference {
                uri: "https://s.example/1".to_owned(),
                idx: 7
            }))
        );
        // Another mechanism next to it is ignored (TSL §6.2: "at least one reference").
        assert!(matches!(
            reference(&payload(json!({
                "status_list": { "idx": 0, "uri": "https://s.example/1" },
                "identifier_list": { "id": "1", "uri": "https://s.example/i" }
            }))),
            Ok(Some(_))
        ));
        let long_uri = format!("https://s.example/{}", "a".repeat(MAX_STATUS_URI_LEN));
        for bad in [
            json!("revoked"),
            json!({}),
            json!({ "identifier_list": { "id": "1", "uri": "https://s.example/i" } }),
            json!({ "status_list": [] }),
            json!({ "status_list": { "uri": "https://s.example/1" } }),
            json!({ "status_list": { "idx": -1, "uri": "https://s.example/1" } }),
            json!({ "status_list": { "idx": 1.5, "uri": "https://s.example/1" } }),
            json!({ "status_list": { "idx": "1", "uri": "https://s.example/1" } }),
            json!({ "status_list": { "idx": 1 } }),
            json!({ "status_list": { "idx": 1, "uri": "" } }),
            json!({ "status_list": { "idx": 1, "uri": 1 } }),
            json!({ "status_list": { "idx": 1, "uri": long_uri } }),
        ] {
            assert_eq!(
                reference(&payload(bad.clone())),
                Err(ValidationError::StatusClaimMalformed),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_checker_a_referenced_status_is_refused() {
        let reference = StatusReference {
            uri: "https://s.example/1".to_owned(),
            idx: 0,
        };
        assert_eq!(check(None, None).await, Ok(StatusResult::NotReferenced));
        assert_eq!(
            check(None, Some(&reference)).await,
            Err(StatusError::NoPolicy)
        );
    }
}
