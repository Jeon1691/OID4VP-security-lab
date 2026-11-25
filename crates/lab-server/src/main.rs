//! Runs the lab server.
//!
//! ```text
//! lab-server --signing-key <jwk file> --issuer-key <public jwk file> [--client-id <id>]
//!            [--mode hardened|research-kid|research-trial=<budget>|conformance]
//!            [--bind <ip:port>] [--session-ttl-secs <n>] [--authorization-endpoint <url>]
//!            [--credential-query-id <id>] [--vct <vct>] [--claims <name,name,...>]
//!   conformance mode only (`conformance` feature):
//!            --tls-cert <chain pem> --tls-key <key pem> --trust-anchor <ca pem>
//!            --public-origin https://<host>[:<port>]
//!            [--client-id-prefix x509_san_dns|x509_hash] [--max-runtime-secs <n>]
//!            [--response-redirect-uri <https url>]
//! ```
//!
//! `LAB_SIGNING_KEY` / `LAB_ISSUER_KEY` / `LAB_CLIENT_ID` / `LAB_MODE` / `LAB_BIND` /
//! `LAB_CREDENTIAL_QUERY_ID` / `LAB_VCT` / `LAB_CLAIMS` are used when the flag is absent.
//! Defaults: hardened on `127.0.0.1:0`, `client_id` = `DEFAULT_CLIENT_ID`, and the synthetic
//! lab Credential Query (`CredentialRequest::synthetic`); `--credential-query-id`, `--vct` and
//! `--claims` replace its parts (claims are top-level claim names, comma-separated).
//!
//! The trusted SD-JWT VC issuer key (EC P-256 public JWK, no `d`) is required too: only
//! presentations whose issuer JWT verifies with it are accepted. The synthetic lab issuer's
//! public key is `crates/lab-server/tests/fixtures/lab_issuer.pub.jwk`.
//!
//! The Request Object signing key (EC P-256 private JWK) is required and only ever read from
//! the named file (buffer zeroized after parsing); the binary contains no key. A did:key
//! `client_id` must be the did:key of that key, or the server refuses to start.
//! The synthetic SpruceID fixture matches the default `client_id`, so a lab run passes it
//! explicitly: `--signing-key crates/lab-server/tests/fixtures/spruce_verifier.jwk`.
//!
//! **Conformance mode** (docs/adr/0002-conformance-mode.md) exists only in a binary built with
//! `--features conformance`, and only on the explicit `--mode conformance` flag: `LAB_MODE`
//! cannot select it, and a binary without the feature refuses the flag. It serves HTTPS on the
//! loopback bind with `--tls-cert` / `--tls-key` (the synthetic fixtures
//! `tests/fixtures/conformance_leaf.pem` / `conformance_leaf.key.pem`, whose key is also
//! `conformance_leaf.jwk` for `--signing-key`), checks them against `--trust-anchor`
//! (`conformance_ca.pem`, also what the suite is configured with), and hands out URLs under
//! `--public-origin` (e.g. `https://host.docker.internal:<port>`; without a port the bound one).
//! `--client-id-prefix` derives the client id from the certificate (`x509_san_dns:<origin host>`
//! or `x509_hash:<leaf hash>`) instead of `--client-id`. It stops by itself after
//! `--max-runtime-secs` (default `DEFAULT_CONFORMANCE_MAX_RUNTIME`).
//!
//! Every mode refuses non-loopback addresses (lab policy; ADR 0002 keeps that for conformance
//! mode too). Build release artifacts with a plain `cargo build -p lab-server`, so the
//! test-only `wallet-sim` feature is not unified in.

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;

use lab_server::{
    CredentialRequest, LabConfig, LabServer, Mode, RequestSigningKey, SharedRouteStrategy,
    TrustedIssuerKey,
};
use protocol_model::ClientIdWire;
use session_core::CandidateBudget;
use zeroize::Zeroizing;

const USAGE: &str = "usage: lab-server --signing-key <jwk file> --issuer-key <public jwk file> \
[--client-id <id>] [--mode hardened|research-kid|research-trial=<budget>|conformance] \
[--bind <ip:port>] [--session-ttl-secs <n>] [--authorization-endpoint <url>] \
[--credential-query-id <id>] [--vct <vct>] [--claims <name,name,...>] \
[conformance: --tls-cert <pem> --tls-key <pem> --trust-anchor <pem> \
--public-origin https://<host>[:<port>] [--client-id-prefix x509_san_dns|x509_hash] \
[--max-runtime-secs <n>] [--response-redirect-uri <url>]]";
/// Separator of the `--claims` list.
const CLAIMS_SEPARATOR: char = ',';
const TRIAL_PREFIX: &str = "research-trial=";
/// The `--mode` value of conformance mode (CLI only, never from `LAB_MODE`).
const CONFORMANCE_MODE: &str = "conformance";
/// Every flag the binary takes; each takes one value.
const FLAGS: [&str; 17] = [
    "--signing-key",
    "--issuer-key",
    "--client-id",
    "--mode",
    "--bind",
    "--session-ttl-secs",
    "--authorization-endpoint",
    "--credential-query-id",
    "--vct",
    "--claims",
    "--tls-cert",
    "--tls-key",
    "--trust-anchor",
    "--public-origin",
    "--client-id-prefix",
    "--max-runtime-secs",
    "--response-redirect-uri",
];
/// Flags meaningful only in conformance mode.
const CONFORMANCE_FLAGS: [&str; 7] = [
    "--tls-cert",
    "--tls-key",
    "--trust-anchor",
    "--public-origin",
    "--client-id-prefix",
    "--max-runtime-secs",
    "--response-redirect-uri",
];
/// Environment fallbacks (flag, variable). Conformance flags have none, on purpose.
const ENV_FALLBACKS: [(&str, &str); 8] = [
    ("--signing-key", "LAB_SIGNING_KEY"),
    ("--issuer-key", "LAB_ISSUER_KEY"),
    ("--client-id", "LAB_CLIENT_ID"),
    ("--mode", "LAB_MODE"),
    ("--bind", "LAB_BIND"),
    ("--credential-query-id", "LAB_CREDENTIAL_QUERY_ID"),
    ("--vct", "LAB_VCT"),
    ("--claims", "LAB_CLAIMS"),
];

fn parse_mode(value: &str) -> Result<Mode, String> {
    match value {
        "hardened" => Ok(Mode::Hardened),
        "research-kid" => Ok(Mode::Research(SharedRouteStrategy::UniqueKid)),
        #[cfg(feature = "conformance")]
        CONFORMANCE_MODE => Ok(Mode::Conformance),
        #[cfg(not(feature = "conformance"))]
        CONFORMANCE_MODE => Err(
            "this lab-server was built without the `conformance` feature; \
             conformance mode needs `cargo build -p lab-server --features conformance`"
                .to_owned(),
        ),
        _ => {
            let budget = value
                .strip_prefix(TRIAL_PREFIX)
                .and_then(|b| b.parse::<usize>().ok())
                .ok_or_else(|| format!("unknown mode {value:?}"))?;
            let budget = CandidateBudget::new(budget).map_err(|e| e.to_string())?;
            Ok(Mode::Research(SharedRouteStrategy::BoundedTrial(budget)))
        }
    }
}

/// The command line as flag -> value; then the environment fallbacks. `LAB_MODE` cannot
/// select conformance mode: that takes the explicit flag.
fn arguments() -> Result<HashMap<&'static str, String>, String> {
    let mut values = HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let flag = FLAGS
            .into_iter()
            .find(|known| *known == flag)
            .ok_or_else(|| USAGE.to_owned())?;
        let value = args.next().ok_or_else(|| USAGE.to_owned())?;
        if values.insert(flag, value).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    for (flag, variable) in ENV_FALLBACKS {
        if let (None, Ok(value)) = (values.get(flag), std::env::var(variable)) {
            if flag == "--mode" && value == CONFORMANCE_MODE {
                return Err("conformance mode needs the explicit --mode conformance flag".into());
            }
            values.insert(flag, value);
        }
    }
    Ok(values)
}

#[cfg(feature = "conformance")]
fn read(path: &str, what: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {what} {path:?}: {e}"))
}

fn seconds(value: &str, flag: &str) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("{flag} must be a number of seconds"))
}

fn config() -> Result<LabConfig, String> {
    let mut args = arguments()?;
    // The mode first: a binary without `conformance` refuses that mode before reading any key.
    let mode = args
        .remove("--mode")
        .as_deref()
        .map_or(Ok(Mode::Hardened), parse_mode)?;
    let path = args
        .remove("--signing-key")
        .ok_or_else(|| USAGE.to_owned())?;
    let jwk = Zeroizing::new(
        std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read signing key {path:?}: {e}"))?,
    );
    let key = RequestSigningKey::from_jwk(&jwk).map_err(|e| format!("{path:?}: {e}"))?;
    let issuer_path = args
        .remove("--issuer-key")
        .ok_or_else(|| USAGE.to_owned())?;
    let issuer = std::fs::read_to_string(&issuer_path)
        .map_err(|e| format!("cannot read issuer key {issuer_path:?}: {e}"))?;
    let issuer =
        TrustedIssuerKey::from_jwk(&issuer).map_err(|e| format!("{issuer_path:?}: {e}"))?;
    let mut config = LabConfig::new(mode, key, issuer);
    if let Some(client_id) = args.remove("--client-id") {
        config.client_id =
            ClientIdWire::new(client_id).map_err(|_| "invalid client_id".to_owned())?;
    }
    if let Some(bind) = args.remove("--bind") {
        config.bind = bind
            .parse()
            .map_err(|_| format!("invalid bind address {bind:?}"))?;
    }
    if let Some(ttl) = args.remove("--session-ttl-secs") {
        config.session_ttl = seconds(&ttl, "--session-ttl-secs")?;
    }
    if let Some(endpoint) = args.remove("--authorization-endpoint") {
        config.authorization_endpoint = endpoint;
    }
    let (query_id, vct, claims) = (
        args.remove("--credential-query-id"),
        args.remove("--vct"),
        args.remove("--claims"),
    );
    if query_id.is_some() || vct.is_some() || claims.is_some() {
        let synthetic = CredentialRequest::synthetic();
        let claims: Vec<String> = match claims {
            Some(list) => list.split(CLAIMS_SEPARATOR).map(str::to_owned).collect(),
            None => synthetic.claims().to_vec(),
        };
        config.credential_request = CredentialRequest::new(
            query_id.unwrap_or_else(|| synthetic.id().to_owned()),
            vct.unwrap_or_else(|| synthetic.vct().to_owned()),
            claims,
        )
        .map_err(|e| format!("credential query: {e}"))?;
    }
    #[cfg(feature = "conformance")]
    if mode == Mode::Conformance {
        conformance(&mut config, &mut args)?;
    }
    if let Some(flag) = CONFORMANCE_FLAGS.iter().find(|f| args.contains_key(*f)) {
        return Err(format!("{flag} is a conformance-mode flag"));
    }
    Ok(config)
}

/// The conformance-mode flags into `config` (all required but the optional ones).
#[cfg(feature = "conformance")]
fn conformance(
    config: &mut LabConfig,
    args: &mut HashMap<&'static str, String>,
) -> Result<(), String> {
    use lab_server::{ConformanceConfig, PublicOrigin, X509_SAN_DNS_PREFIX, X509Credentials};
    let mut required = |flag: &str| {
        args.remove(flag)
            .ok_or_else(|| format!("conformance mode needs {flag}"))
    };
    let cert = read(&required("--tls-cert")?, "TLS certificate chain")?;
    let key = Zeroizing::new(read(&required("--tls-key")?, "TLS key")?);
    let anchor = read(&required("--trust-anchor")?, "trust anchor")?;
    let origin = PublicOrigin::parse(&required("--public-origin")?).map_err(|e| e.to_string())?;
    let credentials = X509Credentials::from_pem(&cert, &key, &anchor).map_err(|e| e.to_string())?;
    match args.remove("--client-id-prefix").as_deref() {
        None => {}
        Some("x509_san_dns") => {
            config.client_id = ClientIdWire::new(format!("{X509_SAN_DNS_PREFIX}{}", origin.host()))
                .map_err(|_| "invalid client_id".to_owned())?;
        }
        Some("x509_hash") => {
            config.client_id = ClientIdWire::new(credentials.x509_hash_client_id())
                .map_err(|_| "invalid client_id".to_owned())?;
        }
        Some(other) => return Err(format!("unknown --client-id-prefix {other:?}")),
    }
    let mut conformance = ConformanceConfig::new(credentials, origin);
    if let Some(runtime) = args.remove("--max-runtime-secs") {
        conformance.max_runtime = seconds(&runtime, "--max-runtime-secs")?;
    }
    conformance.response_redirect_uri = args.remove("--response-redirect-uri");
    config.conformance = Some(conformance);
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let mode = config.mode;
    let client_id = config.client_id.as_str().to_owned();
    let server = match LabServer::start(config).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("lab-server: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "lab-server listening on {} as {} ({mode:?}, client_id {client_id})",
        server.local_addr(),
        server.base_url()
    );
    match server.wait().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lab-server: {e}");
            ExitCode::FAILURE
        }
    }
}
