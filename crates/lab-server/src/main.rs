//! Runs the lab server.
//!
//! ```text
//! lab-server --signing-key <jwk file> --issuer-key <public jwk file> [--client-id <id>]
//!            [--mode hardened|research-kid|research-trial=<budget>] [--bind <ip:port>]
//!            [--credential-query-id <id>] [--vct <vct>] [--claims <name,name,...>]
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
//! Every mode refuses non-loopback addresses (lab policy; anything else needs an
//! explicit future ADR). Build release artifacts with a plain `cargo build -p lab-server`, so
//! the test-only `wallet-sim` feature is not unified in.

use std::process::ExitCode;

use lab_server::{
    CredentialRequest, LabConfig, LabServer, Mode, RequestSigningKey, SharedRouteStrategy,
    TrustedIssuerKey,
};
use protocol_model::ClientIdWire;
use session_core::CandidateBudget;
use zeroize::Zeroizing;

const USAGE: &str = "usage: lab-server --signing-key <jwk file> --issuer-key <public jwk file> \
[--client-id <id>] [--mode hardened|research-kid|research-trial=<budget>] [--bind <ip:port>] \
[--credential-query-id <id>] [--vct <vct>] [--claims <name,name,...>]";
/// Separator of the `--claims` list.
const CLAIMS_SEPARATOR: char = ',';
const TRIAL_PREFIX: &str = "research-trial=";

fn parse_mode(value: &str) -> Result<Mode, String> {
    match value {
        "hardened" => Ok(Mode::Hardened),
        "research-kid" => Ok(Mode::Research(SharedRouteStrategy::UniqueKid)),
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

fn config() -> Result<LabConfig, String> {
    let mut signing_key = std::env::var("LAB_SIGNING_KEY").ok();
    let mut issuer_key = std::env::var("LAB_ISSUER_KEY").ok();
    let mut client_id = std::env::var("LAB_CLIENT_ID").ok();
    let mut mode = std::env::var("LAB_MODE").ok();
    let mut bind = std::env::var("LAB_BIND").ok();
    let mut query_id = std::env::var("LAB_CREDENTIAL_QUERY_ID").ok();
    let mut vct = std::env::var("LAB_VCT").ok();
    let mut claims = std::env::var("LAB_CLAIMS").ok();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--signing-key" => &mut signing_key,
            "--issuer-key" => &mut issuer_key,
            "--client-id" => &mut client_id,
            "--mode" => &mut mode,
            "--bind" => &mut bind,
            "--credential-query-id" => &mut query_id,
            "--vct" => &mut vct,
            "--claims" => &mut claims,
            _ => return Err(USAGE.to_owned()),
        };
        *slot = Some(args.next().ok_or_else(|| USAGE.to_owned())?);
    }
    let path = signing_key.ok_or_else(|| USAGE.to_owned())?;
    let jwk = Zeroizing::new(
        std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read signing key {path:?}: {e}"))?,
    );
    let key = RequestSigningKey::from_jwk(&jwk).map_err(|e| format!("{path:?}: {e}"))?;
    let issuer_path = issuer_key.ok_or_else(|| USAGE.to_owned())?;
    let issuer = std::fs::read_to_string(&issuer_path)
        .map_err(|e| format!("cannot read issuer key {issuer_path:?}: {e}"))?;
    let issuer =
        TrustedIssuerKey::from_jwk(&issuer).map_err(|e| format!("{issuer_path:?}: {e}"))?;
    let mode = mode.as_deref().map_or(Ok(Mode::Hardened), parse_mode)?;
    let mut config = LabConfig::new(mode, key, issuer);
    if let Some(client_id) = client_id {
        config.client_id =
            ClientIdWire::new(client_id).map_err(|_| "invalid client_id".to_owned())?;
    }
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
    if let Some(bind) = bind {
        config.bind = bind
            .parse()
            .map_err(|_| format!("invalid bind address {bind:?}"))?;
    }
    Ok(config)
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
    let server = match LabServer::start(config).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("lab-server: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("lab-server listening on {} ({mode:?})", server.base_url());
    match server.wait().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lab-server: {e}");
            ExitCode::FAILURE
        }
    }
}
