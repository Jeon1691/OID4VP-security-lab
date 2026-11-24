//! Runs the lab server.
//!
//! ```text
//! lab-server [--mode hardened|research-kid|research-trial=<budget>] [--bind <ip:port>]
//! ```
//!
//! `LAB_MODE` / `LAB_BIND` are used when the flag is absent. Defaults: hardened on
//! `127.0.0.1:0`. Every mode refuses non-loopback addresses (lab policy; anything else needs an
//! explicit future ADR). Build release artifacts with a plain `cargo build -p lab-server`, so
//! the test-only `wallet-sim` feature is not unified in.

use std::process::ExitCode;

use lab_server::{LabConfig, LabServer, Mode, SharedRouteStrategy};
use session_core::CandidateBudget;

const USAGE: &str =
    "usage: lab-server [--mode hardened|research-kid|research-trial=<budget>] [--bind <ip:port>]";
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
    let mut mode = std::env::var("LAB_MODE").ok();
    let mut bind = std::env::var("LAB_BIND").ok();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--mode" => &mut mode,
            "--bind" => &mut bind,
            _ => return Err(USAGE.to_owned()),
        };
        *slot = Some(args.next().ok_or_else(|| USAGE.to_owned())?);
    }
    let mut config = LabConfig::new(mode.as_deref().map_or(Ok(Mode::Hardened), parse_mode)?);
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
