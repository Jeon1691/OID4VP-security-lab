//! G6 benchmark and evidence harness (IMP-015/016, CI-008).
//!
//! ```text
//! scenario-runner --out <dir> [--run-id <id>] [--sizes 1,2,8,32,64,128] [--iterations 100]
//!                 [--warmup 10] [--seed 1] [--budget <max N>] [--over-budget 8] [--burst 64]
//!                 [--burst-rounds 10] [--store-iterations 1000] [--fixtures <dir>]
//! ```
//!
//! Starts in-process lab-servers on `127.0.0.1:0`, drives them over real loopback HTTP with the
//! wallet simulator, and writes `results.json`, `results.csv`, `summary.md` and `run.json`
//! into `--out`. `REDIS_URL`, when set, adds the Redis store rows. Run it with `--release`
//! (`scripts/bench.sh` does); a debug build is marked in `run.json`.
//!
//! Exit status 1 if any invariant failed (the files are still written), 2 on bad arguments or
//! a broken run. Methodology and caveats: `docs/benchmarks.md`.

mod http;
mod stats;
mod store;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::json;
use session_core::MAX_CANDIDATE_BUDGET;

/// Pending-session counts of the plan's measurement matrix.
const DEFAULT_SIZES: [usize; 6] = [1, 2, 8, 32, 64, 128];
/// Measured requests per case and N: enough for a stable P95 (5 samples above it) and a rough
/// P99 on one machine, while the full matrix stays at a few minutes in a release build.
const DEFAULT_ITERATIONS: u64 = 100;
/// Unmeasured requests per case first (connection pool, allocator, CPU caches).
const DEFAULT_WARMUP: u64 = 10;
/// Default schedule seed; only the case order depends on it (see `stats::Schedule`).
const DEFAULT_SEED: u64 = 1;
/// Over-budget runs: a budget below the larger N of the matrix (32, 64, 128 exceed it).
const DEFAULT_OVER_BUDGET: usize = 8;
/// Concurrent POSTs per burst round: half the plan's largest concurrent scenario (128), so a
/// bounded-trial burst stays within the default budget with sessions to spare.
const DEFAULT_BURST: usize = 64;
const DEFAULT_BURST_ROUNDS: u64 = 10;
/// Store cycles per backend: store calls take microseconds (memory) to a fraction of a
/// millisecond (Redis on loopback), so a thousand cost well under a second.
const DEFAULT_STORE_ITERATIONS: u64 = 1_000;
/// Synthetic lab-server fixtures (relative to this crate).
const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../lab-server/tests/fixtures");
const SIGNING_KEY_FILE: &str = "spruce_verifier.jwk";
const ISSUER_KEY_FILE: &str = "lab_issuer.jwk";
const ISSUER_PUBLIC_KEY_FILE: &str = "lab_issuer.pub.jwk";
const EXIT_INVARIANT_FAILED: u8 = 1;
const EXIT_BROKEN_RUN: u8 = 2;

const USAGE: &str = "usage: scenario-runner --out <dir> [--run-id <id>] [--sizes <n,...>] \
[--iterations <n>] [--warmup <n>] [--seed <u64>] [--budget <n>] [--over-budget <n>] \
[--burst <n>] [--burst-rounds <n>] [--store-iterations <n>] [--fixtures <dir>]";

struct Args {
    out: PathBuf,
    run_id: String,
    seed: u64,
    store_iterations: u64,
    fixtures: PathBuf,
    http: http::Params,
}

fn parse<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid value for {flag}: {value:?}"))
}

fn args() -> Result<Args> {
    let mut out = None;
    let mut run_id = None;
    let mut sizes = DEFAULT_SIZES.to_vec();
    let mut iterations = DEFAULT_ITERATIONS;
    let mut warmup = DEFAULT_WARMUP;
    let mut seed = DEFAULT_SEED;
    let mut budget = None;
    let mut over_budget = DEFAULT_OVER_BUDGET;
    let mut burst = DEFAULT_BURST;
    let mut burst_rounds = DEFAULT_BURST_ROUNDS;
    let mut store_iterations = DEFAULT_STORE_ITERATIONS;
    let mut fixtures = PathBuf::from(FIXTURES_DIR);
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().with_context(|| USAGE.to_owned())?;
        match flag.as_str() {
            "--out" => out = Some(PathBuf::from(value)),
            "--run-id" => run_id = Some(value),
            "--sizes" => {
                sizes = value
                    .split(',')
                    .map(|v| parse(&flag, v.trim()))
                    .collect::<Result<_>>()?;
            }
            "--iterations" => iterations = parse(&flag, &value)?,
            "--warmup" => warmup = parse(&flag, &value)?,
            "--seed" => seed = parse(&flag, &value)?,
            "--budget" => budget = Some(parse(&flag, &value)?),
            "--over-budget" => over_budget = parse(&flag, &value)?,
            "--burst" => burst = parse(&flag, &value)?,
            "--burst-rounds" => burst_rounds = parse(&flag, &value)?,
            "--store-iterations" => store_iterations = parse(&flag, &value)?,
            "--fixtures" => fixtures = PathBuf::from(value),
            _ => bail!("{USAGE}"),
        }
    }
    let out = out.with_context(|| USAGE.to_owned())?;
    ensure!(
        !sizes.is_empty() && sizes.iter().all(|&n| n > 0),
        "--sizes must list positive session counts"
    );
    ensure!(iterations > 0, "--iterations must be positive");
    let max_n = sizes.iter().copied().max().unwrap_or(1);
    let budget = budget.unwrap_or(max_n);
    ensure!(
        budget >= max_n && budget <= MAX_CANDIDATE_BUDGET,
        "--budget must be at least the largest N and at most {MAX_CANDIDATE_BUDGET}"
    );
    ensure!(
        burst > 0 && burst <= budget,
        "--burst must be positive and within the budget"
    );
    ensure!(over_budget > 0, "--over-budget must be positive");
    let run_id = match run_id {
        Some(id) => id,
        None => format!(
            "local-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default()
        ),
    };
    ensure!(
        !run_id.is_empty()
            && run_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "--run-id must be [A-Za-z0-9._-]"
    );
    Ok(Args {
        out,
        run_id,
        seed,
        store_iterations,
        fixtures,
        http: http::Params {
            sizes,
            iterations,
            warmup,
            budget,
            over_budget,
            burst,
            burst_rounds,
        },
    })
}

fn read(dir: &std::path::Path, file: &str) -> Result<String> {
    let path = dir.join(file);
    std::fs::read_to_string(&path).with_context(|| format!("fixture {file}"))
}

async fn run() -> Result<bool> {
    let args = args()?;
    let fixtures = http::Fixtures {
        signing_jwk: read(&args.fixtures, SIGNING_KEY_FILE)?,
        issuer_jwk: read(&args.fixtures, ISSUER_KEY_FILE)?,
        issuer_public_jwk: read(&args.fixtures, ISSUER_PUBLIC_KEY_FILE)?,
    };
    let redis_url = std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty());
    let profile = if cfg!(debug_assertions) {
        eprintln!("warning: debug build; run with --release for representative numbers");
        "debug"
    } else {
        "release"
    };
    let p = &args.http;
    let run = json!({
        "run_id": args.run_id,
        "profile": profile,
        "seed": args.seed,
        "sizes": p.sizes,
        "iterations": p.iterations,
        "warmup": p.warmup,
        "budget": p.budget,
        "over_budget": p.over_budget,
        "burst": p.burst,
        "burst_rounds": p.burst_rounds,
        "store_iterations": args.store_iterations,
        "store_warmup": p.warmup,
        "redis": redis_url.is_some(),
        "transport": "HTTP/1.1 over 127.0.0.1, server and wallet simulator in one process",
        "worker_threads": std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
    });
    std::fs::create_dir_all(&args.out).context("output directory")?;
    let mut text = serde_json::to_string_pretty(&run)?;
    text.push('\n');
    std::fs::write(args.out.join("run.json"), text)?;

    let mut rows = http::run(&fixtures, p, &args.run_id, args.seed).await?;
    rows.extend(
        store::run(
            &args.run_id,
            args.store_iterations,
            p.warmup,
            redis_url.as_deref(),
        )
        .await?,
    );

    evidence_report::write_json(&args.out.join("results.json"), &run, &rows)?;
    evidence_report::write_csv(&args.out.join("results.csv"), &rows)?;
    let summary = evidence_report::markdown_summary(&args.run_id, &rows);
    std::fs::write(args.out.join("summary.md"), &summary)?;
    let failed: Vec<_> = rows.iter().filter(|r| !r.invariant.holds()).collect();
    for row in &failed {
        eprintln!(
            "invariant FAIL: {} {} N={} {}: {:?}",
            row.scenario, row.strategy, row.pending, row.case, row.invariant
        );
    }
    let checked = rows.iter().filter(|r| r.invariant.holds()).count();
    println!(
        "rows={} invariants_held={checked} invariants_failed={}",
        rows.len(),
        failed.len()
    );
    Ok(failed.is_empty())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_INVARIANT_FAILED),
        Err(e) => {
            eprintln!("scenario-runner: {e:#}");
            ExitCode::from(EXIT_BROKEN_RUN)
        }
    }
}
