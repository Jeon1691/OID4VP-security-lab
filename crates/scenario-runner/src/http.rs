//! HTTP scenarios: a lab-server per strategy × pending-session count, driven over loopback by
//! the wallet simulator. HPKE attempt counts and trial times come from the server's evidence
//! records, never from the client.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use evidence_report::{Invariant, Row};
use lab_server::wallet_sim::{
    PresentationTamper, RequestObject, SealOptions, SyntheticIssuer, WalletSim,
};
use lab_server::{
    CommitResult, DEFAULT_MAX_IN_FLIGHT_REQUESTS, EvidenceRecord, LabConfig, LabServer, Mode,
    Rejection, RequestSigningKey, RouteKind, SharedRouteStrategy, TrustedIssuerKey,
};
use session_core::{CandidateBudget, ResolveError};
use tokio::task::JoinSet;

use crate::stats::{Latencies, Schedule, Usage};

/// HTTP statuses the invariants pin (RFC 9110 §15).
const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
const UNSUPPORTED_MEDIA_TYPE: u16 = 415;
const SERVICE_UNAVAILABLE: u16 = 503;
const SUCCESS_CLASS: std::ops::Range<u16> = 200..300;
const CLIENT_ERROR_CLASS: std::ops::Range<u16> = 400..500;
/// Admission case: a valid form body sent with a media type the endpoint refuses (step 2 of
/// the response pipeline, before the JWE is parsed).
const ADMISSION_CONTENT_TYPE: &str = "application/json";
/// KB-JWT `nonce` of the wrong-nonce case: valid nonce syntax, never issued by the lab.
const FOREIGN_NONCE: &str = "g6-foreign-nonce";
/// Burst "limits on": an in-flight cap of an eighth of the default burst (64) and two
/// decryption slots, so the burst must shed load (503) and queue trials.
const LIMITED_IN_FLIGHT: usize = 8;
const LIMITED_DECRYPTIONS: usize = 2;
/// Longest violation text kept per row; the first violation is enough to start debugging.
const MAX_VIOLATION_NOTE: usize = 240;

/// The fixture keys every server and wallet is built from (synthetic, read at run time so no
/// key is compiled into the runner).
pub struct Fixtures {
    pub signing_jwk: String,
    pub issuer_jwk: String,
    pub issuer_public_jwk: String,
}

impl Fixtures {
    fn config(&self, mode: Mode) -> Result<LabConfig> {
        Ok(LabConfig::new(
            mode,
            RequestSigningKey::from_jwk(&self.signing_jwk).context("signing key fixture")?,
            TrustedIssuerKey::from_jwk(&self.issuer_public_jwk).context("issuer key fixture")?,
        ))
    }

    fn wallet(&self) -> Result<WalletSim> {
        let issuer = SyntheticIssuer::from_jwk(&self.issuer_jwk).context("issuer fixture")?;
        WalletSim::new(&issuer).context("wallet simulator")
    }
}

/// Session resolution strategy under test (fixed per server, as in lab-server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Hardened mode: one response_uri per session.
    UniqueUri,
    /// Research mode, shared route, per-session `kid`.
    UniqueKid,
    /// Research mode, shared route and key (OIDF #792 shape), trial up to `budget`.
    BoundedTrial { budget: usize },
}

impl Strategy {
    const fn name(self) -> &'static str {
        match self {
            Self::UniqueUri => "unique_uri",
            Self::UniqueKid => "unique_kid",
            Self::BoundedTrial { .. } => "bounded_trial",
        }
    }

    fn mode(self) -> Result<Mode> {
        Ok(match self {
            Self::UniqueUri => Mode::Hardened,
            Self::UniqueKid => Mode::Research(SharedRouteStrategy::UniqueKid),
            Self::BoundedTrial { budget } => Mode::Research(SharedRouteStrategy::BoundedTrial(
                CandidateBudget::new(budget).context("candidate budget")?,
            )),
        })
    }

    const fn route(self) -> RouteKind {
        match self {
            Self::UniqueUri => RouteKind::Unique,
            Self::UniqueKid | Self::BoundedTrial { .. } => RouteKind::Shared,
        }
    }

    const fn budget(self) -> Option<usize> {
        match self {
            Self::BoundedTrial { budget } => Some(budget),
            Self::UniqueUri | Self::UniqueKid => None,
        }
    }

    /// Most HPKE attempts one request may make with `n` sessions pending.
    const fn max_attempts(self, n: usize) -> usize {
        match self {
            Self::UniqueUri | Self::UniqueKid => 1,
            Self::BoundedTrial { .. } => n,
        }
    }
}

/// Where the session the JWE is for sits in the route's pending (= bounded-trial) order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    First,
    Middle,
    Last,
}

impl Position {
    /// Deduplication priority for small N: `Last` first, so N = 1 reports `valid_last` (the
    /// row the plan's invariant and the summary use).
    const BY_PRIORITY: [Self; 3] = [Self::Last, Self::First, Self::Middle];

    const fn index(self, n: usize) -> usize {
        match self {
            Self::First => 0,
            Self::Middle => n.saturating_sub(1) / 2,
            Self::Last => n.saturating_sub(1),
        }
    }
}

/// What one measured request sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    /// An honest response for the session at this position.
    Valid(Position),
    /// One ciphertext character flipped: no candidate opens.
    InvalidCiphertext,
    /// Opens for its session, but the KB-JWT carries a nonce the lab never issued.
    WrongNonce,
    /// The exact JWE of a session committed just before (unmeasured), posted again.
    Replay,
    /// Refused at admission (media type), before the JWE is parsed.
    Admission,
    /// Bounded trial with more pending sessions than the budget.
    OverBudget,
}

impl Case {
    const fn name(self) -> &'static str {
        match self {
            Self::Valid(Position::First) => "valid_first",
            Self::Valid(Position::Middle) => "valid_middle",
            Self::Valid(Position::Last) => "valid_last",
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::WrongNonce => "wrong_nonce",
            Self::Replay => "replay",
            Self::Admission => "admission",
            Self::OverBudget => "over_budget",
        }
    }

    /// The rule [`check`] enforces, as recorded in the row.
    const fn rule(self, strategy: Strategy) -> &'static str {
        match (self, strategy) {
            (Self::Valid(_), Strategy::UniqueUri | Strategy::UniqueKid) => {
                "200, committed, attempts == 1"
            }
            (Self::Valid(_), Strategy::BoundedTrial { .. }) => {
                "200, committed, attempts <= N, attempts == N when last"
            }
            (Self::InvalidCiphertext | Self::WrongNonce, _) => {
                "400, not committed, attempts <= max for strategy"
            }
            (Self::Replay, Strategy::UniqueUri | Strategy::UniqueKid) => {
                "400, not committed, attempts == 0"
            }
            (Self::Replay, Strategy::BoundedTrial { .. }) => "400, not committed, attempts <= N",
            (Self::Admission, _) => "415, admission rejection, attempts == 0",
            (Self::OverBudget, _) => "400, budget exceeded, attempts == 0",
        }
    }
}

/// Run parameters of the HTTP scenarios.
pub struct Params {
    pub sizes: Vec<usize>,
    pub iterations: u64,
    pub warmup: u64,
    pub budget: usize,
    pub over_budget: usize,
    pub burst: usize,
    pub burst_rounds: u64,
}

/// One session in the client's pool: its verified Request Object (the response target).
struct Pooled {
    request: RequestObject,
}

/// One answered request.
struct Sample {
    latency: Duration,
    status: u16,
    record: Option<EvidenceRecord>,
}

/// A running server and the wallet driving it.
struct Lab {
    server: LabServer,
    wallet: WalletSim,
    route: RouteKind,
}

impl Lab {
    async fn start(fixtures: &Fixtures, strategy: Strategy, config: LabConfig) -> Result<Self> {
        let server = LabServer::start(config)
            .await
            .context("lab server starts")?;
        ensure!(server.local_addr().ip().is_loopback(), "loopback only");
        Ok(Self {
            server,
            wallet: fixtures.wallet()?,
            route: strategy.route(),
        })
    }

    async fn session(&self) -> Result<Pooled> {
        let session = self
            .wallet
            .create_session(&self.server.base_url(), self.route, None)
            .await
            .context("session is created")?;
        let request = self
            .wallet
            .fetch_request(&session)
            .await
            .context("request object verifies")?;
        Ok(Pooled { request })
    }

    async fn fill(&self, pool: &mut Vec<Pooled>, n: usize) -> Result<()> {
        while pool.len() < n {
            pool.push(self.session().await?);
        }
        Ok(())
    }

    /// POSTs `jwe` to `uri`, timing only the HTTP exchange, and collects its evidence record.
    async fn post(&self, uri: &str, jwe: &str) -> Result<Sample> {
        let started = Instant::now();
        let reply = self.wallet.post_response(uri, jwe).await?;
        let latency = started.elapsed();
        Ok(Sample {
            latency,
            status: reply.status,
            record: self.one_record(),
        })
    }

    /// The single evidence record since the last call, or `None` if there is not exactly one.
    fn one_record(&self) -> Option<EvidenceRecord> {
        let mut records = self.server.evidence().take();
        (records.len() == 1).then(|| records.remove(0))
    }

    /// Runs `case` once against `pool` (kept at `n` pending sessions in insertion order).
    async fn run(&self, case: Case, pool: &mut Vec<Pooled>, n: usize) -> Result<Sample> {
        let last = n.saturating_sub(1);
        match case {
            Case::Valid(position) => {
                let target = pool.remove(position.index(n));
                let jwe = self.wallet.seal(&target.request, &SealOptions::default())?;
                let sample = self.post(&target.request.response_uri, &jwe).await?;
                // A new session goes to the end of the route's order, as in the registry.
                self.fill(pool, n).await?;
                Ok(sample)
            }
            Case::InvalidCiphertext | Case::WrongNonce | Case::OverBudget => {
                let target = pool.get(last).context("pool is filled")?;
                let opts = match case {
                    Case::InvalidCiphertext => SealOptions {
                        tamper_ciphertext: true,
                        ..SealOptions::default()
                    },
                    Case::WrongNonce => SealOptions {
                        presentation: PresentationTamper::KbNonce(FOREIGN_NONCE.to_owned()),
                        ..SealOptions::default()
                    },
                    _ => SealOptions::default(),
                };
                let jwe = self.wallet.seal(&target.request, &opts)?;
                self.post(&target.request.response_uri, &jwe).await
            }
            Case::Replay => {
                let target = pool.remove(last);
                let jwe = self.wallet.seal(&target.request, &SealOptions::default())?;
                let first = self.post(&target.request.response_uri, &jwe).await?;
                ensure!(
                    first.status == OK,
                    "replay setup: first post must commit (status {})",
                    first.status
                );
                self.fill(pool, n).await?;
                self.post(&target.request.response_uri, &jwe).await
            }
            Case::Admission => {
                let target = pool.get(last).context("pool is filled")?;
                let jwe = self.wallet.seal(&target.request, &SealOptions::default())?;
                let body = format!("response={jwe}").into_bytes();
                let started = Instant::now();
                let reply = self
                    .wallet
                    .post_raw(&target.request.response_uri, ADMISSION_CONTENT_TYPE, body)
                    .await?;
                let latency = started.elapsed();
                Ok(Sample {
                    latency,
                    status: reply.status,
                    record: self.one_record(),
                })
            }
        }
    }

    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// The invariants that must hold for every request of `case`; a violation fails the run.
fn check(strategy: Strategy, n: usize, case: Case, sample: &Sample) -> Result<(), String> {
    let record = sample
        .record
        .as_ref()
        .ok_or("not exactly one evidence record")?;
    let attempts = record.hpke_attempts;
    let committed = record.commit_result == CommitResult::Committed;
    let fail = |what: &str| {
        Err(format!(
            "{what}: status {}, attempts {attempts}, N {n}, rejection {:?}",
            sample.status, record.rejection
        ))
    };
    if attempts > 0 && record.trial_time.is_zero() {
        return fail("trial ran but no trial time was recorded");
    }
    match case {
        Case::Valid(position) => {
            if sample.status != OK || !committed {
                return fail("valid response not committed");
            }
            match strategy {
                Strategy::UniqueUri | Strategy::UniqueKid if attempts != 1 => {
                    fail("unique strategy must make exactly one attempt")
                }
                Strategy::BoundedTrial { .. } if attempts > n => fail("attempts exceed N"),
                Strategy::BoundedTrial { .. }
                    if position.index(n) == n.saturating_sub(1) && attempts != n =>
                {
                    fail("correct session last: attempts must equal N")
                }
                _ => Ok(()),
            }
        }
        Case::InvalidCiphertext | Case::WrongNonce => {
            if sample.status != BAD_REQUEST || committed {
                fail("invalid response accepted")
            } else if attempts > strategy.max_attempts(n) {
                fail("attempts exceed the strategy maximum")
            } else {
                Ok(())
            }
        }
        Case::Replay => {
            let max = match strategy {
                Strategy::UniqueUri | Strategy::UniqueKid => 0,
                Strategy::BoundedTrial { .. } => n,
            };
            if sample.status != BAD_REQUEST || committed {
                fail("replay accepted")
            } else if attempts > max {
                fail("replay made too many attempts")
            } else {
                Ok(())
            }
        }
        Case::Admission => {
            if sample.status != UNSUPPORTED_MEDIA_TYPE
                || attempts != 0
                || !matches!(record.rejection, Some(Rejection::Admission(_)))
            {
                fail("admission rejection must precede any attempt")
            } else {
                Ok(())
            }
        }
        Case::OverBudget => {
            if sample.status != BAD_REQUEST
                || attempts != 0
                || !matches!(
                    record.rejection,
                    Some(Rejection::Resolve(
                        ResolveError::CandidateBudgetExceeded { .. }
                    ))
                )
            {
                fail("over-budget request must be refused with zero attempts")
            } else {
                Ok(())
            }
        }
    }
}

/// Per-row accumulator.
struct Acc {
    latency: Latencies,
    trial: Latencies,
    requests: u64,
    status_2xx: u64,
    status_4xx: u64,
    status_503: u64,
    committed: u64,
    attempts_min: u64,
    attempts_max: u64,
    attempts_sum: u64,
    candidates_max: u64,
    busy: Duration,
    violations: u64,
    first_violation: Option<String>,
}

fn u(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

impl Acc {
    fn new() -> Self {
        Self {
            latency: Latencies::new(),
            trial: Latencies::new(),
            requests: 0,
            status_2xx: 0,
            status_4xx: 0,
            status_503: 0,
            committed: 0,
            attempts_min: u64::MAX,
            attempts_max: 0,
            attempts_sum: 0,
            candidates_max: 0,
            busy: Duration::ZERO,
            violations: 0,
            first_violation: None,
        }
    }

    fn violation(&mut self, note: String) {
        self.violations += 1;
        if self.first_violation.is_none() {
            self.first_violation = Some(note.chars().take(MAX_VIOLATION_NOTE).collect());
        }
    }

    fn add(&mut self, sample: &Sample) {
        self.requests += 1;
        self.latency.record(sample.latency);
        self.busy += sample.latency;
        if SUCCESS_CLASS.contains(&sample.status) {
            self.status_2xx += 1;
        } else if sample.status == SERVICE_UNAVAILABLE {
            self.status_503 += 1;
        } else if CLIENT_ERROR_CLASS.contains(&sample.status) {
            self.status_4xx += 1;
        }
        if let Some(record) = &sample.record {
            let attempts = u(record.hpke_attempts);
            self.attempts_min = self.attempts_min.min(attempts);
            self.attempts_max = self.attempts_max.max(attempts);
            self.attempts_sum += attempts;
            self.candidates_max = self.candidates_max.max(u(record.candidate_count));
            if record.commit_result == CommitResult::Committed {
                self.committed += 1;
            }
            if attempts > 0 {
                self.trial.record(record.trial_time);
            }
        }
    }

    fn row(self, head: RowHead<'_>, wall: Duration, cpu: Option<Duration>, rule: &str) -> Row {
        let recorded = self.requests.max(1);
        let invariant = match (rule.is_empty(), self.first_violation) {
            (true, _) => Invariant::NotApplicable,
            (false, None) => Invariant::Pass(rule.to_owned()),
            (false, Some(first)) => Invariant::Fail(format!(
                "{} of {} requests broke \"{rule}\"; first: {first}",
                self.violations, self.requests
            )),
        };
        let wall = wall.as_secs_f64();
        Row {
            run_id: head.run_id.to_owned(),
            scenario: head.scenario.to_owned(),
            strategy: head.strategy.name().to_owned(),
            pending: head.pending,
            budget: head.strategy.budget(),
            case: head.case.to_owned(),
            limits: head.limits.to_owned(),
            requests: self.requests,
            status_2xx: self.status_2xx,
            status_4xx: self.status_4xx,
            status_503: self.status_503,
            committed: self.committed,
            attempts_min: if self.attempts_min == u64::MAX {
                0
            } else {
                self.attempts_min
            },
            attempts_max: self.attempts_max,
            attempts_mean: self.attempts_sum as f64 / recorded as f64,
            candidates_max: self.candidates_max,
            latency: self.latency.percentiles(),
            trial: self.trial.percentiles(),
            throughput_rps: if wall > 0.0 {
                self.requests as f64 / wall
            } else {
                0.0
            },
            rejection_ratio: (self.requests - self.status_2xx) as f64 / recorded as f64,
            cpu_ms: cpu.map(|c| c.as_secs_f64() * MILLIS_PER_SECOND),
            rss_kib: Usage::sample().map(|u| u.rss_kib),
            invariant,
        }
    }
}

const MILLIS_PER_SECOND: f64 = 1_000.0;

/// Identifying columns of a row.
struct RowHead<'a> {
    run_id: &'a str,
    scenario: &'a str,
    strategy: Strategy,
    pending: usize,
    case: &'a str,
    limits: &'a str,
}

fn cpu_since(before: Option<Usage>) -> Option<Duration> {
    Some(Usage::sample()?.cpu.saturating_sub(before?.cpu))
}

/// Cases of a normal block, valid positions deduplicated by index (N = 1 has one position),
/// in report order.
fn cases(n: usize) -> Vec<Case> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for position in Position::BY_PRIORITY {
        let index = position.index(n);
        if !seen.contains(&index) {
            seen.push(index);
            out.push(Case::Valid(position));
        }
    }
    out.sort_by_key(|c| match c {
        Case::Valid(p) => p.index(n),
        _ => n,
    });
    out.extend([
        Case::InvalidCiphertext,
        Case::WrongNonce,
        Case::Replay,
        Case::Admission,
    ]);
    out
}

/// Runs every case of one strategy × N block on a fresh server; cases run in seeded order,
/// each warm-up then measured iterations back to back. Rows come back in `block_cases` order.
async fn block(
    fixtures: &Fixtures,
    params: &Params,
    run_id: &str,
    strategy: Strategy,
    n: usize,
    block_cases: &[Case],
    schedule: &mut Schedule,
) -> Result<Vec<Row>> {
    let lab = Lab::start(fixtures, strategy, fixtures.config(strategy.mode()?)?).await?;
    let mut pool = Vec::with_capacity(n);
    lab.fill(&mut pool, n).await?;
    let mut order: Vec<usize> = (0..block_cases.len()).collect();
    schedule.shuffle(&mut order);
    let mut rows: Vec<(usize, Row)> = Vec::with_capacity(order.len());
    for slot in order {
        let case = block_cases[slot];
        let mut acc = Acc::new();
        for _ in 0..params.warmup {
            let sample = lab.run(case, &mut pool, n).await?;
            if let Err(e) = check(strategy, n, case, &sample) {
                acc.violation(format!("warm-up: {e}"));
            }
        }
        let before = Usage::sample();
        for _ in 0..params.iterations {
            let sample = lab.run(case, &mut pool, n).await?;
            if let Err(e) = check(strategy, n, case, &sample) {
                acc.violation(e);
            }
            acc.add(&sample);
        }
        let cpu = cpu_since(before);
        let busy = acc.busy;
        let head = RowHead {
            run_id,
            scenario: "http",
            strategy,
            pending: n,
            case: case.name(),
            limits: "default",
        };
        rows.push((slot, acc.row(head, busy, cpu, case.rule(strategy))));
    }
    lab.shutdown().await;
    rows.sort_by_key(|(slot, _)| *slot);
    Ok(rows.into_iter().map(|(_, row)| row).collect())
}

/// Every HTTP scenario: unique-uri, unique-kid and bounded trial (budget >= N) for each N, the
/// over-budget runs (N > budget), and the burst with limits on and off.
pub async fn run(
    fixtures: &Fixtures,
    params: &Params,
    run_id: &str,
    seed: u64,
) -> Result<Vec<Row>> {
    let mut schedule = Schedule::new(seed);
    let mut rows = Vec::new();
    let strategies = [
        Strategy::UniqueUri,
        Strategy::UniqueKid,
        Strategy::BoundedTrial {
            budget: params.budget,
        },
    ];
    for strategy in strategies {
        for &n in &params.sizes {
            eprintln!("http: {} N={n}", strategy.name());
            let block_cases = cases(n);
            rows.extend(
                block(
                    fixtures,
                    params,
                    run_id,
                    strategy,
                    n,
                    &block_cases,
                    &mut schedule,
                )
                .await?,
            );
        }
    }
    let over = Strategy::BoundedTrial {
        budget: params.over_budget,
    };
    for &n in params.sizes.iter().filter(|&&n| n > params.over_budget) {
        eprintln!("http: over budget N={n} budget={}", params.over_budget);
        rows.extend(
            block(
                fixtures,
                params,
                run_id,
                over,
                n,
                &[Case::OverBudget],
                &mut schedule,
            )
            .await?,
        );
    }
    for strategy in [strategies[0], strategies[2]] {
        for limited in [true, false] {
            eprintln!(
                "burst: {} N={} limits {}",
                strategy.name(),
                params.burst,
                if limited { "on" } else { "off" }
            );
            rows.push(burst(fixtures, params, run_id, strategy, limited).await?);
        }
    }
    Ok(rows)
}

/// `params.burst` sessions, all answered at once with valid responses, `burst_rounds` times
/// (after one warm-up round). Limits on: [`LIMITED_IN_FLIGHT`] / [`LIMITED_DECRYPTIONS`];
/// off: the default in-flight cap (above the burst) and one decryption slot per request.
async fn burst(
    fixtures: &Fixtures,
    params: &Params,
    run_id: &str,
    strategy: Strategy,
    limited: bool,
) -> Result<Row> {
    let n = params.burst;
    let mut config = fixtures.config(strategy.mode()?)?;
    if limited {
        config.max_in_flight_requests = LIMITED_IN_FLIGHT;
        config.max_concurrent_decryptions = LIMITED_DECRYPTIONS;
    } else {
        config.max_in_flight_requests = DEFAULT_MAX_IN_FLIGHT_REQUESTS.max(n);
        config.max_concurrent_decryptions = n;
    }
    let lab = Lab::start(fixtures, strategy, config).await?;
    let mut pool = Vec::with_capacity(n);
    let mut acc = Acc::new();
    let mut wall = Duration::ZERO;
    let mut cpu = Duration::ZERO;
    let mut cpu_known = true;
    for round in 0..=params.burst_rounds {
        let measured = round > 0;
        lab.fill(&mut pool, n).await?;
        let batch: Vec<Pooled> = std::mem::take(&mut pool);
        let mut sealed = Vec::with_capacity(batch.len());
        for pooled in &batch {
            sealed.push(lab.wallet.seal(&pooled.request, &SealOptions::default())?);
        }
        let before = Usage::sample();
        let started = Instant::now();
        let mut set = JoinSet::new();
        for (i, (pooled, jwe)) in batch.iter().zip(sealed).enumerate() {
            let wallet = lab.wallet.clone();
            let uri = pooled.request.response_uri.clone();
            set.spawn(async move {
                let t = Instant::now();
                let reply = wallet.post_response(&uri, &jwe).await;
                (i, t.elapsed(), reply)
            });
        }
        let mut answers = Vec::with_capacity(batch.len());
        while let Some(joined) = set.join_next().await {
            let (i, latency, reply) = joined.context("burst task")?;
            answers.push((i, latency, reply?.status));
        }
        let round_wall = started.elapsed();
        let round_cpu = cpu_since(before);
        let records = lab.server.evidence().take();
        let admitted = answers
            .iter()
            .filter(|a| a.2 != SERVICE_UNAVAILABLE)
            .count();
        let mut violations = Vec::new();
        if records.len() != admitted {
            violations.push(format!(
                "{} evidence records for {admitted} admitted requests (503s must leave none)",
                records.len()
            ));
        }
        for record in &records {
            let committed = record.commit_result == CommitResult::Committed;
            if !committed || record.hpke_attempts > strategy.max_attempts(n) {
                violations.push(format!(
                    "admitted request: attempts {}, commit {:?}",
                    record.hpke_attempts, record.commit_result
                ));
            }
        }
        if let Some(&(_, _, status)) = answers
            .iter()
            .find(|a| a.2 != OK && a.2 != SERVICE_UNAVAILABLE)
        {
            violations.push(format!("unexpected status {status}"));
        }
        if !limited && admitted != answers.len() {
            violations.push("503 with limits off".to_owned());
        }
        // Sessions refused with 503 were never seen by the pipeline and stay pending.
        let refused: Vec<usize> = answers
            .iter()
            .filter(|a| a.2 == SERVICE_UNAVAILABLE)
            .map(|a| a.0)
            .collect();
        pool = batch
            .into_iter()
            .enumerate()
            .filter(|(i, _)| refused.contains(i))
            .map(|(_, p)| p)
            .collect();
        if !measured {
            for v in violations {
                acc.violation(format!("warm-up: {v}"));
            }
            continue;
        }
        wall += round_wall;
        match round_cpu {
            Some(c) => cpu += c,
            None => cpu_known = false,
        }
        for v in violations {
            acc.violation(v);
        }
        let mut by_index = records.into_iter();
        for (_, latency, status) in &answers {
            let record = if *status == SERVICE_UNAVAILABLE {
                None
            } else {
                by_index.next()
            };
            acc.add(&Sample {
                latency: *latency,
                status: *status,
                record,
            });
        }
    }
    lab.shutdown().await;
    let head = RowHead {
        run_id,
        scenario: "burst",
        strategy,
        pending: n,
        case: "valid_concurrent",
        limits: if limited { "on" } else { "off" },
    };
    let rule = if limited {
        "every admitted request commits within the attempt bound; 503s leave no evidence"
    } else {
        "no 503; every request commits within the attempt bound"
    };
    Ok(acc.row(head, wall, cpu_known.then_some(cpu), rule))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_dedupe_for_small_n() {
        assert_eq!(cases(1)[0], Case::Valid(Position::Last));
        assert_eq!(
            cases(1)
                .iter()
                .filter(|c| matches!(c, Case::Valid(_)))
                .count(),
            1
        );
        assert_eq!(
            cases(2)
                .iter()
                .filter(|c| matches!(c, Case::Valid(_)))
                .count(),
            2
        );
        assert_eq!(
            cases(8)
                .iter()
                .filter(|c| matches!(c, Case::Valid(_)))
                .count(),
            3
        );
        assert_eq!(Position::Middle.index(8), 3);
        assert_eq!(Position::Last.index(128), 127);
    }
}
