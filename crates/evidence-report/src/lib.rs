//! G6 benchmark evidence (IMP-016): one [`Row`] per scenario × pending sessions × case, written
//! as JSON ([`write_json`]), CSV ([`write_csv`]) and a short Markdown summary
//! ([`markdown_summary`]).
//!
//! Every row carries the run id, which names the run directory and its `manifest.json`
//! (environment, toolchain, source revision). Rows are evidence, not pass/fail: absolute
//! numbers depend on the machine and are never compared across runs automatically. The one
//! exception is [`Invariant`], which records the protocol invariants a run must hold (HPKE
//! attempt counts, zero attempts before admission); a violated invariant fails the run.
//!
//! JSON and CSV come from one column list ([`Row::cells`]), so both always carry the same
//! fields in the same order.

use std::fmt::Write as _;
use std::io;
use std::path::Path;

use serde_json::{Map, Value};

/// Latency summary of one row, in microseconds. Computed by the caller (scenario-runner uses
/// hdrhistogram with three significant digits).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Percentiles {
    /// Median.
    pub p50_us: f64,
    /// 95th percentile.
    pub p95_us: f64,
    /// 99th percentile.
    pub p99_us: f64,
    /// Largest sample.
    pub max_us: f64,
    /// Arithmetic mean.
    pub mean_us: f64,
}

/// Outcome of the invariants that apply to a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invariant {
    /// No invariant applies (a measurement only).
    NotApplicable,
    /// Every sample held the named rule.
    Pass(String),
    /// At least one sample broke it; the first violations, for the report.
    Fail(String),
}

impl Invariant {
    /// `true` unless [`Invariant::Fail`].
    #[must_use]
    pub const fn holds(&self) -> bool {
        !matches!(self, Self::Fail(_))
    }

    fn status(&self) -> &'static str {
        match self {
            Self::NotApplicable => "n/a",
            Self::Pass(_) => "pass",
            Self::Fail(_) => "FAIL",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::NotApplicable => "",
            Self::Pass(rule) | Self::Fail(rule) => rule,
        }
    }
}

/// One scenario × pending-session count × case.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// Run id; also the name of the run directory holding `manifest.json`.
    pub run_id: String,
    /// `http` (sequential loopback POSTs), `burst` (concurrent POSTs) or `store` (registry
    /// operations without HTTP).
    pub scenario: String,
    /// `unique_uri`, `unique_kid`, `bounded_trial` (http, burst) or `memory` / `redis` (store).
    pub strategy: String,
    /// Pending sessions on the route (http, burst) when the measured request arrives.
    pub pending: usize,
    /// Bounded-trial candidate budget, if any.
    pub budget: Option<usize>,
    /// What was sent (`valid_first`, `invalid_ciphertext`, ...) or the store operation.
    pub case: String,
    /// `default`, `on` or `off` (burst: request limits binding or not).
    pub limits: String,
    /// Measured requests (warm-up excluded).
    pub requests: u64,
    /// Answers 2xx.
    pub status_2xx: u64,
    /// Answers 4xx.
    pub status_4xx: u64,
    /// Answers 503 (in-flight limit).
    pub status_503: u64,
    /// Requests the server committed (evidence `CommitResult::Committed`).
    pub committed: u64,
    /// HPKE attempts per request from server evidence: minimum, maximum, mean.
    pub attempts_min: u64,
    /// See `attempts_min`.
    pub attempts_max: u64,
    /// See `attempts_min`.
    pub attempts_mean: f64,
    /// Largest candidate count `resolve` returned.
    pub candidates_max: u64,
    /// Client-side latency (HTTP request to answer, or one store call).
    pub latency: Option<Percentiles>,
    /// Server-side trial time (evidence `trial_time`) over requests that ran a trial.
    pub trial: Option<Percentiles>,
    /// Requests per second: `requests` / summed latency (sequential) or / round wall time
    /// (burst).
    pub throughput_rps: f64,
    /// Non-2xx answers / requests.
    pub rejection_ratio: f64,
    /// Process CPU time (user + system) over the row's measured loop, if the OS exposes it.
    /// Server and client share the process, so it also covers the client's off-clock work in
    /// that loop: refilling the session pool, sealing, and the replay set-up POST. Empty for
    /// rows measured in an interleaved loop (valid positions), where it is not attributable.
    pub cpu_ms: Option<f64>,
    /// Process resident set size after the row, KiB, if the OS exposes it.
    pub rss_kib: Option<u64>,
    /// Invariant outcome.
    pub invariant: Invariant,
}

/// One CSV / JSON cell.
#[derive(Debug, Clone, PartialEq)]
enum Cell {
    Str(String),
    Int(u64),
    Float(f64),
    Null,
}

/// Fixed decimals for floats in CSV and Markdown: sub-microsecond digits are noise at loopback
/// HTTP latencies.
const FLOAT_DECIMALS: usize = 1;
/// Decimals for ratios (0..1), so a single rejection in a few hundred requests stays visible.
const RATIO_DECIMALS: usize = 4;

fn u(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

fn opt_f(v: Option<f64>) -> Cell {
    v.map_or(Cell::Null, Cell::Float)
}

fn percentile_cells(prefix: &str, p: Option<Percentiles>, out: &mut Vec<(String, Cell)>) {
    let values = p.map(|p| [p.p50_us, p.p95_us, p.p99_us, p.max_us, p.mean_us]);
    for (i, name) in ["p50_us", "p95_us", "p99_us", "max_us", "mean_us"]
        .into_iter()
        .enumerate()
    {
        out.push((format!("{prefix}_{name}"), opt_f(values.map(|v| v[i]))));
    }
}

impl Row {
    /// Column names and values, in output order.
    fn cells(&self) -> Vec<(String, Cell)> {
        let s = |v: &str| Cell::Str(v.to_owned());
        let mut out = vec![
            ("run_id".to_owned(), s(&self.run_id)),
            ("scenario".to_owned(), s(&self.scenario)),
            ("strategy".to_owned(), s(&self.strategy)),
            ("pending".to_owned(), Cell::Int(u(self.pending))),
            (
                "budget".to_owned(),
                self.budget.map_or(Cell::Null, |b| Cell::Int(u(b))),
            ),
            ("case".to_owned(), s(&self.case)),
            ("limits".to_owned(), s(&self.limits)),
            ("requests".to_owned(), Cell::Int(self.requests)),
            ("status_2xx".to_owned(), Cell::Int(self.status_2xx)),
            ("status_4xx".to_owned(), Cell::Int(self.status_4xx)),
            ("status_503".to_owned(), Cell::Int(self.status_503)),
            ("committed".to_owned(), Cell::Int(self.committed)),
            ("attempts_min".to_owned(), Cell::Int(self.attempts_min)),
            ("attempts_max".to_owned(), Cell::Int(self.attempts_max)),
            ("attempts_mean".to_owned(), Cell::Float(self.attempts_mean)),
            ("candidates_max".to_owned(), Cell::Int(self.candidates_max)),
        ];
        percentile_cells("latency", self.latency, &mut out);
        percentile_cells("trial", self.trial, &mut out);
        out.extend([
            (
                "throughput_rps".to_owned(),
                Cell::Float(self.throughput_rps),
            ),
            (
                "rejection_ratio".to_owned(),
                Cell::Float(self.rejection_ratio),
            ),
            ("cpu_ms".to_owned(), opt_f(self.cpu_ms)),
            (
                "rss_kib".to_owned(),
                self.rss_kib.map_or(Cell::Null, Cell::Int),
            ),
            ("invariant".to_owned(), s(self.invariant.status())),
            ("invariant_detail".to_owned(), s(self.invariant.detail())),
        ]);
        out
    }
}

fn json_cell(cell: Cell) -> Value {
    match cell {
        Cell::Str(v) => Value::String(v),
        Cell::Int(v) => Value::from(v),
        Cell::Float(v) => serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
        Cell::Null => Value::Null,
    }
}

fn csv_cell(name: &str, cell: &Cell) -> String {
    match cell {
        Cell::Str(v) => csv_escape(v),
        Cell::Int(v) => v.to_string(),
        Cell::Float(v) if name == "rejection_ratio" => format!("{v:.RATIO_DECIMALS$}"),
        Cell::Float(v) => format!("{v:.FLOAT_DECIMALS$}"),
        Cell::Null => String::new(),
    }
}

/// RFC 4180: quote a field that contains a comma, quote or line break; double inner quotes.
fn csv_escape(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_owned()
    }
}

/// The rows as a JSON document `{"run": run, "rows": [...]}`.
#[must_use]
pub fn to_json(run: &Value, rows: &[Row]) -> Value {
    let rows = rows
        .iter()
        .map(|row| {
            Value::Object(
                row.cells()
                    .into_iter()
                    .map(|(k, v)| (k, json_cell(v)))
                    .collect::<Map<_, _>>(),
            )
        })
        .collect();
    serde_json::json!({ "run": run, "rows": Value::Array(rows) })
}

/// The rows as CSV (RFC 4180, `\n` line ends), one header line.
#[must_use]
pub fn to_csv(rows: &[Row]) -> String {
    let header = rows.first().map_or_else(Vec::new, |row| {
        row.cells().into_iter().map(|(name, _)| name).collect()
    });
    let mut out = header.join(",");
    out.push('\n');
    for row in rows {
        let line: Vec<String> = row
            .cells()
            .iter()
            .map(|(name, cell)| csv_cell(name, cell))
            .collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// Writes [`to_json`] to `path`: the same document, one row per line, so committed runs stay
/// small and diff row by row.
///
/// # Errors
/// I/O errors.
pub fn write_json(path: &Path, run: &Value, rows: &[Row]) -> io::Result<()> {
    std::fs::write(path, json_lines(run, rows).map_err(io::Error::other)?)
}

fn json_lines(run: &Value, rows: &[Row]) -> serde_json::Result<String> {
    let doc = to_json(run, rows);
    let mut text = format!("{{\"run\": {},\n\"rows\": [", serde_json::to_string(run)?);
    for (i, row) in doc["rows"].as_array().into_iter().flatten().enumerate() {
        text.push_str(if i == 0 { "\n" } else { ",\n" });
        text.push_str(&serde_json::to_string(row)?);
    }
    text.push_str("\n]}\n");
    Ok(text)
}

/// Writes [`to_csv`] to `path`.
///
/// # Errors
/// I/O errors.
pub fn write_csv(path: &Path, rows: &[Row]) -> io::Result<()> {
    std::fs::write(path, to_csv(rows))
}

fn us(v: f64) -> String {
    format!("{v:.FLOAT_DECIMALS$}")
}

fn triple(p: Option<Percentiles>) -> String {
    p.map_or_else(
        || "–".to_owned(),
        |p| format!("{} / {} / {}", us(p.p50_us), us(p.p95_us), us(p.p99_us)),
    )
}

/// Cases shown in the HTTP summary table: the worst-case valid position and the cheapest
/// failure. Every other case is in the CSV / JSON.
const SUMMARY_CASES: [&str; 2] = ["valid_last", "invalid_ciphertext"];

/// A short Markdown summary: the valid-last and invalid-ciphertext HTTP rows (attempts and
/// percentiles), the over-budget, burst and store rows, and every failed invariant.
#[must_use]
pub fn markdown_summary(run_id: &str, rows: &[Row]) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "# G6 benchmark summary — run `{run_id}`\n");
    let _ = writeln!(
        md,
        "Evidence, not pass/fail: numbers are from one machine (see `manifest.json`) and are \
         not comparable across machines. Latencies in µs, `p50 / p95 / p99`. Full rows: \
         `results.csv` / `results.json`.\n"
    );
    let _ = writeln!(md, "## HTTP (sequential, loopback)\n");
    let _ = writeln!(
        md,
        "| strategy | N | case | HPKE attempts (min–max) | e2e latency | server trial time | invariant |"
    );
    let _ = writeln!(md, "| --- | ---: | --- | --- | --- | --- | --- |");
    for row in rows
        .iter()
        .filter(|r| r.scenario == "http" && SUMMARY_CASES.contains(&r.case.as_str()))
    {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {}–{} | {} | {} | {} |",
            row.strategy,
            row.pending,
            row.case,
            row.attempts_min,
            row.attempts_max,
            triple(row.latency),
            triple(row.trial),
            row.invariant.status()
        );
    }
    let over: Vec<&Row> = rows
        .iter()
        .filter(|r| r.scenario == "http" && r.case == "over_budget")
        .collect();
    if !over.is_empty() {
        let _ = writeln!(md, "\n## Over budget (bounded trial, N > budget)\n");
        let _ = writeln!(
            md,
            "| N | budget | HPKE attempts (max) | e2e latency | invariant |"
        );
        let _ = writeln!(md, "| ---: | ---: | ---: | --- | --- |");
        for row in over {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} |",
                row.pending,
                row.budget.unwrap_or_default(),
                row.attempts_max,
                triple(row.latency),
                row.invariant.status()
            );
        }
    }
    let burst: Vec<&Row> = rows.iter().filter(|r| r.scenario == "burst").collect();
    if !burst.is_empty() {
        let _ = writeln!(
            md,
            "\n## Burst (concurrent valid POSTs, limits on vs off)\n"
        );
        let _ = writeln!(
            md,
            "| strategy | N | limits | requests | 503 | rejection ratio | throughput (req/s) | e2e latency | invariant |"
        );
        let _ = writeln!(
            md,
            "| --- | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |"
        );
        for row in burst {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {:.RATIO_DECIMALS$} | {} | {} | {} |",
                row.strategy,
                row.pending,
                row.limits,
                row.requests,
                row.status_503,
                row.rejection_ratio,
                us(row.throughput_rps),
                triple(row.latency),
                row.invariant.status()
            );
        }
    }
    let limits: Vec<&Row> = rows.iter().filter(|r| r.scenario == "limits").collect();
    if !limits.is_empty() {
        let _ = writeln!(
            md,
            "\n## In-flight cap (controlled admission: cap requests held, one more sent)\n"
        );
        let _ = writeln!(md, "| cap | probes | 503 | probe latency | invariant |");
        let _ = writeln!(md, "| ---: | ---: | ---: | --- | --- |");
        for row in limits {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} |",
                row.pending,
                row.requests,
                row.status_503,
                triple(row.latency),
                row.invariant.status()
            );
        }
    }
    let store: Vec<&Row> = rows.iter().filter(|r| r.scenario == "store").collect();
    if !store.is_empty() {
        let _ = writeln!(md, "\n## Session store (no HTTP): memory vs Redis\n");
        let _ = writeln!(
            md,
            "| backend | operation | requests | latency | invariant |"
        );
        let _ = writeln!(md, "| --- | --- | ---: | --- | --- |");
        for row in store {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} |",
                row.strategy,
                row.case,
                row.requests,
                triple(row.latency),
                row.invariant.status()
            );
        }
    }
    let failed: Vec<&Row> = rows.iter().filter(|r| !r.invariant.holds()).collect();
    let _ = writeln!(md, "\n## Invariants\n");
    if failed.is_empty() {
        let checked = rows
            .iter()
            .filter(|r| matches!(r.invariant, Invariant::Pass(_)))
            .count();
        let _ = writeln!(md, "All {checked} checked rows hold their invariants.");
    } else {
        for row in failed {
            let _ = writeln!(
                md,
                "- **FAIL** {} {} N={} {}: {}",
                row.scenario,
                row.strategy,
                row.pending,
                row.case,
                row.invariant.detail()
            );
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(case: &str, invariant: Invariant) -> Row {
        Row {
            run_id: "run-1".to_owned(),
            scenario: "http".to_owned(),
            strategy: "bounded_trial".to_owned(),
            pending: 8,
            budget: Some(128),
            case: case.to_owned(),
            limits: "default".to_owned(),
            requests: 10,
            status_2xx: 10,
            status_4xx: 0,
            status_503: 0,
            committed: 10,
            attempts_min: 8,
            attempts_max: 8,
            attempts_mean: 8.0,
            candidates_max: 8,
            latency: Some(Percentiles {
                p50_us: 100.0,
                p95_us: 150.0,
                p99_us: 199.9,
                max_us: 250.0,
                mean_us: 110.0,
            }),
            trial: None,
            throughput_rps: 9000.0,
            rejection_ratio: 0.0,
            cpu_ms: None,
            rss_kib: Some(1024),
            invariant,
        }
    }

    #[test]
    fn csv_rows_have_as_many_fields_as_the_header() {
        let rows = [
            row("valid_last", Invariant::Pass("attempts == N".to_owned())),
            row("invalid, \"quoted\"", Invariant::NotApplicable),
        ];
        let csv = to_csv(&rows);
        let mut lines = csv.lines();
        let header_fields = lines.next().expect("header").split(',').count();
        let first = lines.next().expect("row");
        assert_eq!(first.split(',').count(), header_fields);
        assert!(csv.contains("\"invalid, \"\"quoted\"\"\""));
        assert!(first.starts_with("run-1,http,bounded_trial,8,128,valid_last,"));
    }

    #[test]
    fn json_carries_every_column_and_nulls_for_missing_values() {
        let rows = [row("valid_last", Invariant::NotApplicable)];
        let json = to_json(&serde_json::json!({ "run_id": "run-1" }), &rows);
        let first = &json["rows"][0];
        assert_eq!(first["attempts_max"], 8);
        assert_eq!(first["trial_p50_us"], Value::Null);
        assert_eq!(first["cpu_ms"], Value::Null);
        assert_eq!(first["invariant"], "n/a");
        assert_eq!(
            first.as_object().expect("object").len(),
            rows[0].cells().len()
        );
        let lines = json_lines(&serde_json::json!({ "run_id": "run-1" }), &rows).expect("json");
        let parsed: Value = serde_json::from_str(&lines).expect("one-row-per-line JSON parses");
        assert_eq!(parsed, json);
    }

    #[test]
    fn summary_lists_failed_invariants() {
        let rows = [
            row(
                "valid_last",
                Invariant::Fail("attempts 7 != N 8".to_owned()),
            ),
            row(
                "invalid_ciphertext",
                Invariant::Pass("not committed".to_owned()),
            ),
        ];
        let md = markdown_summary("run-1", &rows);
        assert!(md.contains("| bounded_trial | 8 | valid_last | 8–8 | 100.0 / 150.0 / 199.9 |"));
        assert!(md.contains("**FAIL** http bounded_trial N=8 valid_last: attempts 7 != N 8"));
    }
}
