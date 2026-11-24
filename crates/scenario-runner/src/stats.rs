//! Measurement helpers: latency histograms, the seeded schedule PRNG and process usage.

use std::time::Duration;

use evidence_report::Percentiles;
use hdrhistogram::Histogram;

/// Highest latency the histograms track: 60 s, far above the server's 10 s request timeout,
/// so no answered request is ever clamped.
const MAX_TRACKED_NANOS: u64 = 60_000_000_000;
/// hdrhistogram precision: three significant digits (0.1% value resolution), the library's
/// customary setting; enough to separate loopback latencies without large bucket arrays.
const SIGNIFICANT_DIGITS: u8 = 3;
const NANOS_PER_MICRO: f64 = 1_000.0;
/// Quantiles reported per row.
const P50: f64 = 0.50;
const P95: f64 = 0.95;
const P99: f64 = 0.99;

/// Latency samples in nanoseconds.
pub struct Latencies(Histogram<u64>);

impl Latencies {
    /// An empty histogram from 1 ns to [`MAX_TRACKED_NANOS`].
    ///
    /// # Panics
    /// Never: the bounds and precision are constants hdrhistogram accepts.
    #[must_use]
    pub fn new() -> Self {
        Self(
            Histogram::new_with_bounds(1, MAX_TRACKED_NANOS, SIGNIFICANT_DIGITS)
                .expect("constant histogram bounds are valid"),
        )
    }

    /// Records one sample (clamped into the tracked range).
    pub fn record(&mut self, d: Duration) {
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX).max(1);
        self.0.saturating_record(nanos);
    }

    /// Number of samples.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.0.len()
    }

    /// P50/P95/P99/max/mean in microseconds, or `None` without samples.
    #[must_use]
    pub fn percentiles(&self) -> Option<Percentiles> {
        if self.0.is_empty() {
            return None;
        }
        let us = |nanos: u64| nanos as f64 / NANOS_PER_MICRO;
        Some(Percentiles {
            p50_us: us(self.0.value_at_quantile(P50)),
            p95_us: us(self.0.value_at_quantile(P95)),
            p99_us: us(self.0.value_at_quantile(P99)),
            max_us: us(self.0.max()),
            mean_us: self.0.mean() / NANOS_PER_MICRO,
        })
    }
}

/// SplitMix64 (Steele, Lea, Flood, "Fast splittable pseudorandom number generators", OOPSLA
/// 2014; constants as in Vigna's reference `splitmix64.c`). Not cryptographic: it only fixes
/// the order in which cases run, so a run's schedule is reproducible from its seed. Keys,
/// nonces and tokens always come from the OS CSPRNG inside lab-server and the simulator.
pub struct Schedule(u64);

/// Golden-ratio increment of SplitMix64.
const SPLITMIX_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
/// SplitMix64 output mixing multipliers (Stafford's "Mix13" variant).
const SPLITMIX_MUL1: u64 = 0xBF58_476D_1CE4_E5B9;
const SPLITMIX_MUL2: u64 = 0x94D0_49BB_1331_11EB;
const SPLITMIX_SHIFT1: u32 = 30;
const SPLITMIX_SHIFT2: u32 = 27;
const SPLITMIX_SHIFT3: u32 = 31;

impl Schedule {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(SPLITMIX_GAMMA);
        let mut z = self.0;
        z = (z ^ (z >> SPLITMIX_SHIFT1)).wrapping_mul(SPLITMIX_MUL1);
        z = (z ^ (z >> SPLITMIX_SHIFT2)).wrapping_mul(SPLITMIX_MUL2);
        z ^ (z >> SPLITMIX_SHIFT3)
    }

    /// Fisher-Yates shuffle driven by this generator.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let bound = u64::try_from(i + 1).unwrap_or(u64::MAX);
            // Modulo bias is irrelevant for a schedule permutation of a handful of cases.
            let j = usize::try_from(self.next() % bound).unwrap_or(0);
            items.swap(i, j);
        }
    }
}

/// Process CPU time (user + system) and resident set size, where the OS exposes them without
/// `unsafe`: Linux reads `/proc/self/stat` and `/proc/self/status`; other Unix systems
/// (macOS) run `ps`. Server and client share this process, so both are included.
#[derive(Debug, Clone, Copy)]
pub struct Usage {
    pub cpu: Duration,
    pub rss_kib: u64,
}

impl Usage {
    /// A sample, or `None` where unsupported or unreadable.
    #[must_use]
    pub fn sample() -> Option<Self> {
        if cfg!(target_os = "linux") {
            linux_usage()
        } else if cfg!(unix) {
            ps_usage()
        } else {
            None
        }
    }
}

/// `utime` and `stime` are fields 14 and 15 of `/proc/<pid>/stat` (proc(5)); counted here from
/// the first field after the parenthesised command name, i.e. field 3.
const STAT_UTIME_AFTER_COMM: usize = 11;
const STAT_STIME_AFTER_COMM: usize = 12;

fn linux_usage() -> Option<Usage> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let ticks = |i: usize| fields.get(i)?.parse::<u64>().ok();
    let total = ticks(STAT_UTIME_AFTER_COMM)? + ticks(STAT_STIME_AFTER_COMM)?;
    let hz = clock_ticks_per_second()?;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss_kib = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let secs = total as f64 / hz as f64;
    Some(Usage {
        cpu: Duration::from_secs_f64(secs),
        rss_kib,
    })
}

/// `sysconf(_SC_CLK_TCK)` without libc: `getconf CLK_TCK`.
fn clock_ticks_per_second() -> Option<u64> {
    let out = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()?;
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

const SECS_PER_MINUTE: f64 = 60.0;
const SECS_PER_DAY: f64 = 86_400.0;

/// `ps -o rss=,time= -p <pid>`: RSS in KiB and accumulated CPU time as `[[dd-]hh:]mm:ss.ss`
/// (macOS prints hundredths; procps whole seconds, which is why Linux reads `/proc`).
fn ps_usage() -> Option<Usage> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=,time=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let mut parts = text.split_whitespace();
    let rss_kib = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let (days, clock) = match time.split_once('-') {
        Some((d, rest)) => (d.parse::<f64>().ok()?, rest),
        None => (0.0, time),
    };
    let mut secs = 0.0;
    for part in clock.split(':') {
        secs = secs * SECS_PER_MINUTE + part.parse::<f64>().ok()?;
    }
    Some(Usage {
        cpu: Duration::from_secs_f64(days.mul_add(SECS_PER_DAY, secs)),
        rss_kib,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_a_reproducible_permutation() {
        let mut a: Vec<u32> = (0..7).collect();
        let mut b = a.clone();
        Schedule::new(42).shuffle(&mut a);
        Schedule::new(42).shuffle(&mut b);
        assert_eq!(a, b);
        let mut sorted = a.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..7).collect::<Vec<_>>());
    }

    #[test]
    fn percentiles_are_in_microseconds() {
        let mut h = Latencies::new();
        for micros in 1..=100 {
            h.record(Duration::from_micros(micros));
        }
        let p = h.percentiles().expect("samples");
        assert!((p.p50_us - 50.0).abs() < 0.1, "{p:?}");
        assert!((p.max_us - 100.0).abs() < 0.1, "{p:?}");
        assert_eq!(h.len(), 100);
        assert!(Latencies::new().percentiles().is_none());
    }

    #[test]
    fn process_usage_is_sampled_on_unix() {
        if cfg!(unix) {
            let usage = Usage::sample().expect("usage on unix");
            assert!(usage.rss_kib > 0);
        }
    }
}
