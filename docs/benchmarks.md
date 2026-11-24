# G6 benchmarks: methodology and evidence

Gate G6 (IMP-015 scenario-runner, IMP-016 evidence-report, CI-008 bench workflow). Measures
what each session-resolution strategy costs on the HPKE-0 `direct_post.jwt` path, how many HPKE
attempts it makes, and what the request limits do under a burst. Synthetic data, loopback only.

**The results are evidence, not pass/fail.** Absolute numbers depend on the machine, OS, power
state and background load. They are never compared across machines automatically, and no
latency threshold gates a PR. A run fails only when a protocol invariant breaks (see
[Invariants](#invariants)).

## Reproduce

```bash
make bench                                   # = scripts/bench.sh evidence/g6
scripts/bench.sh <out-root> -- --iterations 200 --sizes 1,8,128 --seed 7
cargo bench -p scenario-runner               # criterion micro-benchmarks (HPKE open, resolve)
```

`scripts/bench.sh` builds `scenario-runner` with `--release --locked`, runs it, and writes
`<out-root>/<run-id>/` (run id `<UTC yyyymmddThhmmssZ>-<git sha>`, or `BENCH_RUN_ID`). Then it
writes `manifest.json` with `scripts/evidence_manifest.sh`. The manifest records the commit
SHA and the git tree hash of `crates/` (`lab_crates_tree`), which stays the same across rebases
of identical sources. `<out-root>` is optional, and runner arguments always follow `--`.
Exit status: 0 = every invariant held, 1 = an invariant broke (all files are still written),
2 = the run could not complete (build failure, bad arguments, broken run). `bench.sh` is not a
stage of `scripts/ci_local.sh`, and `ci.yml` never runs it.

Redis rows need `REDIS_URL`. Locally, use the gate's disposable Valkey image:

```bash
docker run -d --rm --name g6-valkey -p 127.0.0.1:6379:6379 --read-only --user 999:999 \
  --cap-drop ALL --security-opt no-new-privileges \
  valkey/valkey:8.1.12@sha256:5032c4dd7abe08d6fd9382054608183e2bf1f7e3895ef619b8784698454325f7 \
  valkey-server --save '' --appendonly no
REDIS_URL=redis://127.0.0.1:6379/ make bench
docker rm -f g6-valkey
```

In GitHub Actions, run `bench.yml` with **Run workflow** (`workflow_dispatch` only). Its inputs
are `sizes` (at most 8 values), `iterations` (at most 1000), `warmup` (at most 100) and `seed`.
It runs on `ubuntu-24.04` with the same Valkey service container as the `redis` job, and
uploads the run directory as the `evidence-bench` artifact (kept 30 days). It is not part of
`ci-gate`.

Runner flags (defaults in brackets): `--sizes` [1,2,8,32,64,128], `--iterations` [100],
`--warmup` [10], `--seed` [1], `--budget` [largest N], `--over-budget` [8],
`--burst` [64, at most the budget], `--burst-rounds` [10], `--store-iterations` [1000],
`--fixtures` [lab-server test fixtures].

A run must exercise every invariant, so the runner refuses arguments that would leave one out:
the largest N must exceed `--over-budget`, `--burst` must exceed the limits-on in-flight cap
(8), and `--burst-rounds` must be positive.

## Set-up

* Each strategy × N block gets a fresh `LabServer` (default config unless stated) on
  `127.0.0.1:0`, in the runner's own process (tokio multi-thread runtime). The wallet simulator
  (`lab-server` feature `wallet-sim`) talks to it over real HTTP/1.1 with keep-alive. Nothing
  leaves loopback.
* Strategies:
  * `unique_uri`: hardened mode, one response_uri per session.
  * `unique_kid`: research mode, shared route, one key and `kid` per session.
  * `bounded_trial`: research mode, shared route, one shared key and `kid` (the OIDF #792
    shape), budget = largest N (128).
* N = pending sessions on the route when the measured request arrives: 1, 2, 8, 32, 64, 128.
  The client keeps a pool of exactly N sessions in creation order. session-core resolves
  bounded-trial candidates in that order, so pool position = candidate position. A committed
  session is replaced by a new one at the end of the order before the next request.
* Order: per block, the cases run in an order shuffled by the seed. The generator is
  SplitMix64, and only the schedule is seeded: all keys, nonces and tokens come from the OS
  CSPRNG.
  * The valid positions (first / middle / last) are **interleaved request by request**: each
    round runs every position once, in a freshly seeded order. Drift in CPU frequency, caches
    or the allocator therefore spreads evenly over the positions their latencies are compared
    across.
  * Every other case runs `--warmup` unmeasured requests, then `--iterations` measured ones
    back to back.
  * Sealing the JWE, creating sessions and the replay set-up POST happen off the clock. Only
    the HTTP exchange of the measured request is timed.
* Fixtures: the synthetic signing and issuer keys in `crates/lab-server/tests/fixtures`. They
  are read at run time, never compiled into the runner.

### Cases

| Case | Request | Expected outcome |
| --- | --- | --- |
| `valid_first` / `valid_middle` / `valid_last` | Honest response for the session at pool index 0, ⌊(N−1)/2⌋ or N−1 (deduplicated for small N; N = 1 has only `valid_last`) | 200, committed |
| `invalid_ciphertext` | Honest response for the last session, one ciphertext character flipped | 400, no candidate opens (`Decrypt`) |
| `wrong_nonce` | Opens for the last session, but its KB-JWT carries a `nonce` the lab never issued | 400, opens, then validation fails |
| `replay` | The exact JWE of a session committed just before (set-up POST unmeasured), posted again | 400, nothing committed; refused at resolve (unique) or no candidate opens (bounded) |
| `admission` | A valid form body sent as `application/json` | 415 before the JWE is parsed |
| `over_budget` | Bounded trial, budget 8, N = 32 / 64 / 128 pending | 400 at resolve, before any HPKE |
| `valid_concurrent` (burst) | N = 64 honest responses at once, 10 rounds after one warm-up round, limits on and off | see below |

Burst limits: **on** = `max_in_flight_requests` 8 and `max_concurrent_decryptions` 2, so the
burst sheds load (503) and queues trials. **Off** = the default in-flight cap (512, above the
burst) and one decryption slot per concurrent request, so neither limit binds. The lab has no
rate limiter: "rate limit" here means the in-flight cap. A 503 is answered by the limit
middleware before the pipeline runs, so it leaves no evidence record and makes no HPKE attempt.

### Session store (no HTTP)

`store` rows time session-core's `MemoryRegistry` and, with `REDIS_URL`, session-redis's
`RedisRegistry` with `TimeSource::RedisServer` (the production setting), in a fresh namespace.
Each cycle is `insert`, then unique-uri `resolve`, then `claim`: 1000 measured cycles after the
warm-up. For Redis, a `PING` on a separate connection measures the network round trip, so
`claim − ping` approximates the script cost. Keys never go to Redis (session-redis key table).

## Metrics

One CSV / JSON row per scenario × strategy × N × case (`results.csv`, `results.json`). Every
row carries `run_id`, which names the run directory and its `manifest.json`.

| Column | Meaning | Source |
| --- | --- | --- |
| `requests`, `status_2xx`, `status_4xx`, `status_503` | Measured requests and their HTTP answers | client |
| `committed` | Requests the server committed (`CommitResult::Committed`) | server evidence |
| `attempts_min/max/mean` | HPKE open attempts per request (`EvidenceRecord::hpke_attempts`), over requests that left an evidence record (a 503 leaves none) | server evidence |
| `candidates_max` | Largest candidate set `resolve` returned | server evidence |
| `latency_*_us` | End-to-end HTTP latency (request sent to answer read), P50/P95/P99/max/mean | client, `Instant` |
| `trial_*_us` | Server trial time (`EvidenceRecord::trial_time`): every HPKE open and the validation of each opened plaintext, on the blocking pool, without the wait for a decryption slot. Requests without a trial are excluded. In a burst, concurrent trials compete for CPU cores, so this includes contention | server evidence |
| `throughput_rps` | Sequential: requests / summed latency (= 1 / mean). Burst: requests / round wall time, 503 answers included. Store: 1 / mean | client |
| `rejection_ratio` | Non-2xx answers / requests | client |
| `cpu_ms` | Process CPU time (user + system) over the row's measured loop, including the client's off-clock work in it (pool refill, sealing, replay set-up). Empty for the interleaved valid rows | OS, see below |
| `rss_kib` | Process resident set size after the row | OS, see below |
| `invariant`, `invariant_detail` | `pass` / `FAIL` / `n/a` and the rule (or the first violation) | runner |

Percentiles come from hdrhistogram (1 ns to 60 s, three significant digits, so values are
within 0.1 %). With 100 samples, P99 is the second-largest sample: read it as "near the
maximum", not as a stable tail estimate. Raise `--iterations` for tails.

`summary.md` holds the valid-last and invalid-ciphertext rows (attempts and P50/P95/P99 of
latency and trial time), plus the over-budget, burst and store rows and any failed invariant.
`run.json` holds the scenario parameters and the build profile; `manifest.json` embeds it.

### CPU and RSS

Sampled without `unsafe` (the workspace forbids it), so no `getrusage`:

* **Linux:** `/proc/self/stat` `utime + stime` divided by `getconf CLK_TCK` (usually 100 Hz,
  so 10 ms resolution), and `VmRSS` from `/proc/self/status`.
* **macOS / other Unix:** `ps -o rss=,time= -p <pid>`. macOS prints CPU time in hundredths of a
  second.
* **Elsewhere:** empty columns.

The server and the wallet simulator share the process, so `cpu_ms` includes the client side:
sealing (HPKE, ES256 KB-JWT), session creation and the off-clock set-up requests. It is a
coarse within-run indicator, never a server cost. The interleaved valid positions share one
loop, so their CPU time cannot be split per position, and those rows leave `cpu_ms` empty. RSS
is a point sample, not a peak.

## Invariants

Checked on every request, warm-up included. A violation marks the row `FAIL`, and its detail
counts measured and warm-up violations separately. Any `FAIL` makes the runner exit 1.

Attempt counts are exact, not bounds. Every case that reaches the trial runs with N sessions
pending, and the lab tries every candidate:

* valid, every position: 200, committed, **attempts == 1** for `unique_uri` / `unique_kid`,
  **attempts == N** for `bounded_trial`.
* `invalid_ciphertext`: 400, not committed, `CryptoResult::NoneOpened` and `Rejection::Decrypt`,
  **attempts == 1** (unique) or **N** (bounded).
* `wrong_nonce`: 400, not committed, opened and then `ValidationResult::Failed` with
  `Rejection::Validation`, **attempts == 1** (unique) or **N** (bounded).
* `replay`, unique strategies: 400, not committed, `Rejection::Resolve` (the consumed session is
  no candidate), **attempts == 0**.
* `replay`, bounded trial: 400, not committed, `NoneOpened`, **attempts == N** (the N pending
  sessions are tried, and none opens).
* `over_budget`: 400, `ResolveError::CandidateBudgetExceeded`, **attempts == 0**.
* `admission`: 415, `Rejection::Admission`, **attempts == 0**.
* every request: exactly one evidence record, and a recorded trial time whenever an attempt was
  made.
* burst, every round: every admitted request commits within the strategy's attempt bound and a
  503 leaves no evidence record. With limits on, at least one request is shed (503). With
  limits off, none is.

The unit tests in `scenario-runner` (listed in the gate's required tests) feed records that
break each rule and check that the row fails and that the exit status is 1.

## Reading the results

* Bounded trial tries **every** candidate, with no early exit (lab-server design: a second
  validating candidate must be seen in order to refuse it). The **attempt count** is therefore
  independent of the correct session's position, and the invariant proves it on every request.
  Its cost grows linearly with N, so response time reveals the route's population.
* **Latency by position** (first / middle / last) is reported with its spread (P50/P95/P99,
  max), measured interleaved. Equal attempt counts do not make the work identical: the opened
  candidate also runs holder-binding validation, and memory and cache effects differ. Small
  latency differences between positions are measurement results, **not** a constant-time or
  no-side-channel claim. This harness does not test that property.
* The per-candidate cost is about one HPKE-0 open: criterion's `hpke0_open/wrong_session_info`
  (the shared key with another session's `session_info`, which is exactly how a wrong candidate
  fails) and the bounded-trial `trial_time` / N agree. `resolve` itself stays in the
  microseconds even at N = 128 (`resolve/bounded_trial/128`).
* Unique strategies stay at one attempt; their latency does not depend on N.
* Burst throughput with limits on counts the 503 answers, which are cheap. Compare `committed`
  and the latency percentiles, not throughput alone.
* Over budget and admission are refused before any HPKE work. Their latency is the HTTP and
  resolve floor.
* `trial_time` below `latency` is HTTP, routing, the claim and client overhead.

## Caveats

* **Loopback and in-process.** Client and server share one process, its CPU and its tokio
  runtime. Loopback has no network latency, no TLS and no real wallet.
* **Synthetic workload.** One credential shape and one holder key. Every bounded-trial
  candidate except the correct one fails at the AEAD tag after the ECDH, which is the cheapest
  failure.
* **CI VM noise.** Shared runners vary in CPU model, frequency and neighbours from run to run.
  Compare only rows of the same run, or runs on the same runner class with their manifests.
* **macOS Docker.** Docker Desktop runs Valkey in a Linux VM, so on macOS every Redis round
  trip includes the VM's port-forwarding hop. Compare `claim` against `ping` of the same run,
  not against a native server. On Linux CI it is a service container on the runner host.
* **Warm-up.** The first block of a run (unique-uri, N = 1) can still show frequency ramp-up
  in its P95/P99.
* **Release builds only.** A debug build is marked `"profile": "debug"` in `run.json`, and its
  HPKE trial is more than an order of magnitude slower.
* **Burst trial time includes contention.** Concurrent trials compete for cores (and, with
  limits off, up to one blocking thread per request), so burst `trial_*` is not the
  single-request cost.
* **Not a Verifier build.** `scenario-runner` enables lab-server's test-only `wallet-sim`. It is
  kept out of the workspace `default-members`, and the gate step
  `default_members_are_verifier_builds` fails if a default member enables `wallet-sim` or
  `lab-instrumentation`. A `--workspace` build (or `-p scenario-runner`) is never a Verifier
  build.

## Runs

Runs go to `evidence/g6/<run-id>/` (`results.csv`, `results.json` with one row per line,
`summary.md`, `run.json`, `bench.log`, `manifest.json`). A sample run is committed on `main`
separately, as its own evidence change.
