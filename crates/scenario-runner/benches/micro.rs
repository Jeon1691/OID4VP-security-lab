//! Criterion micro-benchmarks behind the G6 HTTP numbers (`cargo bench -p scenario-runner`):
//!
//! * `hpke0_open/{right_key,wrong_session_info,wrong_key}`: parse + HPKE-0 open of one compact
//!   JWE. `wrong_session_info` is exactly the bounded-trial failure: the route's shared key with
//!   another session's `session_info` (different nonce), so the key schedule differs and the
//!   AEAD tag fails after the full ECDH. A bounded trial pays it for every candidate but one, so
//!   N × `wrong_session_info` is its crypto floor (validation of the opened plaintext comes on
//!   top). `wrong_key` (another recipient key) is the unique-strategy failure shape and only
//!   approximates the trial's.
//! * `resolve/{unique_uri,unique_kid,bounded_trial}/N`: session-core `MemoryRegistry::resolve`
//!   with N pending sessions on one shared route (unique-uri: one route per session).
//!
//! Synthetic keys and values only; nothing here touches the network.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use jose_hpke::rand_core::UnwrapErr;
use jose_hpke::test_support::seal_compact;
use jose_hpke::{CompactJwe, RecipientPrivateKey, SessionInfo};
use protocol_model::{ClientIdWire, KeyId, NonceWire, RequestBinding, ResponseUriWire, SessionId};
use session_core::{
    CandidateBudget, IngressHint, MemoryRegistry, NewSession, RegistryConfig, ResolutionStrategy,
    RoutePolicy, RouteToken, SystemClock,
};

/// Pending-session counts of the G6 matrix.
const SIZES: [usize; 6] = [1, 2, 8, 32, 64, 128];
/// Synthetic binding values (reserved `.invalid` TLD, RFC 2606 §2).
const CLIENT_ID: &str = "x509_san_dns:verifier.lab.invalid";
const RESPONSE_URI: &str = "https://verifier.lab.invalid/post";
const KID: &str = "g6-bench-kid";
/// Plaintext about the size of an honest lab `vp_token` (one SD-JWT+KB, ~1.2 KB).
const PLAINTEXT_BYTES: usize = 1200;
/// Session lifetime: far longer than any benchmark.
const TTL: std::time::Duration = std::time::Duration::from_secs(3600);

fn binding(nonce: &str, response_uri: &str) -> RequestBinding {
    RequestBinding::DirectPostJwt {
        client_id: ClientIdWire::new(CLIENT_ID).expect("client_id"),
        nonce: NonceWire::new(nonce).expect("nonce"),
        response_uri: ResponseUriWire::new(response_uri).expect("response_uri"),
    }
}

fn hpke_open(c: &mut Criterion) {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let key = RecipientPrivateKey::generate(&mut rng);
    let other = RecipientPrivateKey::generate(&mut rng);
    let info = SessionInfo::from_binding(&binding("g6-nonce", RESPONSE_URI));
    let other_info = SessionInfo::from_binding(&binding("g6-other-nonce", RESPONSE_URI));
    let jwe = seal_compact(
        &key.public_key(),
        Some(KID),
        info.as_bytes(),
        &vec![b'x'; PLAINTEXT_BYTES],
        &mut rng,
    )
    .expect("seal");
    let mut group = c.benchmark_group("hpke0_open");
    group.bench_function("right_key", |b| {
        b.iter(|| {
            let parsed = CompactJwe::parse(black_box(&jwe)).expect("parse");
            black_box(parsed.open(&key, info.as_bytes()).expect("opens"))
        });
    });
    group.bench_function("wrong_session_info", |b| {
        b.iter(|| {
            let parsed = CompactJwe::parse(black_box(&jwe)).expect("parse");
            black_box(parsed.open(&key, other_info.as_bytes()).is_err())
        });
    });
    group.bench_function("wrong_key", |b| {
        b.iter(|| {
            let parsed = CompactJwe::parse(black_box(&jwe)).expect("parse");
            black_box(parsed.open(&other, info.as_bytes()).is_err())
        });
    });
    group.finish();
}

/// A registry with `n` pending sessions on one shared route, each with its own `kid`.
fn shared_registry(n: usize, route: &RouteToken) -> MemoryRegistry<(), ()> {
    let registry = MemoryRegistry::with_config(
        Arc::new(SystemClock),
        RegistryConfig {
            route_policy: RoutePolicy::Shared,
            ..RegistryConfig::default()
        },
    );
    for i in 0..n {
        registry
            .insert(NewSession {
                id: SessionId::new(format!("s-{i}")).expect("id"),
                binding: binding(&format!("n-{i}"), RESPONSE_URI),
                route_token: route.clone(),
                kid: Some(KeyId::new(format!("k-{i}")).expect("kid")),
                key: (),
                ttl: TTL,
            })
            .expect("insert");
    }
    registry
}

fn resolve(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve");
    for n in SIZES {
        let route = RouteToken::generate().expect("OS CSPRNG");
        let shared = shared_registry(n, &route);
        let last_kid = KeyId::new(format!("k-{}", n - 1)).expect("kid");
        let budget = CandidateBudget::new(n).expect("budget");
        group.bench_with_input(BenchmarkId::new("bounded_trial", n), &n, |b, _| {
            let hint = IngressHint::new(route.clone(), None);
            b.iter(|| {
                black_box(
                    shared
                        .resolve(&hint, ResolutionStrategy::BoundedTrial(budget))
                        .expect("resolves"),
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("unique_kid", n), &n, |b, _| {
            let hint = IngressHint::new(route.clone(), Some(last_kid.clone()));
            b.iter(|| {
                black_box(
                    shared
                        .resolve(&hint, ResolutionStrategy::UniqueKid)
                        .expect("resolves"),
                )
            });
        });
        let unique: MemoryRegistry<(), ()> =
            MemoryRegistry::with_config(Arc::new(SystemClock), RegistryConfig::default());
        let mut last_route = None;
        for i in 0..n {
            let r = RouteToken::generate().expect("OS CSPRNG");
            unique
                .insert(NewSession {
                    id: SessionId::new(format!("u-{i}")).expect("id"),
                    binding: binding(&format!("n-{i}"), RESPONSE_URI),
                    route_token: r.clone(),
                    kid: None,
                    key: (),
                    ttl: TTL,
                })
                .expect("insert");
            last_route = Some(r);
        }
        let hint = IngressHint::new(last_route.expect("n > 0"), None);
        group.bench_with_input(BenchmarkId::new("unique_uri", n), &n, |b, _| {
            b.iter(|| {
                black_box(
                    unique
                        .resolve(&hint, ResolutionStrategy::UniqueUri)
                        .expect("resolves"),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, hpke_open, resolve);
criterion_main!(benches);
