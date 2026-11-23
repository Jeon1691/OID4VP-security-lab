//! Shared fixtures for the session-core integration tests. Synthetic values only.
//!
//! Each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use protocol_model::{ClientIdWire, KeyId, NonceWire, RequestBinding, ResponseUriWire, SessionId};
use session_core::{
    ManualClock, MemoryRegistry, NewSession, ResponseDigest, RouteToken, Timestamp,
};

/// Stand-in for the jose-hpke private key handle the lab-server will plug in. The registry
/// treats it as opaque; tests only use the index to check which key a candidate carries.
#[derive(Debug, PartialEq, Eq)]
pub struct TestKey(pub usize);

/// Stand-in for the validated presentation result stored on commit.
pub type TestResult = String;

pub type Registry = MemoryRegistry<TestKey, TestResult>;

/// Arbitrary fixed start time (2023-11-14T22:13:20Z); only differences matter.
pub const T0: Timestamp = Timestamp::from_unix_millis(1_700_000_000_000);

/// Session lifetime used by the fixtures. Five minutes, a typical Authorization Request TTL;
/// tests move the manual clock relative to it.
pub const TTL: Duration = Duration::from_secs(300);

/// Session counts the strategy tests sweep (task matrix: 1, 2, 8, 32, 64, 128).
pub const SCALES: [usize; 6] = [1, 2, 8, 32, 64, 128];

const CLIENT_ID: &str = "x509_san_dns:verifier.lab.example";
const RESPONSE_URI_BASE: &str = "https://verifier.lab.example/post";

pub fn registry() -> (Arc<ManualClock>, Registry) {
    let clock = Arc::new(ManualClock::new(T0));
    let registry = Registry::new(clock.clone());
    (clock, registry)
}

pub fn sid(i: usize) -> SessionId {
    SessionId::new(format!("session-{i}")).expect("valid session id")
}

pub fn kid(i: usize) -> KeyId {
    KeyId::new(format!("kid-{i}")).expect("valid kid")
}

pub fn route() -> RouteToken {
    RouteToken::generate().expect("OS CSPRNG available")
}

pub fn digest(tag: u8) -> ResponseDigest {
    ResponseDigest::new([tag; 32])
}

pub fn binding(i: usize, route: &RouteToken) -> RequestBinding {
    RequestBinding::DirectPostJwt {
        client_id: ClientIdWire::new(CLIENT_ID).expect("valid client_id"),
        nonce: NonceWire::new(format!("nonce-{i}")).expect("valid nonce"),
        response_uri: ResponseUriWire::new(format!(
            "{RESPONSE_URI_BASE}/{}",
            route.to_url_segment()
        ))
        .expect("valid response_uri"),
    }
}

pub fn new_session(i: usize, route: &RouteToken, kid: Option<KeyId>) -> NewSession<TestKey> {
    NewSession {
        id: sid(i),
        binding: binding(i, route),
        route_token: route.clone(),
        kid,
        key: TestKey(i),
        ttl: TTL,
    }
}
