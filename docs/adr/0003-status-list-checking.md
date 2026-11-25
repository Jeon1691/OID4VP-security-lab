# ADR 0003: Token Status List checking before commit

- **Status:** Proposed, 2026-11-25. Implemented at the project owner's request (add status
  checking per the owner's implementation and re-verification criteria, then re-run C3 / C4);
  the owner has not yet accepted the decisions below as an ADR.
- **Scope:** `crates/lab-server` (`status_list`, the response pipeline's commit step, the
  `conformance` feature, the binary's `--status-list-*` flags, the test-only `status_sim`),
  `scripts/conformance_fixtures.py` (status CA and signer fixtures),
  `tools/oidf-suite/driver/run_plan.py`.
- **Amends:** `README.md` "Out of scope: ... status/revocation"; ADR 0002 (conformance mode
  gains an outbound HTTPS client, for status lists only).
- **Related:** draft-ietf-oauth-status-list-14 ("TSL"; the latest revision, -19 of 20 March
  2026, keeps the same validation rules and makes the out-of-range rejection a MUST, which the
  lab already applies); SD-JWT VC draft-27 §2.2.2.3 (`status` is never disclosed); HAIP 1.0;
  `tools/oidf-suite/README.md` §5a, §5d.

This ADR records a lab design decision. It is not a statement of the OpenID Foundation's
position.

## Context

The C3 / C4 runs (`evidence/oidf/20261125T044623Z-61dbb05/`) ended as expected except for one
module the lab could not pass: `present-revoked-credential` FAILED, because the lab never
fetched the status list the credential referenced (`EnsureVerifierFetchedRevocationList`), and
answered the revoked credential with `200`. The three positive modules with a status reference
carried a WARNING for the same reason.

What the suite does (`tools/oidf-suite/README.md` §5a, read from release-v5.3.5): every
credential except the one of `present-credential-without-status` carries a permanent
`status.status_list` `{idx, uri}`, with `uri` =
`https://localhost:8443/test/a/<alias>/statuslists/<id>`. The served Status List Token
(`typ` `statuslist+jwt`, ES256) is signed with the configured credential issuer key
(`credential.signing_jwk`) and carries that key's `x5c` (the driver's throwaway self-signed
certificate) and a `jwk` header. Even indices are VALID, odd ones INVALID. The suite records a
fetch only for a `GET`; it warns about any other method, a body, undefined query parameters, or
an `Accept` that excludes `application/statuslist+jwt`. The suite nginx's TLS certificate is a
self-signed `CN=localhost` with no SAN.

The owner's criteria for the change:

1. Check status after the credential and holder binding validated, before the session success
   is committed. Fetch the list from an HTTPS address the issuer policy allows; continue on
   `0x00`, refuse `0x01`. Record a failed fetch, an untrusted signature, an expired token and
   an out-of-range index apart from revocation; all of them block acceptance where status
   checking is required.
2. Validate the suite fixture and the HAIP certificate chain separately: re-run the suite with
   an explicitly pinned test key, and verify a HAIP trust chain with a list signing
   certificate issued by a separate CA.
3. In the re-run, show both the fetch and the verdict: positive modules reach REVIEW without
   the fetch warning; the revoked case is refused after an actual fetch, with no successful
   session; and the same credential flips from accepted to refused when only the list value
   changes from `0x00` to `0x01`.

## Decision

1. **Where.** `server::commit`, which every response route reaches after a single validated
   candidate (unique HPKE-0, shared research, ECDH-ES research, conformance), runs the status
   step first, then the replay guard, then the claim. The credential has been fully verified by
   then (TSL §8.3: Referenced Token processing first), so an invalid credential never causes a
   fetch. A refusal answers the generic 400 and leaves the session pending. The reference is
   parsed from the processed payload; a `status` claim without a well-formed `status_list`
   is a validation failure (`ValidationError::StatusClaimMalformed`).
2. **Fail closed without a policy.** A credential that references a status list is refused
   (`StatusError::NoPolicy`) by every build without the `conformance` feature, and by a
   conformance server without a status policy. A credential without a `status` claim is
   accepted without a fetch (`StatusResult::NotReferenced`): the lab requires a check only
   where the credential asks for one.
3. **Conformance only.** The fetch (hyper's HTTP/1.1 client over rustls, ring, TLS 1.3) and the
   inflation (`miniz_oxide`) are in the `conformance` feature; both crates were already in
   `Cargo.lock`, so no new crate entered it. The default Verifier build still contains no TLS or
   HTTP client.
4. **Issuer policy.** `StatusListPolicy` = a URI prefix (an `https` URL ending in `/`) + a
   trust + a pinned TLS server certificate. A `uri` is followed only if it starts with the
   prefix and the rest is RFC 3986 unreserved characters and `/`, with no query, fragment,
   percent-encoding or dot segment. Every address its host resolves to must be loopback (the
   lab's loopback-only network policy, also against a misconfigured prefix).
5. **Fetch.** One `GET` with `Accept: application/statuslist+jwt` and no body (TSL §8.1), a
   5 s deadline for the whole fetch (half the request timeout), exactly `200`, `Content-Type`
   `application/statuslist+jwt` (§8.2), no `Content-Encoding`, body at most 64 KiB. No
   redirects (stricter than §8.2's "SHOULD follow"; §11.4) and no caching (every check
   fetches; `ttl` is checked for shape only).
6. **TLS.** The Status Provider's end-entity certificate is pinned byte for byte, and the TLS
   1.3 handshake signature must verify with its key. Path validation and the name are not
   checked: the suite's certificate has no SAN, so no WebPKI validation could accept it, and a
   pin is the stronger statement for a fixed lab endpoint. The driver reads the certificate from
   `localhost:8443` at the start of each run (trust on first use, over host loopback), stores it
   as evidence and pins it.
7. **Token trust**, one of:
   - `PinnedKey`: one explicitly configured EC P-256 public key. Header `jwk`, `x5c` and `kid`
     are ignored, so the suite's self-signed `x5c` and self-asserted `jwk` give no trust.
     The suite runs use this, with the issuer's public key passed explicitly
     (`--status-list-key`).
   - `X509`: the `x5c` chain (1-4 certificates, leaf first, without the anchor) must chain to a
     configured status trust anchor now; the leaf must not be self-signed and must carry no
     extended key usage. TSL §10 defines `id-kp-oauthStatusSigning` but its OID is still TBD
     (through -19), so no certificate can carry it; requiring no EKU at all keeps a TLS server
     certificate (`serverAuth`) of the same PKI from signing lists. The leaf's P-256 key must
     verify the ES256 signature. Tested with a separate synthetic status CA and a signer it
     issued (`status_ca.pem`, `status_signer.pem`); the suite cannot exercise this mode, since
     its `x5c` is the driver's self-signed certificate.
8. **Token checks** (TSL §5.1, §8.3): compact JWS, no `crit`, `typ` `statuslist+jwt`, `alg`
   ES256; signature; `sub` = `uri` exactly; `iat` required, `exp` / `nbf` / `ttl` optional,
   integers (`ttl` positive); not expired; `iat` / `nbf` at most 60 s ahead; `bits` in
   {1, 2, 4, 8}; `lst` canonical base64url of ZLIB, inflated to at most 1 MiB; `idx` in range.
   Value `0x00` is accepted; `0x01` is `Revoked`, `0x02` `Suspended`, any other `NotValid(v)`.
9. **Evidence.** `EvidenceRecord::status_result` (`NotRun` / `NotReferenced` / `Valid` /
   `Failed(StatusError)`) and `Rejection::Status`. Only `Revoked`, `Suspended` and `NotValid`
   are statements about the credential; every other variant says its status could not be
   established. A conformance server prints its policy at start and one evidence line per
   response POST (outcomes only), which the plan driver checks per module.

## Consequences

- The lab can now pass `present-revoked-credential` and drop the fetch warning from the
  positive modules, and the driver checks the lab side too: a module is as expected only if the
  lab's own evidence, the suite's fetch log entry and the session state agree with the suite
  result.
- A credential with a `status` claim no longer passes in hardened or research mode (it did
  before, unchecked). The lab's own synthetic issuer issues none unless a test asks for one.
- `verify_sd_jwt_vc` (public) now also refuses a malformed `status` claim.
- Each status-checked response costs one TLS connection and one fetch; nothing is cached.

### Risks

- The TLS pin is trust on first use for the suite: whatever answers on `localhost:8443` when
  the driver starts is pinned. It is host loopback, during a run the operator started; the
  pinned certificate's SHA-256 is in the run manifest.
- `PinnedKey` trusts whatever that key signs for any `uri` under the prefix. The suite's key is
  the synthetic issuer fixture, whose private half is in the repository.
- A Status Provider that answers slowly holds the response POST for up to 5 s.

## Alternatives considered

- **Trust the token's `x5c` or `jwk` as the suite sends them.** Rejected: a self-signed `x5c`
  or self-asserted `jwk` proves nothing (TSL §11.3 lists neither as a resolution route); the
  suite itself says it adds the `jwk` only for its own wallet tests.
- **Re-issue the suite's issuer certificate from the status CA**, so C4 could run in `X509`
  mode. Not done: the owner asked for the suite re-run with a pinned test key, and for the HAIP
  chain to be verified separately. It remains possible later (the driver controls
  `credential.signing_jwk.x5c`).
- **Follow redirects / cache by `ttl`.** Not needed for the suite or the criteria; both widen
  what a credential can make the Verifier fetch or trust. Left out.
- **WebPKI validation of the Status Provider's certificate.** Impossible with the suite's
  certificate (no SAN); a pin is used instead.
