# OIDF conformance run: lab conformance mode

Local run of the OpenID Foundation conformance suite (prebuilt images, OrbStack) against
the lab Verifier's time-boxed conformance mode, synthetic data only. **This is not a
certification and nothing was submitted to the OpenID Foundation.** REVIEW is not PASSED:
it is the best result a positive module can reach, after a human-checkable screenshot
(here a rendering of the lab's own result endpoint JSON for that session).
The suite has no OpenID4VP 1.1 or HPKE plan: the lab's primary HPKE-0 path is not covered.

## C3: `oid4vp-1final-verifier-test-plan`

Variant `{"vp_profile": "plain_vp", "credential_format": "sd_jwt_vc", "client_id_prefix": "x509_san_dns", "request_method": "request_uri_signed", "response_mode": "direct_post.jwt"}`, alias `oid4vp-lab-c3-def5a66b5b20be19`, lab commit `8e487fa00e66` (dirty: False).

Lab status list policy: uri prefix https://localhost:8443/test/a/oid4vp-lab-c3-def5a66b5b20be19/statuslists/, trust pinned key (thumbprint 4Vfes1N2h2msnV9WmtWt1VE03QEQSNksLUEK43jSABY), TLS certificate pinned (sha-256 S5Eqk6kZS2dypRaJN6xY-g3r4idJCcxjjjd9E7nWJCk).

| Module | Status | Result | Expected | Lab: status / commit (suite-logged list fetches, session) | Reason (non-PASSED) | Lab test |
| --- | --- | --- | --- | --- | --- | --- |
| [happy-flow](c3/logs/happy-flow.json) | FINISHED | REVIEW | REVIEW | Valid / Committed (1, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`conformance_round_trip_over_https_commits_with_x509_san_dns`](../../../crates/lab-server/tests/conformance_mode_e2e.rs) |
| [minimal-cnf-jwk](c3/logs/minimal-cnf-jwk.json) | FINISHED | REVIEW | REVIEW | Valid / Committed (1, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`credential_with_minimal_cnf_jwk_is_accepted`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [request-uri-method-post](c3/logs/request-uri-method-post.json) | FINISHED | SKIPPED | SKIPPED | no response (0, pending) | the lab sends no request_uri_method=post, so the suite skips this module | none |
| [request-uri-fetched-twice](c3/logs/request-uri-fetched-twice.json) | FINISHED | REVIEW | REVIEW | Valid / Committed (1, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`served_request_object_is_signed_once_and_never_changes`](../../../crates/lab-server/tests/signed_request_object_e2e.rs) |
| [invalid-kb-jwt-signature](c3/logs/invalid-kb-jwt-signature.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_corrupted_signature_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-credential-signature](c3/logs/invalid-credential-signature.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`issuer_jwt_with_corrupted_signature_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-sd-hash](c3/logs/invalid-sd-hash.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_wrong_sd_hash_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-kb-jwt-nonce](c3/logs/invalid-kb-jwt-nonce.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_wrong_nonce_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-kb-jwt-aud](c3/logs/invalid-kb-jwt-aud.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_wrong_aud_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [kb-jwt-iat-in-past](c3/logs/kb-jwt-iat-in-past.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_stale_iat_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [kb-jwt-iat-in-future](c3/logs/kb-jwt-iat-in-future.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_future_iat_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [present-revoked-credential](c3/logs/present-revoked-credential.json) | FINISHED | PASSED | PASSED | Failed(Revoked) / NotRun (1, pending) |  | [`same_credential_flips_from_accepted_to_revoked_when_only_the_list_changes`](../../../crates/lab-server/tests/status_list_e2e.rs) |
| [present-credential-without-status](c3/logs/present-credential-without-status.json) | FINISHED | REVIEW | REVIEW | NotReferenced / Committed (0, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`honest_sd_jwt_kb_presentation_commits_only_the_requested_claims`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [wrong-vct](c3/logs/wrong-vct.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`sd_jwt_vc_profile_enforces_vct_and_exactly_the_requested_claims`](../../../crates/lab-server/src/sd_jwt.rs) |

Encrypted responses in the suite log: 13, `alg` / `enc` ECDH-ES / A128GCM, 13 distinct `kid` values (one fresh lab key per session).
Suite (JVM in the server container) to lab: every `request_uri` GET and `response_uri` POST completed over the lab's TLS 1.3-only listener (see the HTTP entries in each log).
Driver to lab: {"alpn": null, "cipher": "TLS_AES_256_GCM_SHA384", "version": "TLSv1.3"}.

## C4: `oid4vp-1final-verifier-haip-test-plan`

Variant `{"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"}`, alias `oid4vp-lab-c4-f781ffa67fdc4b08`, lab commit `8e487fa00e66` (dirty: False).

Lab status list policy: uri prefix https://localhost:8443/test/a/oid4vp-lab-c4-f781ffa67fdc4b08/statuslists/, trust pinned key (thumbprint 4Vfes1N2h2msnV9WmtWt1VE03QEQSNksLUEK43jSABY), TLS certificate pinned (sha-256 S5Eqk6kZS2dypRaJN6xY-g3r4idJCcxjjjd9E7nWJCk).

| Module | Status | Result | Expected | Lab: status / commit (suite-logged list fetches, session) | Reason (non-PASSED) | Lab test |
| --- | --- | --- | --- | --- | --- | --- |
| [happy-flow](c4/logs/happy-flow.json) | FINISHED | REVIEW | REVIEW | Valid / Committed (1, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`conformance_round_trip_with_x509_hash_a256gcm_and_redirect_uri`](../../../crates/lab-server/tests/conformance_mode_e2e.rs) |
| [minimal-cnf-jwk](c4/logs/minimal-cnf-jwk.json) | FINISHED | REVIEW | REVIEW | Valid / Committed (1, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`credential_with_minimal_cnf_jwk_is_accepted`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [request-uri-method-post](c4/logs/request-uri-method-post.json) | FINISHED | SKIPPED | SKIPPED | no response (0, pending) | the lab sends no request_uri_method=post, so the suite skips this module | none |
| [request-uri-fetched-twice](c4/logs/request-uri-fetched-twice.json) | FINISHED | REVIEW | REVIEW | Valid / Committed (1, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`served_request_object_is_signed_once_and_never_changes`](../../../crates/lab-server/tests/signed_request_object_e2e.rs) |
| [invalid-kb-jwt-signature](c4/logs/invalid-kb-jwt-signature.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_corrupted_signature_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-credential-signature](c4/logs/invalid-credential-signature.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`issuer_jwt_with_corrupted_signature_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-sd-hash](c4/logs/invalid-sd-hash.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_wrong_sd_hash_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-kb-jwt-nonce](c4/logs/invalid-kb-jwt-nonce.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_wrong_nonce_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [invalid-kb-jwt-aud](c4/logs/invalid-kb-jwt-aud.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_wrong_aud_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [kb-jwt-iat-in-past](c4/logs/kb-jwt-iat-in-past.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_stale_iat_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [kb-jwt-iat-in-future](c4/logs/kb-jwt-iat-in-future.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`kb_jwt_with_future_iat_is_rejected`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [present-revoked-credential](c4/logs/present-revoked-credential.json) | FINISHED | PASSED | PASSED | Failed(Revoked) / NotRun (1, pending) |  | [`same_credential_flips_from_accepted_to_revoked_when_only_the_list_changes`](../../../crates/lab-server/tests/status_list_e2e.rs) |
| [present-credential-without-status](c4/logs/present-credential-without-status.json) | FINISHED | REVIEW | REVIEW | NotReferenced / Committed (0, consumed) | positive module: REVIEW after the screenshot upload is its best result (not PASSED) | [`honest_sd_jwt_kb_presentation_commits_only_the_requested_claims`](../../../crates/lab-server/tests/holder_binding_e2e.rs) |
| [wrong-vct](c4/logs/wrong-vct.json) | FINISHED | PASSED | PASSED | NotRun / NotRun (0, pending) |  | [`sd_jwt_vc_profile_enforces_vct_and_exactly_the_requested_claims`](../../../crates/lab-server/src/sd_jwt.rs) |

Encrypted responses in the suite log: 13, `alg` / `enc` ECDH-ES / A128GCM, 13 distinct `kid` values (one fresh lab key per session).
Suite (JVM in the server container) to lab: every `request_uri` GET and `response_uri` POST completed over the lab's TLS 1.3-only listener (see the HTTP entries in each log).
Driver to lab: {"alpn": null, "cipher": "TLS_AES_256_GCM_SHA384", "version": "TLSv1.3"}.
