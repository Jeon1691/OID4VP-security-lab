# OIDF OpenID4VP #792: lab reproduction

Status: G7 groundwork. All sources below are public and were retrieved on **2026-11-25**. All
lab data is synthetic and every lab endpoint is loopback only. This document states lab
findings. It is not a statement of the OpenID Foundation Working Group's position.

## 1. Sources

| Source | URL | State on 2026-11-25 |
| --- | --- | --- |
| Issue #792, "HPKE `session_info` requires the session that only decryption can reveal" (author `fujie`) | <https://github.com/openid/OpenID4VP/issues/792> | Open. Opened 2026-08-31, milestone "Final 1.1" added 2026-09-10. No comments. No linked or cross-referenced PRs (GitHub API timeline: one `milestoned` event). |
| Issue #793, "`session_info`: is the redirect form limited to `direct_post.jwt`?" (same author) | <https://github.com/openid/OpenID4VP/issues/793> | Open, no comments |
| Issue #781, "HPKE algorithm clarification" | <https://github.com/openid/OpenID4VP/issues/781> | Open |
| Issue #708, "Better guidance how the Verifier matches the incoming `direct_post` request with the user session" | <https://github.com/openid/OpenID4VP/issues/708> | Closed 2026-05-07 |
| Issue #692, "Define HPKE info parameter" / PR #703, "Define usage of HPKE and `info` structure to be used." | <https://github.com/openid/OpenID4VP/issues/692>, <https://github.com/openid/OpenID4VP/pull/703> | Closed / merged 2026-04-26 |
| OpenID4VC-HAIP PR #362, "First pass at HAIP HPKE section"; HAIP #356, #357 | <https://github.com/openid/OpenID4VC-HAIP/pull/362> | Merged and closed 2026-09-24. **The issue calls PR #362 "open"; that has changed since the issue was written.** |
| OpenID4VP 1.1 Editor's draft, "Published: 11 November 2026" (the version the lab pins) | <https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-1_1-wg-draft.html> | HTML SHA-256 `14545ac3877df0a80345dd70c6d0366be1496ba69b21234b779e4d200d9ccc76` |

The issue and the GitHub threads were read with `gh api` (GET only). Nothing was posted
anywhere.

**Section numbers.** The issue cites "§14.3.2" for Protection of the Response URI. In the
11 November 2026 draft, §14.3 is Session Fixation and Protection of the Response URI is
**§14.4.2**. The draft's Document History records the earlier numbering ("Section 14.3.2. Protection
of the Response URI"). Below, section numbers follow the 11 November 2026 draft.

### 1.1 Spec text quoted (11 November 2026 Editor's draft)

- **§5.1, `client_metadata.jwks`**: "Each JWK in the set MUST have a kid (Key ID) parameter
  that uniquely identifies the key within the context of the request."
- **§8.3**: "If the selected public key contains a kid parameter, the JWE MUST include the same
  value in the kid JWE Header Parameter (as defined in Section 4.1.6) of the encrypted
  response. This enables the Verifier to easily identify the specific public key that was
  used to encrypt the response."
- **§8.3**: "The payload of the encrypted JWT response MUST include the contents of the
  response as defined in Section 8.1 as top-level JSON members."
- **§8.3.1**: "Additionally, a session_info structure MUST be calculated and utilized for
  encryption and decryption independently by the Wallet and the Verifier. This ensures that
  decryption fails closed when the session information needed for verification of the
  credential is invalid."
- **§8.3.1** (redirect form): `session_info = ASCII("OpenID4VP-si") || BYTE(255) ||
  ASCII(clientId) || BYTE(255) || ASCII(nonce) || BYTE(255) || ASCII(responseUri)`.
- **§8.3.1**: "The session_info structure's bytes are used as the value of the info parameter
  when using Integrated Encryption as the Key Management Mode. If the recipient_structure is
  being used then it is used as the value of the recipient_extra_info parameter instead."
- **§8.3.2**: "The Wallet adds the response parameter containing the JWT as defined in Section
  8.3 in the body of an HTTP POST request using the application/x-www-form-urlencoded content
  type."
- **§8.2, Note**: "The Verifier's component providing the user interface (Frontend) and the
  Verifier's component providing the Response URI need to be able to map authorization
  requests to the respective authorization responses. The Verifier MAY use the state
  Authorization Request parameter to add appropriate data to the Authorization Response for
  that purpose, for details see Section 13.3."
- **§5.2, `state`**: "REQUIRED under the conditions defined in Section 5.3. Otherwise, state is
  RECOMMENDED, see Section 14.4."
- **§5.2, `nonce`**: "The Verifier MUST create a fresh, cryptographically random number with
  sufficient entropy for every Authorization Request and store it with its current session.
  The nonce SHOULD contain at least 128 bits of entropy."
- **§13.3, step (6)**: "The Verifier's Response URI checks whether the state value is a valid
  request-id."
- **§14.2.2**: "The Verifier MUST validate every individual Verifiable Presentation in an
  Authorization Response and ensure that it is linked to the values of the client_id and the
  nonce parameter it had used for the respective Authorization Request."
- **§14.4.2**: "The Verifier SHOULD protect its Response URI from inadvertent requests by
  checking that the value of the received state parameter corresponds to a recent
  Authorization Request."
- **§14.7**: "an attacker might be able to alter Authorization Response parameters and
  generate a new encrypted Authorization Response for the Verifier, as encryption is
  performed using the public key of the Verifier (which is likely to be widely known when not
  ephemeral to the request/response)."

The issue says that §14.3.2 and §13.3 "already discuss protecting the Response URI and using
unique URIs". In the 11 November 2026 draft I found no text that recommends a response_uri per
transaction. A case-insensitive search for "unique" returns no hit about Response URIs. §13.3
and §14.4.2 correlate through `state` (a request-id).

## 2. The issue's claims, stated precisely

| # | Claim (issue wording in quotes) |
| --- | --- |
| C1 | §8.3.1 makes `session_info` (client_id ‖ nonce ‖ responseUri) the HPKE `info`. "Decryption therefore requires knowing **which session** the response belongs to." |
| C2 | "The only session identifier the response carries, `state`, is inside the ciphertext." A `direct_post.jwt` body is `response=<JWE>` "...and nothing else", so there is "nothing to correlate on". |
| C3 | Under 1.0, and under 1.1 with ECDH-ES, decryption needs only the private key: `kid` → key → decrypt → `state` → session. Under HPKE, a 1.0-style Verifier "breaks the moment it accepts an HPKE response" (a compatibility issue). |
| C4 | "`kid` identifies a *key*, not a session." The §8.3 `kid` sentence is unchanged in 1.1. |
| C5 | The dependency is circular: decrypt needs `session_info`, `session_info` needs the session, and the session is identified by `state`, which is inside the ciphertext. |
| C6 | There are three undocumented workarounds: (1) "A distinct `response_uri` per transaction" ("also strengthens the binding"); (2) "A distinct encryption key per session, identified by `kid`" ("Stretches `kid`", "costs a keypair per presentation"); (3) "Trial decryption against every pending session. O(n) HPKE operations per response; not viable at scale." |
| C7 | #708 made `state` RECOMMENDED and set aside response-URI identifiers. The current text "points implementers at `state`, which cannot work for `direct_post.jwt` with HPKE." |
| C8 | Under the HAIP 1.1 HPKE profile every presentation is HPKE, so this affects every transaction. HAIP defers `session_info` to VP 1.1. |
| C9 | There is also a "security half": `session_info` "has no ECDH-ES equivalent, so the fail-closed property §8.3.1 describes only holds for HPKE". |
| C10 | The issue asks for §8.3.1 to say that the Verifier must identify the session *before* decrypting and to name at least one mechanism, or at least to add a non-normative note on the per-transaction `response_uri`. It also suggests revisiting the #708 guidance for the encrypted case. |

## 3. Reproduction status per claim

The test names are the lab's (`cargo test -p lab-server`, plus jose-hpke and session-core).
New tests are in `crates/lab-server/tests/issue_792_scenarios.rs` and are listed in
`REQUIRED_TESTS` (`scripts/ci_local.sh`).

| Claim | Status | Evidence |
| --- | --- | --- |
| C1 | **Reproduced** (crypto level and HTTP level) | jose-hpke `direct_post_bound_jwe_opens_only_with_identical_session` and `direct_post_bound_jwe_fails_with_any_single_field_changed`. The second includes empty `info`, which is the "decrypt first" order. HTTP: `jwe_bound_to_another_sessions_values_fails` (each of nonce, client_id and response_uri changed → `Rejection::Decrypt`, 1 attempt, session pending). |
| C2 | **Reproduced** (the no-correlator part) | New: `issue_792_shared_uri_and_kid_leave_nothing_outside_the_ciphertext_to_correlate_on`. With a shared URI and a shared key, the request objects of N=8 sessions differ only in `nonce`, the protected headers of their honest JWEs are byte-identical, and the resolver must return all N live sessions as candidates. The lab issues no `state` at all. |
| C3 | **Partly reproduced** | The HPKE half is covered by C1: the key alone with empty `info` cannot open. The ECDH-ES half is only the G0-D SpruceID round trip (`ecdh_es_direct_post_jwt_round_trip_completes_with_success`). That flow routes by a per-session URL path, not by `state`, so the lab has no 1.0-style "decrypt, then read `state`" Verifier. |
| C4 | **Reproduced** | Bounded trial: every session shares one `kid`, so `kid` selects nothing (`issue_792_workarounds_compared_on_one_population`: N distinct sessions, 1 distinct `kid`). New: `issue_792_kid_of_another_session_on_the_unique_kid_route_fails_closed` shows that even when `kid` is per session, it is an unauthenticated hint. Note that §5.1 requires a `kid` that is unique "within the context of the request", not across requests, so one key and `kid` shared by every request (bounded trial) is permitted by the text, and `kid` is not specified as a session identifier. |
| C5 | **Reproduced** (as the consequence of C1 + C2) | The lab can only break the loop with a pre-decryption selector (route token or per-session `kid`) or by trying every candidate. |
| C6 (1) | **Reproduced** | `unique_uri_among_many_sessions_consumes_only_the_addressed_one` (N=8). New matrix: `issue_792_workarounds_compared_on_one_population` (N=2/8/32: 1 candidate, 1 attempt). Binding strength: the response_uri case of `jwe_bound_to_another_sessions_values_fails`. |
| C6 (2) | **Reproduced** | `unique_kid_on_shared_route_yields_one_candidate_and_one_attempt`, the matrix test (1 attempt), and the new misdirected-`kid` test. |
| C6 (3) | **Reproduced**, with the cost measured as an attempt count, never as time | `bounded_trial_succeeds_with_right_session_last_within_budget` (`hpke_attempts == N` for N=2/8/32, no stop-at-first), the matrix test, and `bounded_trial_over_budget_is_rejected_without_decryption`. |
| C7 | **Consistent** (lab policy) | The lab cannot check `state` before decryption, so it never relies on it. A cleartext `state` next to `response` is refused at admission: new `issue_792_cleartext_state_beside_the_jwe_is_refused_before_decryption`. `state` alone is refused as well: the "missing response" case in `admission_failures_are_rejected_before_decryption`. |
| C8 | Not testable in the lab | The lab is HPKE-only on its HTTP path, which is the same situation as the HAIP HPKE profile. HAIP itself is out of scope. |
| C9 | **Partly** | HPKE fail-closed behaviour: C1 tests. The lab has no Verifier that accepts both ECDH-ES and HPKE. jose-hpke refuses any `alg` other than `HPKE-0` (`rejects_unsupported_alg`), so the downgrade path does not exist on the lab's HTTP route. |
| C10 | Spec proposal | See §6. The lab supplies the evidence; the wording belongs to the WG. |

## 4. What the lab shows that the issue does not

1. **With HPKE, trial decryption selects exactly one session, and the nonce is what makes it
   do so.** On a shared URI with a shared key, client_id and response_uri are the same for every
   session. The fresh per-request `nonce` (a §5.2 MUST) is then the only part of
   `session_info` that differs, and exactly one of N candidates opens
   (`CryptoResult::Opened { opened: 1 }` in the C2 and C6 tests). The issue treats trial
   decryption only as a cost. *Inference, not tested:* with ECDH-ES and a shared key, every
   candidate would decrypt, so trial decryption could not select a session at all.
2. **A successful decryption does not show which session a response belongs to.** All three
   `session_info` inputs are in the Request Object, which anyone holding the `request_uri` can
   fetch, and HPKE encrypts to a public key (§14.7). A sender can therefore make a response
   open for any session it chooses. In
   `issue_792_trial_opens_the_session_the_sender_bound_and_holder_binding_decides`, a valid
   holder proof for A is sealed with B's `session_info`. It opens for B only and is refused by
   B's KB-JWT `nonce` check (`ValidationError::KbNonceMismatch`, §14.2.2). Correlating by trial
   decryption is only as strong as the holder-binding check that follows it.
3. **Nonce reuse turns trial decryption into a mis-correlation and replay problem.** If a
   Verifier violates the §5.2 nonce MUST and reuses a nonce under a shared key and URI, two
   sessions have the same `session_info`. Three things follow:
   - one response validates for both (`bounded_trial_with_two_validating_sessions_is_an_integrity_failure`
     → `Rejection::Ambiguous`, nothing claimed);
   - once one session is consumed, the same JWE validates for the other
     (`cross_session_replay_on_shared_route_is_rejected` → `CrossSessionReplay`);
   - the same KB-JWT re-sealed in a fresh JWE also validates for the other
     (`holder_proof_resealed_for_another_session_is_rejected` → `HolderProofReplay`).

   State kept per session cannot see any of this. The lab needs a Verifier-wide replay guard.
4. **Bounded trial fails all at once when the budget is exceeded.** When the live population
   exceeds the budget, every response on that route is refused before decryption, honest ones
   included (`bounded_trial_over_budget_is_rejected_without_decryption`). Whoever can open
   sessions can therefore deny service on the shared route. Below the budget, each
   unauthenticated POST costs N HPKE decapsulations. The issue notes the O(n) cost; it does not
   discuss that any unauthenticated sender can trigger it, or the all-or-nothing failure once
   the budget is exceeded.
5. **The shared strategies leak information through timing (documented, not measured).** The
   number of attempts per POST equals the live population under bounded trial, and unique-kid
   reveals whether a `kid` is pending. The HTTP answer never shows this, but response timing
   can (lab-server `lib.rs`, "Threat-model notes"). The lab records attempt counts only and
   never compares absolute timings.
6. **`kid` is attacker-controlled input.** A misdirected `kid` selects a different session,
   whose key fails to open the JWE. Nothing is consumed. (New misdirected-`kid` test;
   `jwe_without_kid_is_rejected_on_every_route` for a missing `kid`.)

## 5. What the issue covers and the lab does not (gaps)

- **A 1.0 or ECDH-ES Verifier that correlates on `state`.** The lab has none (C3), and the lab
  issues no `state`, so §14.4.2's SHOULD (check `state`) is never exercised, before or after
  decryption.
- **Other HPKE algorithms.** The issue was implemented with `HPKE-0`, `HPKE-1`, `HPKE-2`,
  `HPKE-3`, `HPKE-4` and `HPKE-7`. The lab supports `HPKE-0` only
  (`draft22_hpke7_compact_vector_is_rejected_as_unsupported_alg`). Key Encryption /
  `recipient_extra_info` is refused (`draft22_hpke0_ke_compact_vector_is_rejected`).
- **`dc_api.jwt`.** The `session_info` form is tested only at the crypto level
  (`dc_api_session_info_matches_openid4vp_example`,
  `direct_post_and_dc_api_session_info_never_cross_open`). The lab has no DC API flow.
- **ECDH-ES/HPKE coexistence and HAIP 1.1 profiles** (C8, C9).
- **Cross-implementation interop** (the issue used a Go wallet and a TypeScript verifier).
  The lab has Rust plus the pinned SpruceID tree. The Python baseline comparison (INTEROP-02)
  is planned in `oidf-conformance-plan.md` §6.
- **Lab-internal gaps:**
  - The lab-server scenarios run on the in-memory registry only. session-redis has the
    resolution contract tests (`redis::bounded_trial_*`) but is not wired into lab-server.
  - Response Code / session-fixation flows (§13.3, §14.3) are not implemented.
  - The timing channel of §4 item 5 is not measured.

## 6. Recommendations (lab findings)

### 6.1 Spec requirements the lab relies on (MUST / SHOULD in the 11 November 2026 draft)

- §5.2: a fresh nonce for every Authorization Request (MUST). Findings §4.1 and §4.3 depend on
  it.
- §8.3.1: `session_info` for encryption and decryption (MUST).
- §5.1 and §8.3: every JWK in `client_metadata.jwks` has a `kid` (MUST, §5.1), and the JWE
  carries the chosen JWK's `kid` (MUST, §8.3). The lab advertises every key with a `kid`, so
  refusing a JWE without one on every route (`jwe_without_kid_is_rejected_on_every_route`)
  follows from these two MUSTs.
- §14.2.2: every presentation is bound to `client_id` and `nonce` (MUST).

### 6.2 Candidate spec text (offered to the WG as input, not decided)

1. **§8.3.1, a note on ordering (non-normative).** "When HPKE is used, the Verifier needs to
   determine the Authorization Request a response answers *before* decrypting it, because
   `session_info` is an input to decryption, and parameters such as `state` are only available
   after decryption. One way to do this is a `response_uri` unique to each Authorization
   Request. The value of the `kid` JWE Header Parameter identifies a key, not a request."

   This is the issue's own minimum proposal (C10). The lab result for it is a constant cost of
   1 HPKE attempt (C6 (1)).
2. **§8.3.1 or §14, decryption is not authentication (non-normative).** "Successful
   decryption with a given `session_info` does not show that the response was produced for that
   Authorization Request, since every input to `session_info` is known to anyone who obtained
   the request. The checks of Section 14.2 remain required."

   Evidence: §4 item 2. This applies §14.7 to HPKE.
3. **§14 (security consideration).** "Verifiers that try decryption against several pending
   requests spend one HPKE decapsulation per pending request on every response, can be made to
   do so by any sender, and can reveal the number of pending requests through timing."

   Evidence: §4 items 4 and 5.
4. **§8.2 Note / §14.4.2 (`state` guidance).** Distinguish `direct_post.jwt` from
   `direct_post`, for example: "For Response Mode `direct_post.jwt`, `state` is inside the
   encrypted response and can only be checked after decryption." This follows from C7.

### 6.3 Lab policy (stricter than the spec, so not proposed as MUSTs)

- Unique response_uri per session, as the only strategy in Hardened mode. A shared route exists
  only in Research mode and needs a fixed strategy (`hardened_mode_has_no_shared_route`).
- Only `response` in the body: a cleartext `state` or `vp_token` is refused at admission.
- A Verifier-wide replay guard on the JWE digest and the holder-proof digest.
- A hard candidate budget; no stop-at-first under bounded trial.
- A generic error body for every post-admission failure
  (`generic_rejection_bodies_are_byte_identical`).

## 7. Scenario table

Abbreviations:
- **N**: live sessions on the route.
- **cid**: client_id.
- **uri**: response_uri.
- **key**: encryption key and `kid`.
- **"honest"**: the wallet simulator with default options.

Strategies:
- **UU**: unique URI (Hardened).
- **UK**: unique kid (Research, shared URI).
- **BT**: bounded trial (Research, shared URI and key).

| ID | Sessions | Shared attributes | Sender capability | Expected Verifier behaviour | Observed (test) |
| --- | --- | --- | --- | --- | --- |
| S1 | N=2/8/32 | cid | honest | UU: 1 candidate, 1 attempt, only the target consumed | 1/1, others pending (`issue_792_workarounds_compared_on_one_population`; `unique_uri_among_many_sessions_consumes_only_the_addressed_one`) |
| S2 | N=2/8/32 | cid, uri | honest | UK: 1 candidate, 1 attempt | 1/1 (same matrix test; `unique_kid_on_shared_route_yields_one_candidate_and_one_attempt`) |
| S3 | N=2/8/32 | cid, uri, key | honest | BT: N candidates, N attempts, exactly 1 opens | N/N, `opened: 1` (matrix test; `bounded_trial_succeeds_with_right_session_last_within_budget`) |
| S4 | N=8 | cid, uri, key | passive observer of the POST | BT: nothing before decryption tells the sessions apart | identical protected header bytes, request objects differ only in nonce, N candidates (`issue_792_shared_uri_and_kid_leave_nothing_outside_the_ciphertext_to_correlate_on`) |
| S5 | N=budget+1 | cid, uri, key | can create sessions | BT: refuse before decryption, 0 attempts | `CandidateBudgetExceeded`, honest response refused, 0 attempts (`bounded_trial_over_budget_is_rejected_without_decryption`) |
| S6 | 2 | cid, uri, key | adds cleartext `state` beside `response` | lab policy: admission refusal, 0 attempts | 400, `UnexpectedParameter`, session pending, JWE alone then commits (`issue_792_cleartext_state_beside_the_jwe_is_refused_before_decryption`) |
| S7 | 2 | cid, uri | sets B's `kid` on a JWE for A | UK: selects B, fails to open, nothing consumed | 1 attempt, `Decrypt`, A and B pending (`issue_792_kid_of_another_session_on_the_unique_kid_route_fails_closed`) |
| S8 | 2 | cid | seals for A's key with B's nonce, a foreign cid, or B's uri | UU: fail closed | 1 attempt, `Decrypt` each (`jwe_bound_to_another_sessions_values_fails`) |
| S9 | 2 | cid, uri, key | reads B's public request object; seals A's valid proof with B's `session_info` | BT: opens for B, refused by holder binding | 2 attempts, `opened: 1`, `KbNonceMismatch`, both pending; A then commits (`issue_792_trial_opens_the_session_the_sender_bound_and_holder_binding_decides`) |
| S10 | 2 | cid, uri, key, **nonce** (violates §5.2) | honest | BT: integrity failure, claim nothing | 2 open, 2 validate, `Ambiguous` (`bounded_trial_with_two_validating_sessions_is_an_integrity_failure`) |
| S11 | 2 sequential | cid, uri, key, **nonce** | replays A's consumed JWE to B | refuse across sessions | `CrossSessionReplay`, B pending (`cross_session_replay_on_shared_route_is_rejected`) |
| S12 | 2 sequential | cid, uri, key, **nonce** | re-seals A's KB-JWT in a fresh JWE for B | refuse across sessions | `HolderProofReplay`, B pending (`holder_proof_resealed_for_another_session_is_rejected`) |
| S13 | 2 | cid | seals A's valid proof for B (fresh nonces) | UU: holder binding refuses | `KbNonceMismatch` (`valid_kb_jwt_replayed_to_another_session_fails_the_nonce_binding`) |
| S14 | 1 | none | replays one JWE (sequentially / 2-16-128 concurrently) | commit exactly once | (`sequential_replay_is_rejected`, `concurrent_identical_posts_consume_exactly_once`) |
| S15 | none (crypto) | none | Verifier decrypts with the key and empty `info` (1.0 order) | AEAD failure | `Error::Decryption` (`direct_post_bound_jwe_fails_with_any_single_field_changed`) |
| S16 | none | none | asks a Hardened server for the shared route | not served | 404, no shared sessions (`hardened_mode_has_no_shared_route`) |

## 8. Open questions

- Will the WG close #792 with normative text (§8.3.1 MUST/SHOULD), a note, or a cross-reference
  only? Issue #793 (the scope of the redirect form) affects which Response Modes the ordering
  note covers.
- Should the lab add a 1.0-style ECDH-ES shared-key Verifier, to observe that every candidate
  decrypts (§4 item 1 is currently an inference)?
- Should the lab issue `state` inside the JWE and check it after decryption, to exercise
  §14.4.2?
