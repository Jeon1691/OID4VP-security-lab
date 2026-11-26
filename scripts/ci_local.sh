#!/usr/bin/env bash
# PR gate (Notion 04 · CI §4, CI-001/CI-002). Shared by `make gate` and the GitHub Actions jobs,
# so local and CI runs execute the same steps.
#
# Usage: scripts/ci_local.sh [OUT_DIR] [STAGE...]
#   STAGE = quality | test | supply-chain   (default: all three, in that order)
#         | redis                           (opt-in: session-redis against a real server)
# The redis stage uses REDIS_URL if set (CI service container); otherwise it starts a
# disposable Redis-compatible server (Valkey) in Docker and removes it on exit.
# Every step must run and pass; a step that is skipped or runs zero tests fails the gate.
set -euo pipefail
export CARGO_TERM_COLOR=never

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-evidence/local}"
shift || true
STAGES=("$@")
[[ ${#STAGES[@]} -gt 0 ]] || STAGES=(quality test supply-chain)
mkdir -p "$OUT"

# Logs are evidence: strip the absolute checkout path and home directory before keeping them.
sanitize() { sed -e "s#${ROOT}#.#g" -e "s#${HOME}#~#g"; }

LOG=""
step() {
  local name="$1"
  shift
  echo "## ${name}: $*" | tee -a "$LOG"
  if "$@" 2>&1 | sanitize >>"$LOG"; then
    echo "${name}=pass" | tee -a "$LOG"
  else
    echo "${name}=FAIL" | tee -a "$LOG"
    exit 1
  fi
}

stage_quality() {
  step fmt cargo fmt --all -- --check
  step clippy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  step machete cargo machete
  # The gate scripts and workflows are part of the trusted computing base of every result.
  step shellcheck shellcheck scripts/*.sh
  # Re-derives the synthetic conformance fixtures byte for byte; prints SKIP and passes where
  # OpenSSL is older than 3.4 (e.g. ubuntu-24.04's 3.0) or missing.
  step conformance_fixtures python3 -I scripts/conformance_fixtures.py check
  step actionlint actionlint
}

# Named G0 tests that must have run and passed; guards against "green with nothing executed".
REQUIRED_TESTS=(
  signed_request_binding_matches_stored_session
  timed_out_parked_post_is_no_longer_counted_as_parked
  new_connections_are_refused_while_shutdown_drains
  each_session_gets_a_distinct_response_uri
  wire_strings_round_trip_byte_exact
  non_ascii_values_are_rejected
  accepted_session_info_values_are_all_below_0x80
  unknown_response_mode_is_rejected
  state_is_limited_to_the_url_safe_set
  ecdh_es_direct_post_jwt_round_trip_completes_with_success
  tampered_jwe_ciphertext_is_not_accepted
  jwe_with_unadvertised_enc_is_rejected
  jwe_with_wrong_kid_is_rejected
  jwe_with_zip_header_is_rejected
  non_form_content_type_is_rejected_before_decryption
  missing_response_parameter_is_rejected_before_decryption
  duplicated_response_parameter_is_rejected_before_decryption
  characterize_upstream_verify_response_reprocesses_replayed_jwe
  # jose-hpke (IMP-004..006): official vectors and the key fail-closed checks.
  rfc9180_derive_key_pair_matches_vector
  rfc9180_base_p256_opens_all_vector_encryptions_in_sequence
  rfc9180_base_p256_exporter_values_match
  rfc9180_first_encryption_opens_via_codec_open_base
  draft22_hpke0_compact_vector_decrypts_to_generator_plaintext
  draft22_hpke0_protected_header_is_bound_as_aad
  draft22_hpke0_ke_compact_vector_is_rejected
  rejects_enc_header_parameter
  rejects_duplicate_header_parameter
  rejects_non_canonical_trailing_bits
  rejects_escaped_duplicate_header_parameter
  rejects_separator_flood_at_maximum_length
  rejects_kid_typ_cty_with_control_bidi_or_empty_values
  rejects_protected_header_over_lab_limit
  direct_post_session_info_matches_openid4vp_example
  dc_api_session_info_matches_openid4vp_example
  from_binding_matches_openid4vp_examples
  invalid_session_info_inputs_cannot_be_constructed
  direct_post_bound_jwe_fails_with_any_single_field_changed
  dc_api_bound_jwe_fails_with_any_single_field_changed
  direct_post_and_dc_api_session_info_never_cross_open
  state_is_not_a_session_info_input
  # jose-ecdh-es (OpenID4VP 1.0-style ECDH-ES, research only): RFC 7518 Appendix C, josekit and
  # SpruceID interop, and the fail-closed header / segment checks.
  rfc7518_appendix_c_concat_kdf_matches_vector
  rfc7518_appendix_c_key_agreement_yields_the_printed_key
  josekit_ecdh_es_a128gcm_and_a256gcm_jwes_open
  josekit_jwes_with_apu_and_apv_open
  sealed_jwes_decrypt_with_josekit
  sealed_jwes_with_apu_and_apv_decrypt_with_josekit
  spruce_ecdh_es_direct_post_jwt_response_opens_with_jose_ecdh_es
  ecdh_es_shared_key_opens_every_candidate_response
  ecdh_es_tampered_ciphertext_tag_or_iv_fails_decryption
  ecdh_es_tampered_protected_header_fails_decryption
  ecdh_es_wrong_recipient_key_fails_decryption
  ecdh_es_rejects_key_wrapping_hpke_dir_and_every_other_alg
  ecdh_es_rejects_unsupported_enc
  ecdh_es_rejects_off_curve_epk
  ecdh_es_rejects_wrong_curve_or_key_type_epk
  ecdh_es_rejects_epk_with_private_key
  ecdh_es_rejects_non_empty_encrypted_key
  ecdh_es_rejects_zip_header_parameter
  ecdh_es_rejects_crit_header_parameter
  ecdh_es_rejects_duplicate_header_parameter
  ecdh_es_rejects_duplicate_epk_member
  ecdh_es_rejects_bad_base64url_segments
  ecdh_es_rejects_wrong_iv_length
  ecdh_es_rejects_wrong_tag_length
  ecdh_es_rejects_malformed_epk_coordinates
  ecdh_es_rejects_unknown_epk_member
  ecdh_es_rejects_unknown_header_parameter
  ecdh_es_rejects_equal_or_malformed_apu_apv
  ecdh_es_rejects_oversized_input_and_header
  ecdh_es_rejects_wrong_segment_count_and_json_serialization
  josekit_jwe_does_not_open_with_another_key
  rfc7518_appendix_c_kdf_binds_every_input
  # End-to-end KAT: the OpenID4VP 1.0 §8.3 encrypted response example opens to its payload.
  openid4vp_1_0_section_8_3_example_opens_to_the_printed_payload
  # session-core (IMP-007/011/012): strategies, exactly-once claim, state machine.
  unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid
  unique_kid_yields_exactly_one_candidate_among_sessions_sharing_route
  bounded_trial_returns_all_candidates_within_budget
  bounded_trial_rejects_more_candidates_than_budget
  expired_sessions_are_never_candidates
  consumed_sessions_are_never_candidates
  unknown_route_token_or_kid_yields_no_candidate
  route_token_debug_does_not_reveal_the_token
  concurrent_claims_of_one_session_commit_exactly_once
  concurrent_async_claims_commit_exactly_once
  sequential_replay_after_consume_is_rejected
  claim_after_expiry_is_rejected
  failed_attempt_leaves_session_pending_and_claimable
  at_most_one_successful_commit_per_session
  unique_uri_checks_route_uniqueness_before_kid
  dropped_claim_future_commits_nothing
  stale_candidate_cannot_claim_a_reinserted_session
  insert_beyond_pending_capacity_is_rejected
  consumed_records_are_purged_after_retention
  unique_route_policy_rejects_duplicate_route_token
  route_token_parse_rejects_malformed_input
  # lab-server HPKE-0 HTTP path (IMP-008..010): G2/G3/G4.
  unique_uri_form_post_succeeds_with_one_hpke_attempt
  unique_uri_among_many_sessions_consumes_only_the_addressed_one
  request_object_carries_exact_wire_values
  # lab-server signed Request Objects (JAR, RFC 9101; OpenID4VP 1.1 §5, §5.10.1).
  request_uri_serves_signed_jar_with_spec_header_and_claims
  lab_request_signature_is_byte_identical_to_spruce_p256_signer
  signed_request_object_binding_bytes_match_stored_session_and_session_info
  served_request_object_is_signed_once_and_never_changes
  wallet_refuses_tampered_request_payload
  wallet_refuses_request_signed_with_wrong_key
  wallet_refuses_request_with_wrong_typ
  wallet_refuses_unsigned_alg_none_request
  wallet_refuses_request_with_foreign_client_id_or_aud
  request_signing_key_is_loaded_from_config_and_never_printed
  start_refuses_did_key_client_id_that_is_not_the_signing_keys
  start_accepts_the_did_key_of_any_signing_key
  start_refuses_client_id_prefixes_the_lab_cannot_sign_for
  request_object_carries_iat_and_exp_of_the_session_ttl
  wallet_refuses_expired_or_exp_less_request
  wallet_refuses_request_served_with_wrong_content_type
  wallet_refuses_request_with_crit_header_or_extra_segment
  wallet_refuses_request_with_missing_or_unresolvable_kid
  wallet_refuses_attacker_did_key_claiming_the_lab_client_id
  request_object_exp_never_precedes_the_stored_session_expiry
  unique_kid_on_shared_route_yields_one_candidate_and_one_attempt
  bounded_trial_succeeds_with_right_session_last_within_budget
  bounded_trial_over_budget_is_rejected_without_decryption
  bounded_trial_with_two_validating_sessions_is_an_integrity_failure
  admission_failures_are_rejected_before_decryption
  jwe_bound_to_another_sessions_values_fails
  sequential_replay_is_rejected
  concurrent_identical_posts_consume_exactly_once
  invalid_jwe_does_not_consume_the_session
  generic_rejection_bodies_are_byte_identical
  hardened_mode_has_no_shared_route
  every_mode_binds_loopback_only
  malformed_or_oversized_vp_token_is_rejected_and_does_not_consume
  results_are_served_only_by_result_token
  jwe_without_kid_is_rejected_on_every_route
  request_limit_sheds_load_and_times_out_stalled_bodies
  cross_session_replay_on_shared_route_is_rejected
  holder_proof_resealed_for_another_session_is_rejected
  research_nonce_length_is_capped_so_the_presentation_always_fits
  shutdown_drains_in_flight_requests_and_commits_nothing_afterwards
  connection_cap_holds_connections_stalled_before_headers
  stalled_header_connection_is_closed_at_the_header_timeout_and_frees_its_slot
  sweep_expires_and_purges_stale_sessions
  # OIDF OpenID4VP #792 scenarios (G7; docs/interop/issue-792-reproduction.md).
  issue_792_shared_uri_and_kid_leave_nothing_outside_the_ciphertext_to_correlate_on
  issue_792_cleartext_state_beside_the_jwe_is_refused_before_decryption
  issue_792_workarounds_compared_on_one_population
  issue_792_kid_of_another_session_on_the_unique_kid_route_fails_closed
  issue_792_trial_opens_the_session_the_sender_bound_and_holder_binding_decides
  # lab-server `state` per session, inside the JWE, checked after decryption (OpenID4VP 1.1
  # §5.2, §8.3, §14.4.2).
  state_round_trips_inside_the_jwe_on_every_route
  response_without_state_is_refused_and_the_honest_response_then_commits
  state_of_another_live_session_is_refused
  bounded_trial_jwe_that_opens_for_b_but_carries_a_state_is_refused_for_b
  reused_nonce_with_fresh_state_selects_one_session_and_refuses_a_replay
  research_state_knob_is_research_only_bounded_and_charset_checked
  unrecognized_payload_members_are_ignored
  state_mismatching_candidate_tried_first_does_not_stop_the_validating_one
  # lab-server ECDH-ES research route (`ecdh-es-research`, ADR 0001): #792 C3/C9 observed
  # directly, experiments E1-E7 (docs/interop/issue-792-reproduction.md §7, S23-S38), the
  # session cap, duplicate state, expiry, the per-server opt-in and the key-kind separation.
  ecdh_es_shared_key_opens_for_every_live_session_and_only_state_selects
  ecdh_es_request_object_advertises_the_shared_key_and_both_enc_values
  ecdh_es_honest_round_trip_commits_the_session_named_by_state
  ecdh_es_state_swap_routes_to_the_named_session_and_fails_its_nonce
  ecdh_es_missing_unknown_or_foreign_state_is_refused_and_consumes_nothing
  ecdh_es_replays_commit_once_and_reused_values_hit_the_replay_guard
  ecdh_es_two_live_sessions_sharing_nonce_and_state_are_ambiguous
  ecdh_es_and_hpke_routes_never_accept_each_others_jwes
  ecdh_es_route_refuses_plaintext_vp_token_at_admission
  hardened_mode_has_no_ecdh_es_route_and_refuses_ecdh_es_sessions
  research_mode_without_the_opt_in_has_no_ecdh_es_route
  ecdh_es_route_caps_pending_sessions_at_the_candidate_budget
  ecdh_es_duplicate_state_with_distinct_nonces_is_disambiguated_by_holder_binding
  ecdh_es_response_for_an_expired_session_is_refused
  ecdh_es::tests::ecdh_es_trial_never_opens_with_an_hpke_key
  ecdh_es::tests::hpke_trial_never_opens_with_an_ecdh_es_key
  # lab-server holder binding (Evidence level 3): SD-JWT VC + KB-JWT (OpenID4VP 1.1 B.3;
  # RFC 9901 §7.1/§7.3; draft-ietf-oauth-sd-jwt-vc-27), over HTTP and against RFC 9901 vectors.
  request_object_dcql_query_requests_the_sd_jwt_vc_and_its_claims
  honest_sd_jwt_kb_presentation_commits_only_the_requested_claims
  kb_jwt_with_wrong_aud_is_rejected
  kb_jwt_with_wrong_nonce_is_rejected
  kb_jwt_with_stale_iat_is_rejected
  kb_jwt_with_future_iat_is_rejected
  kb_jwt_with_wrong_sd_hash_is_rejected
  kb_jwt_signed_by_a_non_cnf_key_is_rejected
  kb_jwt_with_alg_none_is_rejected
  presentation_without_kb_jwt_is_rejected
  disclosure_altered_in_transit_is_rejected
  unreferenced_disclosure_is_rejected
  duplicate_disclosure_is_rejected
  withheld_requested_claim_is_rejected
  unrequested_disclosed_claim_is_rejected
  credential_signed_by_an_untrusted_issuer_is_rejected
  issuer_jwt_with_alg_none_is_rejected
  valid_kb_jwt_replayed_to_another_session_fails_the_nonce_binding
  valid_kb_jwt_replayed_to_another_verifier_fails_the_audience_binding
  sd_jwt_kb_built_with_ssi_is_accepted_by_the_lab_verifier
  ssi_kb_jwt_payload_with_null_exp_is_rejected_as_malformed
  lab_wallet_presentation_verifies_with_ssi
  trusted_issuer_key_config_accepts_only_p256_public_jwks
  # OIDF conformance plan §5 C1: offline gap tests and the configurable Credential Query.
  issuer_jwt_with_corrupted_signature_is_rejected
  kb_jwt_with_corrupted_signature_is_rejected
  credential_with_minimal_cnf_jwk_is_accepted
  configured_credential_query_is_requested_and_enforced
  sd_jwt::tests::suite_shaped_pid_credential_with_status_and_decoys_is_accepted
  # lab-server conformance mode (`conformance`, ADR 0002): HTTPS on loopback, x509 client ids,
  # ECDH-ES on the unique route, the start checks, the time box and the explicit flag.
  conformance_round_trip_over_https_commits_with_x509_san_dns
  conformance_round_trip_with_x509_hash_a256gcm_and_redirect_uri
  conformance_sessions_get_fresh_encryption_keys
  conformance_negative_responses_are_refused_and_consume_nothing
  conformance_route_refuses_hpke_and_hpke_route_refuses_ecdh_es
  conformance_mode_serves_no_shared_or_research_routes
  wallet_refuses_conformance_request_without_x5c_or_for_another_client_id
  conformance_mode_refuses_to_start_unless_everything_fits
  conformance_server_stops_at_its_maximum_runtime
  conformance_time_box_closes_kept_alive_connections
  wallet_refuses_x509_san_dns_matched_only_by_a_wildcard
  binary_refuses_conformance_mode_from_the_environment
  rfc9901_fixture_provenance_is_pinned
  rfc9901_disclosure_digests_match_the_printed_hashes
  rfc9901_section_5_2_presentation_verifies_and_yields_the_printed_payload
  rfc9901_appendix_a3_sd_jwt_vc_passes_the_lab_profile
  rfc9901_examples_fail_closed_on_wrong_binding_issuer_or_profile
  rfc9901_presentation_edits_are_rejected
  sd_jwt::tests::object_array_and_recursive_disclosures_are_reconstructed_and_decoys_dropped
  sd_jwt::tests::duplicate_digest_and_claim_name_collision_are_rejected
  sd_jwt::tests::duplicate_unreferenced_and_reserved_disclosures_are_rejected
  sd_jwt::tests::disclosure_shape_must_match_where_its_digest_is_found
  sd_jwt::tests::sd_alg_and_payload_structure_are_strict
  sd_jwt::tests::issuer_jwt_policy_and_validity_are_enforced
  sd_jwt::tests::key_binding_jwt_claims_and_header_are_enforced
  sd_jwt::tests::sizes_and_counts_are_bounded_before_any_crypto
  sd_jwt::tests::sd_jwt_vc_profile_enforces_vct_and_exactly_the_requested_claims
  sd_jwt::tests::kb_jwt_exp_and_nbf_have_their_own_error
  sd_jwt::tests::disclosures_outside_the_requested_claims_are_rejected_at_any_depth
  sd_jwt::tests::non_disclosable_claims_must_not_carry_digests
  jose::tests::strict_json_refuses_duplicate_members_at_any_depth
  # lab-server Token Status List checking (ADR 0003; draft-ietf-oauth-status-list-14 §4.1,
  # §5.1, §6.2, §7.1, §8.1-§8.3, §11.3): the 0x00 -> 0x01 flip of one credential, every
  # failure class apart from revocation, the issuer URI policy, x5c to a separate status CA,
  # and fail closed without a policy.
  same_credential_flips_from_accepted_to_revoked_when_only_the_list_changes
  credential_without_status_is_accepted_without_a_fetch
  token_and_list_failures_are_refused_and_recorded_apart_from_revocation
  fetch_failures_are_refused_and_recorded_apart_from_revocation
  uri_outside_the_issuer_policy_is_refused_without_a_fetch
  x509_trust_accepts_only_a_signer_certified_by_the_status_ca
  without_a_status_policy_a_referenced_status_is_refused
  status_policy_needs_a_request_timeout_above_the_fetch_deadline
  status_list::tests::status_values_are_read_as_tsl_section_4_1_packs_them
  status_list::tests::only_valid_is_accepted_and_every_other_value_has_its_own_refusal
  status_list::tests::status_reference_is_parsed_strictly
  status_list::tests::without_a_checker_a_referenced_status_is_refused
  status_list::policy::tests::uri_prefix_and_uri_policy_are_strict
  status_list::policy::tests::status_signer_certificates_must_carry_no_extended_key_usage
  # session-redis (IMP-014): the shared contract suite on MemoryRegistry, and the fail-closed
  # checks that need no server. The Redis side runs in the redis stage.
  memory::unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid
  memory::bounded_trial_rejects_more_candidates_than_budget
  memory::concurrent_async_claims_commit_exactly_once
  memory::sequential_replay_after_consume_is_rejected
  memory::insert_beyond_pending_capacity_is_rejected
  memory::consumed_records_are_purged_after_retention
  memory::candidate_from_another_registry_cannot_claim_its_session
  memory::direct_post_binding_round_trips_with_its_state
  codec::tests::direct_post_binding_round_trips_with_its_state
  codec::tests::undecodable_state_fails_closed
  unreachable_redis_fails_closed_at_connect
  connect_rejects_malformed_namespace
  # G6 benchmark harness (IMP-015/016): report columns and the reproducible case schedule.
  tests::csv_rows_have_as_many_fields_as_the_header
  tests::json_carries_every_column_and_nulls_for_missing_values
  tests::summary_lists_failed_invariants
  stats::tests::schedule_is_a_reproducible_permutation
  stats::tests::percentiles_are_in_microseconds
  http::tests::positions_dedupe_for_small_n
  # G6 invariants: exact attempt counts, rejection reasons, failing rows and exit status.
  http::tests::honest_records_pass_every_case
  http::tests::violated_invariants_fail_the_check
  http::tests::bounded_trial_must_try_every_candidate_at_every_position
  http::tests::unique_failures_must_make_exactly_one_attempt
  http::tests::failure_cases_must_carry_their_rejection_reason
  http::tests::a_violation_fails_the_row
  http::tests::attempts_mean_counts_only_requests_with_an_evidence_record
  http::tests::burst_without_503_is_not_a_violation
  http::tests::in_flight_cap_requires_a_503_beyond_the_held_requests
  http::tests::bounded_trial_still_sees_n_candidates_when_the_block_outlives_the_session_ttl
  tests::exit_code_fails_when_any_row_breaks_its_invariant
  tests::arguments_must_exercise_over_budget_and_the_limited_burst
  store::tests::store_rows_leave_cpu_ms_empty
)

# Fails unless every named test ran and passed in this stage's log, and at least one test ran.
require_tests() {
  local t passed
  for t in "$@"; do
    if ! grep -Eq "^test ${t} \.\.\. ok$" "$LOG"; then
      echo "required_tests=FAIL (${t} did not pass)" | tee -a "$LOG"
      exit 1
    fi
  done
  passed=$(grep -Eo 'test result: ok\. [0-9]+ passed' "$LOG" | awk '{s+=$4} END {print s+0}')
  echo "tests_passed_total=${passed}" | tee -a "$LOG"
  if [[ "$passed" -eq 0 ]]; then
    echo "required_tests=FAIL (0 tests executed)" | tee -a "$LOG"
    exit 1
  fi
  echo "required_tests=pass" | tee -a "$LOG"
}

stage_test() {
  step build cargo build --workspace --all-targets --locked
  step test cargo test --workspace --all-features --locked
  step doctest cargo test --doc --workspace --locked
  require_tests "${REQUIRED_TESTS[@]}"
}

# The Redis-backed tests are `#[ignore]`d in the test stage (no server there), so a plain
# `cargo test` can never report them as passed. This stage runs exactly them (`--ignored`) and
# requires every one of these names to have passed.
REDIS_REQUIRED_TESTS=(
  redis::unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid
  redis::unique_kid_yields_exactly_one_candidate_among_sessions_sharing_route
  redis::bounded_trial_returns_all_candidates_within_budget
  redis::bounded_trial_rejects_more_candidates_than_budget
  redis::bounded_trial_budget_counts_only_live_sessions
  redis::expired_sessions_are_never_candidates
  redis::consumed_sessions_are_never_candidates
  redis::unknown_route_token_or_kid_yields_no_candidate
  redis::unique_strategy_refuses_an_ambiguous_hint
  redis::unique_uri_checks_route_uniqueness_before_kid
  redis::unique_kid_checks_kid_uniqueness_before_route
  redis::concurrent_async_claims_commit_exactly_once
  redis::dropped_claim_future_commits_nothing
  redis::sequential_replay_after_consume_is_rejected
  redis::claim_after_expiry_is_rejected
  redis::claim_just_before_expiry_succeeds
  redis::failed_attempt_leaves_session_pending_and_claimable
  redis::stale_candidate_cannot_claim_a_reinserted_session
  redis::claim_of_unknown_session_is_rejected
  redis::expire_and_purge_touch_only_due_sessions
  redis::consumed_records_are_purged_after_retention
  redis::insert_beyond_pending_capacity_is_rejected
  redis::unique_route_policy_rejects_duplicate_route_token
  redis::insert_rejects_duplicate_id_and_zero_ttl
  redis::snapshots_are_point_in_time_copies
  redis::snapshot_round_trips_every_field
  redis::candidate_from_another_registry_cannot_claim_its_session
  redis::direct_post_binding_round_trips_with_its_state
  # STATE-03: two workers (separate connections) racing 2/16/128-way.
  two_workers_racing_claims_commit_exactly_once
  # STATE-05: fail closed, no in-memory fallback.
  redis_killed_mid_run_fails_closed_without_memory_fallback
  # Key material stays in-process; tampered or undecodable records fail closed.
  private_keys_never_reach_redis
  worker_without_the_key_fails_closed
  swapped_key_reference_fails_closed
  undecodable_record_fails_closed
  local_keys_are_dropped_once_sessions_leave_pending
  index_entry_naming_another_session_fails_closed
  counters_at_or_above_1e14_round_trip_exactly
  # The local key table stays bounded and sheds due keys while Redis is down.
  due_keys_are_dropped_while_redis_is_unreachable
  refused_insert_drops_its_key_immediately
  key_table_growth_is_bounded_during_an_outage
  # Candidates are bound to their namespace; expiry is judged on Redis server time.
  candidate_from_another_namespace_cannot_claim_its_session
  server_time_mode_inserts_resolves_claims_and_sweeps
  claim_delayed_past_the_ttl_in_transit_is_not_committed
  redis_matches_memory_registry_on_random_operation_sequences
  # G6 benchmark store rows: the run removes exactly its own Redis namespace, also on failure.
  store::tests::redis_namespace_is_removed_after_a_run_and_neighbours_survive
  store::tests::redis_namespace_is_removed_when_a_bench_op_fails
)

# Disposable server when REDIS_URL is unset: Valkey 8.1 (BSD-3-Clause, Redis 7.2 protocol and
# Lua API, so the whole toolchain stays OSI-permissive), pinned by its multi-arch index digest,
# bound to loopback on a random host port, no persistence, read-only root filesystem,
# unprivileged user (the image's `valkey`, uid 999), no capabilities. Removed on exit.
REDIS_IMAGE="valkey/valkey:8.1.12@sha256:5032c4dd7abe08d6fd9382054608183e2bf1f7e3895ef619b8784698454325f7"
REDIS_UID=999
# Readiness: up to 50 PINGs 0.2 s apart (10 s); a local server answers within about a second.
REDIS_READY_TRIES=50
REDIS_READY_INTERVAL=0.2
REDIS_CONTAINER=""

redis_teardown() {
  [[ -z "$REDIS_CONTAINER" ]] || docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
}

redis_start() {
  local port i
  REDIS_CONTAINER="$(docker run -d --rm -p 127.0.0.1::6379 --read-only \
    --user "${REDIS_UID}:${REDIS_UID}" --cap-drop ALL --security-opt no-new-privileges \
    "$REDIS_IMAGE" valkey-server --save '' --appendonly no)" || return 1
  trap redis_teardown EXIT
  port="$(docker port "$REDIS_CONTAINER" 6379/tcp | head -n 1)" || return 1
  port="${port##*:}"
  for ((i = 0; i < REDIS_READY_TRIES; i++)); do
    if [[ "$(docker exec "$REDIS_CONTAINER" valkey-cli ping 2>/dev/null)" == PONG ]]; then
      export REDIS_URL="redis://127.0.0.1:${port}/"
      return 0
    fi
    sleep "$REDIS_READY_INTERVAL"
  done
  return 1
}

stage_redis() {
  # Not through `step`: its pipeline runs the command in a subshell, and REDIS_URL must reach
  # the cargo step below. The URL itself is not logged.
  if [[ -n "${REDIS_URL:-}" ]]; then
    echo "redis_server=pass (REDIS_URL provided)" | tee -a "$LOG"
  elif redis_start >>"$LOG" 2>&1; then
    echo "redis_server=pass (disposable ${REDIS_IMAGE})" | tee -a "$LOG"
  else
    echo "redis_server=FAIL" | tee -a "$LOG"
    exit 1
  fi
  step redis_test cargo test -p session-redis --all-features --locked -- --ignored
  # Only the bin target: the criterion bench target (test = true) takes no libtest flags.
  step redis_bench_test cargo test -p scenario-runner --bin scenario-runner --locked -- --ignored
  require_tests "${REDIS_REQUIRED_TESTS[@]}"
}

# cargo-audit has its own ignore list; it must stay identical to the reviewed deny.toml baseline.
# Only entries are compared (deny: `id = "..."`, audit: quoted list items), never comments.
deny_ids() { grep -Eo 'id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' deny.toml | grep -Eo 'RUSTSEC-[0-9-]+' | sort -u; }
audit_ids() { grep -Eo '^ *"RUSTSEC-[0-9]{4}-[0-9]{4}"' .cargo/audit.toml | grep -Eo 'RUSTSEC-[0-9-]+' | sort -u; }
advisory_baseline_sync() { diff <(deny_ids) <(audit_ids); }

# Containment: the advisory baseline is accepted only for lab-server's SpruceID tree. The core
# crates must not reach any of it, directly or transitively (cargo-deny wrappers only cover
# named crates, so check the resolved graph itself). evidence-report (G6) is a plain library and
# held to the same rule; scenario-runner is not, it drives lab-server's wallet simulator (ssi).
CORE_CRATES=(protocol-model jose-hpke session-core session-redis evidence-report)
# jose-ecdh-es is held to the same rule for its normal and build dependencies. Its interop tests
# use josekit (the JWE code SpruceID encrypts with) as a dev-dependency, so dev edges are not
# checked for it; deny.toml [bans] still keeps openid4vp and ssi out of its graph.
CORE_CRATES_NORMAL_ONLY=(jose-ecdh-es)
SPRUCE_TREE_RE='^(openid4vp|josekit|ssi|ssi-[a-z0-9-]+|did-[a-z0-9-]+|rsa|im|sized-chunks|bitmaps|smallstr|serde_cbor|derivative|clear_on_drop|proc-macro-error|chrono) '
core_containment() {
  local c tree hits=0
  for c in "${CORE_CRATES[@]}"; do
    # Resolve first: a failing `cargo tree` must fail the step, not read as "no match".
    tree="$(cargo tree --locked -p "$c" -e normal,build,dev --prefix none)" || return 1
    if grep -E "$SPRUCE_TREE_RE" <<<"$tree"; then
      echo "containment violated by $c"
      hits=1
    fi
  done
  for c in "${CORE_CRATES_NORMAL_ONLY[@]}"; do
    tree="$(cargo tree --locked -p "$c" -e normal,build --prefix none)" || return 1
    if grep -E "$SPRUCE_TREE_RE" <<<"$tree"; then
      echo "containment violated by $c"
      hits=1
    fi
  done
  return "$hits"
}

# The Verifier build (lab-server default features, which the binary uses) must not contain
# sender-side sealing (jose-hpke `test-support`, the wallet simulator's HTTP client), the
# SpruceID tree (`openid4vp`, `ssi*`: the wallet simulator's Request Object verification) or the
# decryption pause lever. Both are only reachable through the `wallet-sim` /
# `lab-instrumentation` features that tests enable via the self dev-dependency.
#
# jose-ecdh-es (ECDH-ES) is reachable only through the research feature `ecdh-es-research`
# (docs/adr/0001-ecdh-es-research-route.md). The default build, and so the binary, must not
# depend on it at all. The `ecdh-es-research` build must reach it (so the check below inspects
# a real graph, not an empty query that passes silently) without its sealing `test-support`, and
# must not pull in the test-only lab-server features or their SpruceID / HTTP-client tree.
verifier_without_sealing() {
  local features ecdh_es research research_own research_normal own normal
  features="$(cargo tree --locked -p lab-server -e normal,features -i jose-hpke)" || return 1
  # stderr carries only cargo's "nothing to print" note; a cargo failure still fails the step.
  ecdh_es="$(cargo tree --locked -p lab-server -e normal -i jose-ecdh-es 2>/dev/null)" || return 1
  if [[ -n "$ecdh_es" ]]; then
    echo "the default lab-server build depends on jose-ecdh-es"
    return 1
  fi
  research="$(cargo tree --locked -p lab-server --features ecdh-es-research -e normal,features \
    -i jose-ecdh-es)" || return 1
  if ! grep -Eq '^jose-ecdh-es v' <<<"$research"; then
    echo "the ecdh-es-research build does not reach jose-ecdh-es; this check would be vacuous"
    return 1
  fi
  if grep -F 'feature "test-support"' <<<"$research"; then
    echo "the ecdh-es-research build enables jose-ecdh-es test-support (sealing)"
    return 1
  fi
  research_own="$(cargo tree --locked -p lab-server --features ecdh-es-research \
    -e normal,features -i lab-server)" || return 1
  research_normal="$(cargo tree --locked -p lab-server --features ecdh-es-research -e normal \
    --prefix none)" || return 1
  if grep -E 'lab-server feature "(wallet-sim|lab-instrumentation)"' <<<"$research_own" \
    || grep -E '^(reqwest|openid4vp|ssi|ssi-[a-z0-9-]+) ' <<<"$research_normal"; then
    echo "test-only feature reachable from the ecdh-es-research build"
    return 1
  fi
  own="$(cargo tree --locked -p lab-server -e normal,features -i lab-server)" || return 1
  normal="$(cargo tree --locked -p lab-server -e normal --prefix none)" || return 1
  if grep -F 'feature "test-support"' <<<"$features" \
    || grep -E 'lab-server feature "(wallet-sim|lab-instrumentation|ecdh-es-research|conformance)"' <<<"$own" \
    || grep -E '^(reqwest|openid4vp|ssi|ssi-[a-z0-9-]+) ' <<<"$normal"; then
    echo "test-only, research or conformance feature reachable from the default lab-server build"
    return 1
  fi
  # No TLS / X.509 code in the default build (conformance mode only, ADR 0002).
  if grep -E "$TLS_TREE_RE" <<<"$normal"; then
    echo "the default lab-server build contains TLS / X.509 crates"
    return 1
  fi
}

# The `conformance` build (docs/adr/0002-conformance-mode.md) must reach its TLS stack and
# jose-ecdh-es (so the checks below inspect a real graph), with the ring provider only (no
# aws-lc-rs), and without sealing (`test-support`), the test-only lab-server features, the
# research route, or the SpruceID / HTTP-client tree.
TLS_TREE_RE='^(rustls|rustls-webpki|tokio-rustls|ring|aws-lc-rs|aws-lc-sys) '
conformance_without_sealing() {
  local tree own codecs
  tree="$(cargo tree --locked -p lab-server --features conformance -e normal --prefix none)" \
    || return 1
  own="$(cargo tree --locked -p lab-server --features conformance -e normal,features \
    -i lab-server)" || return 1
  codecs="$(cargo tree --locked -p lab-server --features conformance -e normal,features \
    -i jose-ecdh-es)" || return 1
  if ! grep -Eq '^rustls v' <<<"$tree" || ! grep -Eq '^jose-ecdh-es v' <<<"$tree"; then
    echo "the conformance build does not reach rustls / jose-ecdh-es; this check would be vacuous"
    return 1
  fi
  if grep -E '^(aws-lc-rs|aws-lc-sys) ' <<<"$tree"; then
    echo "the conformance build contains aws-lc (ring is the only provider)"
    return 1
  fi
  if grep -F 'feature "test-support"' <<<"$codecs" \
    || grep -E 'lab-server feature "(wallet-sim|lab-instrumentation|ecdh-es-research)"' <<<"$own" \
    || grep -E '^(reqwest|openid4vp|ssi|ssi-[a-z0-9-]+|josekit) ' <<<"$tree"; then
    echo "sealing, test-only or research code reachable from the conformance build"
    return 1
  fi
}

# The binary refuses conformance mode unless built with the feature, before reading any file
# (ADR 0002 kill switch). Built into its own target directory, so no feature-unified build of
# the workspace can stand in for it.
binary_refuses_conformance_without_feature() {
  local out
  out="$(cargo run --locked -q -p lab-server --target-dir target/verifier-only -- \
    --mode conformance 2>&1)" && return 1
  grep -F 'was built without the' <<<"$out"
}

# session-core's `store-backend` feature (candidate / snapshot constructors for store backends)
# is for session-redis only. The Verifier build (lab-server default features, alone) must build
# without it, and its feature graph must not enable it.
verifier_without_store_backend() {
  local features
  features="$(cargo tree --locked -p lab-server -e features -i session-core)" || return 1
  if grep -F 'feature "store-backend"' <<<"$features"; then
    echo "session-core store-backend reachable from lab-server"
    return 1
  fi
}

# A plain `cargo build` / `cargo run` at the root builds the workspace default members. They must
# leave lab-server a Verifier build: scenario-runner (G6) enables `wallet-sim` as a normal
# dependency and is therefore kept out of `default-members`. This fails if it (or any other
# crate that turns on a test-only lab-server feature, or the ECDH-ES research route) re-enters
# them, or if any default member turns on a codec's sealing `test-support` (jose-hpke,
# jose-ecdh-es) as a normal dependency. `--workspace` builds are never Verifier builds.
default_members_are_verifier_builds() {
  local own codec sealing=0
  own="$(cargo tree --locked -e normal,features -i lab-server)" || return 1
  if grep -E 'lab-server feature "(wallet-sim|lab-instrumentation|ecdh-es-research|conformance)"' <<<"$own"; then
    echo "a default workspace member enables a test-only, research or conformance lab-server feature"
    return 1
  fi
  for codec in jose-hpke jose-ecdh-es; do
    own="$(cargo tree --locked -e normal,features -i "$codec")" || return 1
    if grep -F "$codec feature \"test-support\"" <<<"$own"; then
      echo "a default workspace member enables $codec test-support"
      sealing=1
    fi
  done
  return "$sealing"
}

stage_supply_chain() {
  step deny cargo deny --locked check advisories licenses bans sources
  step advisory_baseline_sync advisory_baseline_sync
  step core_containment core_containment
  step verifier_without_sealing verifier_without_sealing
  step default_members_are_verifier_builds default_members_are_verifier_builds
  step lab_server_default_check cargo check -p lab-server --locked
  # Each optional feature alone (library and binary): the workspace clippy runs with
  # --all-features only, so code that builds only in combination would otherwise slip through.
  step lab_server_wallet_sim_check \
    cargo clippy --locked -p lab-server --features wallet-sim --lib --bins -- -D warnings
  step lab_server_ecdh_es_research_check \
    cargo clippy --locked -p lab-server --features ecdh-es-research --lib --bins -- -D warnings
  step lab_server_conformance_check \
    cargo clippy --locked -p lab-server --features conformance --lib --bins -- -D warnings
  step lab_server_wallet_sim_conformance_check \
    cargo clippy --locked -p lab-server --features wallet-sim,conformance --lib --bins -- -D warnings
  step conformance_without_sealing conformance_without_sealing
  step binary_refuses_conformance_without_feature binary_refuses_conformance_without_feature
  step verifier_without_store_backend verifier_without_store_backend
  step audit cargo audit --deny warnings
}

for stage in "${STAGES[@]}"; do
  case "$stage" in
    quality | test | supply-chain | redis) ;;
    *) echo "unknown stage: $stage" >&2; exit 2 ;;
  esac
  LOG="$OUT/ci_${stage//-/_}.log"
  : >"$LOG"
  "stage_${stage//-/_}"
  echo "stage_${stage//-/_}=pass" | tee -a "$LOG"
done
echo "gate=pass (${STAGES[*]})"
