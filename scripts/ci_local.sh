#!/usr/bin/env bash
# PR gate (Notion 04 · CI §4, CI-001/CI-002). Shared by `make gate` and the GitHub Actions jobs,
# so local and CI runs execute the same steps.
#
# Usage: scripts/ci_local.sh [OUT_DIR] [STAGE...]
#   STAGE = quality | test | supply-chain   (default: all three, in that order)
#         | redis                           (opt-in: session-redis against a real server)
# The redis stage uses REDIS_URL if set (CI service container); otherwise it starts a
# disposable Redis in Docker and removes it on exit.
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
  presentation_with_extra_or_oversized_members_is_rejected_and_does_not_consume
  results_are_served_only_by_result_token
  jwe_without_kid_is_rejected_on_every_route
  request_limit_sheds_load_and_times_out_stalled_bodies
  cross_session_replay_on_shared_route_is_rejected
  research_nonce_length_is_capped_so_the_presentation_always_fits
  shutdown_drains_in_flight_requests_and_commits_nothing_afterwards
  connection_cap_holds_connections_stalled_before_headers
  stalled_header_connection_is_closed_at_the_header_timeout_and_frees_its_slot
  sweep_expires_and_purges_stale_sessions
  # session-redis (IMP-014): the shared contract suite on MemoryRegistry, and the fail-closed
  # checks that need no server. The Redis side runs in the redis stage.
  memory::unique_uri_yields_exactly_one_candidate_among_sessions_sharing_kid
  memory::bounded_trial_rejects_more_candidates_than_budget
  memory::concurrent_async_claims_commit_exactly_once
  memory::sequential_replay_after_consume_is_rejected
  memory::insert_beyond_pending_capacity_is_rejected
  memory::consumed_records_are_purged_after_retention
  unreachable_redis_fails_closed_at_connect
  connect_rejects_malformed_namespace
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
  redis_matches_memory_registry_on_random_operation_sequences
)

# Disposable server when REDIS_URL is unset: the multi-arch index digest of redis:8.4.8, bound to
# loopback on a random host port, no persistence, read-only root filesystem, unprivileged user
# (the image's `redis`, uid 999), no capabilities. Removed on exit, pass or fail.
REDIS_IMAGE="redis:8.4.8@sha256:2e431571225bc941481b753c16192d5e71107c2e5dc6691ed3c416bf69550a9b"
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
    "$REDIS_IMAGE" redis-server --save '' --appendonly no)" || return 1
  trap redis_teardown EXIT
  port="$(docker port "$REDIS_CONTAINER" 6379/tcp | head -n 1)" || return 1
  port="${port##*:}"
  for ((i = 0; i < REDIS_READY_TRIES; i++)); do
    if [[ "$(docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null)" == PONG ]]; then
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
  require_tests "${REDIS_REQUIRED_TESTS[@]}"
}

# cargo-audit has its own ignore list; it must stay identical to the reviewed deny.toml baseline.
# Only entries are compared (deny: `id = "..."`, audit: quoted list items), never comments.
deny_ids() { grep -Eo 'id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' deny.toml | grep -Eo 'RUSTSEC-[0-9-]+' | sort -u; }
audit_ids() { grep -Eo '^ *"RUSTSEC-[0-9]{4}-[0-9]{4}"' .cargo/audit.toml | grep -Eo 'RUSTSEC-[0-9-]+' | sort -u; }
advisory_baseline_sync() { diff <(deny_ids) <(audit_ids); }

# Containment: the advisory baseline is accepted only for lab-server's SpruceID tree. The core
# crates must not reach any of it, directly or transitively (cargo-deny wrappers only cover
# named crates, so check the resolved graph itself).
CORE_CRATES=(protocol-model jose-hpke session-core session-redis)
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
  return "$hits"
}

# The Verifier build (lab-server default features, which the binary uses) must not contain
# sender-side sealing (jose-hpke `test-support`, the wallet simulator's HTTP client), the
# SpruceID tree (`openid4vp`, `ssi*`: the wallet simulator's Request Object verification) or the
# decryption pause lever. Both are only reachable through the `wallet-sim` /
# `lab-instrumentation` features that tests enable via the self dev-dependency.
verifier_without_sealing() {
  local features own normal
  features="$(cargo tree --locked -p lab-server -e normal,features -i jose-hpke)" || return 1
  own="$(cargo tree --locked -p lab-server -e normal,features -i lab-server)" || return 1
  normal="$(cargo tree --locked -p lab-server -e normal --prefix none)" || return 1
  if grep -F 'feature "test-support"' <<<"$features" \
    || grep -E 'lab-server feature "(wallet-sim|lab-instrumentation)"' <<<"$own" \
    || grep -E '^(reqwest|openid4vp|ssi|ssi-[a-z0-9-]+) ' <<<"$normal"; then
    echo "test-only feature reachable from the default lab-server build"
    return 1
  fi
}

stage_supply_chain() {
  step deny cargo deny --locked check advisories licenses bans sources
  step advisory_baseline_sync advisory_baseline_sync
  step core_containment core_containment
  step verifier_without_sealing verifier_without_sealing
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
