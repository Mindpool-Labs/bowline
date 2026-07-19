use bowline_core::{
    enforcement::{
        AuthorityProtocol, EvidenceState, KillReadResult, PlanTarget, RouteMode, SelectionReason,
    },
    ledger::{
        validate_authority_run_v2, AuthorityDecisionV2, AuthorityFallbackReasonV2,
        AuthorityGrantBindingV2, AuthorityOutcomeV2, AuthorityRecordV2,
        AuthorityRunValidationError, AuthoritySelectionFactsV2, CandidateFailureClassV2,
        CircuitStateV2, CompletionStateV2, UsageSource,
    },
    run::AuthorityRunManifestV2,
    supply::TaskClass,
};

fn digest(label: &str) -> String {
    format!("sha256:{:064x}", label.len())
}

fn candidate_decision() -> AuthorityDecisionV2 {
    AuthorityDecisionV2 {
        decision_id: "decision-1".into(),
        replaces_decision_id: None,
        configured_fallback_target: None,
        ts_ms: 10,
        route_id: "chat-canary".into(),
        mode: RouteMode::CanaryEnforce,
        protocol: AuthorityProtocol::ChatCompletions,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest("workload")),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        requested_supply_id: Some("owned/a".into()),
        reason: SelectionReason::CandidateSelected,
        evidence_state: EvidenceState::Presented,
        selection_facts: AuthoritySelectionFactsV2::canonical_candidate(7),
        target: PlanTarget::Candidate,
        intended_dispatch: 1,
        grant: Some(AuthorityGrantBindingV2 {
            grant_digest: digest("grant"),
            expires_at_ms: 100,
            economics_source_digest: digest("economics"),
            quality_source_digest: digest("quality"),
            opportunity_digest: digest("opportunity"),
        }),
        selected_supply_id: Some("owned/a".into()),
        baseline_supply_id: Some("public/b".into()),
        actuator_identity_digest: Some(digest("endpoint")),
        actuator_config_digest: Some(digest("actuator")),
        enforcement_config_digest: digest("enforcement"),
        route_config_digest: digest("route"),
        model_rewritten: true,
    }
}

#[test]
fn every_fallback_reason_has_one_canonical_selection_fact_row() {
    let reasons = [
        AuthorityFallbackReasonV2::KillNotArmed,
        AuthorityFallbackReasonV2::RouteMismatch,
        AuthorityFallbackReasonV2::UntrustedIdentity,
        AuthorityFallbackReasonV2::UnsupportedShape,
        AuthorityFallbackReasonV2::GrantMissing,
        AuthorityFallbackReasonV2::SignatureMissing,
        AuthorityFallbackReasonV2::SignatureInvalid,
        AuthorityFallbackReasonV2::GrantMismatch,
        AuthorityFallbackReasonV2::GrantStale,
        AuthorityFallbackReasonV2::ApprovalMissing,
        AuthorityFallbackReasonV2::ApprovalSignatureInvalid,
        AuthorityFallbackReasonV2::ApprovalUnbound,
        AuthorityFallbackReasonV2::ApprovalExpired,
        AuthorityFallbackReasonV2::WorkloadMismatch,
        AuthorityFallbackReasonV2::AllowlistMiss,
        AuthorityFallbackReasonV2::RolloutMiss,
        AuthorityFallbackReasonV2::PinnedModelMismatch,
        AuthorityFallbackReasonV2::CircuitOpen,
        AuthorityFallbackReasonV2::AdmissionSaturated,
        AuthorityFallbackReasonV2::CandidateUnavailable,
        AuthorityFallbackReasonV2::ActuatorUnavailable,
    ];
    for reason in reasons {
        let facts = AuthoritySelectionFactsV2::canonical_fallback(reason);
        facts.validate_fallback(reason).unwrap();
        let mut contradictions = Vec::new();
        macro_rules! flip_bool {
            ($field:ident) => {{
                let mut value = facts.clone();
                value.$field = !value.$field;
                contradictions.push(value);
            }};
        }
        flip_bool!(route_matched);
        flip_bool!(identity_trusted);
        flip_bool!(shape_supported);
        flip_bool!(grant_present);
        flip_bool!(grant_matched);
        flip_bool!(grant_fresh);
        flip_bool!(workload_matched);
        flip_bool!(allowlist_matched);
        flip_bool!(rollout_selected);
        flip_bool!(pinned_model_matched);
        let mut value = facts.clone();
        value.kill_state = if value.kill_state == KillReadResult::Armed {
            KillReadResult::Bypass
        } else {
            KillReadResult::Armed
        };
        contradictions.push(value);
        let mut value = facts.clone();
        value.bucket = if value.bucket.is_some() {
            None
        } else {
            Some(1)
        };
        contradictions.push(value);
        let mut value = facts.clone();
        value.candidate_availability = match value.candidate_availability {
            None => Some(bowline_core::enforcement::CandidateAvailability::Available),
            Some(bowline_core::enforcement::CandidateAvailability::Available) => {
                Some(bowline_core::enforcement::CandidateAvailability::Unavailable)
            }
            Some(_) => Some(bowline_core::enforcement::CandidateAvailability::Available),
        };
        contradictions.push(value);
        let mut value = facts.clone();
        value.actuator_available = match value.actuator_available {
            None => Some(false),
            Some(current) => Some(!current),
        };
        contradictions.push(value);
        let mut value = facts.clone();
        value.circuit_before = if value.circuit_before == CircuitStateV2::NotApplicable {
            CircuitStateV2::Closed
        } else {
            CircuitStateV2::NotApplicable
        };
        contradictions.push(value);
        for contradiction in contradictions {
            assert!(
                contradiction.validate_fallback(reason).is_err(),
                "{reason:?}"
            );
        }
    }
}

fn success_outcome() -> AuthorityOutcomeV2 {
    AuthorityOutcomeV2 {
        decision_id: "decision-1".into(),
        replaces_decision_id: None,
        ts_ms: 20,
        route_id: "chat-canary".into(),
        mode: RouteMode::CanaryEnforce,
        protocol: AuthorityProtocol::ChatCompletions,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest("workload")),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        requested_supply_id: Some("owned/a".into()),
        selection_facts: AuthoritySelectionFactsV2::canonical_candidate(7),
        grant_digest: Some(digest("grant")),
        grant_expires_at_ms: Some(100),
        model_rewritten: true,
        selected_supply_id: Some("owned/a".into()),
        baseline_supply_id: Some("public/b".into()),
        actuator_identity_digest: Some(digest("endpoint")),
        actuator_config_digest: Some(digest("actuator")),
        enforcement_config_digest: digest("enforcement"),
        route_config_digest: digest("route"),
        target: PlanTarget::Candidate,
        fallback_reason: None,
        circuit_before: CircuitStateV2::Closed,
        circuit_after: CircuitStateV2::Closed,
        actual_dispatch: 1,
        completion: CompletionStateV2::Succeeded,
        candidate_failure: None,
        status: Some(200),
        input_tokens: Some(100),
        output_tokens: Some(50),
        usage_source: UsageSource::Observed,
        observed_actual_cost_micros: Some(10),
        approved_counterfactual_cost_micros: Some(20),
        enforced_modeled_delta_micros: Some(10),
    }
}

fn manifest(record_count: u64) -> AuthorityRunManifestV2 {
    AuthorityRunManifestV2 {
        schema_version: 2,
        run_id: "authority-run".into(),
        started_at_ms: 1,
        ended_at_ms: Some(30),
        clean_shutdown: true,
        writer_healthy: true,
        writer_error: None,
        enforcement_digest: digest("enforcement"),
        actuator_set_digest: digest("actuators"),
        grant_set_digest: digest("grants"),
        accepted: record_count,
        recorded: record_count,
        dropped: 0,
        next_sequence: record_count + 1,
        records_file: "authority-authority-run.bwl".into(),
        records_bytes: Some(123),
        records_digest: Some(digest("records")),
        last_flush_at_ms: Some(25),
    }
}

#[test]
fn schema_v2_candidate_and_zero_authority_shapes_are_strict() {
    let candidate = candidate_decision();
    candidate.validate().expect("candidate decision is exact");

    let mut zero = candidate.clone();
    zero.decision_id = "decision-2".into();
    zero.reason = SelectionReason::KillNotArmed;
    zero.evidence_state = EvidenceState::Unverified;
    zero.target = PlanTarget::Original;
    zero.intended_dispatch = 1;
    zero.selection_facts =
        AuthoritySelectionFactsV2::canonical_fallback(AuthorityFallbackReasonV2::KillNotArmed);
    zero.grant = None;
    zero.selected_supply_id = Some("public/b".into());
    zero.actuator_identity_digest = None;
    zero.actuator_config_digest = None;
    zero.model_rewritten = false;
    zero.validate().expect("zero-authority bypass is explicit");

    let mut malformed = zero.clone();
    malformed.grant = candidate.grant;
    assert!(
        malformed.validate().is_err(),
        "bypass cannot carry authority"
    );

    let mut fail_closed = zero;
    fail_closed.target = PlanTarget::None;
    fail_closed.intended_dispatch = 0;
    fail_closed.selected_supply_id = None;
    fail_closed
        .validate()
        .expect("fail-closed binds zero dispatch");
}

#[test]
fn non_authority_rows_preserve_actual_kill_state_without_granting_authority() {
    for mode in [RouteMode::Observe, RouteMode::Recommend] {
        for kill_state in [
            KillReadResult::Armed,
            KillReadResult::Bypass,
            KillReadResult::Missing,
            KillReadResult::Unsafe,
            KillReadResult::Unreadable,
            KillReadResult::Malformed,
            KillReadResult::QueueUnavailable,
        ] {
            let mut decision = candidate_decision();
            decision.mode = mode;
            decision.reason = if mode == RouteMode::Observe {
                SelectionReason::ObserveOnly
            } else {
                SelectionReason::RecommendationOnly
            };
            decision.evidence_state = if mode == RouteMode::Observe {
                EvidenceState::NotRequired
            } else {
                EvidenceState::Unverified
            };
            decision.selection_facts =
                AuthoritySelectionFactsV2::canonical_non_authority(kill_state);
            decision.target = PlanTarget::Original;
            decision.intended_dispatch = 1;
            decision.grant = None;
            decision.selected_supply_id = decision.baseline_supply_id.clone();
            decision.actuator_identity_digest = None;
            decision.actuator_config_digest = None;
            decision.model_rewritten = false;
            decision.validate().unwrap_or_else(|error| {
                panic!("{mode:?}/{kill_state:?} must be valid non-authority evidence: {error}")
            });
        }
    }
}

#[test]
fn candidate_and_terminal_impossible_states_are_exhaustively_rejected() {
    let candidate = candidate_decision();
    let invalid_decisions = [
        {
            let mut value = candidate.clone();
            value.selection_facts.bucket = None;
            value
        },
        {
            let mut value = candidate.clone();
            value.selection_facts.kill_state = KillReadResult::Bypass;
            value
        },
        {
            let mut value = candidate.clone();
            value.selection_facts.allowlist_matched = false;
            value
        },
        {
            let mut value = candidate.clone();
            value.selection_facts.rollout_selected = false;
            value
        },
        {
            let mut value = candidate.clone();
            value.mode = RouteMode::Observe;
            value
        },
        {
            let mut value = candidate.clone();
            value.grant = None;
            value
        },
    ];
    assert!(invalid_decisions
        .iter()
        .all(|value| value.validate().is_err()));

    let terminal = success_outcome();
    let invalid_outcomes = [
        {
            let mut value = terminal.clone();
            value.selection_facts.bucket = None;
            value
        },
        {
            let mut value = terminal.clone();
            value.selection_facts.kill_state = KillReadResult::Bypass;
            value
        },
        {
            let mut value = terminal.clone();
            value.selection_facts.allowlist_matched = false;
            value
        },
        {
            let mut value = terminal.clone();
            value.selection_facts.rollout_selected = false;
            value
        },
        {
            let mut value = terminal.clone();
            value.grant_digest = None;
            value.grant_expires_at_ms = None;
            value
        },
        {
            let mut value = terminal.clone();
            value.actuator_config_digest = None;
            value
        },
    ];
    assert!(invalid_outcomes
        .iter()
        .all(|value| value.validate().is_err()));

    let mut zero = candidate;
    zero.target = PlanTarget::Original;
    assert!(
        zero.validate().is_err(),
        "zero authority cannot retain CandidateSelected"
    );
}

#[test]
fn embeddings_candidate_schema_is_rejected_independently() {
    let mut decision = candidate_decision();
    decision.protocol = AuthorityProtocol::Embeddings;
    assert!(decision.validate().is_err());

    let mut outcome = success_outcome();
    outcome.protocol = AuthorityProtocol::Embeddings;
    assert!(outcome.validate().is_err());
}

#[test]
fn complete_run_requires_exact_decision_terminal_pairs_and_sequences() {
    let records = vec![
        AuthorityRecordV2::decision(1, candidate_decision()).unwrap(),
        AuthorityRecordV2::outcome(2, success_outcome()).unwrap(),
    ];
    let valid = validate_authority_run_v2(&manifest(2), &records).expect("complete authority run");
    assert_eq!(valid.run_id(), "authority-run");

    let missing = validate_authority_run_v2(&manifest(1), &records[..1]).unwrap_err();
    assert_eq!(missing, AuthorityRunValidationError::MissingTerminal);

    let duplicate = vec![
        records[0].clone(),
        records[1].clone(),
        AuthorityRecordV2::outcome(3, success_outcome()).unwrap(),
    ];
    assert_eq!(
        validate_authority_run_v2(&manifest(3), &duplicate).unwrap_err(),
        AuthorityRunValidationError::DuplicateTerminal
    );

    let gap = vec![
        records[0].clone(),
        AuthorityRecordV2::outcome(3, success_outcome()).unwrap(),
    ];
    assert_eq!(
        validate_authority_run_v2(&manifest(2), &gap).unwrap_err(),
        AuthorityRunValidationError::SequenceGap
    );

    let mut wrong_manifest_binding = manifest(2);
    wrong_manifest_binding.enforcement_digest = digest("different-enforcement");
    assert_eq!(
        validate_authority_run_v2(&wrong_manifest_binding, &records).unwrap_err(),
        AuthorityRunValidationError::PairMismatch
    );
}

#[test]
fn caller_supplied_clean_schemas_are_diagnostics_not_complete_run_authority() {
    let records = vec![
        AuthorityRecordV2::decision(1, candidate_decision()).unwrap(),
        AuthorityRecordV2::outcome(2, success_outcome()).unwrap(),
    ];
    let diagnostics = validate_authority_run_v2(&manifest(2), &records).unwrap();
    assert_eq!(diagnostics.run_id(), "authority-run");
    let source = include_str!("../src/ledger.rs");
    let signature = source
        .split("pub fn validate_authority_run_v2")
        .nth(1)
        .unwrap()
        .split('{')
        .next()
        .unwrap();
    assert!(signature.contains("AuthorityRunDiagnosticsV2"));
    assert!(!signature.contains("ValidatedCompleteAuthorityRunV2"));
}

#[test]
fn terminal_must_bind_the_decision_dispatch_and_fallback_reason() {
    let mut decision = candidate_decision();
    decision.reason = SelectionReason::KillNotArmed;
    decision.evidence_state = EvidenceState::Unverified;
    decision.target = bowline_core::enforcement::PlanTarget::Original;
    decision.intended_dispatch = 1;
    decision.selection_facts =
        AuthoritySelectionFactsV2::canonical_fallback(AuthorityFallbackReasonV2::KillNotArmed);
    decision.grant = None;
    decision.selected_supply_id = decision.baseline_supply_id.clone();
    decision.actuator_identity_digest = None;
    decision.actuator_config_digest = None;
    decision.model_rewritten = false;
    let mut terminal = success_outcome();
    terminal.target = bowline_core::enforcement::PlanTarget::Original;
    terminal.selection_facts = decision.selection_facts.clone();
    terminal.circuit_before = decision.selection_facts.circuit_before;
    terminal.circuit_after = terminal.circuit_before;
    terminal.grant_digest = None;
    terminal.grant_expires_at_ms = None;
    terminal.model_rewritten = false;
    terminal.selected_supply_id = Some("public/b".into());
    terminal.actuator_identity_digest = None;
    terminal.actuator_config_digest = None;
    terminal.observed_actual_cost_micros = None;
    terminal.approved_counterfactual_cost_micros = None;
    terminal.enforced_modeled_delta_micros = None;
    let records = vec![
        AuthorityRecordV2::decision(1, decision).unwrap(),
        AuthorityRecordV2::Outcome {
            schema_version: 2,
            sequence: 2,
            outcome: terminal.clone(),
        },
    ];
    assert_eq!(
        validate_authority_run_v2(&manifest(2), &records).unwrap_err(),
        AuthorityRunValidationError::PairMismatch
    );
    terminal.fallback_reason = Some(AuthorityFallbackReasonV2::KillNotArmed);
    let records = vec![
        records[0].clone(),
        AuthorityRecordV2::outcome(2, terminal).unwrap(),
    ];
    validate_authority_run_v2(&manifest(2), &records).expect("fallback reason is exact");
}

#[test]
fn terminal_serialization_repeats_all_authority_bindings() {
    let encoded = serde_json::to_value(success_outcome()).unwrap();
    for field in [
        "route_id",
        "mode",
        "protocol",
        "task_class",
        "app",
        "resolved_tags",
        "requested_supply_id",
        "selection_facts",
        "grant_digest",
        "grant_expires_at_ms",
        "model_rewritten",
        "selected_supply_id",
        "baseline_supply_id",
        "actuator_identity_digest",
        "actuator_config_digest",
        "enforcement_config_digest",
        "route_config_digest",
        "workload_identity_digest",
    ] {
        assert!(
            encoded.get(field).is_some(),
            "missing terminal field {field}"
        );
    }
}

#[test]
fn schema_v2_identity_strings_remain_readable_and_missing_fields_default_to_none() {
    let decision_value = serde_json::to_value(candidate_decision()).unwrap();
    let decision: AuthorityDecisionV2 = serde_json::from_value(decision_value.clone()).unwrap();
    assert_eq!(decision.app.as_deref(), Some("support"));
    assert!(decision.workload_identity_digest.is_some());

    let mut missing = decision_value.as_object().unwrap().clone();
    missing.remove("app");
    missing.remove("workload_identity_digest");
    let missing: AuthorityDecisionV2 = serde_json::from_value(missing.into()).unwrap();
    assert_eq!(missing.app, None);
    assert_eq!(missing.workload_identity_digest, None);

    let mut outcome = serde_json::to_value(success_outcome())
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    outcome.remove("app");
    outcome.remove("workload_identity_digest");
    let outcome: AuthorityOutcomeV2 = serde_json::from_value(outcome.into()).unwrap();
    assert_eq!(outcome.app, None);
    assert_eq!(outcome.workload_identity_digest, None);
}

#[test]
fn every_repeated_terminal_binding_is_checked_independently() {
    macro_rules! reject_tamper {
        ($field:ident, $value:expr) => {{
            let mut outcome = success_outcome();
            outcome.$field = $value;
            let records = vec![
                AuthorityRecordV2::decision(1, candidate_decision()).unwrap(),
                AuthorityRecordV2::Outcome {
                    schema_version: 2,
                    sequence: 2,
                    outcome,
                },
            ];
            assert_eq!(
                validate_authority_run_v2(&manifest(2), &records).unwrap_err(),
                AuthorityRunValidationError::PairMismatch,
                "tampered field {} was accepted",
                stringify!($field)
            );
        }};
    }

    reject_tamper!(route_id, "other-route".into());
    reject_tamper!(mode, RouteMode::Enforce);
    reject_tamper!(protocol, AuthorityProtocol::Responses);
    reject_tamper!(task_class, TaskClass::Mechanical);
    reject_tamper!(workload_identity_digest, Some(digest("other-workload")));
    reject_tamper!(app, Some("other-app".into()));
    reject_tamper!(resolved_tags, vec!["other-tag".into()]);
    reject_tamper!(requested_supply_id, Some("other-requested".into()));
    let mut selection = AuthoritySelectionFactsV2::canonical_candidate(7);
    selection.bucket = Some(8);
    reject_tamper!(selection_facts, selection);
    reject_tamper!(grant_digest, Some(digest("other-grant")));
    reject_tamper!(grant_expires_at_ms, Some(101));
    reject_tamper!(model_rewritten, false);
    reject_tamper!(selected_supply_id, Some("owned/other".into()));
    reject_tamper!(baseline_supply_id, Some("public/other".into()));
    reject_tamper!(actuator_identity_digest, Some(digest("other-endpoint")));
    reject_tamper!(actuator_config_digest, Some(digest("other-actuator")));
    reject_tamper!(enforcement_config_digest, digest("other-enforcement"));
    reject_tamper!(route_config_digest, digest("other-route-config"));
    reject_tamper!(actual_dispatch, 0);
}

#[test]
fn crash_drop_writer_failure_and_cancellation_make_run_unusable() {
    let decision = AuthorityRecordV2::decision(1, candidate_decision()).unwrap();
    let mut cancelled = success_outcome();
    cancelled.completion = CompletionStateV2::Cancelled;
    cancelled.input_tokens = None;
    cancelled.output_tokens = None;
    cancelled.usage_source = UsageSource::Missing;
    cancelled.observed_actual_cost_micros = None;
    cancelled.approved_counterfactual_cost_micros = None;
    cancelled.enforced_modeled_delta_micros = None;
    let records = vec![decision, AuthorityRecordV2::outcome(2, cancelled).unwrap()];
    assert!(validate_authority_run_v2(&manifest(2), &records).is_err());

    for changed in [
        {
            let mut value = manifest(2);
            value.clean_shutdown = false;
            value
        },
        {
            let mut value = manifest(2);
            value.dropped = 1;
            value
        },
        {
            let mut value = manifest(2);
            value.writer_healthy = false;
            value.writer_error = Some("sync failed".into());
            value
        },
    ] {
        assert!(validate_authority_run_v2(&changed, &records).is_err());
    }
}

#[test]
fn candidate_completion_status_and_failure_class_table_is_strict() {
    let valid = [
        (CompletionStateV2::Succeeded, None, Some(200)),
        (CompletionStateV2::Succeeded, None, Some(400)),
        (CompletionStateV2::Succeeded, None, Some(404)),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Connect),
            None,
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::ResponseHeaderTimeout),
            None,
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::StreamIdleTimeout),
            Some(200),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::TransportStream),
            Some(200),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::ProtocolIncomplete),
            Some(200),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Authentication),
            Some(401),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Authentication),
            Some(403),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Server),
            Some(500),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Server),
            Some(599),
        ),
    ];
    for (completion, failure, status) in valid {
        let mut outcome = success_outcome();
        outcome.completion = completion;
        outcome.candidate_failure = failure;
        outcome.status = status;
        if completion == CompletionStateV2::Failed
            || status.is_some_and(|s| !(200..=299).contains(&s))
        {
            if completion == CompletionStateV2::Failed {
                outcome.input_tokens = None;
                outcome.output_tokens = None;
                outcome.usage_source = UsageSource::Missing;
            }
            outcome.observed_actual_cost_micros = None;
            outcome.approved_counterfactual_cost_micros = None;
            outcome.enforced_modeled_delta_micros = None;
        }
        outcome.validate().expect("table entry is valid");
        let encoded = serde_json::to_string(&outcome).unwrap();
        assert!(!encoded.contains("prompt"));
        assert!(!encoded.contains("authorization"));
        assert!(!encoded.contains("https://"));
    }

    let invalid = [
        (CompletionStateV2::Succeeded, None, Some(401)),
        (CompletionStateV2::Succeeded, None, Some(403)),
        (CompletionStateV2::Succeeded, None, Some(500)),
        (CompletionStateV2::Succeeded, None, Some(599)),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Connect),
            Some(200),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::ResponseHeaderTimeout),
            Some(200),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::StreamIdleTimeout),
            Some(401),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::TransportStream),
            Some(403),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::ProtocolIncomplete),
            Some(500),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Authentication),
            None,
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Authentication),
            Some(400),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Authentication),
            Some(500),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Server),
            None,
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Server),
            Some(499),
        ),
        (
            CompletionStateV2::Failed,
            Some(CandidateFailureClassV2::Server),
            Some(600),
        ),
    ];
    for (completion, failure, status) in invalid {
        let mut outcome = success_outcome();
        outcome.completion = completion;
        outcome.candidate_failure = failure;
        outcome.status = status;
        if completion == CompletionStateV2::Failed {
            outcome.input_tokens = None;
            outcome.output_tokens = None;
            outcome.usage_source = UsageSource::Missing;
            outcome.observed_actual_cost_micros = None;
            outcome.approved_counterfactual_cost_micros = None;
            outcome.enforced_modeled_delta_micros = None;
        }
        assert!(outcome.validate().is_err(), "accepted invalid table entry");

        let records = vec![
            AuthorityRecordV2::decision(1, candidate_decision()).unwrap(),
            AuthorityRecordV2::Outcome {
                schema_version: 2,
                sequence: 2,
                outcome,
            },
        ];
        assert!(
            validate_authority_run_v2(&manifest(2), &records).is_err(),
            "whole-run validation accepted contradictory terminal"
        );
    }
}

#[test]
fn authority_cost_numbers_stay_in_the_exact_signed_json_range() {
    let mut outcome = success_outcome();
    outcome.observed_actual_cost_micros = Some(i64::MAX as u64 + 1);
    outcome.approved_counterfactual_cost_micros = Some(i64::MAX as u64 + 1);
    outcome.enforced_modeled_delta_micros = Some(0);
    assert!(outcome.validate().is_err());
}

#[test]
fn every_predispatch_fallback_has_a_zero_authority_pair() {
    for reason in [
        AuthorityFallbackReasonV2::KillNotArmed,
        AuthorityFallbackReasonV2::RouteMismatch,
        AuthorityFallbackReasonV2::UntrustedIdentity,
        AuthorityFallbackReasonV2::UnsupportedShape,
        AuthorityFallbackReasonV2::GrantMissing,
        AuthorityFallbackReasonV2::SignatureMissing,
        AuthorityFallbackReasonV2::SignatureInvalid,
        AuthorityFallbackReasonV2::GrantMismatch,
        AuthorityFallbackReasonV2::GrantStale,
        AuthorityFallbackReasonV2::ApprovalMissing,
        AuthorityFallbackReasonV2::ApprovalSignatureInvalid,
        AuthorityFallbackReasonV2::ApprovalUnbound,
        AuthorityFallbackReasonV2::ApprovalExpired,
        AuthorityFallbackReasonV2::WorkloadMismatch,
        AuthorityFallbackReasonV2::AllowlistMiss,
        AuthorityFallbackReasonV2::RolloutMiss,
        AuthorityFallbackReasonV2::PinnedModelMismatch,
        AuthorityFallbackReasonV2::AdmissionSaturated,
        AuthorityFallbackReasonV2::CircuitOpen,
        AuthorityFallbackReasonV2::CandidateUnavailable,
        AuthorityFallbackReasonV2::ActuatorUnavailable,
    ] {
        for target in [
            bowline_core::enforcement::PlanTarget::Original,
            bowline_core::enforcement::PlanTarget::None,
        ] {
            let mut decision = candidate_decision();
            decision.reason = reason.into();
            decision.evidence_state = EvidenceState::Unverified;
            decision.target = target;
            decision.intended_dispatch =
                u8::from(target == bowline_core::enforcement::PlanTarget::Original);
            decision.selection_facts = AuthoritySelectionFactsV2::canonical_fallback(reason);
            decision.grant = None;
            decision.selected_supply_id = (target
                == bowline_core::enforcement::PlanTarget::Original)
                .then(|| "public/b".to_string());
            decision.actuator_identity_digest = None;
            decision.actuator_config_digest = None;
            decision.model_rewritten = false;

            let mut terminal = success_outcome();
            terminal.target = target;
            terminal.fallback_reason = Some(reason);
            terminal.actual_dispatch = decision.intended_dispatch;
            terminal.selection_facts = decision.selection_facts.clone();
            terminal.circuit_before = decision.selection_facts.circuit_before;
            terminal.circuit_after = terminal.circuit_before;
            terminal.grant_digest = None;
            terminal.grant_expires_at_ms = None;
            terminal.model_rewritten = false;
            terminal.selected_supply_id = decision.selected_supply_id.clone();
            terminal.actuator_identity_digest = None;
            terminal.actuator_config_digest = None;
            terminal.observed_actual_cost_micros = None;
            terminal.approved_counterfactual_cost_micros = None;
            terminal.enforced_modeled_delta_micros = None;
            if target == bowline_core::enforcement::PlanTarget::None {
                terminal.completion = CompletionStateV2::Local;
                terminal.status = Some(503);
                terminal.input_tokens = None;
                terminal.output_tokens = None;
                terminal.usage_source = UsageSource::Missing;
            }
            let records = vec![
                AuthorityRecordV2::decision(1, decision).unwrap(),
                AuthorityRecordV2::outcome(2, terminal).unwrap(),
            ];
            validate_authority_run_v2(&manifest(2), &records).unwrap();
        }
    }
}

#[test]
fn legacy_v1_fixture_bytes_and_shape_are_unchanged() {
    let fixture = include_bytes!("fixtures/decision-record-v1.json");
    let decoded: bowline_core::ledger::DecisionRecord = serde_json::from_slice(fixture).unwrap();
    assert_eq!(
        serde_json::to_vec(&decoded).unwrap(),
        fixture.strip_suffix(b"\n").unwrap_or(fixture)
    );
    assert!(serde_json::from_slice::<AuthorityRecordV2>(fixture).is_err());
}
