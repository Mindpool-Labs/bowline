use bowline_core::{
    enforcement::{AuthorityProtocol, EvidenceState, PlanTarget, RouteMode, SelectionReason},
    ledger::{
        AuthorityDecisionV2, AuthorityGrantBindingV2, AuthorityLedgerV2, AuthorityOutcomeV2,
        AuthorityRecordV2, AuthoritySelectionFactsV2, CandidateFailureClassV2, CircuitStateV2,
        CompletionStateV2, UsageSource,
    },
    report::{
        compute_controlled_enforcement_diagnostic_report, compute_controlled_enforcement_report,
        ControlledEnforcementModeRow, ControlledEnforcementReport, ControlledEnforcementTotals,
    },
    run::{AuthorityRunDigestsV2, AuthorityRunStoreV2},
    supply::TaskClass,
};

#[test]
fn canonical_totals_are_explicit_and_unvalidated_shadow_opportunity_is_unavailable() {
    let totals = ControlledEnforcementTotals {
        decisions: 4,
        candidate_dispatches: 2,
        pre_dispatch_rejections: 1,
        bypasses: 1,
        fail_closed: 1,
        failures: 1,
        cancellations: 1,
        incomplete: 2,
        observed_enforced_cost_micros: Some(700_000),
        enforced_modeled_delta_micros: Some(300_000),
    };
    let report = ControlledEnforcementReport {
        schema_version: 1,
        authority_schema_version: 2,
        complete: true,
        run_id: "synthetic-authority-run".into(),
        records_digest: format!("sha256:{}", "a".repeat(64)),
        totals: totals.clone(),
        by_mode: vec![ControlledEnforcementModeRow {
            mode: RouteMode::Enforce,
            totals,
        }],
        shadow_opportunity: None,
    };

    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["totals"]["observed_enforced_cost_micros"], 700_000);
    assert_eq!(value["totals"]["enforced_modeled_delta_micros"], "300000");
    assert!(value["shadow_opportunity"].is_null());
    assert!(value.get("realized_savings").is_none());
}

fn digest(_value: char) -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn cancelled_pair() -> (AuthorityRecordV2, AuthorityRecordV2) {
    let facts = AuthoritySelectionFactsV2::canonical_candidate(7);
    let decision = AuthorityDecisionV2 {
        decision_id: "decision-1".into(),
        replaces_decision_id: None,
        configured_fallback_target: None,
        ts_ms: 10,
        route_id: "chat-canary".into(),
        mode: RouteMode::CanaryEnforce,
        protocol: AuthorityProtocol::ChatCompletions,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest('w')),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        requested_supply_id: Some("owned/a".into()),
        reason: SelectionReason::CandidateSelected,
        evidence_state: EvidenceState::Presented,
        selection_facts: facts.clone(),
        target: PlanTarget::Candidate,
        intended_dispatch: 1,
        grant: Some(AuthorityGrantBindingV2 {
            grant_digest: digest('g'),
            expires_at_ms: 100,
            economics_source_digest: digest('e'),
            quality_source_digest: digest('q'),
            opportunity_digest: digest('o'),
        }),
        selected_supply_id: Some("owned/a".into()),
        baseline_supply_id: Some("public/b".into()),
        actuator_identity_digest: Some(digest('i')),
        actuator_config_digest: Some(digest('a')),
        enforcement_config_digest: digest('c'),
        route_config_digest: digest('r'),
        model_rewritten: true,
    };
    let outcome = AuthorityOutcomeV2 {
        decision_id: decision.decision_id.clone(),
        replaces_decision_id: None,
        ts_ms: 20,
        route_id: decision.route_id.clone(),
        mode: decision.mode,
        protocol: decision.protocol,
        task_class: decision.task_class,
        workload_identity_digest: decision.workload_identity_digest.clone(),
        app: decision.app.clone(),
        resolved_tags: decision.resolved_tags.clone(),
        requested_supply_id: decision.requested_supply_id.clone(),
        selection_facts: facts,
        grant_digest: decision
            .grant
            .as_ref()
            .map(|grant| grant.grant_digest.clone()),
        grant_expires_at_ms: decision.grant.as_ref().map(|grant| grant.expires_at_ms),
        model_rewritten: true,
        selected_supply_id: decision.selected_supply_id.clone(),
        baseline_supply_id: decision.baseline_supply_id.clone(),
        actuator_identity_digest: decision.actuator_identity_digest.clone(),
        actuator_config_digest: decision.actuator_config_digest.clone(),
        enforcement_config_digest: decision.enforcement_config_digest.clone(),
        route_config_digest: decision.route_config_digest.clone(),
        target: PlanTarget::Candidate,
        fallback_reason: None,
        circuit_before: CircuitStateV2::Closed,
        circuit_after: CircuitStateV2::Closed,
        actual_dispatch: 1,
        completion: CompletionStateV2::Cancelled,
        candidate_failure: None,
        status: Some(200),
        input_tokens: None,
        output_tokens: None,
        usage_source: UsageSource::Missing,
        observed_actual_cost_micros: None,
        approved_counterfactual_cost_micros: None,
        enforced_modeled_delta_micros: None,
    };
    (
        AuthorityRecordV2::decision(1, decision).unwrap(),
        AuthorityRecordV2::outcome(2, outcome).unwrap(),
    )
}

fn candidate_pair_for_status(
    decision_id: &str,
    status: u16,
    tokens: bool,
    costs: bool,
) -> (AuthorityRecordV2, AuthorityRecordV2) {
    candidate_pair_with_usage(
        decision_id,
        status,
        tokens.then_some(10),
        tokens.then_some(20),
        costs,
    )
}

fn candidate_pair_with_usage(
    decision_id: &str,
    status: u16,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    costs: bool,
) -> (AuthorityRecordV2, AuthorityRecordV2) {
    let (
        AuthorityRecordV2::Decision { mut decision, .. },
        AuthorityRecordV2::Outcome { mut outcome, .. },
    ) = cancelled_pair()
    else {
        unreachable!()
    };
    decision.decision_id = decision_id.to_owned();
    outcome.decision_id = decision_id.to_owned();
    outcome.status = Some(status);
    outcome.input_tokens = input_tokens;
    outcome.output_tokens = output_tokens;
    outcome.usage_source = if input_tokens.is_some() || output_tokens.is_some() {
        UsageSource::Observed
    } else {
        UsageSource::Missing
    };
    if matches!(status, 401 | 403) || (500..=599).contains(&status) {
        outcome.completion = CompletionStateV2::Failed;
        outcome.candidate_failure = Some(if matches!(status, 401 | 403) {
            CandidateFailureClassV2::Authentication
        } else {
            CandidateFailureClassV2::Server
        });
        outcome.circuit_after = CircuitStateV2::Open;
    } else {
        outcome.completion = CompletionStateV2::Succeeded;
        outcome.candidate_failure = None;
        outcome.circuit_after = CircuitStateV2::Closed;
    }
    if costs {
        outcome.observed_actual_cost_micros = Some(10);
        outcome.approved_counterfactual_cost_micros = Some(20);
        outcome.enforced_modeled_delta_micros = Some(10);
    } else {
        outcome.observed_actual_cost_micros = None;
        outcome.approved_counterfactual_cost_micros = None;
        outcome.enforced_modeled_delta_micros = None;
    }
    (
        AuthorityRecordV2::decision(1, decision).unwrap(),
        AuthorityRecordV2::outcome(2, outcome).unwrap(),
    )
}

#[test]
fn partial_observed_usage_is_valid_but_non_applicable_and_does_not_poison_report() {
    let pairs = [
        candidate_pair_with_usage("complete", 200, Some(10), Some(20), true),
        candidate_pair_with_usage("input-only", 200, Some(11), None, false),
        candidate_pair_with_usage("output-only", 200, None, Some(22), false),
    ];
    for (_, record) in &pairs[1..] {
        let AuthorityRecordV2::Outcome { outcome, .. } = record else {
            unreachable!()
        };
        assert!(outcome.validate().is_ok());
        assert_eq!(outcome.observed_actual_cost_micros, None);
        assert_eq!(outcome.approved_counterfactual_cost_micros, None);
        assert_eq!(outcome.enforced_modeled_delta_micros, None);
    }

    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("authority");
    let store = AuthorityRunStoreV2::create(
        &directory,
        AuthorityRunDigestsV2 {
            enforcement: digest('c'),
            actuator_set: digest('a'),
            grant_set: digest('g'),
        },
    )
    .unwrap();
    let snapshot = store.snapshot();
    let mut ledger =
        AuthorityLedgerV2::create(&directory, &snapshot.records_file, 1024 * 1024).unwrap();
    for (index, mut record) in pairs
        .into_iter()
        .flat_map(|(decision, outcome)| [decision, outcome])
        .enumerate()
    {
        let sequence = u64::try_from(index + 1).unwrap();
        match &mut record {
            AuthorityRecordV2::Decision {
                sequence: value, ..
            }
            | AuthorityRecordV2::Outcome {
                sequence: value, ..
            } => *value = sequence,
        }
        assert_eq!(store.accept().unwrap(), sequence);
        ledger.append(&record).unwrap();
        store.recorded(sequence).unwrap();
    }
    let (bytes, records_digest) = ledger.integrity().unwrap();
    store
        .finish(true, Some(bytes), Some(records_digest))
        .unwrap();
    let manifest = store.manifest_path().to_path_buf();
    drop(ledger);
    drop(store);
    let validated = AuthorityLedgerV2::read_validated_authority_run(&manifest).unwrap();
    let report = compute_controlled_enforcement_report(&validated).unwrap();
    assert_eq!(report.totals.observed_enforced_cost_micros, Some(10));
    assert_eq!(report.totals.enforced_modeled_delta_micros, Some(10));
    assert_eq!(report.totals.incomplete, 2);
}

#[test]
fn modeled_delta_http_status_matrix_uses_only_complete_observed_2xx_outcomes() {
    let non_success = [
        101, 300, 301, 302, 304, 307, 308, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 599,
    ];
    let mut records = Vec::new();
    for (index, status) in non_success.into_iter().enumerate() {
        let id = format!("non-success-{index}");
        let (decision, outcome) = candidate_pair_for_status(&id, status, true, false);
        let AuthorityRecordV2::Outcome { outcome: clean, .. } = &outcome else {
            unreachable!()
        };
        assert!(clean.validate().is_ok(), "status {status} without costs");
        let mut costful = clean.clone();
        costful.observed_actual_cost_micros = Some(10);
        costful.approved_counterfactual_cost_micros = Some(20);
        costful.enforced_modeled_delta_micros = Some(10);
        assert!(
            costful.validate().is_err(),
            "status {status} must reject modeled costs"
        );
        records.push(decision);
        records.push(outcome);
    }
    for status in [200, 204, 299] {
        let (decision, outcome) =
            candidate_pair_for_status(&format!("success-{status}"), status, true, true);
        records.push(decision);
        records.push(outcome);
    }
    let (decision, outcome) = candidate_pair_for_status("missing-usage", 200, false, false);
    records.push(decision);
    records.push(outcome);

    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("authority");
    let store = AuthorityRunStoreV2::create(
        &directory,
        AuthorityRunDigestsV2 {
            enforcement: digest('c'),
            actuator_set: digest('a'),
            grant_set: digest('g'),
        },
    )
    .unwrap();
    let snapshot = store.snapshot();
    let mut ledger =
        AuthorityLedgerV2::create(&directory, &snapshot.records_file, 1024 * 1024).unwrap();
    for (index, mut record) in records.into_iter().enumerate() {
        let sequence = u64::try_from(index + 1).unwrap();
        match &mut record {
            AuthorityRecordV2::Decision {
                sequence: value, ..
            }
            | AuthorityRecordV2::Outcome {
                sequence: value, ..
            } => *value = sequence,
        }
        assert_eq!(store.accept().unwrap(), sequence);
        ledger.append(&record).unwrap();
        store.recorded(sequence).unwrap();
    }
    let (bytes, records_digest) = ledger.integrity().unwrap();
    store
        .finish(true, Some(bytes), Some(records_digest))
        .unwrap();
    let manifest = store.manifest_path().to_path_buf();
    drop(ledger);
    drop(store);
    let validated = AuthorityLedgerV2::read_validated_authority_run(&manifest).unwrap();
    let report = compute_controlled_enforcement_report(&validated).unwrap();
    assert_eq!(report.totals.observed_enforced_cost_micros, Some(30));
    assert_eq!(report.totals.enforced_modeled_delta_micros, Some(30));
}

#[test]
fn validated_diagnostic_report_counts_cancellation_but_withholds_modeled_delta() {
    let (decision, outcome) = cancelled_pair();
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("authority");
    let store = AuthorityRunStoreV2::create(
        &directory,
        AuthorityRunDigestsV2 {
            enforcement: digest('c'),
            actuator_set: digest('a'),
            grant_set: digest('g'),
        },
    )
    .unwrap();
    let snapshot = store.snapshot();
    let mut ledger =
        AuthorityLedgerV2::create(&directory, &snapshot.records_file, 1024 * 1024).unwrap();
    assert_eq!(store.accept().unwrap(), 1);
    ledger.append(&decision).unwrap();
    store.recorded(1).unwrap();
    assert_eq!(store.accept().unwrap(), 2);
    ledger.append(&outcome).unwrap();
    store.recorded(2).unwrap();
    let (bytes, records_digest) = ledger.integrity().unwrap();
    store
        .finish(true, Some(bytes), Some(records_digest))
        .unwrap();
    let manifest_path = store.manifest_path().to_path_buf();
    drop(ledger);
    drop(store);
    let validated =
        AuthorityLedgerV2::read_validated_authority_diagnostic_run(&manifest_path).unwrap();
    let report = compute_controlled_enforcement_diagnostic_report(&validated).unwrap();
    assert!(!report.complete);
    assert_eq!(report.totals.cancellations, 1);
    assert_eq!(report.totals.incomplete, 1);
    assert_eq!(report.totals.enforced_modeled_delta_micros, None);

    // Raw bytes cannot be substituted after the opaque validated read is produced.
    let mut tampered = std::fs::read(directory.join(&snapshot.records_file)).unwrap();
    tampered.push(0);
    std::fs::write(directory.join(&snapshot.records_file), tampered).unwrap();
    assert!(AuthorityLedgerV2::read_validated_authority_diagnostic_run(&manifest_path).is_err());
}

#[test]
fn computation_accepts_only_a_validated_schema_v2_run() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("authority");
    let digest = |value: char| format!("sha256:{}", value.to_string().repeat(64));
    let store = AuthorityRunStoreV2::create(
        &directory,
        AuthorityRunDigestsV2 {
            enforcement: digest('a'),
            actuator_set: digest('b'),
            grant_set: digest('c'),
        },
    )
    .unwrap();
    let snapshot = store.snapshot();
    let mut ledger =
        AuthorityLedgerV2::create(&directory, &snapshot.records_file, 1024 * 1024).unwrap();
    let (bytes, records_digest) = ledger.integrity().unwrap();
    store
        .finish(true, Some(bytes), Some(records_digest))
        .unwrap();
    let manifest = store.manifest_path().to_path_buf();
    drop(ledger);
    drop(store);
    let validated = AuthorityLedgerV2::read_validated_authority_run(&manifest).unwrap();

    let report = compute_controlled_enforcement_report(&validated).unwrap();
    assert!(report.complete);
    assert_eq!(report.totals, ControlledEnforcementTotals::default());
    assert!(report.shadow_opportunity.is_none());
}
