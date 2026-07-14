use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use bowline_core::enforcement::{EnforcementPlan, EvidenceState};
use bowline_core::{
    enforcement::{AuthorityProtocol, KillReadResult, PlanTarget, RouteMode, SelectionReason},
    ledger::{
        AuthorityFallbackReasonV2, AuthorityLedgerV2, AuthorityOutcomeV2,
        AuthoritySelectionFactsV2, CircuitStateV2, CompletionStateV2, UsageSource,
    },
    run::AuthorityRunStoreV2,
    supply::TaskClass,
};
use bowline_gateway::observation::{
    prepare_zero_authority_decision_v2, AuthorityDecisionContextV2, PreparedAuthorityDecisionV2,
};
use bowline_gateway::writer::{
    spawn_managed_authority_writer, AuthorityWriterOptions, DispatchAttemptV2, ManagedWriterError,
};

fn digest(value: u8) -> String {
    format!("sha256:{value:064x}")
}

fn options(path: &std::path::Path) -> AuthorityWriterOptions {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    AuthorityWriterOptions {
        directory: path.to_path_buf(),
        enforcement_digest: digest(1),
        actuator_digests: Vec::new(),
        grant_digests: Vec::new(),
        queue_capacity: 2,
        max_records_bytes: 1024 * 1024,
    }
}

fn decision(id: &str) -> PreparedAuthorityDecisionV2 {
    prepare_zero_authority_decision_v2(
        &EnforcementPlan {
            target: PlanTarget::Original,
            mode: RouteMode::Enforce,
            reason: SelectionReason::CandidateUnavailable,
            evidence_state: EvidenceState::Unverified,
            bucket: Some(1),
            selected_supply_id: Some("public/b".into()),
            baseline_supply_id: Some("public/b".into()),
            actuator_digest: None,
            config_digest: Some(digest(1)),
            route_digest: Some(digest(11)),
            model_rewritten: false,
            grant_digest: None,
            dispatch_count: 1,
        },
        AuthorityDecisionContextV2 {
            decision_id: id.into(),
            ts_ms: 10,
            route_id: "route".into(),
            protocol: AuthorityProtocol::Responses,
            task_class: TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(4)),
            kill_state: KillReadResult::Armed,
            method: "POST".into(),
            path: "/v1/responses".into(),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            request_body_digest: [7; 32],
            requested_supply_id: None,
        },
    )
    .unwrap()
}

fn outcome(id: &str) -> AuthorityOutcomeV2 {
    AuthorityOutcomeV2 {
        decision_id: id.into(),
        replaces_decision_id: None,
        ts_ms: 20,
        route_id: "route".into(),
        mode: RouteMode::Enforce,
        protocol: AuthorityProtocol::Responses,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest(4)),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        requested_supply_id: None,
        selection_facts: {
            let mut facts = AuthoritySelectionFactsV2::canonical_fallback(
                AuthorityFallbackReasonV2::CandidateUnavailable,
            );
            facts.bucket = Some(1);
            facts
        },
        grant_digest: None,
        grant_expires_at_ms: None,
        model_rewritten: false,
        selected_supply_id: Some("public/b".into()),
        baseline_supply_id: Some("public/b".into()),
        actuator_identity_digest: None,
        actuator_config_digest: None,
        enforcement_config_digest: digest(1),
        route_config_digest: digest(11),
        target: PlanTarget::Original,
        fallback_reason: Some(AuthorityFallbackReasonV2::CandidateUnavailable),
        circuit_before: CircuitStateV2::Closed,
        circuit_after: CircuitStateV2::Closed,
        actual_dispatch: 1,
        completion: CompletionStateV2::Succeeded,
        candidate_failure: None,
        status: Some(200),
        input_tokens: Some(10),
        output_tokens: Some(5),
        usage_source: UsageSource::Observed,
        observed_actual_cost_micros: None,
        approved_counterfactual_cost_micros: None,
        enforced_modeled_delta_micros: None,
    }
}

#[tokio::test]
async fn configured_unicode_punctuation_identifiers_persist_as_a_complete_authority_pair() {
    let tempdir = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(tempdir.path())).unwrap();
    let prepared = prepare_zero_authority_decision_v2(
        &EnforcementPlan {
            target: PlanTarget::Original,
            mode: RouteMode::Enforce,
            reason: SelectionReason::CandidateUnavailable,
            evidence_state: EvidenceState::Unverified,
            bucket: Some(1),
            selected_supply_id: Some("public/基準:v1?".into()),
            baseline_supply_id: Some("public/基準:v1?".into()),
            actuator_digest: None,
            config_digest: Some(digest(1)),
            route_digest: Some(digest(11)),
            model_rewritten: false,
            grant_digest: None,
            dispatch_count: 1,
        },
        AuthorityDecisionContextV2 {
            decision_id: "decision-1".into(),
            ts_ms: 10,
            route_id: "routé:α/v1!".into(),
            protocol: AuthorityProtocol::Responses,
            task_class: TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(4)),
            kill_state: KillReadResult::Armed,
            method: "POST".into(),
            path: "/v1/responses".into(),
            app: Some("app:支援!".into()),
            resolved_tags: vec!["environment:test".into(), "région:eu-west/1".into()],
            request_body_digest: [7; 32],
            requested_supply_id: Some("requested/模型:v1?".into()),
        },
    )
    .unwrap();
    let handle = writer.reserve_and_flush_decision(prepared).await.unwrap();
    let attempt = DispatchAttemptV2 {
        request_body_digest: [7; 32],
        target: PlanTarget::Original,
        selected_supply_id: Some("public/基準:v1?".into()),
        requested_supply_id: Some("requested/模型:v1?".into()),
        route_id: "routé:α/v1!".into(),
        method: "POST".into(),
        path: "/v1/responses".into(),
        protocol: AuthorityProtocol::Responses,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest(4)),
        app: Some("app:支援!".into()),
        resolved_tags: vec!["environment:test".into(), "région:eu-west/1".into()],
        bucket: Some(1),
    };
    let authorized = handle.authorize_dispatch(attempt).await.unwrap();
    let mut terminal = outcome("decision-1");
    terminal.route_id = "routé:α/v1!".into();
    terminal.app = Some("app:支援!".into());
    terminal.resolved_tags = vec!["environment:test".into(), "région:eu-west/1".into()];
    terminal.requested_supply_id = Some("requested/模型:v1?".into());
    terminal.selected_supply_id = Some("public/基準:v1?".into());
    terminal.baseline_supply_id = Some("public/基準:v1?".into());
    writer
        .append_and_flush_outcome(authorized, terminal)
        .await
        .unwrap();
    writer.shutdown(Duration::from_secs(2)).await.unwrap();

    let read = AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
    assert_eq!(read.records().len(), 2);
    assert_eq!(read.complete().run_id(), writer.manifest_snapshot().run_id);
}

#[tokio::test]
async fn handle_exists_only_after_decision_is_durably_readable() {
    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    let handle = writer
        .reserve_and_flush_decision(decision("decision-1"))
        .await
        .expect("decision is flushed");
    assert!(!handle.authorizes_candidate());

    let manifest = writer.manifest_snapshot();
    let records = AuthorityLedgerV2::read_all(temp.path(), &manifest.records_file).unwrap();
    assert_eq!(records.len(), 1, "ack means decision is already durable");

    let authorized = handle.authorize_dispatch(attempt([7; 32])).await.unwrap();
    assert!(writer.manifest_snapshot().writer_healthy);
    writer
        .append_and_flush_outcome(authorized, outcome("decision-1"))
        .await
        .expect("terminal is flushed");
    writer.shutdown(Duration::from_secs(2)).await.unwrap();

    let verified = AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
    assert_eq!(verified.complete().run_id(), verified.manifest().run_id);
    assert_eq!(verified.records().len(), 2);
}

#[tokio::test]
async fn authoritative_restart_read_rejects_tampered_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    let handle = writer
        .reserve_and_flush_decision(decision("decision-1"))
        .await
        .unwrap();
    writer
        .append_and_flush_outcome(
            handle.authorize_dispatch(attempt([7; 32])).await.unwrap(),
            outcome("decision-1"),
        )
        .await
        .unwrap();
    writer.shutdown(Duration::from_secs(2)).await.unwrap();
    let manifest = AuthorityRunStoreV2::load_manifest(writer.manifest_path()).unwrap();
    let directory = std::fs::canonicalize(temp.path()).unwrap();
    assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_ok());
    assert_eq!(
        AuthorityLedgerV2::read_authoritative_run(&directory, &manifest)
            .unwrap()
            .len(),
        2
    );
    let path = temp.path().join(&manifest.records_file);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(AuthorityLedgerV2::read_authoritative_run(&directory, &manifest).is_err());
    assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
}

#[tokio::test]
async fn authoritative_restart_read_rejects_symlinked_record_file() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    let handle = writer
        .reserve_and_flush_decision(decision("decision-1"))
        .await
        .unwrap();
    writer
        .append_and_flush_outcome(
            handle.authorize_dispatch(attempt([7; 32])).await.unwrap(),
            outcome("decision-1"),
        )
        .await
        .unwrap();
    writer.shutdown(Duration::from_secs(2)).await.unwrap();
    let manifest = AuthorityRunStoreV2::load_manifest(writer.manifest_path()).unwrap();
    let path = temp.path().join(&manifest.records_file);
    let outside = temp.path().join("outside-copy");
    std::fs::copy(&path, &outside).unwrap();
    std::fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
}

#[tokio::test]
async fn authoritative_restart_requires_private_owned_directory_and_record_modes() {
    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    let handle = writer
        .reserve_and_flush_decision(decision("decision-1"))
        .await
        .unwrap();
    writer
        .append_and_flush_outcome(
            handle.authorize_dispatch(attempt([7; 32])).await.unwrap(),
            outcome("decision-1"),
        )
        .await
        .unwrap();
    writer.shutdown(Duration::from_secs(2)).await.unwrap();
    let manifest = AuthorityRunStoreV2::load_manifest(writer.manifest_path()).unwrap();
    let record = temp.path().join(&manifest.records_file);

    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
}

#[tokio::test]
async fn mismatched_or_reused_handle_cannot_append_a_terminal() {
    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    let handle = writer
        .reserve_and_flush_decision(decision("decision-1"))
        .await
        .unwrap();
    let error = writer
        .append_and_flush_outcome(
            handle.authorize_dispatch(attempt([7; 32])).await.unwrap(),
            outcome("different"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ManagedWriterError::InvalidRecordContext));
    writer.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!writer.manifest_snapshot().clean_shutdown);
}

#[tokio::test]
async fn flushed_handle_rejects_every_exact_dispatch_binding_mismatch() {
    let mut attempts = Vec::new();
    let mut changed = attempt([99; 32]);
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.target = PlanTarget::None;
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.selected_supply_id = Some("public/other".into());
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.requested_supply_id = Some("pinned/model".into());
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.route_id = "other-route".into();
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.method = "GET".into();
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.path = "/v1/chat/completions".into();
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.protocol = AuthorityProtocol::ChatCompletions;
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.task_class = TaskClass::Judgment;
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.workload_identity_digest = Some(digest(99));
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.app = Some("other-app".into());
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.resolved_tags = vec!["other".into()];
    attempts.push(changed);
    changed = attempt([7; 32]);
    changed.bucket = Some(2);
    attempts.push(changed);

    for (index, changed) in attempts.into_iter().enumerate() {
        let temp = tempfile::tempdir().unwrap();
        let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
        let handle = writer
            .reserve_and_flush_decision(decision(&format!("decision-{index}")))
            .await
            .unwrap();
        let error = handle
            .authorize_dispatch(changed)
            .await
            .expect_err("mismatched request cannot use exact authority");
        assert!(matches!(error, ManagedWriterError::InvalidRecordContext));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let snapshot = writer.manifest_snapshot();
        assert!(
            !snapshot.writer_healthy,
            "tamper {index} left writer healthy"
        );
        assert!(!snapshot.clean_shutdown, "tamper {index} left run clean");
        assert!(snapshot.writer_error.is_some());
        assert_eq!(
            (snapshot.accepted, snapshot.recorded, snapshot.dropped),
            (1, 1, 0)
        );
        assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
    }
}

#[tokio::test]
async fn dropped_or_live_authority_handles_make_shutdown_incomplete() {
    for authorized in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
        let handle = writer
            .reserve_and_flush_decision(decision("abandoned"))
            .await
            .unwrap();
        if authorized {
            drop(handle.authorize_dispatch(attempt([7; 32])).await.unwrap());
        } else {
            drop(handle);
        }
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let snapshot = writer.manifest_snapshot();
        assert!(!snapshot.writer_healthy);
        assert!(!snapshot.clean_shutdown);
        assert!(snapshot.writer_error.is_some());
        assert_eq!(
            (snapshot.accepted, snapshot.recorded, snapshot.dropped),
            (1, 1, 0)
        );
        assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
    }

    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    let live = writer
        .reserve_and_flush_decision(decision("live"))
        .await
        .unwrap();
    writer.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!writer.manifest_snapshot().writer_healthy);
    assert!(!writer.manifest_snapshot().clean_shutdown);
    drop(live);
}

fn attempt(request_body_digest: [u8; 32]) -> DispatchAttemptV2 {
    DispatchAttemptV2 {
        request_body_digest,
        target: PlanTarget::Original,
        selected_supply_id: Some("public/b".into()),
        requested_supply_id: None,
        route_id: "route".into(),
        method: "POST".into(),
        path: "/v1/responses".into(),
        protocol: AuthorityProtocol::Responses,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest(4)),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        bucket: Some(1),
    }
}

#[tokio::test]
async fn shutdown_refuses_new_authority_and_never_returns_a_handle() {
    let temp = tempfile::tempdir().unwrap();
    let writer = spawn_managed_authority_writer(options(temp.path())).unwrap();
    writer.shutdown(Duration::from_secs(2)).await.unwrap();
    let error = writer
        .reserve_and_flush_decision(decision("decision-1"))
        .await
        .unwrap_err();
    assert!(matches!(error, ManagedWriterError::Closed));
}
