use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use bowline_core::{
    config::{
        load_owned_cost_catalog, AuthoritySigningConfig, Config, OwnedCostCatalog,
        PromotionApprovalConfig, RuntimeConfig,
    },
    economics::{
        canonical_quality_projection_digest, ActionableEconomicsReport, AnalysisMode, Blocker,
        BuildProvenance, OpportunityKey, OpportunityRow, QualityEvidenceSummary,
        QualityJoinEvidence, QualitySourceBinding, ReconciliationState, SelectedBillingEvidence,
        SelectedEvidence, SelectedTrafficEvidence, SourceBindingCheck, MAX_ANALYSIS_RUNS,
    },
    enforcement::{
        economics_opportunity_digest, route_workload_digest, ActiveRuntimeProvenance,
        AuthorityProtocol, CandidateAvailability, EnforcementConfigV1, KillReadResult, PlanTarget,
        QualityPromotionSource, SelectionReason, SelectionRequestFacts,
    },
    policy::PolicyBundle,
    quality::{
        EvaluatorKind, EvaluatorStatus, GateResult, PromotionAssessment, PromotionGates,
        PromotionMetrics, PromotionVerdict, QualityEvidenceOverlay, QualityProtocol,
    },
    quality_report::{
        canonical_outcomes_digest, quality_report_digest, quality_report_v2_digest,
        write_quality_report_v2, QualityReport, QualityReportV2,
    },
    quality_run::{
        QualityAttemptStatus, QualityEvaluatorEvidence, QualityOutcome, QualityProvenance,
        QualityRunManifest, QUALITY_RUN_SCHEMA_VERSION,
    },
    supply::{Registry, TaskClass},
    traffic::ProtocolKind,
};
use bowline_gateway::enforcement_loader::{
    load_verified_promotion_grant as load_verified_promotion_grant_with_active,
    load_verified_promotion_grant_signed, load_verified_promotion_grant_with_approval,
    load_verified_recommendation_evidence as load_verified_recommendation_evidence_with_active,
    load_verified_recommendation_evidence_signed, read_private_bundle_file,
    seal_promotion_authorization_for_route, select_enforcement_target,
    select_enforcement_target_without_grant, select_recommendation_target, BoundedKillStateReader,
    EnforcementLoadError, GatewayEvidenceState, KillStateReader, PromotionGrantLoad,
};
use bowline_gateway::observation::{
    prepare_candidate_authority_decision_v2, CandidatePreparationV2,
};
use bowline_gateway::{
    serve_with_shutdown,
    writer::{spawn_managed_writer, ManagedWriterOptions},
    GatewayDeps,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const ROUTE_ID: &str = "support-chat";
const ACTUAL_SUPPLY: &str = "public/openai";
const CANDIDATE_SUPPLY: &str = "owned/llama";
const QUALITY_RUN_ID: &str = "00000000-0000-0000-0000-000000000001";
const POLICY_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const REGISTRY_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const OWNED_COST_DIGEST: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const DATASET_DIGEST: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const EVALUATOR_DIGEST: &str =
    "sha256:5555555555555555555555555555555555555555555555555555555555555555";
const NOW_MS: u64 = 1_100;
const TEST_POLICY_SOURCE: &str =
    "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n";
const TEST_REGISTRY_SOURCE: &str = r#"{"feed_version":"test","entries":[{"id":"public/openai","model":"baseline","location":"public","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0},"ratings":{"mechanical":0.9}},{"id":"owned/llama","model":"candidate","location":"local","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{"mechanical":0.9}}]}"#;
const ANALYSIS_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct PositiveFixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    validated: bowline_core::enforcement::ValidatedEnforcement,
    workload_digest: String,
    economics_bundle_digest: String,
    quality_report_digest: String,
    quality_source_digest: String,
    active: ActiveRuntimeProvenance,
}

fn test_active_runtime_provenance() -> ActiveRuntimeProvenance {
    let policy = PolicyBundle::from_yaml(TEST_POLICY_SOURCE).unwrap();
    ActiveRuntimeProvenance::from_loaded(
        &policy,
        TEST_REGISTRY_SOURCE,
        &OwnedCostCatalog::default(),
    )
}

fn load_verified_promotion_grant(
    validated: &bowline_core::enforcement::ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
    now_ms: u64,
) -> Result<bowline_gateway::enforcement_loader::VerifiedPromotionGrant, EnforcementLoadError> {
    let active = test_active_runtime_provenance();
    load_verified_promotion_grant_with_active(validated, route_id, evidence_root, &active, now_ms)
}

fn load_verified_recommendation_evidence(
    validated: &bowline_core::enforcement::ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
    now_ms: u64,
) -> Result<bowline_gateway::enforcement_loader::VerifiedRecommendationEvidence, EnforcementLoadError>
{
    let active = test_active_runtime_provenance();
    load_verified_recommendation_evidence_with_active(
        validated,
        route_id,
        evidence_root,
        &active,
        now_ms,
    )
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn plain_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn unframed_domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn canonical_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn make_private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn copy_private_directory(source: &Path, destination: &Path) {
    make_private_directory(destination);
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_private_directory(&entry.path(), &target);
        } else {
            write_private(&target, &fs::read(entry.path()).unwrap());
        }
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    write_private(path, &serde_json::to_vec(value).unwrap());
}

fn quality_outcome() -> QualityOutcome {
    QualityOutcome {
        sequence: 1,
        case_id: "case-1".into(),
        candidate_supply_id: CANDIDATE_SUPPLY.into(),
        candidate_model: "llama".into(),
        protocol: QualityProtocol::Chat,
        task_class: TaskClass::Mechanical,
        dispatched: true,
        status: QualityAttemptStatus::Completed,
        reason: None,
        candidate_error: None,
        latency_ms: Some(10),
        input_tokens: Some(10),
        output_tokens: Some(5),
        candidate_cost_usd: Some(0.01),
        evaluator_outcomes: vec![QualityEvaluatorEvidence {
            evaluator_id: "answer".into(),
            kind: EvaluatorKind::ExactMatch,
            status: EvaluatorStatus::Pass,
            error_code: None,
            required: true,
            subjective: false,
            latency_ms: None,
        }],
        cost_evaluators: Vec::new(),
        judge: None,
        dataset_digest: DATASET_DIGEST.into(),
        evaluator_digest: EVALUATOR_DIGEST.into(),
    }
}

fn quality_manifest(active: &ActiveRuntimeProvenance) -> QualityRunManifest {
    QualityRunManifest {
        schema_version: QUALITY_RUN_SCHEMA_VERSION,
        binary_version: "fixture".into(),
        run_id: QUALITY_RUN_ID.into(),
        started_at_ms: 100,
        completed_at_ms: Some(900),
        valid_until_ms: 2_500,
        clean_shutdown: true,
        cancelled: false,
        provenance: QualityProvenance {
            dataset_manifest_digest: digest('6'),
            cases_digest: digest('7'),
            dataset_digest: DATASET_DIGEST.into(),
            evaluator_digest: EVALUATOR_DIGEST.into(),
            candidate_config_digest: digest('8'),
            policy_digest: active.policy_digest().into(),
            registry_digest: active.registry_digest().into(),
            owned_cost_digest: Some(active.owned_cost_digest().into()),
            judge_model_digest: None,
            judge_rubric_digest: None,
            judge_template_digest: None,
            judge_config_digest: None,
            judge_endpoint_digest: None,
            judge_authorization_reference_digest: None,
        },
        planned_request_upper_bound: 1,
        reserved_candidate_credits: 1,
        reserved_judge_credits: 0,
        candidate_dispatches: 1,
        judge_dispatches: 0,
        unused_judge_credits: 0,
        accepted: 1,
        recorded: 1,
        dropped: 0,
        completed: 1,
        errors: 0,
        cancelled_outcomes: 0,
        next_sequence: 2,
        writer_healthy: true,
        writer_error: None,
        last_flush_at_ms: Some(900),
        outcomes_digest: None,
        quality_report_digest: None,
    }
}

fn eligible_overlay() -> QualityEvidenceOverlay {
    QualityEvidenceOverlay {
        overlay_key: digest('9'),
        candidate_supply_id: CANDIDATE_SUPPLY.into(),
        task_class: TaskClass::Mechanical,
        protocol: QualityProtocol::Chat,
        dataset_digest: DATASET_DIGEST.into(),
        evaluator_digest: EVALUATOR_DIGEST.into(),
        completed_at_ms: 900,
        valid_until_ms: 2_500,
        assessment: PromotionAssessment {
            completion_verdict: PromotionVerdict::Eligible,
            effective_verdict: PromotionVerdict::Eligible,
            stale: false,
            gates: PromotionGates {
                policy: GateResult::Pass,
                capacity: GateResult::Pass,
                evidence: GateResult::Pass,
                cost: GateResult::Pass,
                quality: GateResult::Pass,
            },
            blockers: Vec::new(),
            metrics: PromotionMetrics {
                dispatched_attempts: 1,
                candidate_capacity_errors: 0,
                candidate_error_rate: Some(0.0),
                successful_latencies: 1,
                p95_latency_ms: Some(10),
                quality_sample_count: 1,
                quality_pass_count: 1,
                observed_pass_rate: Some(1.0),
                wilson_lower_95: Some(1.0),
                optional_evaluator_errors: 0,
                candidate_cost_usd: Some(0.01),
                judge_cost_usd: Some(0.0),
            },
        },
    }
}

fn write_quality_bundle(
    root: &Path,
    workload_digest: &str,
    active: &ActiveRuntimeProvenance,
) -> (String, String, QualitySourceBinding) {
    let directory = root.join("quality/run-1");
    make_private_directory(&root.join("quality"));
    make_private_directory(&directory);
    let outcome = quality_outcome();
    let outcomes_digest = canonical_outcomes_digest(std::slice::from_ref(&outcome)).unwrap();
    let mut manifest = quality_manifest(active);
    let report_v1 = QualityReport::new(
        &manifest,
        vec![eligible_overlay()],
        900,
        false,
        false,
        outcomes_digest.clone(),
    )
    .unwrap();
    let report = QualityReportV2::from_v1(report_v1, workload_digest.into()).unwrap();
    let report_digest = quality_report_v2_digest(&report).unwrap();
    manifest.outcomes_digest = Some(outcomes_digest);
    manifest.quality_report_digest = Some(report_digest.clone());
    let canonical_manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    write_private(&directory.join("manifest.json"), &manifest_bytes);
    write_quality_report_v2(&directory, &report).unwrap();

    let payload = serde_json::to_vec(&outcome).unwrap();
    let mut ledger = b"BWQ1\n".to_vec();
    ledger.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    ledger.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    ledger.extend_from_slice(&payload);
    write_private(&directory.join("outcomes.bwq"), &ledger);
    let source = QualityPromotionSource {
        schema_version: 2,
        run_id: QUALITY_RUN_ID.into(),
        completed_at_ms: 900,
        valid_until_ms: 2_500,
        workload_identity_digest: workload_digest.into(),
        task_class: TaskClass::Mechanical,
        protocol: AuthorityProtocol::ChatCompletions,
        candidate_supply_id: CANDIDATE_SUPPLY.into(),
        effective_verdict: PromotionVerdict::Eligible,
        manifest_digest: canonical_digest(
            b"bowline.economics.quality-manifest.v1",
            &canonical_manifest_bytes,
        ),
        outcomes_digest: report.outcomes_digest.clone(),
        report_digest: report_digest.clone(),
        manifest_valid: true,
        outcomes_valid: true,
        report_valid: true,
        policy_digest: active.policy_digest().into(),
        registry_digest: active.registry_digest().into(),
        owned_cost_digest: active.owned_cost_digest().into(),
    };
    let source_digest = unframed_domain_digest(
        b"bowline.enforcement.quality-source.v1",
        &serde_json::to_vec(&source).unwrap(),
    );
    let manifest_digest = source.manifest_digest.clone();
    let projection_digest = canonical_quality_projection_digest(&[QualityJoinEvidence {
        run_id: QUALITY_RUN_ID.into(),
        schema_version: 2,
        completed_at_ms: 900,
        valid_until_ms: 2_500,
        workload_identity_digest: Some(workload_digest.into()),
        task_class: TaskClass::Mechanical,
        protocol: ProtocolKind::ChatCompletions,
        candidate_supply_id: CANDIDATE_SUPPLY.into(),
        effective_verdict: PromotionVerdict::Eligible,
        manifest_valid: true,
        outcomes_digest_valid: true,
        report_digest_valid: true,
    }])
    .unwrap();
    let binding = QualitySourceBinding {
        run_id: QUALITY_RUN_ID.into(),
        schema_version: 2,
        manifest_digest: manifest_digest.clone(),
        recomputed_manifest_digest: manifest_digest,
        outcomes_digest: source.outcomes_digest.clone(),
        recomputed_outcomes_digest: source.outcomes_digest.clone(),
        report_digest: report_digest.clone(),
        recomputed_report_digest: report_digest.clone(),
        registry_digest: active.registry_digest().into(),
        owned_cost_digest: active.owned_cost_digest().into(),
        policy_digest: active.policy_digest().into(),
        join_projection_digest: projection_digest,
    };
    (report_digest, source_digest, binding)
}

fn selected_evidence(quality: QualitySourceBinding) -> SelectedEvidence {
    SelectedEvidence {
        traffic: SelectedTrafficEvidence {
            run_id: "traffic-1".into(),
            records_digest: digest('a'),
            manifest_digest: digest('b'),
            recovery_digest: digest('c'),
        },
        billing: Some(SelectedBillingEvidence {
            run_id: "billing-1".into(),
            rows_digest: digest('d'),
            manifest_digest: digest('e'),
            recovery_digest: digest('f'),
        }),
        quality: vec![quality],
    }
}

fn matched(source: &str, field: &str, expected: String) -> SourceBindingCheck {
    SourceBindingCheck {
        source: source.into(),
        field: field.into(),
        kind: "checksum".into(),
        observed: Some(expected.clone()),
        expected: Some(expected),
        matched: true,
    }
}

fn exact_source_bindings(selected: &SelectedEvidence) -> Vec<SourceBindingCheck> {
    let provenance = selected.quality.first().unwrap();
    let mut checks = vec![
        matched("analysis", "analysis-manifest", ANALYSIS_DIGEST.into()),
        matched(
            "traffic",
            "selected-records",
            selected.traffic.records_digest.clone(),
        ),
        matched(
            "traffic",
            "manifest",
            selected.traffic.manifest_digest.clone(),
        ),
        matched(
            "traffic",
            "recovery",
            selected.traffic.recovery_digest.clone(),
        ),
        matched("traffic", "manifest-recovery", digest('0')),
        matched("config", "configuration", CONFIG_DIGEST.into()),
        matched("traffic", "registry", provenance.registry_digest.clone()),
    ];
    let billing = selected.billing.as_ref().unwrap();
    checks.extend([
        matched("billing", "normalized-rows", billing.rows_digest.clone()),
        matched("billing", "manifest", billing.manifest_digest.clone()),
        matched("billing", "recovery", billing.recovery_digest.clone()),
        matched("billing", "manifest-recovery", digest('1')),
        matched("billing", "registry", provenance.registry_digest.clone()),
        matched(
            "traffic",
            "owned-cost",
            provenance.owned_cost_digest.clone(),
        ),
        matched("traffic", "policy", provenance.policy_digest.clone()),
    ]);
    for quality in &selected.quality {
        checks.extend([
            matched(&quality.run_id, "manifest", quality.manifest_digest.clone()),
            matched(&quality.run_id, "registry", quality.registry_digest.clone()),
            matched(
                &quality.run_id,
                "report-registry",
                quality.registry_digest.clone(),
            ),
            matched(
                &quality.run_id,
                "owned-cost",
                quality.owned_cost_digest.clone(),
            ),
            matched(
                &quality.run_id,
                "report-owned-cost",
                quality.owned_cost_digest.clone(),
            ),
            matched(&quality.run_id, "policy", quality.policy_digest.clone()),
            matched(
                &quality.run_id,
                "report-policy",
                quality.policy_digest.clone(),
            ),
            matched(&quality.run_id, "outcomes", quality.outcomes_digest.clone()),
            matched(
                &quality.run_id,
                "report-outcomes",
                quality.outcomes_digest.clone(),
            ),
            matched(
                &quality.run_id,
                "report-source",
                quality.report_digest.clone(),
            ),
            matched(
                &quality.run_id,
                "report-document",
                quality.report_digest.clone(),
            ),
            matched(
                &quality.run_id,
                "join-projection",
                quality.join_projection_digest.clone(),
            ),
        ]);
    }
    checks
}

fn opportunity(workload_digest: &str) -> OpportunityRow {
    OpportunityRow {
        key: OpportunityKey {
            app: "support".into(),
            team: "team".into(),
            environment: "production".into(),
            cost_center: "cost".into(),
            general_tags: vec!["customer-facing".into(), "production".into()],
            task_class: TaskClass::Mechanical,
            protocol: ProtocolKind::ChatCompletions,
            actual_supply_id: ACTUAL_SUPPLY.into(),
            candidate_supply_id: CANDIDATE_SUPPLY.into(),
        },
        workload_identity_digest: workload_digest.into(),
        record_count: 1,
        input_tokens: Some(10),
        output_tokens: Some(5),
        actual_cost_micros: Some(100),
        candidate_cost_micros: Some(10),
        actual_rate_micros: Some(bowline_core::economics::CostRateMicros {
            input_per_mtok_micros: 10_000_000,
            output_per_mtok_micros: 0,
        }),
        candidate_rate_micros: Some(bowline_core::economics::CostRateMicros {
            input_per_mtok_micros: 1_000_000,
            output_per_mtok_micros: 0,
        }),
        observed_delta_micros: Some(90),
        annualized_delta_micros: Some(900),
        compliant_records: 1,
        violation_records: 0,
        unknown_policy_records: 0,
        policy_violation_reason: None,
        quality: Some(QualityEvidenceSummary {
            run_id: QUALITY_RUN_ID.into(),
            verdict: PromotionVerdict::Eligible,
            completed_at_ms: 900,
            age_ms: 100,
        }),
        reconciliation_state: ReconciliationState::Qualified,
        eligible: true,
        status: "eligible".into(),
        blockers: Vec::new(),
    }
}

fn economics_report(
    selected_evidence: SelectedEvidence,
    opportunity: OpportunityRow,
) -> ActionableEconomicsReport {
    ActionableEconomicsReport {
        schema_version: 1,
        mode: AnalysisMode::BillingReconciled,
        as_of_ms: 1_000,
        window_start_ms: 100,
        window_end_ms: 900,
        complete: true,
        build_provenance: BuildProvenance {
            package_version: "fixture".into(),
            source_revision: "unavailable".into(),
        },
        global_blockers: Vec::new(),
        source_bindings: exact_source_bindings(&selected_evidence),
        selected_evidence,
        reconciliation: serde_json::from_value(json!({
            "state":"qualified","eligible_records":1,"matched_records":1,"unmatched_records":0,
            "total_provider_rows":1,"matched_provider_rows":1,"unmatched_provider_rows":0,
            "qualified_provider_rows":1,"total_imported_charge_micros":100,
            "matched_imported_charge_micros":100,"qualified_imported_charge_micros":100,
            "modeled_actual_cost_micros":100,"record_coverage_ppm":1000000,
            "row_presence_charge_coverage_ppm":1000000,"qualified_charge_coverage_ppm":1000000,
            "charge_variance_micros":0,"charge_variance_ppm":0,"request_delta":0,
            "input_token_delta":0,"output_token_delta":0,"request_count_available_rows":1,
            "request_count_total_rows":1,"input_token_available_rows":1,"input_token_total_rows":1,
            "output_token_available_rows":1,"output_token_total_rows":1,"rows":[],"exceptions":[]
        }))
        .unwrap(),
        dimensions: Vec::new(),
        opportunities: vec![opportunity],
    }
}

fn authority_yaml(
    economics_report_digest: &str,
    opportunity_digest: &str,
    quality_report_digest: &str,
) -> String {
    format!(
        r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {{trust_root: /tmp/kill, relative_path: state}}
actuators:
  - supply_id: {CANDIDATE_SUPPLY}
    base_url: https://inference.example.test/v1
    authorization_env: BOWLINE_TOKEN
    health_path: /models
    remote_acknowledged: true
    connect_timeout_ms: 1000
    response_header_timeout_ms: 1000
    stream_idle_timeout_ms: 1000
    concurrency: 1
    breaker_consecutive_failures: 1
    breaker_cooldown_ms: 1000
    probe_timeout_ms: 1000
    probe_max_bytes: 1024
routes:
  - route_id: {ROUTE_ID}
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    workload: {{app: support, resolved_tags: [customer-facing, production]}}
    mode: enforce
    rollout_ppm: 0
    promoted_supply_id: {CANDIDATE_SUPPLY}
    actual_supply_id: {ACTUAL_SUPPLY}
    task_class: mechanical
    model_authority: rewrite-to-canonical
    fallback: bypass
    promotion:
      economics_bundle_path: economics
      economics_report_digest: {economics_report_digest}
      opportunity_digest: {opportunity_digest}
      quality_run_path: quality/run-1
      authorization_path: authorization/support-chat.json
      quality_run_id: {QUALITY_RUN_ID}
      quality_report_digest: {quality_report_digest}
      policy_digest: {POLICY_DIGEST}
      registry_digest: {REGISTRY_DIGEST}
      owned_cost_digest: {OWNED_COST_DIGEST}
      max_economics_age_ms: 1000
      expires_at_ms: 3000
"#
    )
}

#[test]
fn promotion_authorization_publication_is_exclusive_private_and_verified() {
    let fixture = PositiveFixture::create_unsealed();
    make_private_directory(&fixture.root.join("authorization"));
    let active = fixture.active_runtime_provenance();

    let sealed = seal_promotion_authorization_for_route(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &active,
        NOW_MS,
    )
    .unwrap();
    let sidecar = fixture.root.join("authorization/support-chat.json");
    let metadata = fs::symlink_metadata(&sidecar).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::read(&sidecar).unwrap(),
        [serde_json::to_vec(&sealed).unwrap(), b"\n".to_vec()].concat()
    );
    assert!(seal_promotion_authorization_for_route(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &active,
        NOW_MS,
    )
    .is_err());
    let grant = load_verified_promotion_grant_with_active(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &active,
        NOW_MS,
    )
    .unwrap();
    assert_eq!(grant.route_id(), ROUTE_ID);
}

#[test]
fn unchanged_sidecar_rejects_authorization_env_and_existing_alternate_source_paths() {
    let fixture = PositiveFixture::create();
    copy_private_directory(
        &fixture.root.join("economics"),
        &fixture.root.join("economics-other"),
    );
    copy_private_directory(
        &fixture.root.join("quality/run-1"),
        &fixture.root.join("quality/run-other"),
    );

    let mutations = [
        fixture.enforcement_source().replace(
            "authorization_env: BOWLINE_TOKEN",
            "authorization_env: BOWLINE_OTHER_AUTH_TOKEN",
        ),
        fixture.enforcement_source().replace(
            "economics_bundle_path: economics",
            "economics_bundle_path: economics-other",
        ),
        fixture.enforcement_source().replace(
            "quality_run_path: quality/run-1",
            "quality_run_path: quality/run-other",
        ),
    ];
    for source in mutations {
        let changed = EnforcementConfigV1::from_yaml(&source)
            .unwrap()
            .validate()
            .unwrap();
        assert!(load_verified_promotion_grant_with_active(
            &changed,
            ROUTE_ID,
            &fixture.root,
            &fixture.active,
            NOW_MS,
        )
        .is_err());
    }
}

#[test]
fn unicode_punctuation_route_identifier_seals_and_loads_from_private_evidence() {
    let mut fixture = PositiveFixture::create_unsealed();
    let route_id = "routé:α/v1!";
    let source = fixture
        .enforcement_source()
        .replace("route_id: support-chat", &format!("route_id: {route_id}"));
    fixture.validated = EnforcementConfigV1::from_yaml(&source)
        .unwrap()
        .validate()
        .unwrap();
    make_private_directory(&fixture.root.join("authorization"));

    seal_promotion_authorization_for_route(
        &fixture.validated,
        route_id,
        &fixture.root,
        &fixture.active,
        NOW_MS,
    )
    .unwrap();
    let grant = load_verified_promotion_grant_with_active(
        &fixture.validated,
        route_id,
        &fixture.root,
        &fixture.active,
        NOW_MS,
    )
    .unwrap();
    assert_eq!(grant.route_id(), route_id);
}

#[test]
fn promotion_authorization_rejects_unsafe_tampered_and_oversize_sidecars() {
    for mutation in ["unknown", "self-digest", "oversize", "symlink"] {
        let fixture = PositiveFixture::create();
        let sidecar = fixture.root.join("authorization/support-chat.json");
        match mutation {
            "unknown" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
                value["unexpected"] = json!(true);
                write_json(&sidecar, &value);
            }
            "self-digest" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
                value["authorization_digest"] = json!(digest('9'));
                write_json(&sidecar, &value);
            }
            "oversize" => write_private(&sidecar, &vec![b' '; 64 * 1024 + 1]),
            "symlink" => {
                fs::remove_file(&sidecar).unwrap();
                let replacement = fixture.root.join("replacement.json");
                write_private(&replacement, b"{}\n");
                symlink(replacement, sidecar).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS,)
                .is_err(),
            "accepted {mutation} authorization"
        );
    }
}

#[test]
fn promotion_authorization_rejects_each_active_provenance_mutation() {
    let fixture = PositiveFixture::create();
    let changed_policy = PolicyBundle::from_yaml(
        "version: 1\nidentities: []\nrules:\n  - name: changed\n    default: true\n",
    )
    .unwrap();
    let default_costs = OwnedCostCatalog::default();
    let policy_active =
        ActiveRuntimeProvenance::from_loaded(&changed_policy, TEST_REGISTRY_SOURCE, &default_costs);
    let policy = PolicyBundle::from_yaml(TEST_POLICY_SOURCE).unwrap();
    let registry_active = ActiveRuntimeProvenance::from_loaded(
        &policy,
        &serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(TEST_REGISTRY_SOURCE).unwrap(),
        )
        .unwrap(),
        &default_costs,
    );
    let owned_registry = Registry::from_json(TEST_REGISTRY_SOURCE).unwrap();
    let changed_costs = load_owned_cost_catalog(
        Some(
            r#"{"version":2,"supplies":{"owned/llama":{"monthly_amortization_usd":1.0,"monthly_power_usd":0.0,"monthly_ops_usd":0.0,"monthly_capacity_mtok":1.0}}}"#,
        ),
        Some("public/openai"),
        &owned_registry,
    )
    .unwrap();
    let costs_active =
        ActiveRuntimeProvenance::from_loaded(&policy, TEST_REGISTRY_SOURCE, &changed_costs);

    for (name, active) in [
        ("policy", policy_active),
        ("registry-source-bytes", registry_active),
        ("owned-costs", costs_active),
    ] {
        assert!(
            load_verified_promotion_grant_with_active(
                &fixture.validated,
                ROUTE_ID,
                &fixture.root,
                &active,
                NOW_MS,
            )
            .is_err(),
            "accepted changed {name}"
        );
    }
}

#[tokio::test]
async fn startup_paths_reject_each_sealed_provenance_mutation_before_probe_or_bind() {
    for path in ["normal-deps", "managed-with-provenance", "preflight"] {
        for mutation in ["policy", "registry-source-bytes", "owned-costs"] {
            let fixture = PositiveFixture::create();
            let enforcement_path = fixture.root.join("enforcement.yaml");
            write_private(&enforcement_path, fixture.enforcement_source().as_bytes());
            let policy = match mutation {
                "policy" => PolicyBundle::from_yaml(
                    "version: 1\nidentities: []\nrules:\n  - name: changed\n    default: true\n",
                )
                .unwrap(),
                _ => PolicyBundle::from_yaml(TEST_POLICY_SOURCE).unwrap(),
            };
            let registry_source = if mutation == "registry-source-bytes" {
                serde_json::to_string_pretty(
                    &serde_json::from_str::<serde_json::Value>(TEST_REGISTRY_SOURCE).unwrap(),
                )
                .unwrap()
            } else {
                TEST_REGISTRY_SOURCE.to_owned()
            };
            let registry = Registry::from_json(&registry_source).unwrap();
            let owned_costs = if mutation == "owned-costs" {
                load_owned_cost_catalog(
                    Some(
                        r#"{"version":2,"supplies":{"owned/llama":{"monthly_amortization_usd":1.0,"monthly_power_usd":0.0,"monthly_ops_usd":0.0,"monthly_capacity_mtok":1.0}}}"#,
                    ),
                    Some(ACTUAL_SUPPLY),
                    &registry,
                )
                .unwrap()
            } else {
                OwnedCostCatalog::default()
            };
            let policy_path = fixture.root.join("policy.yaml");
            let registry_path = fixture.root.join("registry.json");
            fs::write(
                &policy_path,
                if mutation == "policy" {
                    "version: 1\nidentities: []\nrules:\n  - name: changed\n    default: true\n"
                } else {
                    TEST_POLICY_SOURCE
                },
            )
            .unwrap();
            fs::write(&registry_path, &registry_source).unwrap();
            let tco_path = (mutation == "owned-costs").then(|| {
                let path = fixture.root.join("tco.json");
                fs::write(
                    &path,
                    r#"{"version":2,"supplies":{"owned/llama":{"monthly_amortization_usd":1.0,"monthly_power_usd":0.0,"monthly_ops_usd":0.0,"monthly_capacity_mtok":1.0}}}"#,
                )
                .unwrap();
                path
            });
            let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let listen = occupied.local_addr().unwrap().to_string();
            let ledger_dir = fixture.root.join(format!("ledger-{path}-{mutation}"));
            let config = Config {
                listen,
                upstream: "http://127.0.0.1:9".into(),
                actual_supply_id: ACTUAL_SUPPLY.into(),
                policy_bundle: policy_path,
                registry_feed: registry_path,
                local_endpoints: Vec::new(),
                ledger_dir: ledger_dir.clone(),
                tco: tco_path,
                attribution: None,
                floors: None,
                enforcement: Some(enforcement_path),
                authority_signing: None,
                promotion_approval: None,
                state_backend: None,
                trusted_proxy_cidrs: Vec::new(),
                runtime: RuntimeConfig::default(),
            };

            let error = if path == "normal-deps" {
                serve_with_shutdown(config, GatewayDeps::default(), async {})
                    .await
                    .unwrap_err()
            } else if path == "managed-with-provenance" {
                let writer = spawn_managed_writer(ManagedWriterOptions {
                    directory: ledger_dir.join("managed"),
                    policy_digest: policy.digest().to_owned(),
                    registry_digest: "test-only".into(),
                    attribution_digest: None,
                    owned_cost_digest: Some(owned_costs.normalized_digest().to_owned()),
                    passive_profile_digest: None,
                    passive_input_digest: None,
                    segment_bytes: 64 * 1024,
                    max_segments: 2,
                    queue_capacity: 8,
                })
                .unwrap();
                let deps = GatewayDeps::managed_with_provenance(
                    policy,
                    &registry_source,
                    Default::default(),
                    owned_costs,
                    writer.clone(),
                )
                .unwrap();
                let error = serve_with_shutdown(config, deps, async {})
                    .await
                    .unwrap_err();
                writer
                    .shutdown(std::time::Duration::from_secs(1))
                    .await
                    .unwrap();
                error
            } else {
                let config_path = fixture.root.join(format!("preflight-{mutation}.yaml"));
                let tco_line = config
                    .tco
                    .as_ref()
                    .map(|value| format!("tco: {}\n", value.display()))
                    .unwrap_or_default();
                fs::write(
                    &config_path,
                    format!(
                        "listen: {}\nupstream: {}\nactual_supply_id: {}\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n{}enforcement: {}\n",
                        config.listen,
                        config.upstream,
                        config.actual_supply_id,
                        config.policy_bundle.display(),
                        config.registry_feed.display(),
                        config.ledger_dir.display(),
                        tco_line,
                        config.enforcement.as_ref().unwrap().display(),
                    ),
                )
                .unwrap();
                let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .ancestors()
                    .nth(2)
                    .unwrap();
                let output = std::process::Command::new(env!("CARGO"))
                    .current_dir(workspace)
                    .args([
                        "run",
                        "--quiet",
                        "-p",
                        "bowline",
                        "--",
                        "preflight",
                        "--config",
                        config_path.to_str().unwrap(),
                        "--json",
                    ])
                    .env_remove("BOWLINE_TOKEN")
                    .output()
                    .unwrap();
                assert!(!output.status.success(), "preflight accepted {mutation}");
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    !stdout.contains("enforcement-actuator-probe"),
                    "preflight probed an actuator before refusing {mutation}: {stdout}"
                );
                anyhow::anyhow!(stdout.into_owned())
            };
            let message = format!("{error:#}");
            assert!(
                message.contains("active provenance mismatch")
                    || message.contains(
                        "sealed authorization does not match active evidence and configuration",
                    ),
                "{path}/{mutation} reached probe or bind instead of refusing the sidecar: {error:#}"
            );
        }
    }
}

fn recommendation_yaml(
    economics_report_digest: &str,
    opportunity_digest: &str,
    quality_report_digest: &str,
) -> String {
    authority_yaml(
        economics_report_digest,
        opportunity_digest,
        quality_report_digest,
    )
    .replace("mode: enforce", "mode: recommend")
    .replace("    model_authority: rewrite-to-canonical\n", "")
}

fn recommendation_config(
    fixture: &PositiveFixture,
) -> bowline_core::enforcement::ValidatedEnforcement {
    let requirement = fixture
        .validated
        .route(ROUTE_ID)
        .unwrap()
        .promotion
        .as_ref()
        .unwrap();
    let validated = EnforcementConfigV1::from_yaml(&with_active_provenance(
        recommendation_yaml(
            &requirement.economics_report_digest,
            &requirement.opportunity_digest,
            &requirement.quality_report_digest,
        ),
        &fixture.active,
    ))
    .unwrap()
    .validate()
    .unwrap();
    reseal_authorization(fixture, &validated, 1_000);
    validated
}

fn reseal_authorization(
    fixture: &PositiveFixture,
    validated: &bowline_core::enforcement::ValidatedEnforcement,
    created_at_ms: u64,
) {
    let sidecar = fixture.root.join("authorization/support-chat.json");
    if sidecar.exists() {
        fs::remove_file(sidecar).unwrap();
    } else {
        make_private_directory(&fixture.root.join("authorization"));
    }
    seal_promotion_authorization_for_route(
        validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        created_at_ms,
    )
    .unwrap();
}

fn with_active_provenance(source: String, active: &ActiveRuntimeProvenance) -> String {
    source
        .replace(POLICY_DIGEST, active.policy_digest())
        .replace(REGISTRY_DIGEST, active.registry_digest())
        .replace(OWNED_COST_DIGEST, active.owned_cost_digest())
}

fn write_economics_bundle(root: &Path, report: &ActionableEconomicsReport) -> (String, String) {
    let directory = root.join("economics");
    make_private_directory(&directory);
    let report_bytes = serde_json::to_vec(report).unwrap();
    let mut payloads = BTreeMap::from([
        ("dimensions.csv", b"dimension\n".to_vec()),
        ("opportunities.csv", b"opportunity\n".to_vec()),
        ("reconciliation.csv", b"reconciliation\n".to_vec()),
        ("report.html", b"<html>fixture</html>\n".to_vec()),
        ("report.json", report_bytes),
        ("report.md", b"# fixture\n".to_vec()),
    ]);
    for (name, bytes) in &payloads {
        write_private(&directory.join(name), bytes);
    }
    let artifacts = payloads
        .iter_mut()
        .map(|(name, bytes)| {
            json!({"name":name,"size_bytes":bytes.len(),"sha256":plain_digest(bytes)})
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "schema_version":1,
        "package_version":"fixture",
        "source_revision":"unavailable",
        "analysis_digest":ANALYSIS_DIGEST,
        "config_digest":CONFIG_DIGEST,
        "source_bindings_digest":plain_digest(&serde_json::to_vec(&report.source_bindings).unwrap()),
        "selected_evidence":report.selected_evidence,
        "artifacts":artifacts
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    write_private(&directory.join("manifest.json"), &manifest_bytes);
    (
        plain_digest(&payloads["report.json"]),
        domain_digest(b"bowline.economics.bundle.v1", &manifest_bytes),
    )
}

impl PositiveFixture {
    fn create() -> Self {
        let fixture = Self::create_unsealed();
        make_private_directory(&fixture.root.join("authorization"));
        seal_promotion_authorization_for_route(
            &fixture.validated,
            ROUTE_ID,
            &fixture.root,
            &fixture.active,
            1_000,
        )
        .unwrap();
        fixture
    }

    fn create_unsealed() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let active = test_active_runtime_provenance();
        let provisional = EnforcementConfigV1::from_yaml(&with_active_provenance(
            authority_yaml(&digest('a'), &digest('b'), &digest('c')),
            &active,
        ))
        .unwrap()
        .validate()
        .unwrap();
        let route = provisional.route(ROUTE_ID).unwrap();
        let workload_digest = route_workload_digest(
            AuthorityProtocol::ChatCompletions,
            route.workload.as_ref().unwrap(),
        )
        .unwrap();
        let (quality_report_digest, quality_source_digest, quality_binding) =
            write_quality_bundle(&root, &workload_digest, &active);
        let opportunity = opportunity(&workload_digest);
        let opportunity_digest = economics_opportunity_digest(&opportunity).unwrap();
        let report = economics_report(selected_evidence(quality_binding), opportunity);
        let (economics_report_digest, economics_bundle_digest) =
            write_economics_bundle(&root, &report);
        let validated = EnforcementConfigV1::from_yaml(&with_active_provenance(
            authority_yaml(
                &economics_report_digest,
                &opportunity_digest,
                &quality_report_digest,
            ),
            &active,
        ))
        .unwrap()
        .validate()
        .unwrap();
        Self {
            _temp: temp,
            root,
            validated,
            workload_digest,
            economics_bundle_digest,
            quality_report_digest,
            quality_source_digest,
            active,
        }
    }

    fn active_runtime_provenance(&self) -> ActiveRuntimeProvenance {
        self.active.clone()
    }

    fn enforcement_source(&self) -> String {
        let promotion = self
            .validated
            .route(ROUTE_ID)
            .unwrap()
            .promotion
            .as_ref()
            .unwrap();
        with_active_provenance(
            authority_yaml(
                &promotion.economics_report_digest,
                &promotion.opportunity_digest,
                &promotion.quality_report_digest,
            ),
            &self.active,
        )
    }

    fn replace_config(&mut self, economics_report_digest: &str, opportunity_digest: &str) {
        self.replace_config_with_timing(economics_report_digest, opportunity_digest, 1_000, 3_000);
    }

    fn replace_config_with_timing(
        &mut self,
        economics_report_digest: &str,
        opportunity_digest: &str,
        max_economics_age_ms: u64,
        expires_at_ms: u64,
    ) {
        let source = with_active_provenance(
            authority_yaml(
                economics_report_digest,
                opportunity_digest,
                &self.quality_report_digest,
            ),
            &self.active,
        )
        .replace(
            "max_economics_age_ms: 1000",
            &format!("max_economics_age_ms: {max_economics_age_ms}"),
        )
        .replace(
            "expires_at_ms: 3000",
            &format!("expires_at_ms: {expires_at_ms}"),
        );
        self.validated = EnforcementConfigV1::from_yaml(&source)
            .unwrap()
            .validate()
            .unwrap();
    }

    fn economics_report(&self) -> ActionableEconomicsReport {
        serde_json::from_slice(&fs::read(self.root.join("economics/report.json")).unwrap()).unwrap()
    }

    fn replace_economics_report(&mut self, report: &ActionableEconomicsReport) {
        let opportunity_digest = economics_opportunity_digest(&report.opportunities[0]).unwrap();
        let (report_digest, bundle_digest) = write_economics_bundle(&self.root, report);
        self.economics_bundle_digest = bundle_digest;
        self.replace_config(&report_digest, &opportunity_digest);
    }

    fn replace_current_timing(&mut self, max_economics_age_ms: u64, expires_at_ms: u64) {
        let report = self.economics_report();
        let report_digest =
            plain_digest(&fs::read(self.root.join("economics/report.json")).unwrap());
        let opportunity_digest = economics_opportunity_digest(&report.opportunities[0]).unwrap();
        self.replace_config_with_timing(
            &report_digest,
            &opportunity_digest,
            max_economics_age_ms,
            expires_at_ms,
        );
    }
}

#[test]
fn enforcement_loader_rejects_parent_paths() {
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        read_private_bundle_file(temp.path(), "../manifest.json", 1024),
        Err(EnforcementLoadError::UnsafePath)
    ));
}

#[test]
fn enforcement_loader_requires_euid_owned_exact_private_tree_modes() {
    for target in [
        "root",
        "economics-dir",
        "quality-parent",
        "quality-run",
        "file",
    ] {
        let fixture = PositiveFixture::create();
        let path = match target {
            "root" => fixture.root.clone(),
            "economics-dir" => fixture.root.join("economics"),
            "quality-parent" => fixture.root.join("quality"),
            "quality-run" => fixture.root.join("quality/run-1"),
            "file" => fixture.root.join("economics/manifest.json"),
            _ => unreachable!(),
        };
        let modes: &[u32] = if target == "file" {
            &[0o400, 0o602, 0o620, 0o640, 0o604, 0o644, 0o660, 0o666]
        } else {
            &[
                0o500, 0o702, 0o720, 0o704, 0o740, 0o750, 0o755, 0o770, 0o777,
            ]
        };
        for mode in modes {
            fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
            assert!(
                load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                    .is_err(),
                "accepted {target} mode {mode:o}"
            );
        }
    }
}

#[test]
fn enforcement_loader_rejects_symlink_ancestor_root_descendant_and_final() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let real = base.join("real");
    let root = real.join("evidence");
    let child = root.join("child");
    make_private_directory(&real);
    make_private_directory(&root);
    make_private_directory(&child);
    write_private(&child.join("value"), b"trusted");

    symlink(&real, base.join("ancestor-link")).unwrap();
    assert!(
        read_private_bundle_file(&base.join("ancestor-link/evidence"), "child/value", 16).is_err()
    );
    symlink(&root, base.join("root-link")).unwrap();
    assert!(read_private_bundle_file(&base.join("root-link"), "child/value", 16).is_err());
    symlink(&child, root.join("child-link")).unwrap();
    assert!(read_private_bundle_file(&root, "child-link/value", 16).is_err());
    symlink(child.join("value"), root.join("final-link")).unwrap();
    assert!(read_private_bundle_file(&root, "final-link", 16).is_err());
}

#[test]
fn enforcement_loader_requires_complete_bounded_sources() {
    let temp = tempfile::tempdir().unwrap();
    let config = EnforcementConfigV1::from_yaml(
        r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {trust_root: /tmp/kill, relative_path: state}
actuators: []
routes: []
"#,
    )
    .unwrap()
    .validate()
    .unwrap();
    assert!(load_verified_promotion_grant(&config, "missing", temp.path(), 1).is_err());
}

#[test]
fn enforcement_loader_builds_exact_grant_from_complete_on_disk_sources() {
    let fixture = PositiveFixture::create();
    let grant =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    assert_eq!(grant.route_id(), ROUTE_ID);
    assert_eq!(grant.workload_identity_digest(), fixture.workload_digest);
    assert_eq!(grant.task_class(), TaskClass::Mechanical);
    assert_eq!(grant.protocol(), AuthorityProtocol::ChatCompletions);
    assert_eq!(grant.actual_supply_id(), ACTUAL_SUPPLY);
    assert_eq!(grant.candidate_supply_id(), CANDIDATE_SUPPLY);
    assert_eq!(
        grant.economics_source_digest(),
        fixture.economics_bundle_digest
    );
    assert_eq!(grant.config_digest(), fixture.validated.normalized_digest());
    assert_eq!(
        grant.actuator_digest(),
        fixture.validated.actuator_digest(CANDIDATE_SUPPLY).unwrap()
    );
    assert_eq!(
        grant.route_digest(),
        fixture.validated.route_digest(ROUTE_ID).unwrap()
    );
    assert_eq!(grant.expires_at_ms(), 2_000);
    assert_eq!(grant.not_before_ms(), 1_000);
    assert!(!grant.is_fresh_at(0));
    assert!(!grant.is_fresh_at(899));
    assert!(!grant.is_fresh_at(999));
    assert!(grant.is_fresh_at(1_000));
    assert!(grant.is_fresh_at(2_000));
    assert!(!grant.is_fresh_at(2_001));
    let serialized = serde_json::to_value(&grant).unwrap();
    assert_eq!(serialized["validation"]["not_before_ms"], json!(1_000));
    assert_eq!(serialized["validation"]["expires_at_ms"], json!(2_000));
    assert_eq!(grant.validation_digest().len(), 71);
    assert_eq!(grant.quality_source_digest(), fixture.quality_source_digest);
    assert_eq!(
        grant.grant_digest(),
        domain_digest(
            b"bowline.enforcement.verified-promotion-grant.v1",
            grant.validation_digest().as_bytes()
        )
    );
}

fn selection_facts(
    validated: &bowline_core::enforcement::ValidatedEnforcement,
    workload_digest: &str,
) -> SelectionRequestFacts {
    let route = validated.route(ROUTE_ID).unwrap();
    let workload = route.workload.as_ref().unwrap();
    SelectionRequestFacts {
        method: route.method.clone(),
        path: route.path.clone(),
        protocol: route.protocol,
        identity_trusted: true,
        authority_metadata_valid: true,
        shape_supported: true,
        task_class: route.task_class.unwrap_or(TaskClass::Unclassified),
        app: Some(workload.app.clone()),
        resolved_tags: workload.resolved_tags.clone(),
        workload_identity_digest: Some(workload_digest.into()),
        request_body_digest: [7; 32],
        requested_supply_id: Some(ACTUAL_SUPPLY.into()),
        kill: KillReadResult::Armed,
        now_ms: NOW_MS,
        candidate_availability: CandidateAvailability::Available,
        actuator_available: true,
    }
}

#[tokio::test]
async fn gateway_selection_requires_exact_opaque_grant_and_validated_context() {
    let fixture = PositiveFixture::create();
    let grant =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let exact = select_enforcement_target(
        &fixture.validated,
        ROUTE_ID,
        &selection_facts(&fixture.validated, &fixture.workload_digest),
        &grant,
    )
    .unwrap();
    assert_eq!(exact.target(), PlanTarget::Candidate);
    assert_eq!(exact.evidence_state(), GatewayEvidenceState::Verified);
    let kill_root = fixture.root.join("preparation-kill");
    make_private_directory(&kill_root);
    write_private(&kill_root.join("state"), b"armed\n");
    let kill_reader =
        BoundedKillStateReader::new(KillStateReader::open(&kill_root, "state").unwrap(), 1);
    let prepare_grant =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let prepared = prepare_candidate_authority_decision_v2(
        &fixture.validated,
        exact,
        prepare_grant,
        "authority-decision".into(),
        &kill_reader,
    )
    .await
    .expect("opaque grant prepares authority decision");
    let CandidatePreparationV2::Fallback(prepared) = prepared else {
        panic!("trusted current time must make the historical fixture stale")
    };
    assert_eq!(prepared.decision().reason, SelectionReason::GrantStale);
    assert!(!prepared.decision().grants_candidate_authority());

    let fabricated_core_cannot_enter_gateway = select_enforcement_target_without_grant(
        &fixture.validated,
        ROUTE_ID,
        &selection_facts(&fixture.validated, &fixture.workload_digest),
    )
    .unwrap();
    assert_ne!(
        fabricated_core_cannot_enter_gateway.target(),
        PlanTarget::Candidate
    );
    assert_eq!(
        fabricated_core_cannot_enter_gateway.evidence_state(),
        GatewayEvidenceState::Unverified
    );

    let requirement = fixture
        .validated
        .route(ROUTE_ID)
        .unwrap()
        .promotion
        .as_ref()
        .unwrap();
    let base = authority_yaml(
        &requirement.economics_report_digest,
        &requirement.opportunity_digest,
        &requirement.quality_report_digest,
    );
    let mutations = [
        (
            "path",
            base.replace("path: /v1/chat/completions", "path: /v1/responses"),
        ),
        (
            "rollout",
            base.replace(
                "mode: enforce\n    rollout_ppm: 0",
                "mode: canary-enforce\n    rollout_ppm: 1000000",
            ),
        ),
        (
            "workload",
            base.replace("app: support", "app: changed-support"),
        ),
        (
            "fallback",
            base.replace("fallback: bypass", "fallback: fail-closed"),
        ),
        (
            "model-authority",
            base.replace("rewrite-to-canonical", "preserve"),
        ),
        (
            "actuator",
            base.replace(
                "https://inference.example.test/v1",
                "https://other.example.test/v1",
            ),
        ),
        (
            "config",
            base.replace(
                "global_candidate_in_flight: 1",
                "global_candidate_in_flight: 2",
            ),
        ),
    ];
    let changed_route_method = base.replace("method: POST", "method: GET");
    assert!(
        EnforcementConfigV1::from_yaml(&changed_route_method)
            .unwrap()
            .validate()
            .is_err(),
        "a changed configured method must not enter the validated gateway boundary"
    );
    for (name, yaml) in mutations {
        let mutated = EnforcementConfigV1::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap();
        let result = select_enforcement_target(
            &mutated,
            ROUTE_ID,
            &selection_facts(&mutated, &fixture.workload_digest),
            &grant,
        )
        .unwrap();
        assert_ne!(result.target(), PlanTarget::Candidate, "{name}");
        assert_ne!(
            result.evidence_state(),
            GatewayEvidenceState::Verified,
            "{name}"
        );
        assert_eq!(result.reason(), SelectionReason::GrantMismatch, "{name}");
    }

    let mut wrong_method = selection_facts(&fixture.validated, &fixture.workload_digest);
    wrong_method.method = "GET".into();
    let result =
        select_enforcement_target(&fixture.validated, ROUTE_ID, &wrong_method, &grant).unwrap();
    assert_ne!(result.target(), PlanTarget::Candidate);
    assert_ne!(result.evidence_state(), GatewayEvidenceState::Verified);
    assert_eq!(result.reason(), SelectionReason::RouteMismatch);
}

#[tokio::test]
async fn candidate_preparation_rereads_kill_and_cannot_backdate_freshness() {
    let fixture = PositiveFixture::create();
    let selection_grant =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let plan = select_enforcement_target(
        &fixture.validated,
        ROUTE_ID,
        &selection_facts(&fixture.validated, &fixture.workload_digest),
        &selection_grant,
    )
    .unwrap();
    let prepare_grant =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let kill_root = fixture.root.join("changed-kill");
    make_private_directory(&kill_root);
    write_private(&kill_root.join("state"), b"bypass\n");
    let kill_reader =
        BoundedKillStateReader::new(KillStateReader::open(&kill_root, "state").unwrap(), 1);
    let result = prepare_candidate_authority_decision_v2(
        &fixture.validated,
        plan,
        prepare_grant,
        "changed-kill".into(),
        &kill_reader,
    )
    .await
    .unwrap();
    let CandidatePreparationV2::Fallback(prepared) = result else {
        panic!("changed kill state must remove candidate authority")
    };
    assert_eq!(prepared.decision().reason, SelectionReason::KillNotArmed);
    assert!(!prepared.decision().grants_candidate_authority());

    let source = include_str!("../src/observation.rs");
    assert!(!source.contains("plan: &GatewayEnforcementPlan"));
    assert!(!source.contains("grant: &VerifiedPromotionGrant"));
}

#[test]
fn enforcement_loader_rejects_wrong_selected_quality_digest() {
    let mut fixture = PositiveFixture::create();
    let mut report = fixture.economics_report();
    let wrong = digest('0');
    report.selected_evidence.quality[0].report_digest = wrong.clone();
    report.selected_evidence.quality[0].recomputed_report_digest = wrong;
    fixture.replace_economics_report(&report);

    let error = load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
        .unwrap_err();
    assert!(
        error.to_string().contains("quality binding")
            || error.to_string().contains("source binding matrix")
    );
}

#[test]
fn enforcement_loader_rejects_split_economics_to_quality_binding_forgery() {
    let mut fixture = PositiveFixture::create();
    let mut report = fixture.economics_report();
    let mut report_only = report.selected_evidence.quality[0].clone();
    report_only.run_id = "00000000-0000-0000-0000-000000000002".into();
    report.selected_evidence.quality[0].report_digest = digest('0');
    report.selected_evidence.quality[0].recomputed_report_digest = digest('0');
    report.selected_evidence.quality.push(report_only);
    report.source_bindings = exact_source_bindings(&report.selected_evidence);
    fixture.replace_economics_report(&report);

    let error = load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("exact economics-to-quality binding"));
}

#[test]
fn enforcement_loader_rejects_manifest_build_analysis_and_config_mismatch() {
    for (field, value) in [
        ("package_version", json!("different-valid-build")),
        (
            "source_revision",
            json!(digest('9').trim_start_matches("sha256:")),
        ),
        ("analysis_digest", json!(digest('8'))),
        ("config_digest", json!(digest('7'))),
    ] {
        let fixture = PositiveFixture::create();
        let path = fixture.root.join("economics/manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest[field] = value;
        write_json(&path, &manifest);
        let error =
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("manifest/report binding mismatch")
                || error.to_string().contains("source binding matrix"),
            "{field}: {error}"
        );
    }
}

#[test]
fn enforcement_loader_recomputes_and_requires_exact_source_binding_matrix() {
    for mutation in 0..8 {
        let mut fixture = PositiveFixture::create();
        let mut report = fixture.economics_report();
        match mutation {
            0 => report.source_bindings.clear(),
            1 => report
                .source_bindings
                .push(report.source_bindings[0].clone()),
            2 => {
                report.source_bindings.pop();
            }
            3 => report
                .source_bindings
                .push(matched("extra", "extra", digest('9'))),
            4 => report.source_bindings[0].kind = "digest".into(),
            5 => report.source_bindings[0].matched = false,
            6 => report.source_bindings[0].observed = Some(digest('9')),
            7 => report.source_bindings[0].expected = None,
            _ => unreachable!(),
        }
        fixture.replace_economics_report(&report);
        let error =
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                .unwrap_err();
        assert!(
            error.to_string().contains("source binding matrix"),
            "mutation {mutation}: {error}"
        );
    }
}

#[test]
fn enforcement_loader_rejects_syntactically_valid_source_binding_tampering() {
    for (source, field) in [
        ("analysis", "analysis-manifest"),
        ("traffic", "selected-records"),
        ("traffic", "manifest"),
        ("traffic", "recovery"),
        ("traffic", "registry"),
        ("traffic", "owned-cost"),
        ("traffic", "policy"),
        ("billing", "normalized-rows"),
        ("billing", "manifest"),
        ("billing", "recovery"),
        ("billing", "registry"),
        ("config", "configuration"),
        (QUALITY_RUN_ID, "manifest"),
        (QUALITY_RUN_ID, "outcomes"),
        (QUALITY_RUN_ID, "report-source"),
        (QUALITY_RUN_ID, "join-projection"),
    ] {
        let mut fixture = PositiveFixture::create();
        let mut report = fixture.economics_report();
        let check = report
            .source_bindings
            .iter_mut()
            .find(|check| check.source == source && check.field == field)
            .unwrap();
        check.expected = Some(digest('9'));
        check.observed = Some(digest('9'));
        check.matched = true;
        fixture.replace_economics_report(&report);
        assert!(
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                .is_err(),
            "accepted {source}/{field}"
        );
    }
}

#[test]
fn enforcement_loader_requires_one_complete_quality_binding_and_summary() {
    for mutation in 0..12 {
        let mut fixture = PositiveFixture::create();
        let mut report = fixture.economics_report();
        let binding = &mut report.selected_evidence.quality[0];
        match mutation {
            0 => binding.schema_version = 1,
            1 => binding.manifest_digest = digest('0'),
            2 => binding.recomputed_manifest_digest = digest('0'),
            3 => binding.outcomes_digest = digest('0'),
            4 => binding.recomputed_outcomes_digest = digest('0'),
            5 => binding.report_digest = digest('0'),
            6 => binding.recomputed_report_digest = digest('0'),
            7 => binding.join_projection_digest = digest('0'),
            8 => {
                report.opportunities[0].quality.as_mut().unwrap().verdict =
                    PromotionVerdict::QualityFailed
            }
            9 => report.opportunities[0].quality.as_mut().unwrap().age_ms += 1,
            10 => {
                report.opportunities[0]
                    .quality
                    .as_mut()
                    .unwrap()
                    .completed_at_ms += 1
            }
            11 => binding.policy_digest = digest('0'),
            _ => unreachable!(),
        }
        report.source_bindings = exact_source_bindings(&report.selected_evidence);
        fixture.replace_economics_report(&report);
        let error =
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact economics-to-quality binding")
                || error.to_string().contains("source binding matrix"),
            "mutation {mutation}: {error}"
        );
    }
}

#[test]
fn enforcement_loader_promotion_rejection_vectors_cover_identity_economics_and_freshness() {
    for mutation in 0..10 {
        let mut fixture = PositiveFixture::create();
        let mut report = fixture.economics_report();
        let row = &mut report.opportunities[0];
        match mutation {
            0 => row.key.actual_supply_id = "public/other".into(),
            1 => row.key.candidate_supply_id = "owned/other".into(),
            2 => row.key.task_class = TaskClass::Judgment,
            3 => row.key.protocol = ProtocolKind::Responses,
            4 => row.actual_cost_micros = None,
            5 => row.candidate_cost_micros = None,
            6 => row.eligible = false,
            7 => row.blockers.push(Blocker::CandidateNotFeasible),
            8 => row.blockers.push(Blocker::PolicyViolation),
            9 => row.blockers.push(Blocker::PolicyUnknown),
            _ => unreachable!(),
        }
        fixture.replace_economics_report(&report);
        assert!(
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                .is_err(),
            "mutation {mutation} was promoted"
        );
    }

    let fixture = PositiveFixture::create();
    assert!(
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, 999).is_err()
    );
    assert!(
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, 899).is_err()
    );
    assert!(
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, 2_001).is_err()
    );
}

#[test]
fn enforcement_loader_each_expiry_source_wins_and_grant_binds_closed_freshness_interval() {
    let economics = PositiveFixture::create();
    let economics_grant =
        load_verified_promotion_grant(&economics.validated, ROUTE_ID, &economics.root, NOW_MS)
            .unwrap();
    assert_eq!(economics_grant.not_before_ms(), 1_000);
    assert_eq!(economics_grant.expires_at_ms(), 2_000);

    let mut quality = PositiveFixture::create();
    quality.replace_current_timing(2_000, 3_000);
    reseal_authorization(&quality, &quality.validated, 1_000);
    let quality_grant =
        load_verified_promotion_grant(&quality.validated, ROUTE_ID, &quality.root, NOW_MS).unwrap();
    assert_eq!(quality_grant.expires_at_ms(), 2_500);

    let mut configured = PositiveFixture::create();
    configured.replace_current_timing(2_000, 1_500);
    reseal_authorization(&configured, &configured.validated, 1_000);
    let configured_grant =
        load_verified_promotion_grant(&configured.validated, ROUTE_ID, &configured.root, NOW_MS)
            .unwrap();
    assert_eq!(configured_grant.expires_at_ms(), 1_500);
    assert!(configured_grant.is_fresh_at(configured_grant.not_before_ms()));
    assert!(configured_grant.is_fresh_at(configured_grant.expires_at_ms()));
    assert!(!configured_grant.is_fresh_at(configured_grant.not_before_ms() - 1));
    assert!(!configured_grant.is_fresh_at(configured_grant.expires_at_ms() + 1));
    assert_ne!(
        economics_grant.validation_digest(),
        quality_grant.validation_digest()
    );
    assert_ne!(
        quality_grant.validation_digest(),
        configured_grant.validation_digest()
    );
    assert_ne!(economics_grant.grant_digest(), quality_grant.grant_digest());
    assert_ne!(
        quality_grant.grant_digest(),
        configured_grant.grant_digest()
    );

    let mut later_not_before = PositiveFixture::create();
    let mut report = later_not_before.economics_report();
    report.as_of_ms = 1_001;
    report.opportunities[0].quality.as_mut().unwrap().age_ms = 101;
    later_not_before.replace_economics_report(&report);
    later_not_before.replace_current_timing(1_000, 2_000);
    reseal_authorization(&later_not_before, &later_not_before.validated, 1_001);
    let later_grant = load_verified_promotion_grant(
        &later_not_before.validated,
        ROUTE_ID,
        &later_not_before.root,
        NOW_MS,
    )
    .unwrap();
    assert_eq!(later_grant.not_before_ms(), 1_001);
    assert_eq!(later_grant.expires_at_ms(), economics_grant.expires_at_ms());
    assert_ne!(
        later_grant.validation_digest(),
        economics_grant.validation_digest()
    );
    assert_ne!(later_grant.grant_digest(), economics_grant.grant_digest());
}

#[test]
fn enforcement_loader_rejects_expired_config_tampering() {
    let mut configured = PositiveFixture::create();
    configured.replace_current_timing(2_000, 1_000);
    reseal_authorization(&configured, &configured.validated, 1_000);
    assert!(load_verified_promotion_grant(
        &configured.validated,
        ROUTE_ID,
        &configured.root,
        NOW_MS,
    )
    .unwrap_err()
    .to_string()
    .contains("stale"));
}

#[test]
fn enforcement_loader_verifies_schema_v1_before_explicit_nonjoinable_rejection() {
    let fixture = PositiveFixture::create();
    let manifest_path = fixture.root.join("quality/run-1/manifest.json");
    let report_path = fixture.root.join("quality/run-1/quality-report.json");
    let mut manifest: QualityRunManifest =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let mut report = QualityReport::new(
        &manifest,
        vec![eligible_overlay()],
        900,
        false,
        false,
        canonical_outcomes_digest(&[quality_outcome()]).unwrap(),
    )
    .unwrap();
    manifest.quality_report_digest = Some(quality_report_digest(&report).unwrap());
    write_json(&manifest_path, &manifest);
    write_json(&report_path, &report);
    let valid_error =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
            .unwrap_err();
    assert!(valid_error
        .to_string()
        .contains("schema v1 is non-joinable"));

    report.outcomes_digest = digest('0');
    write_json(&report_path, &report);
    let tampered_error =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
            .unwrap_err();
    assert!(!tampered_error
        .to_string()
        .contains("schema v1 is non-joinable"));
    assert!(tampered_error
        .to_string()
        .contains("invalid or incomplete enforcement evidence"));
}

#[test]
fn enforcement_loader_promotion_rejection_vectors_cover_config_and_workload() {
    for needle in [POLICY_DIGEST, REGISTRY_DIGEST, OWNED_COST_DIGEST] {
        let fixture = PositiveFixture::create();
        let report = fixture.economics_report();
        let report_digest =
            plain_digest(&fs::read(fixture.root.join("economics/report.json")).unwrap());
        let opportunity_digest = economics_opportunity_digest(&report.opportunities[0]).unwrap();
        let config = EnforcementConfigV1::from_yaml(
            &authority_yaml(
                &report_digest,
                &opportunity_digest,
                &fixture.quality_report_digest,
            )
            .replace(needle, &digest('0')),
        )
        .unwrap()
        .validate()
        .unwrap();
        assert!(load_verified_promotion_grant(&config, ROUTE_ID, &fixture.root, NOW_MS).is_err());
    }

    for selector in [
        "[customer-facing]",
        "[customer-facing, production, reserved:tenant]",
    ] {
        let fixture = PositiveFixture::create();
        let report = fixture.economics_report();
        let report_digest =
            plain_digest(&fs::read(fixture.root.join("economics/report.json")).unwrap());
        let opportunity_digest = economics_opportunity_digest(&report.opportunities[0]).unwrap();
        let config = EnforcementConfigV1::from_yaml(
            &authority_yaml(
                &report_digest,
                &opportunity_digest,
                &fixture.quality_report_digest,
            )
            .replace("[customer-facing, production]", selector),
        )
        .unwrap()
        .validate()
        .unwrap();
        assert!(load_verified_promotion_grant(&config, ROUTE_ID, &fixture.root, NOW_MS).is_err());
    }
    for selector in ["[production, customer-facing]", "[production, production]"] {
        let source = authority_yaml(&digest('a'), &digest('b'), &digest('c'))
            .replace("[customer-facing, production]", selector);
        assert!(EnforcementConfigV1::from_yaml(&source)
            .unwrap()
            .validate()
            .is_err());
    }
}

#[test]
fn enforcement_loader_rejects_quality_schema_v1_and_accepts_exact_source_collection_bound() {
    let fixture = PositiveFixture::create();
    let quality_path = fixture.root.join("quality/run-1/quality-report.json");
    let mut quality: serde_json::Value =
        serde_json::from_slice(&fs::read(&quality_path).unwrap()).unwrap();
    quality["schema_version"] = json!(1);
    write_json(&quality_path, &quality);
    assert!(
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).is_err()
    );

    for count in [MAX_ANALYSIS_RUNS, MAX_ANALYSIS_RUNS + 1] {
        let mut fixture = PositiveFixture::create();
        let mut report = fixture.economics_report();
        while report.selected_evidence.quality.len() < count {
            let index = report.selected_evidence.quality.len();
            let mut extra = report.selected_evidence.quality[0].clone();
            extra.run_id = format!("quality-{index:03}");
            let unique = plain_digest(&index.to_be_bytes());
            extra.report_digest = unique.clone();
            extra.recomputed_report_digest = unique;
            report.selected_evidence.quality.push(extra);
        }
        report.source_bindings = exact_source_bindings(&report.selected_evidence);
        fixture.replace_economics_report(&report);
        if count == MAX_ANALYSIS_RUNS {
            reseal_authorization(&fixture, &fixture.validated, 1_000);
        }
        let result =
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS);
        assert_eq!(result.is_ok(), count == MAX_ANALYSIS_RUNS, "count {count}");
    }
}

#[test]
fn enforcement_loader_rejects_wrong_opportunity_digest_and_workload_identity() {
    let mut wrong_digest = PositiveFixture::create();
    let report_digest =
        plain_digest(&fs::read(wrong_digest.root.join("economics/report.json")).unwrap());
    wrong_digest.replace_config(&report_digest, &digest('0'));
    assert!(load_verified_promotion_grant(
        &wrong_digest.validated,
        ROUTE_ID,
        &wrong_digest.root,
        NOW_MS,
    )
    .unwrap_err()
    .to_string()
    .contains("exact opportunity join is not unique"));

    let mut wrong_workload = PositiveFixture::create();
    let mut report = wrong_workload.economics_report();
    report.opportunities[0].workload_identity_digest = digest('0');
    wrong_workload.replace_economics_report(&report);
    assert!(load_verified_promotion_grant(
        &wrong_workload.validated,
        ROUTE_ID,
        &wrong_workload.root,
        NOW_MS,
    )
    .unwrap_err()
    .to_string()
    .contains("exact opportunity join is not unique"));
}

#[test]
fn enforcement_loader_rejects_quality_manifest_tamper() {
    let fixture = PositiveFixture::create();
    let path = fixture.root.join("quality/run-1/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["completed_at_ms"] = json!(901);
    write_json(&path, &manifest);

    assert!(
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS,)
            .unwrap_err()
            .to_string()
            .contains("invalid or incomplete enforcement evidence")
    );
}

#[test]
fn enforcement_loader_rejects_each_of_six_payload_tampers() {
    for name in [
        "dimensions.csv",
        "opportunities.csv",
        "reconciliation.csv",
        "report.html",
        "report.json",
        "report.md",
    ] {
        let fixture = PositiveFixture::create();
        let path = fixture.root.join("economics").join(name);
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(b"tamper").unwrap();
        let error =
            load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("economics payload hash mismatch: {name}")),
            "unexpected {name} error: {error}"
        );
    }
}

#[test]
fn enforcement_loader_rejects_max_accepted_with_tiny_ledger() {
    let fixture = PositiveFixture::create();
    let path = fixture.root.join("quality/run-1/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["accepted"] = json!(u64::MAX);
    manifest["next_sequence"] = json!(u64::MAX);
    manifest["planned_request_upper_bound"] = json!(u64::MAX);
    manifest["reserved_candidate_credits"] = json!(u64::MAX);
    manifest["clean_shutdown"] = json!(false);
    write_json(&path, &manifest);

    let error = load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS)
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("quality accepted count exceeds bound"));
}

#[test]
fn enforcement_loader_is_the_only_public_grant_creation_boundary() {
    let core = include_str!("../../bowline-core/src/enforcement.rs");
    let gateway = include_str!("../src/enforcement_loader.rs");
    assert!(!core.contains("pub struct VerifiedPromotionGrant"));
    assert!(!core.contains("pub fn verify_promotion_sources"));
    assert!(gateway.contains("pub struct VerifiedPromotionGrant"));
    assert!(gateway.contains("pub fn load_verified_promotion_grant"));
    assert!(gateway.contains("validated: &ValidatedEnforcement"));
    assert!(gateway.contains("grant: &VerifiedPromotionGrant"));
    assert!(!gateway.contains("pub evidence_state: GatewayEvidenceState"));
    assert!(!core.contains("EvidenceState::Verified"));
}

#[test]
fn recommend_without_evidence_is_unverified_original() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    let result = select_enforcement_target_without_grant(
        &validated,
        ROUTE_ID,
        &selection_facts(&validated, &fixture.workload_digest),
    )
    .unwrap();

    assert_eq!(result.target(), PlanTarget::Original);
    assert_eq!(result.reason(), SelectionReason::RecommendationOnly);
    assert_eq!(result.evidence_state(), GatewayEvidenceState::Unverified);
}

#[test]
fn exact_recommendation_evidence_is_verified_but_never_authoritative() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    let evidence =
        load_verified_recommendation_evidence(&validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let result = select_recommendation_target(
        &validated,
        ROUTE_ID,
        &selection_facts(&validated, &fixture.workload_digest),
        &evidence,
    )
    .unwrap();

    assert_eq!(result.target(), PlanTarget::Original);
    assert_eq!(result.reason(), SelectionReason::RecommendationOnly);
    assert_eq!(result.evidence_state(), GatewayEvidenceState::Verified);
    assert_eq!(result.plan().dispatch_count, 0);
    assert_ne!(result.target(), PlanTarget::Candidate);
}

#[test]
fn recommendation_evidence_rejects_stale_tampered_and_mutated_context() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    assert!(
        load_verified_recommendation_evidence(&validated, ROUTE_ID, &fixture.root, 2_001,).is_err()
    );

    let evidence =
        load_verified_recommendation_evidence(&validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let requirement = validated
        .route(ROUTE_ID)
        .unwrap()
        .promotion
        .as_ref()
        .unwrap();
    let base = recommendation_yaml(
        &requirement.economics_report_digest,
        &requirement.opportunity_digest,
        &requirement.quality_report_digest,
    );
    for (name, yaml) in [
        (
            "route",
            base.replace("path: /v1/chat/completions", "path: /v1/responses"),
        ),
        (
            "config",
            base.replace(
                "global_candidate_in_flight: 1",
                "global_candidate_in_flight: 2",
            ),
        ),
        (
            "actuator",
            base.replace(
                "https://inference.example.test/v1",
                "https://changed.example.test/v1",
            ),
        ),
        (
            "workload",
            base.replace("app: support", "app: changed-support"),
        ),
    ] {
        let mutated = EnforcementConfigV1::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap();
        let result = select_recommendation_target(
            &mutated,
            ROUTE_ID,
            &selection_facts(&mutated, &fixture.workload_digest),
            &evidence,
        )
        .unwrap();
        assert_eq!(result.target(), PlanTarget::Original, "{name}");
        assert_eq!(
            result.evidence_state(),
            GatewayEvidenceState::Unverified,
            "{name}"
        );
    }

    let tampered = PositiveFixture::create();
    let tampered_validated = recommendation_config(&tampered);
    let report_path = tampered.root.join("economics/report.json");
    let mut file = OpenOptions::new().append(true).open(report_path).unwrap();
    file.write_all(b"tamper").unwrap();
    assert!(load_verified_recommendation_evidence(
        &tampered_validated,
        ROUTE_ID,
        &tampered.root,
        NOW_MS,
    )
    .is_err());
}

#[test]
fn authority_and_recommendation_evidence_are_route_mode_confined() {
    let fixture = PositiveFixture::create();
    let authority_grant =
        load_verified_promotion_grant(&fixture.validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let recommend = recommendation_config(&fixture);
    assert!(select_enforcement_target(
        &recommend,
        ROUTE_ID,
        &selection_facts(&recommend, &fixture.workload_digest),
        &authority_grant,
    )
    .is_err());

    let recommendation_evidence =
        load_verified_recommendation_evidence(&recommend, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    assert!(select_recommendation_target(
        &fixture.validated,
        ROUTE_ID,
        &selection_facts(&fixture.validated, &fixture.workload_digest),
        &recommendation_evidence,
    )
    .is_err());

    let gateway = include_str!("../src/enforcement_loader.rs");
    assert!(
        !gateway.contains("impl From<VerifiedRecommendationEvidence> for VerifiedPromotionGrant")
    );
    assert!(
        !gateway.contains("impl Into<VerifiedPromotionGrant> for VerifiedRecommendationEvidence")
    );
}

// --- authority_signing: standard-Minisign envelope verification on promotion evidence ---
//
// The signing key below is a throwaway test-only Minisign key pair generated solely to produce
// these fixtures; it authenticates nothing outside this test suite. `GATEWAY_AUTHORIZATION_JSON`
// is the exact, deterministic bytes `PositiveFixture::create()` seals for `ROUTE_ID` (fixed
// digests, fixed timestamps, no wall-clock or random input), so a signature computed over it
// once, offline, verifies identically on every test run.

const TEST_VERIFY_KEY: &str = "untrusted comment: minisign public key 7D993CA9D5D0C222\nRWQiwtDVqTyZfVHo3bp+lvtyh0CIvHkliMEzW6bESmSglCOlNnEB5Fxq\n";

const GATEWAY_AUTHORIZATION_JSON: &str = "{\"schema_version\":1,\"route_id\":\"support-chat\",\"created_at_ms\":1000,\"economics_bundle_digest\":\"sha256:2933c7f784c974a4b1191d55ff89ae1d5df71ddaad0dd62417c8ced1d1b6a71a\",\"economics_report_digest\":\"sha256:2cc45e34338d7f6d20fe94c052d1811668d0af8407e0e96ca071d24c5307f033\",\"opportunity_digest\":\"sha256:b9622c09fffe22f929e0e48e2d4bc67b79682643ab86ff2ad0082771b2872e25\",\"quality_source_digest\":\"sha256:5bed4d2721fb8c31a23090ce2b3b53fe153f47f73e9b7152355aaac6a46fe6fa\",\"quality_run_id\":\"00000000-0000-0000-0000-000000000001\",\"quality_report_digest\":\"sha256:7dd077d47f35c26588cc5685927028bbafb6255468a157c1b5a67a062e188bf5\",\"policy_digest\":\"sha256:fa866bbe091a221af281781243aa63e586d8e22328faa1c63c8b252c99e262b7\",\"registry_digest\":\"sha256:aadab12c615bee889d2a20396d5ce3751575a1172f528295c72126871c1b68fd\",\"owned_cost_digest\":\"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\",\"enforcement_digest\":\"sha256:bd9b70a562b3d4e78826abfc739d90071d4051244ee23644e5da5c5d88efc81c\",\"actuator_digest\":\"sha256:5696131a3e30cb82dfa6baddc9cff47db2101b447c55f950ce93a0b9c17844ec\",\"route_digest\":\"sha256:59101e0cf72b9fe7929f5db190b6778bc06a1313566d508445ef207b0a775d86\",\"workload_identity_digest\":\"sha256:8ad64415d5c48cbf357a640f5ada080cb6705dba82d46edf743ebb960d682ca7\",\"task_class\":\"mechanical\",\"protocol\":\"chat-completions\",\"actual_supply_id\":\"public/openai\",\"candidate_supply_id\":\"owned/llama\",\"authorization_digest\":\"sha256:4377d1eca4e7292cacb2380150e3a3ffa1ea102a9eec0ac01b1ab4a53b8634cd\"}\n";

const GATEWAY_ENVELOPE_VALID_JSON: &str = "{\"envelope_version\":1,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"7D993CA9D5D0C222\",\"payload_sha256\":\"sha256:62789f126dbab1e4228cec4269d71efaf85f122560153c9aa7f720ced117653d\",\"minisign_signature\":\"untrusted comment: signature from minisign secret key\\nRUQiwtDVqTyZfXua/0WIqS12Qzk7vIkuzCpNSL5xV8JSvqgFlAgxYkMahKubhURuovgmlmrTEvKKOhwn8YIZcyB4dq+9kwsosA8=\\ntrusted comment: bowline gateway fixture\\nGPkV60C8KcbEAiEXoxnC0p4r3N/Zq9o/9K1zfxZerwTeLrxBejwp7LgWDwfMeKhack6V6erHq0kLit0KuFp6Cw==\\n\"}";

/// Signed by a *different* throwaway key than `TEST_VERIFY_KEY`, over the same exact payload.
/// Models an operator whose configured `verify_keys` do not include the key that actually signed
/// this evidence.
const GATEWAY_ENVELOPE_WRONG_KEY_JSON: &str = "{\"envelope_version\":1,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"041164092885E85E\",\"payload_sha256\":\"sha256:62789f126dbab1e4228cec4269d71efaf85f122560153c9aa7f720ced117653d\",\"minisign_signature\":\"untrusted comment: signature from minisign secret key\\nRURe6IUoCWQRBBcvBdXPbYLay0vCxVO8/aXUoKnWZUsXk2SJteg58InDoMyNBIo33a7V3nRWI8chUGIenk0ctCa2aRFWVDlUiwY=\\ntrusted comment: bowline gateway fixture (wrong key)\\n7j/bzJYW7cAbPAM/PiFk9N1AbNE5RCcksdxi56seRJFBYv1oxgBjS1ifvi88AprF+id9O2uYcWKmXArUActpAQ==\\n\"}";

/// The *same* signature bytes as `GATEWAY_ENVELOPE_WRONG_KEY_JSON` (produced by the other
/// throwaway key), but with `key_id` relabeled to `TEST_VERIFY_KEY`'s id. Models a forged
/// attribution: the claimed signer matches a configured key, so key lookup succeeds, but the
/// signature was never produced by that key, so cryptographic verification must still fail.
const GATEWAY_ENVELOPE_FORGED_KEY_ID_JSON: &str = "{\"envelope_version\":1,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"7D993CA9D5D0C222\",\"payload_sha256\":\"sha256:62789f126dbab1e4228cec4269d71efaf85f122560153c9aa7f720ced117653d\",\"minisign_signature\":\"untrusted comment: signature from minisign secret key\\nRURe6IUoCWQRBBcvBdXPbYLay0vCxVO8/aXUoKnWZUsXk2SJteg58InDoMyNBIo33a7V3nRWI8chUGIenk0ctCa2aRFWVDlUiwY=\\ntrusted comment: bowline gateway fixture (wrong key)\\n7j/bzJYW7cAbPAM/PiFk9N1AbNE5RCcksdxi56seRJFBYv1oxgBjS1ifvi88AprF+id9O2uYcWKmXArUActpAQ==\\n\"}";

fn signature_sidecar_path(fixture: &PositiveFixture) -> PathBuf {
    fixture
        .root
        .join("authorization/support-chat.json.signature.json")
}

fn required_signing_config() -> AuthoritySigningConfig {
    AuthoritySigningConfig {
        version: 1,
        required: true,
        verify_keys: vec![TEST_VERIFY_KEY.to_owned()],
    }
}

#[test]
fn authority_signing_absent_matches_legacy_grant_loading_exactly() {
    let fixture = PositiveFixture::create();
    let legacy = load_verified_promotion_grant_with_active(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
    )
    .unwrap();
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
    )
    .unwrap();
    let PromotionGrantLoad::Verified(signed) = outcome else {
        panic!("expected a verified grant when authority_signing is unconfigured");
    };
    assert_eq!(signed.grant_digest(), legacy.grant_digest());
    assert_eq!(signed.route_id(), legacy.route_id());
}

#[test]
fn authority_signing_required_and_missing_envelope_is_signature_missing_not_a_hard_error() {
    let fixture = PositiveFixture::create();
    assert!(!signature_sidecar_path(&fixture).exists());
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::SignatureMissing));
}

#[test]
fn authority_signing_not_required_and_missing_envelope_falls_back_to_verified_grant() {
    let fixture = PositiveFixture::create();
    let signing = AuthoritySigningConfig {
        version: 1,
        required: false,
        verify_keys: vec![TEST_VERIFY_KEY.to_owned()],
    };
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&signing),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::Verified(_)));
}

#[test]
fn authority_signing_valid_envelope_verifies_and_grants() {
    let fixture = PositiveFixture::create();
    let sidecar = fixture.root.join("authorization/support-chat.json");
    assert_eq!(
        fs::read(&sidecar).unwrap(),
        GATEWAY_AUTHORIZATION_JSON.as_bytes(),
        "fixture authorization bytes drifted from the pre-signed test vector"
    );
    write_private(
        &signature_sidecar_path(&fixture),
        GATEWAY_ENVELOPE_VALID_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap();
    let PromotionGrantLoad::Verified(grant) = outcome else {
        panic!("expected a verified grant for a valid signature envelope");
    };
    assert_eq!(grant.route_id(), ROUTE_ID);
}

#[test]
fn authority_signing_wrong_configured_key_is_signature_invalid() {
    let fixture = PositiveFixture::create();
    write_private(
        &signature_sidecar_path(&fixture),
        GATEWAY_ENVELOPE_WRONG_KEY_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::SignatureInvalid));
}

#[test]
fn authority_signing_forged_key_id_attribution_is_signature_invalid() {
    let fixture = PositiveFixture::create();
    write_private(
        &signature_sidecar_path(&fixture),
        GATEWAY_ENVELOPE_FORGED_KEY_ID_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::SignatureInvalid));
}

#[test]
fn authority_signing_tampered_payload_is_signature_invalid() {
    let fixture = PositiveFixture::create();
    write_private(
        &signature_sidecar_path(&fixture),
        GATEWAY_ENVELOPE_VALID_JSON.as_bytes(),
    );
    // Flip one hex digit of a digest field: still syntactically valid JSON, but the exact bytes
    // no longer match what was signed.
    let sidecar = fixture.root.join("authorization/support-chat.json");
    let tampered = GATEWAY_AUTHORIZATION_JSON.replacen("owned/llama", "owned/llamb", 1);
    write_private(&sidecar, tampered.as_bytes());
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::SignatureInvalid));
}

#[test]
fn authority_signing_envelope_symlink_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    let replacement = fixture.root.join("replacement-envelope.json");
    write_private(&replacement, GATEWAY_ENVELOPE_VALID_JSON.as_bytes());
    symlink(replacement, signature_sidecar_path(&fixture)).unwrap();
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    );
    assert!(
        outcome.is_err(),
        "a symlinked envelope must retain startup refusal"
    );
}

#[test]
fn authority_signing_envelope_wrong_mode_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    let sidecar = signature_sidecar_path(&fixture);
    write_private(&sidecar, GATEWAY_ENVELOPE_VALID_JSON.as_bytes());
    fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644)).unwrap();
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    );
    assert!(
        outcome.is_err(),
        "a world-readable envelope must retain startup refusal"
    );
}

#[test]
fn authority_signing_envelope_oversized_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    write_private(
        &signature_sidecar_path(&fixture),
        &vec![b' '; 64 * 1024 + 1],
    );
    let outcome = load_verified_promotion_grant_signed(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    );
    assert!(
        outcome.is_err(),
        "an oversized envelope must retain startup refusal"
    );
}

// --- promotion_approval: external-approval artifact binding on promotion ---
//
// Fixtures below are pre-signed offline, once, with throwaway Minisign key pairs unrelated to
// `TEST_VERIFY_KEY` above; they authenticate nothing outside this test suite. Their embedded
// `descriptor_sha256`/`economics_source_digest`/`quality_source_digest` values are the exact
// digests `GATEWAY_AUTHORIZATION_JSON` carries (`authorization_digest`, `economics_bundle_digest`,
// and `quality_source_digest` respectively), so they bind exactly to the grant `PositiveFixture`
// produces.

const TEST_APPROVAL_VERIFY_KEY: &str = "untrusted comment: minisign public key 789874E4D07535A9\nRWSpNXXQ5HSYeME2uwyrWBQg5TXdi+8vGt5J3++X+Z3aBCgUE3YhwS5c\n";

const GATEWAY_APPROVAL_VALID_JSON: &str = "{\"artifact_version\":1,\"descriptor_sha256\":\"sha256:4377d1eca4e7292cacb2380150e3a3ffa1ea102a9eec0ac01b1ab4a53b8634cd\",\"source_evidence\":{\"economics_source_digest\":\"sha256:2933c7f784c974a4b1191d55ff89ae1d5df71ddaad0dd62417c8ced1d1b6a71a\",\"quality_source_digest\":\"sha256:5bed4d2721fb8c31a23090ce2b3b53fe153f47f73e9b7152355aaac6a46fe6fa\"},\"approver\":\"external-approval-workflow\",\"issued_at_ms\":1000,\"expires_at_ms\":4600}";

/// Same claimed binding as `GATEWAY_APPROVAL_VALID_JSON`, but `quality_source_digest` does not
/// match the fixture's actual quality source digest.
const GATEWAY_APPROVAL_UNBOUND_JSON: &str = "{\"artifact_version\":1,\"descriptor_sha256\":\"sha256:4377d1eca4e7292cacb2380150e3a3ffa1ea102a9eec0ac01b1ab4a53b8634cd\",\"source_evidence\":{\"economics_source_digest\":\"sha256:2933c7f784c974a4b1191d55ff89ae1d5df71ddaad0dd62417c8ced1d1b6a71a\",\"quality_source_digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"},\"approver\":\"external-approval-workflow\",\"issued_at_ms\":1000,\"expires_at_ms\":4600}";

const GATEWAY_APPROVAL_ENVELOPE_VALID_JSON: &str = "{\"envelope_version\": 1, \"algorithm\": \"minisign-ed25519\", \"key_id\": \"789874E4D07535A9\", \"payload_sha256\": \"sha256:4a63138836fc0a2c1e1a6cb199882b4f93a9531ef4106585d81907f97d70008b\", \"minisign_signature\": \"untrusted comment: bowline gateway approval fixture\\nRUSpNXXQ5HSYeDV/R3AtV6lk6cu8YEomJpMDfJms03f7zJX2R59+COyih3FbXGoiv0cTiKIHhTxLgXurzGQpA22uCPVBfDHscQc=\\ntrusted comment: bowline external-approval artifact fixture\\nRzyUVtowDRRsiUwtiZ/cjuygCLYxEx6saSE/ajLsyWA/e5Na4VpXx3RZx1hKn8j2NR+KEcuiGzNKtvoX+sY6Bw==\\n\"}";

/// Signed by a *different* throwaway key than `TEST_APPROVAL_VERIFY_KEY`, over the same exact
/// valid payload. Models an operator whose configured `verify_keys` do not include the key that
/// actually signed this artifact.
const GATEWAY_APPROVAL_ENVELOPE_WRONG_KEY_JSON: &str = "{\"envelope_version\": 1, \"algorithm\": \"minisign-ed25519\", \"key_id\": \"523F586596E8204E\", \"payload_sha256\": \"sha256:4a63138836fc0a2c1e1a6cb199882b4f93a9531ef4106585d81907f97d70008b\", \"minisign_signature\": \"untrusted comment: bowline gateway approval fixture wrong key\\nRUROIOiWZVg/UqDvSt8gFjtfV1y+3eeu+II6+o5WbMKTpiJZLyGwY3eZaKF3J+BvifX9dqULxtzqW4S4eOs7s8N6bPZkX9VoTwg=\\ntrusted comment: bowline external-approval artifact fixture\\nxC5zoMwR7ie6FEZclrd6Ehb7WXueBqENErj+bgJajLNL0qnHmt4qpycdz0rOP+Zo5Zjc6593kD1PYQ0GbaZ+DA==\\n\"}";

const GATEWAY_APPROVAL_ENVELOPE_UNBOUND_JSON: &str = "{\"envelope_version\": 1, \"algorithm\": \"minisign-ed25519\", \"key_id\": \"789874E4D07535A9\", \"payload_sha256\": \"sha256:4ed1ef4135f967a3bc4e20e16f5aa362802c6ff4d8bbc9440b33af7a29c24fa8\", \"minisign_signature\": \"untrusted comment: bowline gateway approval fixture\\nRUSpNXXQ5HSYeMBxpDHDOFOcveUD//InX+1+J3+RNQNRS3fzngRAGbR21MklNpZVr2adGWAUxe98Lp/orK/SXvgWxUtSfrVK7wU=\\ntrusted comment: bowline external-approval artifact fixture\\njlZPqThrPC5RZ0K7tKx6FKkot1E7rBbx3LWskDbSITYjCqgGkmpqcEtNOA+0uo/NsocPc8OCBcWvqF9lXVf5Bw==\\n\"}";

/// Same claimed binding as `GATEWAY_APPROVAL_VALID_JSON`, but its own claimed validity window
/// (`issued_at_ms: 100, expires_at_ms: 200`) has already elapsed by `NOW_MS`.
const GATEWAY_APPROVAL_EXPIRED_JSON: &str = "{\"artifact_version\":1,\"descriptor_sha256\":\"sha256:4377d1eca4e7292cacb2380150e3a3ffa1ea102a9eec0ac01b1ab4a53b8634cd\",\"source_evidence\":{\"economics_source_digest\":\"sha256:2933c7f784c974a4b1191d55ff89ae1d5df71ddaad0dd62417c8ced1d1b6a71a\",\"quality_source_digest\":\"sha256:5bed4d2721fb8c31a23090ce2b3b53fe153f47f73e9b7152355aaac6a46fe6fa\"},\"approver\":\"external-approval-workflow\",\"issued_at_ms\":100,\"expires_at_ms\":200}";

const GATEWAY_APPROVAL_ENVELOPE_EXPIRED_JSON: &str = "{\"envelope_version\": 1, \"algorithm\": \"minisign-ed25519\", \"key_id\": \"789874E4D07535A9\", \"payload_sha256\": \"sha256:7b06cbb3c348d35016eb749f4954cf518b400986dbbe1cfa335076906810429b\", \"minisign_signature\": \"untrusted comment: bowline gateway approval fixture\\nRUSpNXXQ5HSYeGsll4LiyokXDOGj9Ingf8ifYXeoUQCymIGfn+s79e/haLq8yzEvVTA0ZgScvWJX1tN3L7ct1kM2RzRJY1Higw0=\\ntrusted comment: bowline external-approval artifact fixture\\n1C6sNa9ezDhsZyGBAFox+D3q0KYgeGhSFgDWSeoCSwm/OYPOlG/7dS6OtwrkPGTQ0yu111CmrCcED/XDL8MhDg==\\n\"}";

/// Both unbound (wrong `quality_source_digest`) *and* outside its own claimed validity window,
/// to prove `Unbound` — not `Expired` — is reported when both conditions hold.
const GATEWAY_APPROVAL_UNBOUND_AND_EXPIRED_JSON: &str = "{\"artifact_version\":1,\"descriptor_sha256\":\"sha256:4377d1eca4e7292cacb2380150e3a3ffa1ea102a9eec0ac01b1ab4a53b8634cd\",\"source_evidence\":{\"economics_source_digest\":\"sha256:2933c7f784c974a4b1191d55ff89ae1d5df71ddaad0dd62417c8ced1d1b6a71a\",\"quality_source_digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"},\"approver\":\"external-approval-workflow\",\"issued_at_ms\":100,\"expires_at_ms\":200}";

const GATEWAY_APPROVAL_ENVELOPE_UNBOUND_AND_EXPIRED_JSON: &str = "{\"envelope_version\": 1, \"algorithm\": \"minisign-ed25519\", \"key_id\": \"789874E4D07535A9\", \"payload_sha256\": \"sha256:8f46d55eeff2c089929aaa4f784a179fff2d8364bac52cbeff8720d88db7e308\", \"minisign_signature\": \"untrusted comment: bowline gateway approval fixture\\nRUSpNXXQ5HSYeHboTOwy+cc2Q3UbNK3rfyOCuWZMapX94tL/jVQtHblhnM6puMoD3fGWEajxPeMz59nI2jWk3bwgvLODAsQITAY=\\ntrusted comment: bowline external-approval artifact fixture\\nOJz5ZbgfJwt8FRUVLJr6kct/hFAycQrlNKJRlVcbbUTXwO1DLM15cdsrb/yR4/nHGVB3Jpv5IsDO2CiyFx+XBw==\\n\"}";

fn approval_artifact_path(fixture: &PositiveFixture) -> PathBuf {
    fixture
        .root
        .join("authorization/support-chat.json.approval.json")
}

fn approval_envelope_path(fixture: &PositiveFixture) -> PathBuf {
    fixture
        .root
        .join("authorization/support-chat.json.approval.json.signature.json")
}

fn required_approval_config() -> PromotionApprovalConfig {
    PromotionApprovalConfig {
        version: 1,
        required: true,
        verify_keys: vec![TEST_APPROVAL_VERIFY_KEY.to_owned()],
        max_age_seconds: 3_600,
    }
}

#[test]
fn promotion_approval_absent_matches_legacy_grant_loading_exactly() {
    let fixture = PositiveFixture::create();
    let legacy = load_verified_promotion_grant_with_active(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
    )
    .unwrap();
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        None,
    )
    .unwrap();
    let PromotionGrantLoad::Verified(grant) = outcome else {
        panic!("expected a verified grant when promotion_approval is unconfigured");
    };
    assert_eq!(grant.grant_digest(), legacy.grant_digest());
    assert_eq!(grant.route_id(), legacy.route_id());
}

#[test]
fn promotion_approval_required_and_missing_artifact_is_approval_missing_not_a_hard_error() {
    let fixture = PositiveFixture::create();
    assert!(!approval_artifact_path(&fixture).exists());
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::ApprovalMissing));
}

#[test]
fn promotion_approval_not_required_and_missing_artifact_falls_back_to_verified_grant() {
    let fixture = PositiveFixture::create();
    let approval = PromotionApprovalConfig {
        version: 1,
        required: false,
        verify_keys: vec![TEST_APPROVAL_VERIFY_KEY.to_owned()],
        max_age_seconds: 3_600,
    };
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&approval),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::Verified(_)));
}

#[test]
fn promotion_approval_required_and_missing_envelope_with_present_artifact_is_approval_missing() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_VALID_JSON.as_bytes(),
    );
    assert!(!approval_envelope_path(&fixture).exists());
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::ApprovalMissing));
}

#[test]
fn promotion_approval_valid_artifact_verifies_binds_and_grants() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_VALID_JSON.as_bytes(),
    );
    write_private(
        &approval_envelope_path(&fixture),
        GATEWAY_APPROVAL_ENVELOPE_VALID_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    let PromotionGrantLoad::Verified(grant) = outcome else {
        panic!("expected a verified grant for a valid, bound, fresh approval artifact");
    };
    assert_eq!(grant.route_id(), ROUTE_ID);
}

#[test]
fn promotion_approval_wrong_configured_key_is_approval_signature_invalid() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_VALID_JSON.as_bytes(),
    );
    write_private(
        &approval_envelope_path(&fixture),
        GATEWAY_APPROVAL_ENVELOPE_WRONG_KEY_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(
        outcome,
        PromotionGrantLoad::ApprovalSignatureInvalid
    ));
}

#[test]
fn promotion_approval_validly_signed_but_unbound_artifact_is_approval_unbound() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_UNBOUND_JSON.as_bytes(),
    );
    write_private(
        &approval_envelope_path(&fixture),
        GATEWAY_APPROVAL_ENVELOPE_UNBOUND_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::ApprovalUnbound));
}

#[test]
fn unbound_takes_precedence_over_also_expired() {
    // This artifact is *both* unbound (wrong `quality_source_digest`) *and* outside its own
    // claimed validity window at `NOW_MS`, proving `Unbound` is reported — not `Expired` — when
    // both conditions hold, exactly matching the documented missing -> bad signature -> unbound
    // -> expired/stale precedence.
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_UNBOUND_AND_EXPIRED_JSON.as_bytes(),
    );
    write_private(
        &approval_envelope_path(&fixture),
        GATEWAY_APPROVAL_ENVELOPE_UNBOUND_AND_EXPIRED_JSON.as_bytes(),
    );
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::ApprovalUnbound));
}

#[test]
fn promotion_approval_expired_artifact_is_approval_expired() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_EXPIRED_JSON.as_bytes(),
    );
    write_private(
        &approval_envelope_path(&fixture),
        GATEWAY_APPROVAL_ENVELOPE_EXPIRED_JSON.as_bytes(),
    );
    // The artifact's own claimed window (`issued_at_ms: 100, expires_at_ms: 200`) has already
    // elapsed by `NOW_MS`; the base grant's independent evidence freshness is untouched.
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::ApprovalExpired));
}

#[test]
fn promotion_approval_artifact_symlink_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    let replacement = fixture.root.join("replacement-approval.json");
    write_private(&replacement, GATEWAY_APPROVAL_VALID_JSON.as_bytes());
    symlink(replacement, approval_artifact_path(&fixture)).unwrap();
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    );
    assert!(
        outcome.is_err(),
        "a symlinked approval artifact must retain startup refusal"
    );
}

#[test]
fn promotion_approval_artifact_wrong_mode_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    let artifact = approval_artifact_path(&fixture);
    write_private(&artifact, GATEWAY_APPROVAL_VALID_JSON.as_bytes());
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).unwrap();
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    );
    assert!(
        outcome.is_err(),
        "a world-readable approval artifact must retain startup refusal"
    );
}

#[test]
fn promotion_approval_artifact_oversized_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        &vec![b' '; 64 * 1024 + 1],
    );
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    );
    assert!(
        outcome.is_err(),
        "an oversized approval artifact must retain startup refusal"
    );
}

#[test]
fn promotion_approval_envelope_oversized_retains_startup_refusal() {
    let fixture = PositiveFixture::create();
    write_private(
        &approval_artifact_path(&fixture),
        GATEWAY_APPROVAL_VALID_JSON.as_bytes(),
    );
    write_private(
        &approval_envelope_path(&fixture),
        &vec![b' '; 64 * 1024 + 1],
    );
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
        Some(&required_approval_config()),
    );
    assert!(
        outcome.is_err(),
        "an oversized approval envelope must retain startup refusal"
    );
}

#[test]
fn authority_signing_rejection_takes_precedence_over_unchecked_promotion_approval() {
    // A missing, `required` `authority_signing` signature must be reported as
    // `SignatureMissing`, never reaching approval-artifact checks at all — even though no
    // approval artifact is present either (which would otherwise also be `ApprovalMissing`).
    let fixture = PositiveFixture::create();
    let outcome = load_verified_promotion_grant_with_approval(
        &fixture.validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
        Some(&required_approval_config()),
    )
    .unwrap();
    assert!(matches!(outcome, PromotionGrantLoad::SignatureMissing));
}

// --- authority_signing over recommendation evidence (same descriptor, never authoritative) ---
//
// `RECOMMEND_ENVELOPE_VALID_JSON` / `RECOMMEND_ENVELOPE_INVALID_JSON` are pre-signed over the
// exact, deterministic bytes `recommendation_config(&fixture)` reseals for `ROUTE_ID` (fixed
// digests/timestamps, no wall-clock or random input) — the same throwaway key as
// `TEST_VERIFY_KEY`, generated exactly like the promotion-side fixtures above.

const RECOMMEND_AUTHORIZATION_JSON: &str = "{\"schema_version\":1,\"route_id\":\"support-chat\",\"created_at_ms\":1000,\"economics_bundle_digest\":\"sha256:2933c7f784c974a4b1191d55ff89ae1d5df71ddaad0dd62417c8ced1d1b6a71a\",\"economics_report_digest\":\"sha256:2cc45e34338d7f6d20fe94c052d1811668d0af8407e0e96ca071d24c5307f033\",\"opportunity_digest\":\"sha256:b9622c09fffe22f929e0e48e2d4bc67b79682643ab86ff2ad0082771b2872e25\",\"quality_source_digest\":\"sha256:5bed4d2721fb8c31a23090ce2b3b53fe153f47f73e9b7152355aaac6a46fe6fa\",\"quality_run_id\":\"00000000-0000-0000-0000-000000000001\",\"quality_report_digest\":\"sha256:7dd077d47f35c26588cc5685927028bbafb6255468a157c1b5a67a062e188bf5\",\"policy_digest\":\"sha256:fa866bbe091a221af281781243aa63e586d8e22328faa1c63c8b252c99e262b7\",\"registry_digest\":\"sha256:aadab12c615bee889d2a20396d5ce3751575a1172f528295c72126871c1b68fd\",\"owned_cost_digest\":\"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\",\"enforcement_digest\":\"sha256:f7e3a4fe3c72d5305a9c93e96be932729cc80c4a5a514693a0239d3494b91b5b\",\"actuator_digest\":\"sha256:5696131a3e30cb82dfa6baddc9cff47db2101b447c55f950ce93a0b9c17844ec\",\"route_digest\":\"sha256:07c659e4778572fdd995a76f0b7ac792de8b053ab073713a9830bc772a64e909\",\"workload_identity_digest\":\"sha256:8ad64415d5c48cbf357a640f5ada080cb6705dba82d46edf743ebb960d682ca7\",\"task_class\":\"mechanical\",\"protocol\":\"chat-completions\",\"actual_supply_id\":\"public/openai\",\"candidate_supply_id\":\"owned/llama\",\"authorization_digest\":\"sha256:c2df47750e7dc1639332e5a1c9f6d8f37e3185ba0c6e2f1ef0c05ce70f89427d\"}\n";

const RECOMMEND_ENVELOPE_VALID_JSON: &str = "{\"envelope_version\":1,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"7D993CA9D5D0C222\",\"payload_sha256\":\"sha256:dbd7f1ae856f3ed9ed5b9df150ce54bcda2d765f034a301c25feaf921cde3e83\",\"minisign_signature\":\"untrusted comment: signature from minisign secret key\\nRUQiwtDVqTyZfSvpYjyLP/3/GJKeuNEVzC7zoIs+sqG0edZjfyDCNI/MeI2dJ7EeMJ2XnT+PPjmq4oqiVXMMmBjWsG9ppjZq0ws=\\ntrusted comment: bowline recommend fixture\\n26O+9nFakGrHrKA6sfwVkwuONozMqBPW8xz1p1nmAyUKAblDlvogXwjEn+5YEzwiDsY1BT0blsGLJnsylQGmDA==\\n\"}";

/// Same signature bytes as `RECOMMEND_ENVELOPE_VALID_JSON`, but with `payload_sha256` corrupted so
/// the digest check fails before the signature is ever checked. Models the promotion-side
/// "present but invalid" case for recommendation evidence.
const RECOMMEND_ENVELOPE_INVALID_JSON: &str = "{\"envelope_version\":1,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"7D993CA9D5D0C222\",\"payload_sha256\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"minisign_signature\":\"untrusted comment: signature from minisign secret key\\nRUQiwtDVqTyZfSvpYjyLP/3/GJKeuNEVzC7zoIs+sqG0edZjfyDCNI/MeI2dJ7EeMJ2XnT+PPjmq4oqiVXMMmBjWsG9ppjZq0ws=\\ntrusted comment: bowline recommend fixture\\n26O+9nFakGrHrKA6sfwVkwuONozMqBPW8xz1p1nmAyUKAblDlvogXwjEn+5YEzwiDsY1BT0blsGLJnsylQGmDA==\\n\"}";

fn recommend_signature_sidecar_path(fixture: &PositiveFixture) -> PathBuf {
    fixture
        .root
        .join("authorization/support-chat.json.signature.json")
}

#[test]
fn recommendation_signing_absent_matches_legacy_loading_exactly() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    let legacy =
        load_verified_recommendation_evidence(&validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    let signed = load_verified_recommendation_evidence_signed(
        &validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        None,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&legacy).unwrap(),
        serde_json::to_value(&signed).unwrap()
    );
}

#[test]
fn recommendation_signing_required_and_valid_signature_is_presented_evidence() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    let sidecar = fixture.root.join("authorization/support-chat.json");
    assert_eq!(
        fs::read(&sidecar).unwrap(),
        RECOMMEND_AUTHORIZATION_JSON.as_bytes(),
        "fixture recommendation authorization bytes drifted from the pre-signed test vector"
    );
    write_private(
        &recommend_signature_sidecar_path(&fixture),
        RECOMMEND_ENVELOPE_VALID_JSON.as_bytes(),
    );
    let evidence = load_verified_recommendation_evidence_signed(
        &validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap();
    let result = select_recommendation_target(
        &validated,
        ROUTE_ID,
        &selection_facts(&validated, &fixture.workload_digest),
        &evidence,
    )
    .unwrap();
    assert_eq!(result.evidence_state(), GatewayEvidenceState::Verified);
    assert_eq!(result.reason(), SelectionReason::RecommendationOnly);
    assert_ne!(result.target(), PlanTarget::Candidate);
}

#[test]
fn recommendation_signing_required_and_missing_envelope_is_rejected_with_typed_reason() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    assert!(!recommend_signature_sidecar_path(&fixture).exists());
    let error = load_verified_recommendation_evidence_signed(
        &validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("signature-missing"),
        "expected the signature-missing reason, got: {error}"
    );
}

#[test]
fn recommendation_signing_required_and_invalid_signature_is_rejected_with_typed_reason() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    write_private(
        &recommend_signature_sidecar_path(&fixture),
        RECOMMEND_ENVELOPE_INVALID_JSON.as_bytes(),
    );
    let error = load_verified_recommendation_evidence_signed(
        &validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&required_signing_config()),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("signature-invalid"),
        "expected the signature-invalid reason, got: {error}"
    );
}

#[test]
fn recommendation_signing_not_required_and_missing_envelope_falls_back_to_legacy() {
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    let signing = AuthoritySigningConfig {
        version: 1,
        required: false,
        verify_keys: vec![TEST_VERIFY_KEY.to_owned()],
    };
    let evidence = load_verified_recommendation_evidence_signed(
        &validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&signing),
    )
    .unwrap();
    let legacy =
        load_verified_recommendation_evidence(&validated, ROUTE_ID, &fixture.root, NOW_MS).unwrap();
    assert_eq!(
        serde_json::to_value(&legacy).unwrap(),
        serde_json::to_value(&evidence).unwrap()
    );
}

#[test]
fn recommendation_signing_not_required_and_present_invalid_signature_is_still_rejected() {
    // Consistent with the documented promotion semantics: `required: false` only tolerates an
    // *absent* envelope. A present-but-invalid envelope is never silently accepted.
    let fixture = PositiveFixture::create();
    let validated = recommendation_config(&fixture);
    write_private(
        &recommend_signature_sidecar_path(&fixture),
        RECOMMEND_ENVELOPE_INVALID_JSON.as_bytes(),
    );
    let signing = AuthoritySigningConfig {
        version: 1,
        required: false,
        verify_keys: vec![TEST_VERIFY_KEY.to_owned()],
    };
    let error = load_verified_recommendation_evidence_signed(
        &validated,
        ROUTE_ID,
        &fixture.root,
        &fixture.active,
        NOW_MS,
        Some(&signing),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("signature-invalid"),
        "expected the signature-invalid reason, got: {error}"
    );
}
