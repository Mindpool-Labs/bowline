use std::collections::BTreeMap;

use bowline_core::{
    billing::{BillingCurrency, BillingRow, ChargeBasis, UsdMicros, BILLING_SCHEMA_VERSION},
    economics::{
        analyze, annualize_micros, canonical_billing_rows_digest,
        canonical_quality_projection_digest, canonical_traffic_records_digest, float_usd_to_micros,
        ppm_within, ActionableEconomicsReport, AnalysisMode, Blocker, BuildProvenance, CostRate,
        EconomicsAnalysis, EconomicsInput, EconomicsRecord, EvidenceBindings, QualityJoinEvidence,
        QualityJoinIndex, QualitySourceBinding, ReconciliationState, ANALYSIS_SCHEMA_VERSION,
        MAX_ANALYSIS_DURATION_MS, MAX_ANALYSIS_RECORDS, MAX_ANALYSIS_RUNS, MAX_ANALYSIS_YAML_BYTES,
        MAX_COST_RATE_USD_PER_MTOK, MAX_DIMENSION_VALUE_BYTES, MAX_EVIDENCE_BINDING_BYTES,
        MAX_FEASIBLE_IDS, MAX_GENERAL_TAGS, MAX_QUALITY_SOURCE_BINDING_BYTES,
        MAX_RATE_CATALOG_ENTRIES, MAX_REPORT_ROWS, YEAR_MS,
    },
    quality::{
        GateResult, PromotionAssessment, PromotionGates, PromotionMetrics, PromotionVerdict,
        QualityEvidenceOverlay, QualityProtocol,
    },
    quality_report::{
        quality_report_v2_digest, QualityEvidenceOverlayV2, QualityReportV2,
        QUALITY_REPORT_SCHEMA_VERSION_V2,
    },
    quality_run::QualityProvenance,
    report::ReportDimensions,
    supply::TaskClass,
    traffic::{CoverageStatus, ProtocolKind},
};
use proptest::prelude::*;

fn digest(ch: char) -> String {
    let nibble = format!("{:x}", ch as u32 % 16);
    format!("sha256:{}", nibble.repeat(64))
}

fn analysis(mode: AnalysisMode) -> EconomicsAnalysis {
    EconomicsAnalysis {
        schema_version: ANALYSIS_SCHEMA_VERSION,
        as_of_ms: 2_000,
        traffic_run_id: "traffic-a".into(),
        mode,
        billing_run_id: (mode == AnalysisMode::BillingReconciled).then(|| "billing-a".into()),
        quality_run_ids: vec!["quality-a".into()],
        window_start_ms: 1_000,
        window_end_ms: 2_000,
        require_request_count: true,
        require_input_tokens: true,
        require_output_tokens: true,
        request_tolerance_ppm: 0,
        input_token_tolerance_ppm: 0,
        output_token_tolerance_ppm: 0,
        minimum_record_coverage_ppm: 1_000_000,
        minimum_qualified_charge_coverage_ppm: 1_000_000,
        maximum_charge_variance_ppm: 1_000_000,
        minimum_duration_ms: 1_000,
        minimum_supported_records: 1,
        annualize: true,
        representative_window_acknowledged: true,
    }
}

fn record(sequence: u64, actual: &str, candidate: &str) -> EconomicsRecord {
    EconomicsRecord {
        id: format!("record-{sequence}"),
        sequence,
        ts_ms: 1_100 + sequence,
        coverage_status: CoverageStatus::Supported,
        dimensions: ReportDimensions {
            app: "support".into(),
            team: "ops".into(),
            environment: "prod".into(),
            cost_center: "cc-1".into(),
            general_tags: vec!["region:east".into()],
            complete: true,
        },
        workload_identity_digest: digest('d'),
        task_class: TaskClass::Mechanical,
        protocol: ProtocolKind::ChatCompletions,
        actual_supply_id: Some(actual.into()),
        candidate_supply_id: Some(candidate.into()),
        recorded_feasible_ids: vec![actual.into(), candidate.into()],
        input_tokens: Some(1_000_000),
        output_tokens: Some(1_000_000),
        usage_observed: true,
        recorded_actual_cost_usd: Some(3.0),
    }
}

fn billing_row(id: &str, supply: &str, start: u64, end: u64, charge: &str) -> BillingRow {
    BillingRow {
        schema_version: BILLING_SCHEMA_VERSION,
        row_id: id.into(),
        period_start_ms: start,
        period_end_ms: end,
        supply_id: supply.into(),
        currency: BillingCurrency::USD,
        charge_basis: ChargeBasis::InferenceUsageNet,
        charge_usd_micros: UsdMicros::parse(charge).unwrap(),
        request_count: Some(1),
        input_tokens: Some(1_000_000),
        output_tokens: Some(1_000_000),
    }
}

fn bindings() -> EvidenceBindings {
    let report = quality_report("quality-a");
    let projection_digest = canonical_quality_projection_digest(&quality_entries(&report)).unwrap();
    let report_digest = quality_report_v2_digest(&report).unwrap();
    EvidenceBindings {
        analysis_digest: digest('a'),
        config_digest: digest('c'),
        recomputed_config_digest: digest('c'),
        traffic_records_digest: digest('t'),
        traffic_manifest_digest: digest('1'),
        recomputed_traffic_manifest_digest: digest('1'),
        traffic_recovery_digest: digest('2'),
        recomputed_traffic_recovery_digest: digest('2'),
        traffic_manifest_recovery_digest: digest('m'),
        recomputed_traffic_manifest_recovery_digest: digest('m'),
        billing_rows_digest: Some(digest('b')),
        billing_manifest_digest: Some(digest('3')),
        recomputed_billing_manifest_digest: Some(digest('3')),
        billing_recovery_digest: Some(digest('4')),
        recomputed_billing_recovery_digest: Some(digest('4')),
        billing_manifest_recovery_digest: Some(digest('5')),
        recomputed_billing_manifest_recovery_digest: Some(digest('5')),
        registry_digest: digest('r'),
        traffic_registry_digest: digest('r'),
        billing_registry_digest: Some(digest('r')),
        owned_cost_digest: digest('o'),
        traffic_owned_cost_digest: digest('o'),
        policy_digest: digest('p'),
        traffic_policy_digest: digest('p'),
        quality_sources: vec![QualitySourceBinding {
            run_id: "quality-a".into(),
            schema_version: 2,
            manifest_digest: digest('1'),
            recomputed_manifest_digest: digest('1'),
            outcomes_digest: digest('2'),
            recomputed_outcomes_digest: digest('2'),
            report_digest: report_digest.clone(),
            recomputed_report_digest: report_digest,
            registry_digest: digest('r'),
            owned_cost_digest: digest('o'),
            policy_digest: digest('p'),
            join_projection_digest: projection_digest,
        }],
        traffic_integrity_complete: true,
        billing_integrity_complete: true,
    }
}

#[test]
fn authoritative_report_names_and_binds_every_selected_evidence_source() {
    let input = input();
    let expected_records = input.bindings.traffic_records_digest.clone();
    let expected_rows = input.bindings.billing_rows_digest.clone().unwrap();
    let expected_quality = input.bindings.quality_sources.clone();
    let report = analyze(input).unwrap();
    assert_eq!(report.selected_evidence.traffic.run_id, "traffic-a");
    assert_eq!(
        report.selected_evidence.traffic.records_digest,
        expected_records
    );
    assert_eq!(
        report.selected_evidence.traffic.manifest_digest,
        digest('1')
    );
    assert_eq!(
        report.selected_evidence.traffic.recovery_digest,
        digest('2')
    );
    let billing = report.selected_evidence.billing.as_ref().unwrap();
    assert_eq!(billing.run_id, "billing-a");
    assert_eq!(billing.rows_digest, expected_rows);
    assert_eq!(billing.manifest_digest, digest('3'));
    assert_eq!(billing.recovery_digest, digest('4'));
    assert_eq!(report.selected_evidence.quality, expected_quality);

    let mut value = serde_json::to_value(&report).unwrap();
    value["selected_evidence"]["traffic"]["run_id"] = serde_json::json!("tampered");
    let tampered: ActionableEconomicsReport = serde_json::from_value(value).unwrap();
    assert_ne!(tampered.selected_evidence, report.selected_evidence);

    let mut oversized = report.selected_evidence.clone();
    oversized.quality = vec![expected_quality[0].clone(); MAX_ANALYSIS_RUNS + 1];
    assert!(oversized.validate().is_err());
    let mut duplicate = report.selected_evidence.clone();
    duplicate.quality.push(expected_quality[0].clone());
    assert!(duplicate.validate().is_err());
}

fn quality(run_id: &str) -> QualityJoinEvidence {
    QualityJoinEvidence {
        run_id: run_id.into(),
        schema_version: 2,
        completed_at_ms: 1_500,
        valid_until_ms: 2_500,
        workload_identity_digest: Some(digest('d')),
        task_class: TaskClass::Mechanical,
        protocol: ProtocolKind::ChatCompletions,
        candidate_supply_id: "owned/cheap".into(),
        effective_verdict: PromotionVerdict::Eligible,
        manifest_valid: true,
        outcomes_digest_valid: true,
        report_digest_valid: true,
    }
}

fn quality_report(run_id: &str) -> QualityReportV2 {
    let provenance = QualityProvenance {
        dataset_manifest_digest: digest('4'),
        cases_digest: digest('5'),
        dataset_digest: digest('6'),
        evaluator_digest: digest('7'),
        candidate_config_digest: digest('8'),
        policy_digest: digest('p'),
        registry_digest: digest('r'),
        owned_cost_digest: Some(digest('o')),
        judge_model_digest: None,
        judge_rubric_digest: None,
        judge_template_digest: None,
        judge_config_digest: None,
        judge_endpoint_digest: None,
        judge_authorization_reference_digest: None,
    };
    let evidence = QualityEvidenceOverlay {
        overlay_key: "quality-a:owned-cheap".into(),
        candidate_supply_id: "owned/cheap".into(),
        task_class: TaskClass::Mechanical,
        protocol: QualityProtocol::Chat,
        dataset_digest: provenance.dataset_digest.clone(),
        evaluator_digest: provenance.evaluator_digest.clone(),
        completed_at_ms: 1_500,
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
            blockers: vec![],
            metrics: PromotionMetrics {
                dispatched_attempts: 1,
                candidate_capacity_errors: 0,
                candidate_error_rate: Some(0.0),
                successful_latencies: 1,
                p95_latency_ms: Some(10),
                quality_sample_count: 1,
                quality_pass_count: 1,
                observed_pass_rate: Some(1.0),
                wilson_lower_95: Some(0.2),
                optional_evaluator_errors: 0,
                candidate_cost_usd: Some(1.0),
                judge_cost_usd: None,
            },
        },
    };
    QualityReportV2 {
        schema_version: QUALITY_REPORT_SCHEMA_VERSION_V2,
        run_id: run_id.into(),
        as_of_ms: 1_500,
        completed_at_ms: 1_500,
        valid_until_ms: 2_500,
        stale: false,
        clean_shutdown: true,
        cancelled: false,
        writer_healthy: true,
        reconciled: true,
        recorded_outcomes: 1,
        outcomes_digest: digest('2'),
        objective_evaluators: true,
        subjective_judge_configured: false,
        subjective_judge_required: false,
        provenance,
        workload_identity_digest: digest('d'),
        candidates: vec![QualityEvidenceOverlayV2 {
            workload_identity_digest: digest('d'),
            evidence,
        }],
    }
}

fn quality_entries(report: &QualityReportV2) -> Vec<QualityJoinEvidence> {
    report
        .candidates
        .iter()
        .map(|candidate| QualityJoinEvidence {
            run_id: report.run_id.clone(),
            schema_version: report.schema_version,
            completed_at_ms: report.completed_at_ms,
            valid_until_ms: report.valid_until_ms,
            workload_identity_digest: Some(candidate.workload_identity_digest.clone()),
            task_class: candidate.evidence.task_class,
            protocol: ProtocolKind::ChatCompletions,
            candidate_supply_id: candidate.evidence.candidate_supply_id.clone(),
            effective_verdict: candidate.evidence.assessment.effective_verdict,
            manifest_valid: true,
            outcomes_digest_valid: true,
            report_digest_valid: true,
        })
        .collect()
}

fn input() -> EconomicsInput {
    let analysis = analysis(AnalysisMode::BillingReconciled);
    let records = vec![record(1, "public/actual", "owned/cheap")];
    let billing_rows = vec![billing_row("row-1", "public/actual", 1_000, 2_000, "3")];
    let mut bindings = bindings();
    bindings.analysis_digest = analysis.digest().unwrap();
    bindings.traffic_records_digest = canonical_traffic_records_digest(&records).unwrap();
    bindings.billing_rows_digest = Some(canonical_billing_rows_digest(&billing_rows).unwrap());
    EconomicsInput {
        analysis,
        records,
        billing_rows,
        quality_reports: vec![quality_report("quality-a")],
        legacy_quality: vec![],
        build_provenance: BuildProvenance {
            package_version: "0.1.0-dev".into(),
            source_revision: "unavailable".into(),
        },
        rates: BTreeMap::from([
            (
                "public/actual".into(),
                CostRate {
                    input_per_mtok_usd: 1.0,
                    output_per_mtok_usd: 2.0,
                },
            ),
            (
                "owned/cheap".into(),
                CostRate {
                    input_per_mtok_usd: 0.25,
                    output_per_mtok_usd: 0.75,
                },
            ),
        ]),
        bindings,
    }
}

fn rebind_selected_values(input: &mut EconomicsInput) {
    input.bindings.traffic_records_digest =
        canonical_traffic_records_digest(&input.records).unwrap();
    input.bindings.billing_rows_digest = (input.analysis.mode == AnalysisMode::BillingReconciled)
        .then(|| canonical_billing_rows_digest(&input.billing_rows).unwrap());
}

fn rebind_quality_projection(input: &mut EconomicsInput) {
    input.bindings.quality_sources[0].join_projection_digest =
        canonical_quality_projection_digest(&quality_entries(&input.quality_reports[0])).unwrap();
}

fn rebind_quality_report(input: &mut EconomicsInput) {
    let digest = quality_report_v2_digest(&input.quality_reports[0]).unwrap();
    input.bindings.quality_sources[0].report_digest = digest.clone();
    input.bindings.quality_sources[0].recomputed_report_digest = digest;
    rebind_quality_projection(input);
}

#[test]
fn manifest_is_strict_and_mode_binds_billing() {
    let yaml = r#"
schema_version: 1
as_of_ms: 2000
traffic_run_id: traffic-a
mode: modeled-only
billing_run_id: billing-a
quality_run_ids: [quality-a]
window_start_ms: 1000
window_end_ms: 2000
require_request_count: true
require_input_tokens: true
require_output_tokens: true
request_tolerance_ppm: 0
input_token_tolerance_ppm: 0
output_token_tolerance_ppm: 0
minimum_record_coverage_ppm: 1000000
minimum_qualified_charge_coverage_ppm: 1000000
maximum_charge_variance_ppm: 1000000
minimum_duration_ms: 1000
minimum_supported_records: 1
annualize: true
representative_window_acknowledged: true
"#;
    assert!(EconomicsAnalysis::from_yaml(yaml).is_err());
    assert!(EconomicsAnalysis::from_yaml(&(yaml.to_owned() + "unknown: true\n")).is_err());

    let mut valid = analysis(AnalysisMode::ModeledOnly);
    valid.billing_run_id = None;
    valid.annualize = false;
    assert!(valid.validate().is_ok());
    valid.quality_run_ids.push("quality-a".into());
    assert!(valid.validate().is_err());
}

#[test]
fn manifest_yaml_bytes_are_bounded_before_parse() {
    let exact = format!("#{}\n", "x".repeat(MAX_ANALYSIS_YAML_BYTES - 2));
    assert_ne!(
        EconomicsAnalysis::from_yaml(&exact).unwrap_err().code(),
        "input-limit"
    );
    let over = format!("#{}\n", "x".repeat(MAX_ANALYSIS_YAML_BYTES - 1));
    assert_eq!(
        EconomicsAnalysis::from_yaml(&over).unwrap_err().code(),
        "input-limit"
    );
}

#[test]
fn manifest_enforces_time_causality_and_bounded_thresholds() {
    let mut value = analysis(AnalysisMode::BillingReconciled);
    value.window_end_ms = value.as_of_ms + 1;
    assert!(value.validate().is_err());
    value.window_end_ms = value.as_of_ms;
    value.request_tolerance_ppm = 1_000_001;
    assert!(value.validate().is_err());
    value.request_tolerance_ppm = 1_000_000;
    value.minimum_duration_ms = 0;
    assert!(value.validate().is_err());
}

#[test]
fn exact_tiling_rejects_gap_overlap_and_partial_boundaries() {
    let mut case = input();
    case.billing_rows = vec![
        billing_row("a", "public/actual", 1_000, 1_400, "1"),
        billing_row("b", "public/actual", 1_500, 2_000, "2"),
    ];
    assert_eq!(
        analyze(case).unwrap_err().code(),
        "billing-window-not-tiled"
    );

    let mut case = input();
    case.billing_rows[0].period_start_ms = 999;
    assert_eq!(
        analyze(case).unwrap_err().code(),
        "billing-window-not-tiled"
    );
}

#[test]
fn reconciliation_uses_exact_denominators_and_separate_charge_coverages() {
    let mut case = input();
    case.billing_rows
        .push(billing_row("row-empty", "public/unused", 1_000, 2_000, "1"));
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.eligible_records, 1);
    assert_eq!(report.reconciliation.matched_records, 1);
    assert_eq!(report.reconciliation.total_provider_rows, 2);
    assert_eq!(report.reconciliation.unmatched_provider_rows, 1);
    assert_eq!(report.reconciliation.request_delta, Some(-1));
    assert_eq!(report.reconciliation.input_token_delta, Some(-1_000_000));
    assert_eq!(report.reconciliation.output_token_delta, Some(-1_000_000));
    assert_eq!(report.reconciliation.request_count_available_rows, 2);
    assert_eq!(report.reconciliation.request_count_total_rows, 2);
    assert_eq!(report.reconciliation.input_token_available_rows, 2);
    assert_eq!(report.reconciliation.input_token_total_rows, 2);
    assert_eq!(report.reconciliation.output_token_available_rows, 2);
    assert_eq!(report.reconciliation.output_token_total_rows, 2);
    assert_eq!(report.reconciliation.rows.len(), 2);
    assert!(report.reconciliation.rows[0].present);
    assert!(report.reconciliation.rows[0].qualified);
    assert!(!report.reconciliation.rows[1].present);
    assert_eq!(report.reconciliation.record_coverage_ppm, Some(1_000_000));
    assert_eq!(
        report.reconciliation.row_presence_charge_coverage_ppm,
        Some(750_000)
    );
    assert_eq!(
        report.reconciliation.qualified_charge_coverage_ppm,
        Some(750_000)
    );
}

#[test]
fn absent_provider_counts_remain_absent_with_explicit_availability() {
    let mut case = input();
    let mut absent = billing_row("row-empty", "public/unused", 1_000, 2_000, "1");
    absent.request_count = None;
    absent.input_tokens = None;
    absent.output_tokens = None;
    case.billing_rows.push(absent);
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.request_delta, None);
    assert_eq!(report.reconciliation.input_token_delta, None);
    assert_eq!(report.reconciliation.output_token_delta, None);
    assert_eq!(report.reconciliation.request_count_available_rows, 1);
    assert_eq!(report.reconciliation.request_count_total_rows, 2);
    assert_eq!(report.reconciliation.input_token_available_rows, 1);
    assert_eq!(report.reconciliation.output_token_available_rows, 1);
}

#[test]
fn required_counts_and_inclusive_tolerance_control_qualification() {
    let mut case = input();
    case.analysis.request_tolerance_ppm = 500_000;
    case.billing_rows[0].request_count = Some(2);
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.qualified_provider_rows, 1);

    let mut case = input();
    case.billing_rows[0].input_tokens = None;
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.qualified_provider_rows, 0);
    assert!(report
        .reconciliation
        .exceptions
        .iter()
        .any(|e| e.code == "required-count-missing"));
}

#[test]
fn zero_denominators_are_explicit_not_complete_zeroes() {
    assert!(ppm_within(0, 0, 0).unwrap());
    assert!(!ppm_within(1, 0, 1_000_000).unwrap());
    let mut case = input();
    case.billing_rows[0].charge_usd_micros = UsdMicros::parse("0").unwrap();
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.row_presence_charge_coverage_ppm, None);
    assert_eq!(report.reconciliation.qualified_charge_coverage_ppm, None);
    assert_eq!(report.reconciliation.charge_variance_ppm, None);
    assert_eq!(report.reconciliation.state, ReconciliationState::Incomplete);
}

#[test]
fn quality_index_rejects_duplicates_and_old_or_invalid_evidence_blocks() {
    assert!(QualityJoinIndex::new(&[quality("quality-a"), quality("quality-b")], 2_000).is_err());
    let mut case = input();
    case.quality_reports[0].valid_until_ms = 1_999;
    case.quality_reports[0].candidates[0]
        .evidence
        .valid_until_ms = 1_999;
    rebind_quality_report(&mut case);
    let report = analyze(case).unwrap();
    assert!(report.opportunities[0]
        .blockers
        .contains(&Blocker::QualityStale));
    assert!(!report.opportunities[0].eligible);

    let mut invalid = quality("quality-a");
    invalid.schema_version = 1;
    invalid.workload_identity_digest = Some(digest('d'));
    assert!(QualityJoinIndex::new(&[invalid], 2_000).is_err());
}

#[test]
fn selected_schema_v1_quality_is_nonjoinable_without_fabricated_workload_identity() {
    let mut case = input();
    case.quality_reports.clear();
    case.legacy_quality = vec![QualityJoinEvidence {
        run_id: "quality-a".into(),
        schema_version: 1,
        completed_at_ms: 1_500,
        valid_until_ms: 2_500,
        workload_identity_digest: None,
        task_class: TaskClass::Mechanical,
        protocol: ProtocolKind::ChatCompletions,
        candidate_supply_id: "owned/cheap".into(),
        effective_verdict: PromotionVerdict::Eligible,
        manifest_valid: true,
        outcomes_digest_valid: true,
        report_digest_valid: true,
    }];
    case.bindings.quality_sources[0].schema_version = 1;
    let report = analyze(case).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::QualityNonJoinable));
}

#[test]
fn build_provenance_is_authoritative_report_data() {
    let report = analyze(input()).unwrap();
    assert_eq!(report.build_provenance.package_version, "0.1.0-dev");
    assert_eq!(report.build_provenance.source_revision, "unavailable");
    assert!(serde_json::to_string(&report)
        .unwrap()
        .contains("build_provenance"));
}

#[test]
fn source_binding_matrix_mismatches_block_without_becoming_signatures() {
    let mut case = input();
    case.bindings.quality_sources[0].policy_digest = digest('x');
    let report = analyze(case).unwrap();
    assert!(report
        .source_bindings
        .iter()
        .all(|binding| binding.kind == "checksum"));
    assert!(report
        .global_blockers
        .contains(&Blocker::PolicyDigestMismatch));
    assert!(report.opportunities.iter().all(|row| !row.eligible));
}

#[test]
fn selected_value_mutation_after_binding_is_detected_by_core_recomputation() {
    let mut traffic = input();
    traffic.records[0].id = "record-mutated".into();
    let report = analyze(traffic).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::SourceChecksumMismatch));

    let mut billing = input();
    billing.billing_rows[0].charge_usd_micros = UsdMicros::parse("4").unwrap();
    let report = analyze(billing).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::SourceChecksumMismatch));
}

#[test]
fn config_and_billing_manifest_recovery_checksums_are_bound() {
    let mut case = input();
    case.bindings.recomputed_config_digest = digest('8');
    case.bindings.recomputed_billing_manifest_recovery_digest = Some(digest('9'));
    let report = analyze(case).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::SourceChecksumMismatch));
    assert!(report.source_bindings.iter().any(|binding| {
        binding.source == "config" && binding.field == "configuration" && !binding.matched
    }));
    assert!(report.source_bindings.iter().any(|binding| {
        binding.source == "billing" && binding.field == "manifest-recovery" && !binding.matched
    }));
}

#[test]
fn quality_manifest_outcomes_report_and_schema_are_bound_independently() {
    let mut case = input();
    case.bindings.quality_sources[0].recomputed_outcomes_digest = digest('9');
    let report = analyze(case).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::SourceChecksumMismatch));
    assert!(report.source_bindings.iter().any(|binding| {
        binding.source == "quality-a" && binding.field == "outcomes" && !binding.matched
    }));

    let mut case = input();
    case.bindings.quality_sources[0].schema_version = 1;
    let report = analyze(case).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::QualityNonJoinable));
}

#[test]
fn quality_join_projection_mutations_are_bound_to_the_verified_source() {
    type ReportMutation = Box<dyn Fn(&mut QualityReportV2)>;
    let mutations: Vec<ReportMutation> = vec![
        Box::new(|r| {
            r.candidates[0].evidence.assessment.completion_verdict =
                PromotionVerdict::QualityFailed;
            r.candidates[0].evidence.assessment.effective_verdict = PromotionVerdict::QualityFailed;
        }),
        Box::new(|r| {
            r.workload_identity_digest = digest('9');
            r.candidates[0].workload_identity_digest = digest('9');
        }),
        Box::new(|r| r.candidates[0].evidence.candidate_supply_id = "owned/other".into()),
        Box::new(|r| r.candidates[0].evidence.task_class = TaskClass::Judgment),
        Box::new(|r| r.candidates[0].evidence.protocol = QualityProtocol::Responses),
        Box::new(|r| {
            r.as_of_ms = 1_499;
            r.completed_at_ms = 1_499;
            r.candidates[0].evidence.completed_at_ms = 1_499;
        }),
        Box::new(|r| {
            r.valid_until_ms = 2_499;
            r.candidates[0].evidence.valid_until_ms = 2_499;
        }),
        Box::new(|r| r.run_id = "quality-other".into()),
        Box::new(|r| r.schema_version = 3),
    ];
    for mutate in mutations {
        let mut case = input();
        mutate(&mut case.quality_reports[0]);
        let outcome = analyze(case);
        assert!(
            outcome.as_ref().is_err_and(|error| matches!(
                error.code(),
                "quality-run-mismatch" | "invalid-quality-evidence"
            )) || outcome.as_ref().is_ok_and(|report| report
                .global_blockers
                .contains(&Blocker::QualityEvidenceMismatch)),
            "mutation unexpectedly remained trusted: {outcome:?}"
        );
    }
}

#[test]
fn mutating_report_and_rebinding_projection_still_requires_the_verified_report_digest() {
    let mut case = input();
    case.quality_reports[0].candidates[0]
        .evidence
        .assessment
        .completion_verdict = PromotionVerdict::QualityFailed;
    case.quality_reports[0].candidates[0]
        .evidence
        .assessment
        .effective_verdict = PromotionVerdict::QualityFailed;
    rebind_quality_projection(&mut case);
    let report = analyze(case).unwrap();
    assert!(report
        .global_blockers
        .contains(&Blocker::SourceChecksumMismatch));
    assert!(report.source_bindings.iter().any(|binding| {
        binding.source == "quality-a" && binding.field == "report-document" && !binding.matched
    }));
}

#[test]
fn missing_observed_usage_never_qualifies_reconciliation_as_zero() {
    let mut case = input();
    case.records[0].usage_observed = false;
    case.records[0].input_tokens = None;
    case.records[0].output_tokens = None;
    case.billing_rows[0].request_count = Some(1);
    case.billing_rows[0].input_tokens = Some(0);
    case.billing_rows[0].output_tokens = Some(0);
    case.billing_rows[0].charge_usd_micros = UsdMicros::parse("0").unwrap();
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.modeled_actual_cost_micros, None);
    assert!(!report.reconciliation.rows[0].qualified);
    assert!(report
        .reconciliation
        .exceptions
        .iter()
        .any(|exception| exception.code == "row-economics-incomplete"));
    assert_eq!(report.reconciliation.state, ReconciliationState::Incomplete);
}

#[test]
fn opposing_row_charge_variances_cannot_cancel_into_qualification() {
    let mut case = input();
    case.analysis.maximum_charge_variance_ppm = 100_000;
    case.bindings.analysis_digest = case.analysis.digest().unwrap();
    let mut second = record(2, "public/actual", "owned/cheap");
    second.ts_ms = 1_600;
    case.records.push(second);
    case.billing_rows = vec![
        billing_row("row-a", "public/actual", 1_000, 1_500, "2"),
        billing_row("row-b", "public/actual", 1_500, 2_000, "4"),
    ];
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.charge_variance_micros, Some(0));
    assert!(report.reconciliation.rows.iter().all(|row| !row.qualified));
    assert_eq!(
        report
            .reconciliation
            .exceptions
            .iter()
            .filter(|exception| exception.code == "row-charge-variance-exceeded")
            .count(),
        2
    );
    assert_eq!(report.reconciliation.state, ReconciliationState::Incomplete);
}

#[test]
fn charge_variance_gate_uses_exact_cross_products_not_truncated_ppm() {
    let mut case = input();
    case.analysis.maximum_charge_variance_ppm = 1;
    case.billing_rows[0].charge_usd_micros = UsdMicros::parse("3.000004").unwrap();
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.charge_variance_ppm, Some(1));
    assert_eq!(report.reconciliation.state, ReconciliationState::Incomplete);
}

#[test]
fn a_group_with_mixed_workload_identities_cannot_reuse_first_quality_join() {
    let mut case = input();
    let mut second = record(2, "public/actual", "owned/cheap");
    second.workload_identity_digest = digest('5');
    case.records.push(second);
    case.billing_rows[0].request_count = Some(2);
    case.billing_rows[0].input_tokens = Some(2_000_000);
    case.billing_rows[0].output_tokens = Some(2_000_000);
    case.billing_rows[0].charge_usd_micros = UsdMicros::parse("6").unwrap();
    let report = analyze(case).unwrap();
    assert!(
        report.opportunities[0]
            .blockers
            .contains(&Blocker::QualityEvidenceMismatch),
        "{:?}",
        report.opportunities
    );
    assert!(!report.opportunities[0].eligible);
}

#[test]
fn per_record_ties_even_and_actual_parity_exclude_shadow_estimate() {
    assert_eq!(float_usd_to_micros(0.000_000_5).unwrap(), 0);
    assert_eq!(float_usd_to_micros(0.000_001_5).unwrap(), 2);
    assert_eq!(float_usd_to_micros(0.000_002_5).unwrap(), 2);
    let mut case = input();
    case.records[0].recorded_actual_cost_usd = Some(3.000_001);
    let report = analyze(case).unwrap();
    assert!(report.opportunities[0]
        .blockers
        .contains(&Blocker::RecordedActualCostMismatch));
    assert_eq!(report.reconciliation.state, ReconciliationState::Incomplete);
    assert!(!report.reconciliation.rows[0].qualified);
    assert!(report.reconciliation.exceptions.iter().any(|exception| {
        exception.code == "recorded-actual-cost-mismatch"
            && exception.record_id.as_deref() == Some("record-1")
    }));
    assert_eq!(report.dimensions[0].modeled_actual_cost_micros, None);
    assert!(!report.complete);
}

#[test]
fn rebound_recorded_actual_cost_mismatch_remains_reconciliation_incomplete() {
    let mut case = input();
    case.records[0].recorded_actual_cost_usd = Some(3.000_001);
    rebind_selected_values(&mut case);
    let report = analyze(case).unwrap();
    assert_eq!(report.reconciliation.state, ReconciliationState::Incomplete);
    assert_eq!(report.reconciliation.qualified_provider_rows, 0);
    assert_eq!(report.reconciliation.qualified_imported_charge_micros, 0);
    assert_eq!(report.dimensions[0].modeled_actual_cost_micros, None);
}

#[test]
fn float_micro_conversion_rejects_the_exclusive_two_to_64_boundary() {
    let exclusive_micros = 2_f64.powi(64);
    let exclusive_usd = exclusive_micros / 1_000_000.0;
    assert!(float_usd_to_micros(exclusive_usd).is_err());

    let adjacent_usd = f64::from_bits(exclusive_usd.to_bits() - 1);
    assert!(float_usd_to_micros(adjacent_usd).is_ok());
}

#[test]
fn modeled_only_is_never_eligible_or_annualized() {
    let mut case = input();
    case.analysis = analysis(AnalysisMode::ModeledOnly);
    case.analysis.billing_run_id = None;
    case.analysis.annualize = false;
    case.billing_rows.clear();
    case.bindings.billing_rows_digest = None;
    case.bindings.billing_manifest_digest = None;
    case.bindings.recomputed_billing_manifest_digest = None;
    case.bindings.billing_recovery_digest = None;
    case.bindings.recomputed_billing_recovery_digest = None;
    case.bindings.billing_manifest_recovery_digest = None;
    case.bindings.recomputed_billing_manifest_recovery_digest = None;
    case.bindings.billing_registry_digest = None;
    let report = analyze(case).unwrap();
    assert!(!report.opportunities[0].eligible);
    assert_eq!(report.opportunities[0].annualized_delta_micros, None);
    assert!(report.opportunities[0]
        .blockers
        .contains(&Blocker::ModeledOnly));
    assert!(report.opportunities[0]
        .blockers
        .contains(&Blocker::BillingNotRequested));
}

#[test]
fn billing_reconciled_eligibility_does_not_require_optional_annualization() {
    let mut case = input();
    case.analysis.annualize = false;
    case.bindings.analysis_digest = case.analysis.digest().unwrap();
    let report = analyze(case).unwrap();
    assert!(report.opportunities[0].eligible);
    assert_eq!(report.opportunities[0].annualized_delta_micros, None);
    assert!(report.opportunities[0]
        .blockers
        .contains(&Blocker::AnnualizationNotRequested));
}

#[test]
fn known_tokens_remain_visible_when_price_is_unknown() {
    let mut case = input();
    case.rates.remove("owned/cheap");
    let report = analyze(case).unwrap();
    assert_eq!(report.opportunities[0].input_tokens, Some(1_000_000));
    assert_eq!(report.opportunities[0].output_tokens, Some(1_000_000));
    assert_eq!(report.opportunities[0].candidate_cost_micros, None);
    assert!(report.opportunities[0]
        .blockers
        .contains(&Blocker::PriceUnknown));
}

#[test]
fn historical_policy_violation_uses_the_stable_recorded_feasible_set_reason() {
    let mut case = input();
    case.records[0]
        .recorded_feasible_ids
        .retain(|id| id != "public/actual");
    let report = analyze(case).unwrap();
    assert_eq!(
        report.opportunities[0].policy_violation_reason.as_deref(),
        Some("actual-supply-not-in-recorded-feasible-set")
    );
}

#[test]
fn dimension_breakdowns_include_task_protocol_and_exact_actual_supply() {
    let mut case = input();
    case.analysis = analysis(AnalysisMode::ModeledOnly);
    case.analysis.billing_run_id = None;
    case.analysis.annualize = false;
    let mut second = record(2, "owned/cheap", "public/actual");
    second.task_class = TaskClass::Judgment;
    second.protocol = ProtocolKind::Responses;
    second.recorded_actual_cost_usd = Some(1.0);
    case.records.push(second);
    case.billing_rows.clear();
    case.bindings.billing_rows_digest = None;
    case.bindings.billing_manifest_digest = None;
    case.bindings.recomputed_billing_manifest_digest = None;
    case.bindings.billing_recovery_digest = None;
    case.bindings.recomputed_billing_recovery_digest = None;
    case.bindings.billing_manifest_recovery_digest = None;
    case.bindings.recomputed_billing_manifest_recovery_digest = None;
    case.bindings.billing_registry_digest = None;
    case.bindings.analysis_digest = case.analysis.digest().unwrap();
    case.bindings.traffic_records_digest = canonical_traffic_records_digest(&case.records).unwrap();
    let report = analyze(case).unwrap();
    assert_eq!(report.dimensions.len(), 2);
    assert_eq!(report.dimensions[0].task_class, TaskClass::Mechanical);
    assert_eq!(report.dimensions[0].protocol, ProtocolKind::ChatCompletions);
    assert_eq!(report.dimensions[0].actual_supply_id, "public/actual");
    assert_eq!(report.dimensions[1].task_class, TaskClass::Judgment);
    assert_eq!(report.dimensions[1].protocol, ProtocolKind::Responses);
    assert_eq!(report.dimensions[1].actual_supply_id, "owned/cheap");
}

#[test]
fn manifest_minima_and_run_references_enforce_compiled_maxima() {
    let mut value = analysis(AnalysisMode::BillingReconciled);
    value.minimum_duration_ms = MAX_ANALYSIS_DURATION_MS + 1;
    assert!(value.validate().is_err());

    let mut value = analysis(AnalysisMode::BillingReconciled);
    value.minimum_supported_records = MAX_ANALYSIS_RECORDS as u64 + 1;
    assert!(value.validate().is_err());

    let mut value = analysis(AnalysisMode::BillingReconciled);
    value.quality_run_ids = (0..=MAX_ANALYSIS_RUNS)
        .map(|index| format!("quality-{index}"))
        .collect();
    assert!(value.validate().is_err());
}

#[test]
fn evidence_binding_strings_and_aggregate_bytes_are_bounded() {
    let mut invalid_digest = input();
    invalid_digest.bindings.registry_digest = "sha256:xyz".into();
    assert_eq!(
        analyze(invalid_digest).unwrap_err().code(),
        "invalid-evidence-binding"
    );

    let mut invalid_run = input();
    invalid_run.bindings.quality_sources[0].run_id = "../quality".into();
    assert_eq!(
        analyze(invalid_run).unwrap_err().code(),
        "invalid-evidence-binding"
    );

    let mut exact_aggregate = input();
    exact_aggregate.bindings.quality_sources = (0..MAX_ANALYSIS_RUNS)
        .map(|index| {
            let mut source = exact_aggregate.bindings.quality_sources[0].clone();
            let prefix = format!("q{index:03}-");
            source.run_id = format!("{prefix}{}", "x".repeat(128 - prefix.len()));
            source
        })
        .collect();
    exact_aggregate.analysis.quality_run_ids = exact_aggregate
        .bindings
        .quality_sources
        .iter()
        .map(|source| source.run_id.clone())
        .collect();
    exact_aggregate.quality_reports.clear();
    exact_aggregate.legacy_quality = exact_aggregate
        .analysis
        .quality_run_ids
        .iter()
        .map(|run_id| {
            let mut evidence = quality_entries(&quality_report(run_id))[0].clone();
            evidence.schema_version = 1;
            evidence.workload_identity_digest = None;
            evidence.candidate_supply_id = run_id.clone();
            evidence
        })
        .collect();
    for source in &mut exact_aggregate.bindings.quality_sources {
        source.schema_version = 1;
    }
    exact_aggregate.bindings.analysis_digest = exact_aggregate.analysis.digest().unwrap();
    assert!(exact_aggregate
        .bindings
        .quality_sources
        .iter()
        .all(|source| {
            source.run_id.len() + 10 * digest('a').len() == MAX_QUALITY_SOURCE_BINDING_BYTES
        }));
    assert_eq!(
        24 * digest('a').len() + MAX_ANALYSIS_RUNS * MAX_QUALITY_SOURCE_BINDING_BYTES,
        MAX_EVIDENCE_BINDING_BYTES
    );
    let exact_result = analyze(exact_aggregate.clone());
    assert!(exact_result.is_ok(), "{exact_result:?}");

    let mut over_aggregate = exact_aggregate;
    over_aggregate
        .bindings
        .quality_sources
        .push(over_aggregate.bindings.quality_sources[0].clone());
    assert_eq!(analyze(over_aggregate).unwrap_err().code(), "input-limit");
}

#[test]
fn record_dimensions_tags_and_feasible_ids_enforce_bounds_and_uniqueness() {
    let mut case = input();
    case.records[0].dimensions.app = "x".repeat(MAX_DIMENSION_VALUE_BYTES + 1);
    assert_eq!(analyze(case).unwrap_err().code(), "invalid-record");

    let mut case = input();
    case.records[0].dimensions.general_tags = (0..=MAX_GENERAL_TAGS)
        .map(|index| format!("tag-{index:04}"))
        .collect();
    assert_eq!(analyze(case).unwrap_err().code(), "invalid-record");

    let mut case = input();
    case.records[0].recorded_feasible_ids = (0..=MAX_FEASIBLE_IDS)
        .map(|index| format!("supply-{index}"))
        .collect();
    assert_eq!(analyze(case).unwrap_err().code(), "invalid-record");

    let mut case = input();
    case.records[0].recorded_feasible_ids = vec!["owned/cheap".into(), "owned/cheap".into()];
    assert_eq!(analyze(case).unwrap_err().code(), "invalid-record");
}

#[test]
fn rate_catalog_and_report_grouping_enforce_compiled_bounds() {
    let mut case = input();
    case.rates.insert(
        "too-expensive".into(),
        CostRate {
            input_per_mtok_usd: MAX_COST_RATE_USD_PER_MTOK + 1.0,
            output_per_mtok_usd: 0.0,
        },
    );
    assert_eq!(analyze(case).unwrap_err().code(), "invalid-cost-rate");

    let mut case = input();
    case.rates = (0..=MAX_RATE_CATALOG_ENTRIES)
        .map(|index| {
            (
                format!("rate-{index}"),
                CostRate {
                    input_per_mtok_usd: 1.0,
                    output_per_mtok_usd: 1.0,
                },
            )
        })
        .collect();
    assert_eq!(analyze(case).unwrap_err().code(), "input-limit");

    let mut case = input();
    case.records = (1..=MAX_REPORT_ROWS as u64 + 1)
        .map(|sequence| {
            let mut value = record(sequence, "public/actual", "owned/cheap");
            value.ts_ms = 1_100;
            value.dimensions.app = format!("app-{sequence}");
            value
        })
        .collect();
    case.bindings.traffic_records_digest = canonical_traffic_records_digest(&case.records).unwrap();
    assert_eq!(analyze(case).unwrap_err().code(), "report-row-limit");
}

#[test]
fn reconciliation_row_cap_accepts_exact_max_and_rejects_provider_row_max_plus_one() {
    let mut case = input();
    let mut rows = vec![billing_row(
        "row-actual",
        "public/actual",
        1_000,
        2_000,
        "3",
    )];
    rows.extend((1..MAX_REPORT_ROWS).map(|index| {
        let mut row = billing_row(
            &format!("row-{index:04}"),
            &format!("provider-only-{index:04}"),
            1_000,
            2_000,
            "0",
        );
        row.request_count = Some(0);
        row.input_tokens = Some(0);
        row.output_tokens = Some(0);
        row
    }));
    case.billing_rows = rows;
    rebind_selected_values(&mut case);
    let report = analyze(case.clone()).unwrap();
    assert_eq!(report.reconciliation.rows.len(), MAX_REPORT_ROWS);
    assert_eq!(report.reconciliation.exceptions.len(), MAX_REPORT_ROWS - 1);

    case.billing_rows.push(billing_row(
        "row-over",
        "provider-only-over",
        1_000,
        2_000,
        "0",
    ));
    assert_eq!(analyze(case).unwrap_err().code(), "report-row-limit");
}

#[test]
fn reconciliation_exception_cap_counts_traffic_and_row_exceptions_without_truncation() {
    let mut case = input();
    case.billing_rows[0].request_count = Some(2);
    case.records
        .extend((2..=MAX_REPORT_ROWS as u64).map(|sequence| {
            let mut value = record(sequence, "public/actual", "owned/cheap");
            value.ts_ms = 1_200;
            value.actual_supply_id = None;
            value
        }));
    rebind_selected_values(&mut case);
    let report = analyze(case.clone()).unwrap();
    assert_eq!(report.reconciliation.exceptions.len(), MAX_REPORT_ROWS);
    assert_eq!(
        report
            .reconciliation
            .exceptions
            .iter()
            .filter(|exception| exception.code == "missing-attribution")
            .count(),
        MAX_REPORT_ROWS - 1
    );
    assert!(report
        .reconciliation
        .exceptions
        .iter()
        .any(|exception| exception.code == "count-tolerance-exceeded"));

    let mut over = record(MAX_REPORT_ROWS as u64 + 1, "public/actual", "owned/cheap");
    over.ts_ms = 1_200;
    over.actual_supply_id = None;
    case.records.push(over);
    assert_eq!(analyze(case).unwrap_err().code(), "report-row-limit");
}

#[test]
fn annualization_is_checked_ties_even_and_uses_exact_year() {
    assert_eq!(YEAR_MS, 31_556_952_000);
    assert_eq!(annualize_micros(1, 2, 1).unwrap(), 0);
    assert_eq!(annualize_micros(3, 2, 1).unwrap(), 2);
    assert!(annualize_micros(i128::MAX, YEAR_MS, 1).is_err());
}

#[test]
fn happy_path_is_eligible_ranked_and_canonical() {
    let report = analyze(input()).unwrap();
    assert!(report.complete, "{:?}", report.global_blockers);
    assert_eq!(report.reconciliation.rows[0].request_delta, Some(0));
    assert_eq!(report.reconciliation.rows[0].input_token_delta, Some(0));
    assert_eq!(report.reconciliation.rows[0].output_token_delta, Some(0));
    assert!(
        report.opportunities[0].eligible,
        "{:?}",
        report.opportunities[0]
    );
    assert_eq!(
        report.opportunities[0].observed_delta_micros,
        Some(2_000_000)
    );
    assert_eq!(
        report.opportunities[0].annualized_delta_micros,
        Some(63_113_904_000_000)
    );
    let json = serde_json::to_string(&report).unwrap();
    let decoded: ActionableEconomicsReport = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, report);
}

proptest! {
    #[test]
    fn record_permutation_is_report_invariant(keys in prop::array::uniform3(any::<u64>())) {
        let mut base = input();
        base.records = vec![
            record(1, "public/actual", "owned/cheap"),
            record(2, "public/actual", "owned/cheap"),
            record(3, "public/actual", "owned/cheap"),
        ];
        base.billing_rows[0].request_count = Some(3);
        base.billing_rows[0].input_tokens = Some(3_000_000);
        base.billing_rows[0].output_tokens = Some(3_000_000);
        base.billing_rows[0].charge_usd_micros = UsdMicros::parse("9").unwrap();
        let expected = analyze(base.clone()).unwrap();
        let mut permutation = [(keys[0], 0usize), (keys[1], 1usize), (keys[2], 2usize)];
        permutation.sort_unstable();
        base.records = permutation
            .into_iter()
            .map(|(_, index)| base.records[index].clone())
            .collect();
        prop_assert_eq!(analyze(base).unwrap(), expected);
    }

    #[test]
    fn checked_cost_aggregation_never_wraps(value in 0u64..=u64::MAX) {
        let sum = (value as i128).checked_add(value as i128);
        prop_assert!(sum.is_some());
        prop_assert!(sum.unwrap() >= 0);
    }
}
