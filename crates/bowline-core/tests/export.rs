use std::collections::{BTreeMap, BTreeSet};

use bowline_core::{
    decision::{Placement, QualityFloors},
    export::build_evidence_bundle_v1,
    ledger::{ActualOutcome, DecisionRecord, RecoveryOutcome, UsageSource},
    policy::WorkloadIdentity,
    report::compute_run_report,
    run::RunManifest,
    supply::{Price, Registry, Retention, SupplyAttributes, SupplyClass, SupplyEntry, TaskClass},
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};

#[test]
fn evidence_decision_projection_is_exact_and_content_safe() {
    let manifest = manifest();
    let record = record();
    let registry = registry();
    let report = compute_run_report(
        std::slice::from_ref(&record),
        &[RecoveryOutcome::Clean { records: 1 }],
        &manifest,
        &registry,
        &Default::default(),
        &QualityFloors::default(),
        Some("supply/actual"),
    )
    .unwrap();
    let report_value = serde_json::to_value(&report).unwrap();

    let bundle =
        build_evidence_bundle_v1(&manifest, &[record], &registry.feed_version, report).unwrap();
    let value = serde_json::to_value(&bundle).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/evidence-bundle-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    if let Err(errors) = validator.validate(&value) {
        panic!(
            "evidence bundle failed schema validation: {}",
            errors
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let decision = value["decisions"][0].as_object().unwrap();
    let keys = decision.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from([
            "actual_est_cost_usd".to_string(),
            "actual_supply_id".to_string(),
            "coverage_reason".to_string(),
            "coverage_status".to_string(),
            "decision_ref".to_string(),
            "observation_source".to_string(),
            "observed_at_ms".to_string(),
            "policy_exposure".to_string(),
            "protocol".to_string(),
            "sequence".to_string(),
            "shadow_est_cost_usd".to_string(),
            "shadow_supply_id".to_string(),
            "task_class".to_string(),
        ])
    );
    assert_eq!(decision["decision_ref"], "fixture-run:1");
    assert_eq!(value["aggregates"], report_value);
    assert_eq!(
        value["coverage"]["protocol_coverage"],
        value["aggregates"]["protocol_coverage"]
    );

    let encoded = serde_json::to_string(&bundle).unwrap();
    for forbidden in [
        "SENTINEL-REQUEST-ID",
        "SENTINEL-ROUTE",
        "SENTINEL-APP",
        "SENTINEL-TAG",
        "SENTINEL-API-KEY",
        "SENTINEL-UPSTREAM",
        "SENTINEL-MODEL",
        "SENTINEL-ATTRIBUTION",
        "SENTINEL-CONTENT",
        "SENTINEL-AUTHORIZATION",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "export leaked forbidden source value {forbidden}"
        );
    }
}

fn manifest() -> RunManifest {
    RunManifest {
        schema_version: 1,
        run_id: "fixture-run".into(),
        started_at_ms: 1_783_785_600_000,
        ended_at_ms: Some(1_783_785_600_500),
        clean_shutdown: true,
        policy_digest: digest('a'),
        registry_digest: digest('b'),
        attribution_digest: Some(digest('c')),
        owned_cost_digest: Some(digest('d')),
        passive_profile_digest: Some(digest('e')),
        passive_input_digest: Some(digest('f')),
        accepted: 1,
        recorded: 1,
        dropped: 0,
        truncated: 0,
        unmapped: 0,
        unpriceable: 0,
        untrusted_identity_headers: 0,
        next_sequence: 2,
        writer_healthy: true,
        writer_error: None,
        last_flush_at_ms: Some(1_783_785_600_500),
        segment_bytes: 64 * 1024,
        max_segments: 8,
        segments: vec!["run-fixture-run-000001.bwl".into()],
        segment_inventory: Vec::new(),
        records_digest: Some(digest('1')),
    }
}

fn record() -> DecisionRecord {
    DecisionRecord {
        id: "SENTINEL-REQUEST-ID".into(),
        ts_ms: 1_783_785_600_123,
        run_id: Some("fixture-run".into()),
        sequence: Some(1),
        accounting_truncated: false,
        protocol: ProtocolKind::Responses,
        observation_source: ObservationSource::Passive,
        coverage_status: CoverageStatus::Supported,
        coverage_reason: None,
        identity: WorkloadIdentity {
            api_key_digest: Some("SENTINEL-API-KEY".into()),
            route: "/SENTINEL-ROUTE".into(),
            app: Some("SENTINEL-APP".into()),
            tags: vec!["SENTINEL-TAG".into(), "SENTINEL-CONTENT".into()],
        },
        decision: bowline_core::decision::Decision {
            policy_digest: digest('a'),
            task_class: TaskClass::Mechanical,
            feasible_ids: vec!["supply/actual".into(), "supply/selected".into()],
            floor: 0.3,
            shadow: Some(Placement {
                supply_id: "supply/selected".into(),
                est_cost_usd: Some(0.0004),
            }),
        },
        actual: ActualOutcome {
            upstream: "https://SENTINEL-UPSTREAM.invalid".into(),
            supply_id: Some("supply/actual".into()),
            model: Some("SENTINEL-MODEL".into()),
            status: 200,
            streamed: false,
            latency_ms: 25,
            input_tokens: Some(100),
            output_tokens: Some(50),
            usage_source: UsageSource::Observed,
            est_cost_usd: Some(0.001),
            attribution_status: bowline_core::attribution::AttributionStatus::Attributed,
            attribution_source: bowline_core::attribution::AttributionSource::InlineResponseHeader,
            attribution_reference: Some(bowline_core::attribution::AttributionRef {
                namespace: "fixture".into(),
                value: "SENTINEL-ATTRIBUTION".into(),
            }),
            attribution_reason: Some("SENTINEL-AUTHORIZATION".into()),
        },
    }
}

fn registry() -> Registry {
    Registry {
        note: None,
        feed_version: "fixture-v1".into(),
        entries: vec![
            entry(
                "supply/actual",
                SupplyClass::PublicApi,
                Some(Price {
                    input_per_mtok_usd: 10.0,
                    output_per_mtok_usd: 20.0,
                }),
            ),
            entry(
                "supply/selected",
                SupplyClass::PublicApi,
                Some(Price {
                    input_per_mtok_usd: 4.0,
                    output_per_mtok_usd: 4.0,
                }),
            ),
        ],
    }
}

fn entry(id: &str, class: SupplyClass, price: Option<Price>) -> SupplyEntry {
    SupplyEntry {
        id: id.into(),
        model: format!("{id}-model"),
        aliases: Vec::new(),
        location: "fixture".into(),
        attributes: SupplyAttributes {
            class,
            jurisdiction: "us".into(),
            retention: Retention::None,
            training_use: false,
            cloud_act_exposure: false,
        },
        price,
        ratings: BTreeMap::from([(TaskClass::Mechanical, 1.0)]),
        available: Some(true),
    }
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}
