use std::collections::BTreeMap;

use bowline_core::{
    config::{load_owned_cost_catalog, OwnedCostCatalog},
    enforcement::{
        route_workload_digest, seal_promotion_authorization, validate_promotion_documents,
        ActiveRuntimeProvenance, AuthorityProtocol, EconomicsPromotionSource, EnforcementConfigV1,
        FallbackMode, ModelAuthority, PromotionAuthorizationV1, PromotionOpportunityEvidence,
        QualityPromotionSource, RouteMode, ValidatedEnforcement, MAX_ACTUATORS,
        MAX_BREAKER_FAILURES, MAX_CONCURRENCY, MAX_ECONOMICS_AGE_MS, MAX_EXPIRY_MS,
        MAX_IDENTIFIER_BYTES, MAX_PATH_BYTES, MAX_PROBE_BYTES, MAX_ROLLOUT_PPM, MAX_ROUTES,
        MAX_TAGS, MAX_TAG_AGGREGATE_BYTES, MAX_TAG_BYTES, MAX_TIMEOUT_MS, MAX_URL_BYTES,
    },
    policy::PolicyBundle,
    quality::PromotionVerdict,
    supply::{Registry, Retention, SupplyAttributes, SupplyClass, SupplyEntry},
};

type ConfigStringSetter = Box<dyn Fn(&mut EnforcementConfigV1, String)>;
type EnforcementMutation = Box<dyn Fn(&mut EnforcementConfigV1)>;

const PROMOTION_NOW_MS: u64 = 1_000_000;
const POLICY_SOURCE: &str =
    "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n";
const REGISTRY_SOURCE: &str = "exact registry source bytes\n";

struct PromotionFixture {
    config: EnforcementConfigV1,
    validated: ValidatedEnforcement,
    economics: EconomicsPromotionSource,
    quality: QualityPromotionSource,
    active: ActiveRuntimeProvenance,
}

fn authority_yaml() -> String {
    r#"
version: 1
global_candidate_in_flight: 64
kill_switch: {trust_root: /var/lib/bowline/kill, relative_path: state}
actuators:
  - supply_id: owned/llama
    base_url: https://inference.example.test/v1
    authorization_env: BOWLINE_ACTUATOR_TOKEN
    health_path: /models
    remote_acknowledged: true
    connect_timeout_ms: 2000
    response_header_timeout_ms: 30000
    stream_idle_timeout_ms: 30000
    concurrency: 16
    probe_timeout_ms: 2000
    probe_max_bytes: 65536
    breaker_consecutive_failures: 3
    breaker_cooldown_ms: 30000
routes:
  - route_id: support-chat
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    workload: {app: support, resolved_tags: [customer-facing, production]}
    mode: canary-enforce
    rollout_ppm: 10000
    promoted_supply_id: owned/llama
    actual_supply_id: public/openai
    task_class: judgment
    model_authority: rewrite-to-canonical
    fallback: bypass
    promotion:
      economics_bundle_path: evidence/economics
      economics_report_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      opportunity_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      quality_run_path: evidence/quality/run-1
      authorization_path: evidence/authorization/support-chat.json
      quality_run_id: quality-1
      quality_report_digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      policy_digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
      registry_digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
      owned_cost_digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      max_economics_age_ms: 86400000
      expires_at_ms: 2000000000000
"#
    .into()
}

fn promotion_fixture() -> PromotionFixture {
    let policy = PolicyBundle::from_yaml(POLICY_SOURCE).unwrap();
    let owned_costs = OwnedCostCatalog::default();
    let active = ActiveRuntimeProvenance::from_loaded(&policy, REGISTRY_SOURCE, &owned_costs);
    let source = authority_yaml()
        .replace(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            active.policy_digest(),
        )
        .replace(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            active.registry_digest(),
        )
        .replace(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            active.owned_cost_digest(),
        );
    let config = EnforcementConfigV1::from_yaml(&source).unwrap();
    let validated = config.validate().unwrap();
    let route = validated.route("support-chat").unwrap();
    let workload_identity_digest =
        route_workload_digest(route.protocol, route.workload.as_ref().unwrap()).unwrap();
    let report_digest = format!("sha256:{}", "a".repeat(64));
    let opportunity_digest = format!("sha256:{}", "b".repeat(64));
    let quality_report_digest = format!("sha256:{}", "c".repeat(64));
    let other_digest = format!("sha256:{}", "1".repeat(64));
    let mut artifact_digests = BTreeMap::new();
    for name in [
        "dimensions.csv",
        "opportunities.csv",
        "reconciliation.csv",
        "report.html",
        "report.json",
        "report.md",
    ] {
        artifact_digests.insert(
            name.to_owned(),
            if name == "report.json" {
                report_digest.clone()
            } else {
                other_digest.clone()
            },
        );
    }
    let economics = EconomicsPromotionSource {
        schema_version: 1,
        as_of_ms: 900_000,
        window_end_ms: 800_000,
        complete: true,
        report_digest,
        bundle_digest: other_digest.clone(),
        artifact_digests,
        selected_traffic_digest: other_digest.clone(),
        selected_billing_digest: Some(other_digest.clone()),
        selected_quality_digests: vec![quality_report_digest.clone()],
        opportunity: PromotionOpportunityEvidence {
            digest: opportunity_digest,
            workload_identity_digest: workload_identity_digest.clone(),
            task_class: route.task_class.unwrap(),
            protocol: route.protocol,
            actual_supply_id: route.actual_supply_id.clone().unwrap(),
            candidate_supply_id: route.promoted_supply_id.clone().unwrap(),
            eligible: true,
            policy_feasible: true,
            capacity_available: true,
            actual_cost_micros: Some(10),
            candidate_cost_micros: Some(1),
            actual_rate_micros: Some(bowline_core::economics::CostRateMicros {
                input_per_mtok_micros: 2_000_000,
                output_per_mtok_micros: 2_000_000,
            }),
            candidate_rate_micros: Some(bowline_core::economics::CostRateMicros {
                input_per_mtok_micros: 1_000_000,
                output_per_mtok_micros: 1_000_000,
            }),
        },
        policy_digest: active.policy_digest().into(),
        registry_digest: active.registry_digest().into(),
        owned_cost_digest: active.owned_cost_digest().into(),
    };
    let quality = QualityPromotionSource {
        schema_version: 2,
        run_id: "quality-1".into(),
        completed_at_ms: 850_000,
        valid_until_ms: 2_000_000,
        workload_identity_digest,
        task_class: route.task_class.unwrap(),
        protocol: route.protocol,
        candidate_supply_id: route.promoted_supply_id.clone().unwrap(),
        effective_verdict: PromotionVerdict::Eligible,
        manifest_digest: other_digest.clone(),
        outcomes_digest: other_digest,
        report_digest: quality_report_digest,
        manifest_valid: true,
        outcomes_valid: true,
        report_valid: true,
        policy_digest: active.policy_digest().into(),
        registry_digest: active.registry_digest().into(),
        owned_cost_digest: active.owned_cost_digest().into(),
    };
    PromotionFixture {
        config,
        validated,
        economics,
        quality,
        active,
    }
}

#[test]
fn promotion_requires_safe_authorization_path() {
    let validated = EnforcementConfigV1::from_yaml(&authority_yaml())
        .unwrap()
        .validate()
        .unwrap();
    let missing = authority_yaml().replace(
        "      authorization_path: evidence/authorization/support-chat.json\n",
        "",
    );
    assert!(EnforcementConfigV1::from_yaml(&missing).is_err());

    for path in ["/absolute/auth.json", "../escape.json", "."] {
        let invalid = authority_yaml().replace("evidence/authorization/support-chat.json", path);
        assert!(EnforcementConfigV1::from_yaml(&invalid)
            .unwrap()
            .validate()
            .is_err());
    }

    let changed = EnforcementConfigV1::from_yaml(&authority_yaml().replace(
        "evidence/authorization/support-chat.json",
        "evidence/authorization/other.json",
    ))
    .unwrap()
    .validate()
    .unwrap();
    assert_ne!(validated.normalized_digest(), changed.normalized_digest());
}

#[test]
fn promotion_authorization_rejects_unknown_missing_and_invalid_fields() {
    let digest = format!("sha256:{}", "1".repeat(64));
    let value = serde_json::json!({
        "schema_version": 1,
        "route_id": "support-chat",
        "created_at_ms": 1_000_000,
        "economics_bundle_digest": digest,
        "economics_report_digest": digest,
        "opportunity_digest": digest,
        "quality_source_digest": digest,
        "quality_run_id": "quality-1",
        "quality_report_digest": digest,
        "policy_digest": digest,
        "registry_digest": digest,
        "owned_cost_digest": digest,
        "enforcement_digest": digest,
        "actuator_digest": digest,
        "route_digest": digest,
        "workload_identity_digest": digest,
        "task_class": "judgment",
        "protocol": "chat-completions",
        "actual_supply_id": "public/openai",
        "candidate_supply_id": "owned/llama",
        "authorization_digest": digest
    });
    assert!(serde_json::from_value::<PromotionAuthorizationV1>(value.clone()).is_ok());
    let object = value.as_object().unwrap();

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<PromotionAuthorizationV1>(unknown).is_err());

    for field in object.keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<PromotionAuthorizationV1>(missing).is_err(),
            "missing field accepted: {field}"
        );
    }

    for field in object.keys() {
        let mut invalid = value.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(field.clone(), serde_json::json!(false));
        assert!(
            serde_json::from_value::<PromotionAuthorizationV1>(invalid).is_err(),
            "invalid field accepted: {field}"
        );
    }
}

#[test]
fn embeddings_schema_rejects_every_authority_surface() {
    let source = r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {trust_root: /tmp/kill, relative_path: state}
actuators: []
routes:
  - {route_id: embeddings, method: POST, path: /v1/embeddings, protocol: embeddings, mode: observe, rollout_ppm: 0}
"#;
    let base = EnforcementConfigV1::from_yaml(source).unwrap();
    assert!(base.validate().is_ok());
    let mut recommend = base.clone();
    recommend.routes[0].mode = RouteMode::Recommend;
    assert!(recommend.validate().is_ok());

    let mut authority_mode = base.clone();
    authority_mode.routes[0].mode = RouteMode::CanaryEnforce;
    assert!(authority_mode.validate().is_err());
    authority_mode.routes[0].mode = RouteMode::Enforce;
    assert!(authority_mode.validate().is_err());

    let mut promoted = base.clone();
    promoted.routes[0].promoted_supply_id = Some("owned/llama".into());
    assert!(promoted.validate().is_err());

    let authority = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
    let mut model_authority = base.clone();
    model_authority.routes[0].model_authority = authority.routes[0].model_authority;
    assert!(model_authority.validate().is_err());
    let mut fallback = base.clone();
    fallback.routes[0].fallback = authority.routes[0].fallback;
    assert!(fallback.validate().is_err());
    let mut promotion = base;
    promotion.routes[0].promotion = authority.routes[0].promotion.clone();
    assert!(promotion.validate().is_err());
}

#[test]
fn promotion_seal_binds_every_current_semantic_and_active_provenance() {
    let fixture = promotion_fixture();
    let authorization = seal_promotion_authorization(
        &fixture.validated,
        "support-chat",
        &fixture.economics,
        &fixture.quality,
        &fixture.active,
        PROMOTION_NOW_MS,
    )
    .unwrap();
    let grant = validate_promotion_documents(
        &fixture.validated,
        "support-chat",
        &fixture.economics,
        &fixture.quality,
        &authorization,
        &fixture.active,
        PROMOTION_NOW_MS,
    )
    .unwrap();
    assert_eq!(
        grant.authorization_digest(),
        authorization.authorization_digest
    );
    assert_eq!(grant.not_before_ms(), authorization.created_at_ms);
    let later_authorization = seal_promotion_authorization(
        &fixture.validated,
        "support-chat",
        &fixture.economics,
        &fixture.quality,
        &fixture.active,
        PROMOTION_NOW_MS + 1,
    )
    .unwrap();
    let later_grant = validate_promotion_documents(
        &fixture.validated,
        "support-chat",
        &fixture.economics,
        &fixture.quality,
        &later_authorization,
        &fixture.active,
        PROMOTION_NOW_MS + 1,
    )
    .unwrap();
    assert_ne!(
        authorization.authorization_digest,
        later_authorization.authorization_digest
    );
    assert_ne!(grant.validation_digest(), later_grant.validation_digest());

    let mutations: Vec<(&str, EnforcementMutation)> = vec![
        (
            "rollout",
            Box::new(|config| config.routes[0].rollout_ppm = 20_000),
        ),
        (
            "fallback",
            Box::new(|config| config.routes[0].fallback = Some(FallbackMode::FailClosed)),
        ),
        (
            "mode",
            Box::new(|config| {
                config.routes[0].mode = RouteMode::Enforce;
                config.routes[0].rollout_ppm = 0;
            }),
        ),
        (
            "model authority",
            Box::new(|config| config.routes[0].model_authority = Some(ModelAuthority::Preserve)),
        ),
        (
            "selector",
            Box::new(|config| config.routes[0].workload.as_mut().unwrap().app = "sales".into()),
        ),
        (
            "task",
            Box::new(|config| {
                config.routes[0].task_class = Some(bowline_core::supply::TaskClass::Mechanical)
            }),
        ),
        (
            "protocol",
            Box::new(|config| config.routes[0].protocol = AuthorityProtocol::Responses),
        ),
        (
            "actual supply",
            Box::new(|config| config.routes[0].actual_supply_id = Some("public/anthropic".into())),
        ),
        (
            "promoted supply",
            Box::new(|config| {
                let mut second = config.actuators[0].clone();
                second.supply_id = "owned/second".into();
                config.actuators.push(second);
                config.routes[0].promoted_supply_id = Some("owned/second".into());
            }),
        ),
        (
            "endpoint",
            Box::new(|config| {
                config.actuators[0].base_url = "https://other.example.test/v1".into()
            }),
        ),
        (
            "actuator timeout",
            Box::new(|config| config.actuators[0].connect_timeout_ms = 2_001),
        ),
        (
            "authorization environment reference",
            Box::new(|config| {
                config.actuators[0].authorization_env = "BOWLINE_OTHER_AUTH_TOKEN".into()
            }),
        ),
        (
            "circuit threshold",
            Box::new(|config| config.actuators[0].breaker_consecutive_failures = 4),
        ),
        (
            "kill path",
            Box::new(|config| config.kill_switch.relative_path = "other-state".into()),
        ),
        (
            "economics binding",
            Box::new(|config| {
                config.routes[0]
                    .promotion
                    .as_mut()
                    .unwrap()
                    .economics_report_digest = format!("sha256:{}", "9".repeat(64))
            }),
        ),
        (
            "authorization path",
            Box::new(|config| {
                config.routes[0]
                    .promotion
                    .as_mut()
                    .unwrap()
                    .authorization_path = "evidence/authorization/other.json".into()
            }),
        ),
        (
            "economics bundle path",
            Box::new(|config| {
                config.routes[0]
                    .promotion
                    .as_mut()
                    .unwrap()
                    .economics_bundle_path = "evidence/economics-other".into()
            }),
        ),
        (
            "quality run path",
            Box::new(|config| {
                config.routes[0]
                    .promotion
                    .as_mut()
                    .unwrap()
                    .quality_run_path = "evidence/quality/run-other".into()
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut changed = fixture.config.clone();
        mutate(&mut changed);
        let changed = changed.validate().unwrap();
        assert!(
            validate_promotion_documents(
                &changed,
                "support-chat",
                &fixture.economics,
                &fixture.quality,
                &authorization,
                &fixture.active,
                PROMOTION_NOW_MS,
            )
            .is_err(),
            "unchanged authorization accepted after {name} mutation"
        );
    }

    let changed_policy =
        PolicyBundle::from_yaml(&POLICY_SOURCE.replace("name: default", "name: changed")).unwrap();
    let default_costs = OwnedCostCatalog::default();
    let policy_mismatch =
        ActiveRuntimeProvenance::from_loaded(&changed_policy, REGISTRY_SOURCE, &default_costs);
    let original_policy = PolicyBundle::from_yaml(POLICY_SOURCE).unwrap();
    let registry_mismatch = ActiveRuntimeProvenance::from_loaded(
        &original_policy,
        "changed registry\n",
        &default_costs,
    );
    let owned_registry = Registry {
        note: None,
        feed_version: "test".into(),
        entries: vec![SupplyEntry {
            id: "owned/test".into(),
            model: "test".into(),
            aliases: Vec::new(),
            location: "local".into(),
            attributes: SupplyAttributes {
                class: SupplyClass::Owned,
                jurisdiction: "local".into(),
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: false,
            },
            price: None,
            ratings: BTreeMap::new(),
            available: Some(true),
        }],
    };
    let changed_costs = load_owned_cost_catalog(
        Some(
            "version: 2\nsupplies:\n  owned/test:\n    monthly_amortization_usd: 10\n    monthly_power_usd: 1\n    monthly_ops_usd: 1\n    monthly_capacity_mtok: 100\n",
        ),
        None,
        &owned_registry,
    )
    .unwrap();
    let owned_cost_mismatch =
        ActiveRuntimeProvenance::from_loaded(&original_policy, REGISTRY_SOURCE, &changed_costs);
    for (name, active) in [
        ("policy", policy_mismatch),
        ("registry", registry_mismatch),
        ("owned cost", owned_cost_mismatch),
    ] {
        assert!(
            validate_promotion_documents(
                &fixture.validated,
                "support-chat",
                &fixture.economics,
                &fixture.quality,
                &authorization,
                &active,
                PROMOTION_NOW_MS,
            )
            .is_err(),
            "unchanged authorization accepted after active {name} mutation"
        );
    }

    let economics = serde_json::to_value(&fixture.economics).unwrap();
    for field in ["enforcement_digest", "actuator_digest", "route_digest"] {
        assert!(economics.get(field).is_none(), "economics leaked {field}");
        let mut invalid = economics.clone();
        invalid.as_object_mut().unwrap().insert(
            field.into(),
            serde_json::json!(format!("sha256:{}", "8".repeat(64))),
        );
        assert!(serde_json::from_value::<EconomicsPromotionSource>(invalid).is_err());
    }
}

#[test]
fn canonical_digests_bind_authorization_env_and_promotion_source_paths() {
    let base = EnforcementConfigV1::from_yaml(&authority_yaml())
        .unwrap()
        .validate()
        .unwrap();

    let mut authorization_env = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
    authorization_env.actuators[0].authorization_env = "BOWLINE_OTHER_AUTH_TOKEN".into();
    let authorization_env = authorization_env.validate().unwrap();
    assert_ne!(
        base.actuator_digest("owned/llama"),
        authorization_env.actuator_digest("owned/llama")
    );
    assert_ne!(
        base.normalized_digest(),
        authorization_env.normalized_digest()
    );

    for changed_path in ["economics", "quality"] {
        let mut changed = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
        let promotion = changed.routes[0].promotion.as_mut().unwrap();
        match changed_path {
            "economics" => promotion.economics_bundle_path = "evidence/economics-other".into(),
            "quality" => promotion.quality_run_path = "evidence/quality/run-other".into(),
            _ => unreachable!(),
        }
        let changed = changed.validate().unwrap();
        assert_ne!(
            base.route_digest("support-chat"),
            changed.route_digest("support-chat"),
            "{changed_path} path did not change the route digest"
        );
        assert_ne!(base.normalized_digest(), changed.normalized_digest());
    }
}

#[test]
fn configured_identifiers_use_one_bounded_trimmed_control_free_grammar() {
    let mut valid = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
    valid.actuators[0].supply_id = "owned/équipe:v1!".into();
    valid.routes[0].promoted_supply_id = Some("owned/équipe:v1!".into());
    valid.routes[0].actual_supply_id = Some("public/基準:v1?".into());
    valid.routes[0].route_id = "routé:α/v1!".into();
    valid.routes[0].workload.as_mut().unwrap().app = "app:支援!".into();
    valid.routes[0].workload.as_mut().unwrap().resolved_tags =
        vec!["environment:test".into(), "région:eu-west/1".into()];
    assert!(valid.validate().is_ok());

    for invalid in [
        "".to_owned(),
        " leading".to_owned(),
        "trailing ".to_owned(),
        "control\nvalue".to_owned(),
        "x".repeat(MAX_IDENTIFIER_BYTES + 1),
    ] {
        let mut config = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
        config.routes[0].route_id = invalid;
        assert!(config.validate().is_err());
    }
}

#[test]
fn unicode_punctuation_authority_vector_validates_and_seals() {
    let fixture = promotion_fixture();
    let mut config = fixture.config.clone();
    config.actuators[0].supply_id = "owned/équipe:v1!".into();
    config.routes[0].route_id = "routé:α/v1!".into();
    config.routes[0].promoted_supply_id = Some("owned/équipe:v1!".into());
    config.routes[0].actual_supply_id = Some("public/基準:v1?".into());
    config.routes[0].workload.as_mut().unwrap().app = "app:支援!".into();
    config.routes[0].workload.as_mut().unwrap().resolved_tags =
        vec!["environment:test".into(), "région:eu-west/1".into()];
    let validated = config.validate().unwrap();
    let route = validated.route("routé:α/v1!").unwrap();
    let workload_digest =
        route_workload_digest(route.protocol, route.workload.as_ref().unwrap()).unwrap();

    let mut economics = fixture.economics.clone();
    economics.opportunity.workload_identity_digest = workload_digest.clone();
    economics.opportunity.actual_supply_id = "public/基準:v1?".into();
    economics.opportunity.candidate_supply_id = "owned/équipe:v1!".into();
    let mut quality = fixture.quality.clone();
    quality.workload_identity_digest = workload_digest;
    quality.candidate_supply_id = "owned/équipe:v1!".into();

    let authorization = seal_promotion_authorization(
        &validated,
        "routé:α/v1!",
        &economics,
        &quality,
        &fixture.active,
        PROMOTION_NOW_MS,
    )
    .unwrap();
    validate_promotion_documents(
        &validated,
        "routé:α/v1!",
        &economics,
        &quality,
        &authorization,
        &fixture.active,
        PROMOTION_NOW_MS,
    )
    .unwrap();
}

#[test]
fn promotion_seal_binds_every_authorization_claim_and_self_digest() {
    let fixture = promotion_fixture();
    let authorization = seal_promotion_authorization(
        &fixture.validated,
        "support-chat",
        &fixture.economics,
        &fixture.quality,
        &fixture.active,
        PROMOTION_NOW_MS,
    )
    .unwrap();
    let value = serde_json::to_value(&authorization).unwrap();
    let digest = format!("sha256:{}", "9".repeat(64));
    let mutations = [
        ("schema_version", serde_json::json!(2)),
        ("route_id", serde_json::json!("changed-route")),
        ("created_at_ms", serde_json::json!(PROMOTION_NOW_MS + 1)),
        ("economics_bundle_digest", serde_json::json!(digest)),
        ("economics_report_digest", serde_json::json!(digest)),
        ("opportunity_digest", serde_json::json!(digest)),
        ("quality_source_digest", serde_json::json!(digest)),
        ("quality_run_id", serde_json::json!("changed-run")),
        ("quality_report_digest", serde_json::json!(digest)),
        ("policy_digest", serde_json::json!(digest)),
        ("registry_digest", serde_json::json!(digest)),
        ("owned_cost_digest", serde_json::json!(digest)),
        ("enforcement_digest", serde_json::json!(digest)),
        ("actuator_digest", serde_json::json!(digest)),
        ("route_digest", serde_json::json!(digest)),
        ("workload_identity_digest", serde_json::json!(digest)),
        ("task_class", serde_json::json!("mechanical")),
        ("protocol", serde_json::json!("responses")),
        ("actual_supply_id", serde_json::json!("changed-actual")),
        (
            "candidate_supply_id",
            serde_json::json!("changed-candidate"),
        ),
        ("authorization_digest", serde_json::json!(digest)),
    ];
    assert_eq!(mutations.len(), value.as_object().unwrap().len());
    for (field, replacement) in mutations {
        let mut invalid = value.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(field.into(), replacement);
        let invalid = serde_json::from_value::<PromotionAuthorizationV1>(invalid).unwrap();
        assert!(
            validate_promotion_documents(
                &fixture.validated,
                "support-chat",
                &fixture.economics,
                &fixture.quality,
                &invalid,
                &fixture.active,
                PROMOTION_NOW_MS,
            )
            .is_err(),
            "changed authorization field accepted: {field}"
        );
    }
}

#[test]
fn enforcement_strict_authority_config_builds_indexes() {
    let validated = EnforcementConfigV1::from_yaml(&authority_yaml())
        .unwrap()
        .validate()
        .unwrap();
    assert_eq!(
        validated.route("support-chat").unwrap().mode,
        RouteMode::CanaryEnforce
    );
    assert!(validated.actuator("owned/llama").is_some());
}

#[test]
fn enforcement_schema_rejects_unknown_overlap_and_missing_probe() {
    for source in [
        authority_yaml().replace("version: 1", "version: 1\nunknown: true"),
        authority_yaml().replace(
            "routes:\n",
            &format!(
                "routes:\n{}",
                authority_yaml().split("routes:\n").nth(1).unwrap()
            ),
        ),
        authority_yaml().replace("    health_path: /models\n", ""),
    ] {
        assert!(EnforcementConfigV1::from_yaml(&source)
            .and_then(|v| v.validate())
            .is_err());
    }
}

#[test]
fn enforcement_established_bounds_are_exact_and_zero_or_next_fail() {
    assert_eq!(
        (MAX_ACTUATORS, MAX_ROUTES, MAX_CONCURRENCY, MAX_TIMEOUT_MS),
        (64, 256, 64, 300_000)
    );
    assert_eq!(MAX_TAG_BYTES, bowline_core::quality::MAX_IDENTIFIER_BYTES);
    let exact = authority_yaml()
        .replace(
            "route_id: support-chat",
            &format!("route_id: {}", "r".repeat(MAX_IDENTIFIER_BYTES)),
        )
        .replace(
            "connect_timeout_ms: 2000",
            &format!("connect_timeout_ms: {MAX_TIMEOUT_MS}"),
        );
    assert!(EnforcementConfigV1::from_yaml(&exact)
        .unwrap()
        .validate()
        .is_ok());
    for source in [
        exact.replace(
            &format!("route_id: {}", "r".repeat(MAX_IDENTIFIER_BYTES)),
            &format!("route_id: {}", "r".repeat(MAX_IDENTIFIER_BYTES + 1)),
        ),
        exact.replace(
            &format!("connect_timeout_ms: {MAX_TIMEOUT_MS}"),
            "connect_timeout_ms: 0",
        ),
        exact.replace(
            &format!("connect_timeout_ms: {MAX_TIMEOUT_MS}"),
            &format!("connect_timeout_ms: {}", MAX_TIMEOUT_MS + 1),
        ),
        exact.replace("concurrency: 16", "concurrency: 65"),
        exact.replace("probe_max_bytes: 65536", "probe_max_bytes: 1048577"),
        exact.replace(
            "max_economics_age_ms: 86400000",
            "max_economics_age_ms: 31536000001",
        ),
    ] {
        assert!(EnforcementConfigV1::from_yaml(&source)
            .unwrap()
            .validate()
            .is_err());
    }
}

#[test]
fn enforcement_every_scalar_bound_accepts_max_and_rejects_zero_or_max_plus_one() {
    let cases = [
        (
            "global_candidate_in_flight: 64",
            MAX_CONCURRENCY as u64,
            true,
        ),
        ("connect_timeout_ms: 2000", MAX_TIMEOUT_MS, true),
        ("response_header_timeout_ms: 30000", MAX_TIMEOUT_MS, true),
        ("stream_idle_timeout_ms: 30000", MAX_TIMEOUT_MS, true),
        ("concurrency: 16", MAX_CONCURRENCY as u64, true),
        ("probe_timeout_ms: 2000", MAX_TIMEOUT_MS, true),
        ("probe_max_bytes: 65536", MAX_PROBE_BYTES as u64, true),
        (
            "breaker_consecutive_failures: 3",
            MAX_BREAKER_FAILURES as u64,
            true,
        ),
        ("breaker_cooldown_ms: 30000", MAX_TIMEOUT_MS, true),
        ("rollout_ppm: 10000", MAX_ROLLOUT_PPM as u64, false),
        ("max_economics_age_ms: 86400000", MAX_ECONOMICS_AGE_MS, true),
    ];
    for (needle, max, zero_invalid) in cases {
        let field = needle.split(':').next().unwrap();
        let max_text = format!("{field}: {max}");
        let max_yaml = authority_yaml().replace(needle, &max_text);
        assert!(
            EnforcementConfigV1::from_yaml(&max_yaml)
                .unwrap()
                .validate()
                .is_ok(),
            "max rejected for {needle}"
        );
        let above = max_yaml.replace(&max_text, &format!("{field}: {}", max + 1));
        assert!(
            EnforcementConfigV1::from_yaml(&above)
                .unwrap()
                .validate()
                .is_err(),
            "max+1 accepted for {needle}"
        );
        if zero_invalid {
            let zero = max_yaml.replace(&max_text, &format!("{field}: 0"));
            assert!(
                EnforcementConfigV1::from_yaml(&zero)
                    .unwrap()
                    .validate()
                    .is_err(),
                "zero accepted for {needle}"
            );
        }
    }
}

#[test]
fn enforcement_every_collection_and_string_bound_is_exact() {
    let base = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
    let mut actuators = base.clone();
    actuators.actuators = (0..MAX_ACTUATORS)
        .map(|index| {
            let mut actuator = base.actuators[0].clone();
            actuator.supply_id = format!("owned/{index}");
            actuator
        })
        .collect();
    actuators.routes.clear();
    assert!(actuators.validate().is_ok());
    actuators.actuators.push(base.actuators[0].clone());
    assert!(actuators.validate().is_err());

    let mut routes = base.clone();
    routes.routes = (0..MAX_ROUTES)
        .map(|index| {
            let mut route = base.routes[0].clone();
            route.route_id = format!("route-{index}");
            route.path = format!("/v1/route/{index}");
            route
        })
        .collect();
    assert!(routes.validate().is_ok());
    routes.routes.push(base.routes[0].clone());
    assert!(routes.validate().is_err());

    for (field, exact, above) in [
        (
            "route_id",
            "r".repeat(MAX_IDENTIFIER_BYTES),
            "r".repeat(MAX_IDENTIFIER_BYTES + 1),
        ),
        (
            "path",
            format!("/{}", "p".repeat(MAX_PATH_BYTES - 1)),
            format!("/{}", "p".repeat(MAX_PATH_BYTES)),
        ),
        (
            "base_url",
            format!(
                "https://x.test/{}",
                "u".repeat(MAX_URL_BYTES - "https://x.test/".len())
            ),
            format!(
                "https://x.test/{}",
                "u".repeat(MAX_URL_BYTES - "https://x.test/".len() + 1)
            ),
        ),
    ] {
        let mut exact_config = base.clone();
        match field {
            "route_id" => exact_config.routes[0].route_id = exact,
            "path" => exact_config.routes[0].path = exact,
            "base_url" => exact_config.actuators[0].base_url = exact,
            _ => unreachable!(),
        }
        assert!(exact_config.validate().is_ok(), "exact {field} rejected");
        match field {
            "route_id" => exact_config.routes[0].route_id = above,
            "path" => exact_config.routes[0].path = above,
            "base_url" => exact_config.actuators[0].base_url = above,
            _ => unreachable!(),
        }
        assert!(exact_config.validate().is_err(), "max+1 {field} accepted");
    }

    let mut tags = base.clone();
    tags.routes[0].workload.as_mut().unwrap().resolved_tags = (0..MAX_TAGS)
        .map(|index| format!("{index:03}{}", "t".repeat(MAX_TAG_BYTES - 3)))
        .collect();
    assert_eq!(
        tags.routes[0]
            .workload
            .as_ref()
            .unwrap()
            .resolved_tags
            .iter()
            .map(String::len)
            .sum::<usize>(),
        MAX_TAG_AGGREGATE_BYTES
    );
    assert!(tags.validate().is_ok());
    tags.routes[0]
        .workload
        .as_mut()
        .unwrap()
        .resolved_tags
        .push("z".into());
    assert!(tags.validate().is_err());
}

#[test]
fn enforcement_every_identifier_path_and_expiry_bound_is_exact() {
    let base = EnforcementConfigV1::from_yaml(&authority_yaml()).unwrap();
    let identifier_cases: Vec<ConfigStringSetter> = vec![
        Box::new(|config, value| {
            config.actuators[0].supply_id = value.clone();
            config.routes[0].promoted_supply_id = Some(value);
        }),
        Box::new(|config, value| config.routes[0].route_id = value),
        Box::new(|config, value| config.routes[0].workload.as_mut().unwrap().app = value),
        Box::new(|config, value| config.routes[0].actual_supply_id = Some(value)),
        Box::new(|config, value| {
            config.routes[0].promotion.as_mut().unwrap().quality_run_id = value
        }),
    ];
    for set in identifier_cases {
        let mut exact = base.clone();
        set(&mut exact, "i".repeat(MAX_IDENTIFIER_BYTES));
        assert!(exact.validate().is_ok());
        set(&mut exact, "i".repeat(MAX_IDENTIFIER_BYTES + 1));
        assert!(exact.validate().is_err());
    }

    let mut auth = base.clone();
    auth.actuators[0].authorization_env = format!("TOKEN_{}", "A".repeat(MAX_IDENTIFIER_BYTES - 6));
    assert!(auth.validate().is_ok());
    auth.actuators[0].authorization_env.push('A');
    assert!(auth.validate().is_err());

    let path_cases: Vec<ConfigStringSetter> = vec![
        Box::new(|config, value| config.kill_switch.relative_path = value),
        Box::new(|config, value| config.actuators[0].health_path = Some(value)),
        Box::new(|config, value| config.routes[0].path = value),
        Box::new(|config, value| {
            config.routes[0]
                .promotion
                .as_mut()
                .unwrap()
                .economics_bundle_path = value
        }),
        Box::new(|config, value| {
            config.routes[0]
                .promotion
                .as_mut()
                .unwrap()
                .quality_run_path = value
        }),
        Box::new(|config, value| {
            config.routes[0]
                .promotion
                .as_mut()
                .unwrap()
                .authorization_path = value
        }),
    ];
    for (index, set) in path_cases.into_iter().enumerate() {
        let mut exact = base.clone();
        let prefix = if matches!(index, 1 | 2) { "/" } else { "" };
        set(
            &mut exact,
            format!("{prefix}{}", "p".repeat(MAX_PATH_BYTES - prefix.len())),
        );
        assert!(exact.validate().is_ok(), "exact path case {index} rejected");
        set(
            &mut exact,
            format!("{prefix}{}", "p".repeat(MAX_PATH_BYTES - prefix.len() + 1)),
        );
        assert!(
            exact.validate().is_err(),
            "max+1 path case {index} accepted"
        );
    }
    let mut trust = base.clone();
    trust.kill_switch.trust_root = format!("/{}", "r".repeat(MAX_PATH_BYTES - 1));
    assert!(trust.validate().is_ok());
    trust.kill_switch.trust_root.push('r');
    assert!(trust.validate().is_err());

    let mut literal_path = base.clone();
    literal_path.kill_switch.trust_root = "/tmp/quote'\"backslash\\amp&pipe| space".to_owned();
    assert!(
        literal_path.validate().is_ok(),
        "valid POSIX trust-root bytes must not be rejected for shell metacharacters"
    );

    for control in ['\n', '\r', '\t', '\u{007f}'] {
        let mut control_path = base.clone();
        control_path.kill_switch.trust_root = format!("/tmp/control{control}root");
        assert!(
            control_path.validate().is_err(),
            "trust root accepted control character U+{:04X}",
            u32::from(control)
        );
    }

    let mut expiry = base;
    expiry.routes[0].promotion.as_mut().unwrap().expires_at_ms = MAX_EXPIRY_MS;
    assert!(expiry.validate().is_ok());
    expiry.routes[0].promotion.as_mut().unwrap().expires_at_ms = MAX_EXPIRY_MS + 1;
    let error = expiry.validate().unwrap_err();
    assert!(error.to_string().contains("exceeds maximum"));
    expiry.routes[0].promotion.as_mut().unwrap().expires_at_ms = 0;
    assert!(expiry.validate().is_err());
}

#[test]
fn enforcement_actuator_url_reuses_credential_rejection() {
    for url in [
        "https://user:pass@example.test/v1",
        "https://example.test/v1?token=x",
        "https://example.test/v1#fragment",
        "https://example.test/v1/%2e%2e",
        "https://example.test/v1/api_key/secret",
        "https://example.test/v1%25token",
    ] {
        let source = authority_yaml().replace("https://inference.example.test/v1", url);
        assert!(
            EnforcementConfigV1::from_yaml(&source)
                .unwrap()
                .validate()
                .is_err(),
            "accepted {url}"
        );
    }
}

#[test]
fn enforcement_actuator_http_accepts_only_loopback_host_variants() {
    for url in [
        "http://127.0.0.1:8080/v1",
        "http://[::1]:8080/v1",
        "http://localhost:8080/v1",
    ] {
        let source = authority_yaml().replace("https://inference.example.test/v1", url);
        assert!(
            EnforcementConfigV1::from_yaml(&source)
                .unwrap()
                .validate()
                .is_ok(),
            "rejected loopback endpoint {url}"
        );
    }
    for url in [
        "http://192.0.2.1:8080/v1",
        "http://[2001:db8::1]:8080/v1",
        "http://example.test:8080/v1",
        "http://user@127.0.0.1:8080/v1",
        "http://127.0.0.1:8080/not-v1?token=x",
    ] {
        let source = authority_yaml().replace("https://inference.example.test/v1", url);
        assert!(
            EnforcementConfigV1::from_yaml(&source)
                .unwrap()
                .validate()
                .is_err(),
            "accepted unsafe endpoint {url}"
        );
    }
}

#[test]
fn enforcement_remote_https_actuator_requires_explicit_acknowledgment() {
    // Omitting the field entirely (serde default) must fail closed, not silently bypass.
    let omitted = authority_yaml().replace("    remote_acknowledged: true\n", "");
    let error = EnforcementConfigV1::from_yaml(&omitted)
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(
        error.to_string().contains("remote_acknowledged"),
        "unacknowledged remote actuator error should mention remote_acknowledged: {error}"
    );

    // An explicit `false` must also fail closed.
    let explicit_false = authority_yaml().replace(
        "    remote_acknowledged: true\n",
        "    remote_acknowledged: false\n",
    );
    assert!(EnforcementConfigV1::from_yaml(&explicit_false)
        .unwrap()
        .validate()
        .is_err());

    // The base fixture (remote_acknowledged: true) must validate.
    assert!(EnforcementConfigV1::from_yaml(&authority_yaml())
        .unwrap()
        .validate()
        .is_ok());
}

#[test]
fn enforcement_embeddings_are_observe_only_and_present_ids_are_always_checked() {
    assert!(EnforcementConfigV1::from_yaml(
        &authority_yaml().replace("protocol: chat-completions", "protocol: embeddings")
    )
    .unwrap()
    .validate()
    .is_err());
    let observe = r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {trust_root: /tmp/kill, relative_path: state}
actuators: []
routes:
  - {route_id: embeddings-observe, method: POST, path: /v1/embeddings, protocol: embeddings, mode: observe, rollout_ppm: 0}
"#;
    assert!(EnforcementConfigV1::from_yaml(observe)
        .unwrap()
        .validate()
        .is_ok());
    let invalid = authority_yaml().replace(
        "actual_supply_id: public/openai",
        "actual_supply_id: ' bad'",
    );
    assert!(EnforcementConfigV1::from_yaml(&invalid)
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn enforcement_embeddings_selector_is_strict_and_participates_in_the_sanitized_digest() {
    let base = r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {trust_root: /tmp/kill, relative_path: state}
actuators: []
routes:
  - {route_id: embeddings-observe, method: POST, path: /v1/embeddings, protocol: embeddings, workload: {app: support, resolved_tags: [customer-facing, production]}, mode: observe, rollout_ppm: 0}
"#;
    let left = EnforcementConfigV1::from_yaml(base)
        .unwrap()
        .validate()
        .unwrap();
    let changed = EnforcementConfigV1::from_yaml(&base.replace("app: support", "app: search"))
        .unwrap()
        .validate()
        .unwrap();
    assert_ne!(left.normalized_digest(), changed.normalized_digest());
    let digest_json = serde_json::to_string(left.digest_document()).unwrap();
    assert!(!digest_json.contains("support"));
    assert!(!digest_json.contains("customer-facing"));
    for invalid in [
        base.replace("app: support", "app: ''"),
        base.replace(
            "app: support",
            &format!("app: {}", "a".repeat(MAX_IDENTIFIER_BYTES + 1)),
        ),
        base.replace(
            "[customer-facing, production]",
            "[production, customer-facing]",
        ),
        base.replace("[customer-facing, production]", "[production, production]"),
        base.replace("customer-facing", "\"bad\\u0000tag\""),
    ] {
        assert!(EnforcementConfigV1::from_yaml(&invalid)
            .unwrap()
            .validate()
            .is_err());
    }
}

#[test]
fn enforcement_digest_is_sanitized_and_control_paths_fail() {
    let validated = EnforcementConfigV1::from_yaml(&authority_yaml())
        .unwrap()
        .validate()
        .unwrap();
    let json = serde_json::to_string(validated.digest_document()).unwrap();
    for raw in [
        "/var/lib/bowline",
        "/models",
        "evidence/economics",
        "evidence/quality",
        "evidence/authorization",
        "BOWLINE_ACTUATOR_TOKEN",
    ] {
        assert!(!json.contains(raw), "leaked {raw}");
    }
    for source in [
        authority_yaml().replace("/var/lib/bowline/kill", "\"/tmp/bad\\u0000root\""),
        authority_yaml().replace("relative_path: state", "relative_path: \"bad\\u0000state\""),
    ] {
        assert!(EnforcementConfigV1::from_yaml(&source)
            .and_then(|config| config.validate())
            .is_err());
    }
}

#[test]
fn enforcement_checked_economics_age_expiry_rejects_overflow() {
    let mut fixture = promotion_fixture();
    fixture.economics.as_of_ms = u64::MAX - 1;
    fixture.economics.window_end_ms = u64::MAX - 1;
    fixture.quality.completed_at_ms = u64::MAX - 2;
    fixture.quality.valid_until_ms = u64::MAX;
    let error = seal_promotion_authorization(
        &fixture.validated,
        "support-chat",
        &fixture.economics,
        &fixture.quality,
        &fixture.active,
        u64::MAX,
    )
    .unwrap_err();
    assert!(error.to_string().contains("expiry overflow"));
}
