use std::borrow::Cow;

use bowline_core::{
    enforcement::{
        enforcement_bucket, rewrite_top_level_model, select_enforcement_plan,
        select_enforcement_plan_without_grant, AuthorityProtocol, CandidateAvailability,
        EnforcementPlan, EnforcementRoute, EvidenceState, FallbackMode, KillReadResult,
        ModelAuthority, PlanTarget, PromotionGrantSnapshot, RewriteError, RewriteLimits, RouteMode,
        SelectionInput, SelectionReason, WorkloadSelector,
    },
    supply::TaskClass,
};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

type SelectionMutation = Box<dyn Fn(&mut SelectionInput, &mut PromotionGrantSnapshot)>;

fn route() -> EnforcementRoute {
    EnforcementRoute {
        route_id: "route-a".into(),
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        protocol: AuthorityProtocol::ChatCompletions,
        workload: Some(WorkloadSelector {
            app: "checkout".into(),
            resolved_tags: vec!["env:prod".into(), "team:payments".into()],
        }),
        mode: RouteMode::CanaryEnforce,
        rollout_ppm: 1_000_000,
        promoted_supply_id: Some("candidate".into()),
        actual_supply_id: Some("baseline".into()),
        task_class: Some(TaskClass::Mechanical),
        model_authority: Some(ModelAuthority::RewriteToCanonical),
        fallback: Some(FallbackMode::Bypass),
        promotion: None,
    }
}

fn input() -> SelectionInput {
    SelectionInput {
        route: route(),
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        protocol: AuthorityProtocol::ChatCompletions,
        identity_trusted: true,
        authority_metadata_valid: true,
        shape_supported: true,
        task_class: TaskClass::Mechanical,
        app: Some("checkout".into()),
        resolved_tags: vec!["env:prod".into(), "team:payments".into()],
        workload_identity_digest: Some(DIGEST_A.into()),
        request_body_digest: [7; 32],
        requested_supply_id: Some("baseline".into()),
        kill: KillReadResult::Armed,
        now_ms: 500,
        candidate_availability: CandidateAvailability::Available,
        actuator_available: true,
    }
}

fn grant() -> PromotionGrantSnapshot {
    PromotionGrantSnapshot {
        route_id: "route-a".into(),
        workload_identity_digest: DIGEST_A.into(),
        task_class: TaskClass::Mechanical,
        protocol: AuthorityProtocol::ChatCompletions,
        actual_supply_id: "baseline".into(),
        candidate_supply_id: "candidate".into(),
        config_digest: DIGEST_B.into(),
        actuator_digest: DIGEST_A.into(),
        route_digest: DIGEST_B.into(),
        grant_digest: DIGEST_A.into(),
        not_before_ms: 100,
        expires_at_ms: 900,
    }
}

fn assert_fallback(plan: &EnforcementPlan, reason: SelectionReason, target: PlanTarget) {
    assert_eq!(plan.reason, reason);
    assert_eq!(plan.target, target);
    assert_eq!(plan.dispatch_count, 0);
    if target == PlanTarget::Original {
        assert_eq!(plan.selected_supply_id.as_deref(), Some("baseline"));
    } else {
        assert!(plan.selected_supply_id.is_none());
    }
    assert!(plan.grant_digest.is_none());
}

#[test]
fn enforcement_selection_precedence_is_fail_safe_and_exhaustive() {
    let base_input = input();
    let base_grant = grant();
    let cases: Vec<(&str, SelectionMutation, SelectionReason)> = vec![
        (
            "kill",
            Box::new(|input, _| input.kill = KillReadResult::Malformed),
            SelectionReason::KillNotArmed,
        ),
        (
            "route",
            Box::new(|input, _| input.path = "/wrong".into()),
            SelectionReason::RouteMismatch,
        ),
        (
            "identity",
            Box::new(|input, _| input.identity_trusted = false),
            SelectionReason::UntrustedIdentity,
        ),
        (
            "authority-metadata",
            Box::new(|input, _| input.authority_metadata_valid = false),
            SelectionReason::UntrustedIdentity,
        ),
        (
            "shape",
            Box::new(|input, _| input.shape_supported = false),
            SelectionReason::UnsupportedShape,
        ),
        (
            "grant",
            Box::new(|_, grant| grant.route_id = "wrong".into()),
            SelectionReason::GrantMismatch,
        ),
        (
            "freshness",
            Box::new(|input, _| input.now_ms = 901),
            SelectionReason::GrantStale,
        ),
        (
            "workload",
            Box::new(|input, _| input.workload_identity_digest = Some(DIGEST_B.into())),
            SelectionReason::WorkloadMismatch,
        ),
        (
            "allowlist",
            Box::new(|input, _| input.app = Some("other".into())),
            SelectionReason::AllowlistMiss,
        ),
        (
            "bucket",
            Box::new(|input, _| input.route.rollout_ppm = 0),
            SelectionReason::RolloutMiss,
        ),
        (
            "pinned",
            Box::new(|input, _| {
                input.route.model_authority = Some(ModelAuthority::Preserve);
                input.requested_supply_id = Some("baseline".into());
            }),
            SelectionReason::PinnedModelMismatch,
        ),
        (
            "circuit",
            Box::new(|input, _| input.candidate_availability = CandidateAvailability::CircuitOpen),
            SelectionReason::CircuitOpen,
        ),
        (
            "admission",
            Box::new(|input, _| {
                input.candidate_availability = CandidateAvailability::AdmissionSaturated
            }),
            SelectionReason::AdmissionSaturated,
        ),
        (
            "actuator",
            Box::new(|input, _| input.actuator_available = false),
            SelectionReason::ActuatorUnavailable,
        ),
    ];

    for index in 0..cases.len() {
        let mut candidate_input = base_input.clone();
        let mut candidate_grant = base_grant.clone();
        for (_, mutate, _) in cases.iter().skip(index).rev() {
            mutate(&mut candidate_input, &mut candidate_grant);
        }
        let plan = select_enforcement_plan(&candidate_input, &candidate_grant);
        assert_fallback(&plan, cases[index].2, PlanTarget::Original);
    }

    let mut fail_closed = input();
    fail_closed.route.fallback = Some(FallbackMode::FailClosed);
    fail_closed.kill = KillReadResult::QueueUnavailable;
    assert_fallback(
        &select_enforcement_plan(&fail_closed, &grant()),
        SelectionReason::KillNotArmed,
        PlanTarget::None,
    );

    let selected = select_enforcement_plan(&input(), &grant());
    assert_eq!(selected.target, PlanTarget::Candidate);
    assert_eq!(selected.reason, SelectionReason::CandidateSelected);
    assert_eq!(selected.mode, RouteMode::CanaryEnforce);
    assert_eq!(selected.selected_supply_id.as_deref(), Some("candidate"));
    assert_eq!(selected.baseline_supply_id.as_deref(), Some("baseline"));
    assert_eq!(selected.config_digest.as_deref(), Some(DIGEST_B));
    assert_eq!(selected.actuator_digest.as_deref(), Some(DIGEST_A));
    assert_eq!(selected.grant_digest.as_deref(), Some(DIGEST_A));
    assert!(selected.model_rewritten);
    assert_eq!(selected.dispatch_count, 0);

    for state in [
        KillReadResult::Bypass,
        KillReadResult::Missing,
        KillReadResult::Unsafe,
        KillReadResult::Unreadable,
        KillReadResult::Malformed,
        KillReadResult::QueueUnavailable,
    ] {
        let mut candidate = input();
        candidate.kill = state;
        assert_fallback(
            &select_enforcement_plan(&candidate, &grant()),
            SelectionReason::KillNotArmed,
            PlanTarget::Original,
        );
        candidate.route.fallback = Some(FallbackMode::FailClosed);
        assert_fallback(
            &select_enforcement_plan(&candidate, &grant()),
            SelectionReason::KillNotArmed,
            PlanTarget::None,
        );
    }
}

#[test]
fn unset_fallback_on_enforce_route_fails_closed_on_a_safety_event_not_open() {
    // A caller-constructed SelectionInput that bypasses EnforcementConfigV1::validate() (which
    // requires `fallback` to be set on authority-granting routes) must still fail closed on a
    // safety event such as the kill switch not being armed -- it must never silently bypass to
    // baseline just because `fallback` happens to be unset.
    let mut candidate = input();
    candidate.route.mode = RouteMode::Enforce;
    candidate.route.fallback = None;
    candidate.kill = KillReadResult::Malformed;

    assert_fallback(
        &select_enforcement_plan_without_grant(&candidate),
        SelectionReason::KillNotArmed,
        PlanTarget::None,
    );
}

#[test]
fn runtime_task_requires_exact_runtime_route_and_grant_equality() {
    let tasks = [
        TaskClass::Mechanical,
        TaskClass::HeavyLifting,
        TaskClass::TasteSensitive,
        TaskClass::Judgment,
        TaskClass::Unclassified,
    ];
    for runtime in tasks {
        for route_task in tasks {
            for grant_task in tasks {
                let mut candidate = input();
                candidate.task_class = runtime;
                candidate.route.task_class = Some(route_task);
                let mut authority = grant();
                authority.task_class = grant_task;
                let plan = select_enforcement_plan(&candidate, &authority);
                assert_eq!(
                    plan.target == PlanTarget::Candidate,
                    runtime == route_task && runtime == grant_task,
                    "runtime={runtime:?} route={route_task:?} grant={grant_task:?}"
                );
            }
        }
    }
}

#[test]
fn canonical_tags_are_set_equal_but_not_subset_or_superset_equal() {
    let mut reversed = input();
    reversed.resolved_tags.reverse();
    assert_eq!(
        select_enforcement_plan(&reversed, &grant()).target,
        PlanTarget::Candidate
    );

    for tags in [
        vec!["env:prod".into(), "env:prod".into(), "team:payments".into()],
        vec!["env:prod".into()],
        vec!["env:prod".into(), "team:payments".into(), "extra".into()],
    ] {
        let mut candidate = input();
        candidate.resolved_tags = tags;
        assert_fallback(
            &select_enforcement_plan(&candidate, &grant()),
            SelectionReason::AllowlistMiss,
            PlanTarget::Original,
        );
    }
}

#[test]
fn unresolved_application_never_matches_a_configured_selector() {
    for app in [None, Some("untrusted".to_owned())] {
        let mut candidate = input();
        candidate.app = app;
        candidate.workload_identity_digest = None;
        assert_ne!(
            select_enforcement_plan(&candidate, &grant()).target,
            PlanTarget::Candidate
        );
    }

    let mut literal = input();
    literal.route.workload.as_mut().unwrap().app = "untrusted".into();
    literal.app = None;
    literal.workload_identity_digest = None;
    assert_ne!(
        select_enforcement_plan(&literal, &grant()).target,
        PlanTarget::Candidate
    );
}

#[test]
fn recommend_needs_no_grant_and_never_grants_authority() {
    let mut recommend = input();
    recommend.route.mode = RouteMode::Recommend;
    recommend.route.promotion = None;
    recommend.route.rollout_ppm = 0;

    let unverified = select_enforcement_plan_without_grant(&recommend);
    assert_eq!(unverified.target, PlanTarget::Original);
    assert_eq!(unverified.evidence_state, EvidenceState::Unverified);
    assert_eq!(unverified.reason, SelectionReason::RecommendationOnly);
    assert!(unverified.grant_digest.is_none());
    assert_eq!(unverified.selected_supply_id.as_deref(), Some("baseline"));

    let presented = select_enforcement_plan(&recommend, &grant());
    assert_eq!(presented.target, PlanTarget::Original);
    assert_eq!(presented.evidence_state, EvidenceState::Presented);
    assert_eq!(presented.reason, SelectionReason::RecommendationOnly);
    assert_eq!(presented.dispatch_count, 0);
    assert_eq!(presented.selected_supply_id.as_deref(), Some("baseline"));
    for kill in [
        KillReadResult::Bypass,
        KillReadResult::Missing,
        KillReadResult::Unsafe,
        KillReadResult::Unreadable,
        KillReadResult::Malformed,
        KillReadResult::QueueUnavailable,
    ] {
        recommend.kill = kill;
        let presented = select_enforcement_plan(&recommend, &grant());
        assert_eq!(presented.target, PlanTarget::Original);
        assert_eq!(presented.reason, SelectionReason::RecommendationOnly);
        assert_eq!(presented.evidence_state, EvidenceState::Presented);
    }

    let candidate = select_enforcement_plan(&input(), &grant());
    assert_eq!(candidate.target, PlanTarget::Candidate);
    assert_eq!(candidate.evidence_state, EvidenceState::Presented);
}

#[test]
fn recommend_rejects_invalid_authority_metadata_as_unverified() {
    let mut recommend = input();
    recommend.route.mode = RouteMode::Recommend;
    recommend.route.promotion = None;
    recommend.route.rollout_ppm = 0;
    recommend.authority_metadata_valid = false;

    let plan = select_enforcement_plan(&recommend, &grant());
    assert_eq!(plan.target, PlanTarget::Original);
    assert_eq!(plan.reason, SelectionReason::RecommendationOnly);
    assert_eq!(plan.evidence_state, EvidenceState::Unverified);
    assert_eq!(plan.dispatch_count, 0);
    assert_eq!(plan.selected_supply_id.as_deref(), Some("baseline"));
    assert!(plan.grant_digest.is_none());
}

#[test]
fn non_authority_modes_remain_original_when_kill_state_changes() {
    let states = [
        KillReadResult::Armed,
        KillReadResult::Bypass,
        KillReadResult::Missing,
        KillReadResult::Unsafe,
        KillReadResult::Unreadable,
        KillReadResult::Malformed,
        KillReadResult::QueueUnavailable,
    ];
    for mode in [RouteMode::Observe, RouteMode::Recommend] {
        for fallback in [FallbackMode::Bypass, FallbackMode::FailClosed] {
            for state in states {
                let mut candidate = input();
                candidate.route.mode = mode;
                candidate.route.rollout_ppm = 0;
                candidate.route.promotion = None;
                candidate.route.fallback = Some(fallback);
                candidate.kill = state;
                let plan = select_enforcement_plan_without_grant(&candidate);
                assert_eq!(plan.target, PlanTarget::Original, "{mode:?}/{fallback:?}");
                assert!(matches!(
                    plan.reason,
                    SelectionReason::ObserveOnly | SelectionReason::RecommendationOnly
                ));
                assert_eq!(plan.dispatch_count, 0);
            }
        }
    }
}

#[test]
fn embeddings_never_select_candidate_with_forged_authority_inputs() {
    let mut candidate = input();
    candidate.protocol = AuthorityProtocol::Embeddings;
    candidate.route.protocol = AuthorityProtocol::Embeddings;
    let mut forged_grant = grant();
    forged_grant.protocol = AuthorityProtocol::Embeddings;

    assert_fallback(
        &select_enforcement_plan(&candidate, &forged_grant),
        SelectionReason::RouteMismatch,
        PlanTarget::Original,
    );
}

#[test]
fn deterministic_bucket_has_exact_framing_and_rollout_boundaries() {
    let bucket = enforcement_bucket("route-a", DIGEST_A, &[7; 32]);
    assert_eq!(bucket, 432_454);
    assert_eq!(enforcement_bucket("route-a", DIGEST_A, &[7; 32]), bucket);
    assert_ne!(enforcement_bucket("route-b", DIGEST_A, &[7; 32]), bucket);
    assert_ne!(enforcement_bucket("route-a", DIGEST_B, &[7; 32]), bucket);
    assert_ne!(enforcement_bucket("route-a", DIGEST_A, &[8; 32]), bucket);

    for (ppm, selected) in [(0, false), (1, false), (999_999, true), (1_000_000, true)] {
        let mut candidate = input();
        candidate.route.rollout_ppm = ppm;
        let plan = select_enforcement_plan(&candidate, &grant());
        assert_eq!(plan.target == PlanTarget::Candidate, selected, "ppm={ppm}");
        assert_eq!(plan.bucket, Some(bucket));
    }

    for (counter, expected_bucket, ppm, selected) in [
        (156_476_u64, 0, 0, false),
        (156_476, 0, 1, true),
        (387_313, 999_999, 999_999, false),
        (387_313, 999_999, 1_000_000, true),
    ] {
        let mut digest = [0_u8; 32];
        digest[..8].copy_from_slice(&counter.to_be_bytes());
        let mut candidate = input();
        candidate.request_body_digest = digest;
        candidate.route.rollout_ppm = ppm;
        let plan = select_enforcement_plan(&candidate, &grant());
        assert_eq!(plan.bucket, Some(expected_bucket));
        assert_eq!(plan.target == PlanTarget::Candidate, selected);
    }

    let plan_json = serde_json::to_value(select_enforcement_plan(&input(), &grant())).unwrap();
    let text = serde_json::to_string(&plan_json).unwrap();
    assert!(!text.contains("request_body_digest"));
    assert!(!text.contains(&"07".repeat(32)));
}

#[test]
fn model_rewrite_preserves_every_non_model_byte() {
    let limits = RewriteLimits {
        max_bytes: 4_096,
        max_depth: 32,
        max_nodes: 128,
    };
    let cases = [
        (
            br#"{"model":"old","n":1e+09,"huge":123456789012345678901234567890}"#.as_slice(),
            br#"{"model":"new","n":1e+09,"huge":123456789012345678901234567890}"#.as_slice(),
        ),
        (
            br#"{ "x" : [true,null,{"model":"nested"}], "\u006dodel" : "old", "z":"a\\\"b" }"#
                .as_slice(),
            br#"{ "x" : [true,null,{"model":"nested"}], "\u006dodel" : "new", "z":"a\\\"b" }"#
                .as_slice(),
        ),
        (
            br#"{"extension":{"deep":{"model":"nested"}},"model":"old","unknown":-0.25E-7}"#
                .as_slice(),
            br#"{"extension":{"deep":{"model":"nested"}},"model":"new","unknown":-0.25E-7}"#
                .as_slice(),
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(
            rewrite_top_level_model(body, "new", limits)
                .unwrap()
                .as_ref(),
            expected
        );
    }
    assert!(matches!(
        rewrite_top_level_model(br#"{"model":"same","x":1}"#, "same", limits).unwrap(),
        Cow::Borrowed(_)
    ));
}

#[test]
fn model_rewrite_rejects_ambiguity_malformed_and_exact_limit_overflow() {
    let limits = RewriteLimits {
        max_bytes: 64,
        max_depth: 3,
        max_nodes: 5,
    };
    let cases = [
        (
            br#"{"model":"a","\u006dodel":"b"}"#.as_slice(),
            RewriteError::DuplicateModel,
        ),
        (br#"{"x":1}"#.as_slice(), RewriteError::MissingModel),
        (br#"{"model":1}"#.as_slice(), RewriteError::ModelNotString),
        (br#"{"model":"x",}"#.as_slice(), RewriteError::MalformedJson),
        (
            b"{\"model\":\"\xff\"}".as_slice(),
            RewriteError::MalformedJson,
        ),
        (b"".as_slice(), RewriteError::MalformedJson),
        (
            br#"{"model":"x","a":{"b":{"c":1}}}"#.as_slice(),
            RewriteError::DepthLimit,
        ),
        (
            br#"{"model":"x","a":1,"b":2,"c":3,"d":4}"#.as_slice(),
            RewriteError::NodeLimit,
        ),
    ];
    for (body, expected) in cases {
        assert_eq!(rewrite_top_level_model(body, "new", limits), Err(expected));
    }

    let exact = format!("{{\"model\":\"{}\"}}", "x".repeat(52));
    assert_eq!(exact.len(), limits.max_bytes);
    assert!(rewrite_top_level_model(exact.as_bytes(), "new", limits).is_ok());
    assert_eq!(
        rewrite_top_level_model(format!("{exact} ").as_bytes(), "new", limits),
        Err(RewriteError::ByteLimit)
    );
    assert!(rewrite_top_level_model(br#"{"model":"x","a":{"b":1}}"#, "new", limits).is_ok());
    assert!(rewrite_top_level_model(br#"{"model":"x","a":1,"b":2,"c":3}"#, "new", limits).is_ok());
}
