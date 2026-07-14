use bowline_core::{
    enforcement::{
        AuthorityProtocol, EnforcementPlan, EvidenceState, KillReadResult, PlanTarget, RouteMode,
        SelectionReason,
    },
    supply::TaskClass,
};
use bowline_gateway::observation::{
    prepare_zero_authority_decision_v2, AuthorityDecisionContextV2,
};

fn digest(value: u8) -> String {
    format!("sha256:{value:064x}")
}

#[test]
fn fabricated_candidate_schema_cannot_cross_the_zero_authority_boundary() {
    let plan = EnforcementPlan {
        target: PlanTarget::Candidate,
        mode: RouteMode::Enforce,
        reason: SelectionReason::CandidateSelected,
        evidence_state: EvidenceState::Presented,
        bucket: Some(42),
        selected_supply_id: Some("candidate".into()),
        baseline_supply_id: Some("baseline".into()),
        actuator_digest: Some(digest(1)),
        config_digest: Some(digest(2)),
        route_digest: Some(digest(3)),
        model_rewritten: true,
        grant_digest: Some(digest(4)),
        dispatch_count: 1,
    };
    let result = prepare_zero_authority_decision_v2(
        &plan,
        AuthorityDecisionContextV2 {
            decision_id: "decision".into(),
            ts_ms: 10,
            route_id: "route".into(),
            protocol: AuthorityProtocol::ChatCompletions,
            task_class: TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(5)),
            kill_state: KillReadResult::Armed,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            request_body_digest: [7; 32],
            requested_supply_id: None,
        },
    );
    assert!(result.is_err());
}

#[test]
fn zero_authority_mapping_rejects_candidate_only_context() {
    let plan = EnforcementPlan {
        target: PlanTarget::None,
        mode: RouteMode::Enforce,
        reason: SelectionReason::KillNotArmed,
        evidence_state: EvidenceState::Unverified,
        bucket: None,
        selected_supply_id: None,
        baseline_supply_id: Some("baseline".into()),
        actuator_digest: None,
        config_digest: Some(digest(2)),
        route_digest: Some(digest(3)),
        model_rewritten: false,
        grant_digest: None,
        dispatch_count: 0,
    };
    let context = AuthorityDecisionContextV2 {
        decision_id: "decision".into(),
        ts_ms: 10,
        route_id: "route".into(),
        protocol: AuthorityProtocol::Responses,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest(5)),
        kill_state: KillReadResult::Bypass,
        method: "POST".into(),
        path: "/v1/responses".into(),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        request_body_digest: [7; 32],
        requested_supply_id: None,
    };
    let prepared = prepare_zero_authority_decision_v2(&plan, context).unwrap();
    assert!(!prepared.decision().grants_candidate_authority());
    assert_eq!(prepared.decision().intended_dispatch, 0);
}
