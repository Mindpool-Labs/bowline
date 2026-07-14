use bowline_core::{
    attribution::{AttributionResult, AttributionStatus},
    config::OwnedCostCatalog,
    decision::{est_cost_usd, Decision},
    enforcement::{
        AuthorityProtocol, EnforcementPlan, KillReadResult, PlanTarget, ValidatedEnforcement,
    },
    ledger::{
        ActualOutcome, AuthorityDecisionV2, AuthorityFallbackReasonV2, AuthorityGrantBindingV2,
        AuthorityRecordError, AuthoritySelectionFactsV2, DecisionRecord, UsageSource,
    },
    policy::WorkloadIdentity,
    supply::{Registry, SupplyClass, TaskClass},
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::enforcement_loader::{
    BoundedKillStateReader, GatewayEnforcementPlan, GatewayEvidenceState, VerifiedPromotionGrant,
};

#[derive(Debug)]
pub struct AuthorityDecisionContextV2 {
    pub decision_id: String,
    pub ts_ms: u64,
    pub route_id: String,
    pub protocol: AuthorityProtocol,
    pub task_class: TaskClass,
    pub workload_identity_digest: Option<String>,
    pub kill_state: KillReadResult,
    pub method: String,
    pub path: String,
    pub app: Option<String>,
    pub resolved_tags: Vec<String>,
    pub request_body_digest: [u8; 32],
    pub requested_supply_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ExactDispatchBindingV2 {
    pub(crate) request_body_digest: [u8; 32],
    pub(crate) target: PlanTarget,
    pub(crate) selected_supply_id: Option<String>,
    pub(crate) requested_supply_id: Option<String>,
    pub(crate) route_id: String,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) protocol: AuthorityProtocol,
    pub(crate) task_class: TaskClass,
    pub(crate) workload_identity_digest: Option<String>,
    pub(crate) app: Option<String>,
    pub(crate) resolved_tags: Vec<String>,
    pub(crate) bucket: Option<u32>,
}

/// A schema-v2 decision prepared at the gateway authority boundary. Its fields are private so a
/// deserialized or fabricated core schema value cannot become dispatch authority.
#[derive(Debug)]
pub struct PreparedAuthorityDecisionV2 {
    decision: AuthorityDecisionV2,
    dispatch_binding: ExactDispatchBindingV2,
    verified_grant: Option<VerifiedPromotionGrant>,
    authorization_revalidation: Option<AuthorizationRevalidationV2>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthorizationRevalidationV2 {
    pub(crate) kill_reader: BoundedKillStateReader,
    pub(crate) not_before_ms: u64,
    pub(crate) expires_at_ms: u64,
    #[cfg(test)]
    pub(crate) now_override: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
}

impl AuthorizationRevalidationV2 {
    pub(crate) fn now_ms(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.now_override.as_ref() {
            return now.load(std::sync::atomic::Ordering::Acquire);
        }
        trusted_now_ms()
    }
}

impl PreparedAuthorityDecisionV2 {
    pub fn decision(&self) -> &AuthorityDecisionV2 {
        &self.decision
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AuthorityDecisionV2,
        ExactDispatchBindingV2,
        Option<VerifiedPromotionGrant>,
        Option<AuthorizationRevalidationV2>,
    ) {
        (
            self.decision,
            self.dispatch_binding,
            self.verified_grant,
            self.authorization_revalidation,
        )
    }
}

#[cfg(test)]
pub(crate) fn test_prepared_authority_decision_v2(
    decision: AuthorityDecisionV2,
) -> PreparedAuthorityDecisionV2 {
    let dispatch_binding = ExactDispatchBindingV2 {
        request_body_digest: [7; 32],
        target: decision.target,
        selected_supply_id: decision.selected_supply_id.clone(),
        requested_supply_id: None,
        route_id: decision.route_id.clone(),
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        protocol: decision.protocol,
        task_class: decision.task_class,
        workload_identity_digest: decision.workload_identity_digest.clone(),
        app: decision.app.clone(),
        resolved_tags: vec!["production".into()],
        bucket: decision.selection_facts.bucket,
    };
    PreparedAuthorityDecisionV2 {
        decision,
        dispatch_binding,
        verified_grant: None,
        authorization_revalidation: None,
    }
}

#[cfg(test)]
pub(crate) fn test_prepared_authority_decision_v2_with_revalidation(
    decision: AuthorityDecisionV2,
    kill_reader: BoundedKillStateReader,
    not_before_ms: u64,
    expires_at_ms: u64,
    now_override: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> PreparedAuthorityDecisionV2 {
    let mut prepared = test_prepared_authority_decision_v2(decision);
    prepared.authorization_revalidation = Some(AuthorizationRevalidationV2 {
        kill_reader,
        not_before_ms,
        expires_at_ms,
        now_override: Some(now_override),
    });
    prepared
}

#[derive(Debug)]
pub enum CandidatePreparationV2 {
    Candidate(PreparedAuthorityDecisionV2),
    Fallback(PreparedAuthorityDecisionV2),
}

pub fn prepare_zero_authority_decision_v2(
    plan: &EnforcementPlan,
    context: AuthorityDecisionContextV2,
) -> Result<PreparedAuthorityDecisionV2, AuthorityRecordError> {
    if plan.target == PlanTarget::Candidate {
        return Err(AuthorityRecordError::InvalidDecision);
    }
    build_prepared_decision(plan, context, None, None)
}

pub async fn prepare_candidate_authority_decision_v2(
    validated: &ValidatedEnforcement,
    gateway_plan: GatewayEnforcementPlan,
    grant: VerifiedPromotionGrant,
    decision_id: String,
    kill_reader: &BoundedKillStateReader,
) -> Result<CandidatePreparationV2, AuthorityRecordError> {
    let kill_state = kill_reader.read_kill_state().await;
    let now_ms = trusted_now_ms();
    let (plan, evidence_state, selection) = gateway_plan.into_parts();
    if selection.protocol == AuthorityProtocol::Embeddings
        || evidence_state != GatewayEvidenceState::Verified
    {
        return Err(AuthorityRecordError::InvalidDecision);
    }
    let route = validated
        .route(&selection.route_id)
        .ok_or(AuthorityRecordError::InvalidDecision)?;
    let opportunity_digest = route
        .promotion
        .as_ref()
        .map(|promotion| promotion.opportunity_digest.clone())
        .ok_or(AuthorityRecordError::InvalidDecision)?;
    if selection.method != route.method
        || selection.path != route.path
        || selection.protocol != route.protocol
        || selection.task_class != route.task_class.unwrap_or(TaskClass::Unclassified)
        || selection.task_class != grant.task_class()
        || selection.selected_bucket != plan.bucket
        || plan.target != PlanTarget::Candidate
        || plan.evidence_state != bowline_core::enforcement::EvidenceState::Presented
        || grant.route_id() != selection.route_id
        || selection.workload_identity_digest.as_deref() != Some(grant.workload_identity_digest())
        || grant.protocol() != selection.protocol
        || plan.grant_digest.as_deref() != Some(grant.grant_digest())
        || plan.config_digest.as_deref() != Some(grant.config_digest())
        || plan.route_digest.as_deref() != Some(grant.route_digest())
        || plan.actuator_digest.as_deref() != Some(grant.actuator_digest())
        || plan.selected_supply_id.as_deref() != Some(grant.candidate_supply_id())
        || plan.baseline_supply_id.as_deref() != Some(grant.actual_supply_id())
    {
        return Err(AuthorityRecordError::InvalidDecision);
    }
    let context = AuthorityDecisionContextV2 {
        decision_id,
        ts_ms: now_ms,
        route_id: selection.route_id.clone(),
        protocol: selection.protocol,
        task_class: selection.task_class,
        workload_identity_digest: selection.workload_identity_digest.clone(),
        kill_state,
        method: selection.method.clone(),
        path: selection.path.clone(),
        app: selection.app.clone(),
        resolved_tags: selection.resolved_tags.clone(),
        request_body_digest: selection.request_body_digest,
        requested_supply_id: selection.requested_supply_id.clone(),
    };
    if kill_state != KillReadResult::Armed || !grant.is_fresh_at(now_ms) {
        let reason = if kill_state == KillReadResult::Armed {
            bowline_core::enforcement::SelectionReason::GrantStale
        } else {
            bowline_core::enforcement::SelectionReason::KillNotArmed
        };
        let target = match route.fallback {
            Some(bowline_core::enforcement::FallbackMode::Bypass) => PlanTarget::Original,
            _ => PlanTarget::None,
        };
        let fallback = EnforcementPlan {
            target,
            mode: route.mode,
            reason,
            evidence_state: bowline_core::enforcement::EvidenceState::Unverified,
            bucket: None,
            selected_supply_id: (target == PlanTarget::Original)
                .then(|| grant.actual_supply_id().to_owned()),
            baseline_supply_id: Some(grant.actual_supply_id().to_owned()),
            actuator_digest: None,
            config_digest: Some(grant.config_digest().to_owned()),
            route_digest: Some(grant.route_digest().to_owned()),
            model_rewritten: false,
            grant_digest: None,
            dispatch_count: u8::from(target == PlanTarget::Original),
        };
        return build_prepared_decision(&fallback, context, None, None)
            .map(CandidatePreparationV2::Fallback);
    }
    let actuator_identity_digest = validated
        .actuator_endpoint_identity_digest(grant.candidate_supply_id())
        .ok_or(AuthorityRecordError::InvalidDecision)?;
    let binding = AuthorityGrantBindingV2 {
        grant_digest: grant.grant_digest().to_owned(),
        expires_at_ms: grant.expires_at_ms(),
        economics_source_digest: grant.economics_source_digest().to_owned(),
        quality_source_digest: grant.quality_source_digest().to_owned(),
        opportunity_digest,
    };
    build_prepared_decision(
        &plan,
        context,
        Some(binding),
        Some(actuator_identity_digest),
    )
    .map(|mut prepared| {
        prepared.authorization_revalidation = Some(AuthorizationRevalidationV2 {
            kill_reader: kill_reader.clone(),
            not_before_ms: grant.not_before_ms(),
            expires_at_ms: grant.expires_at_ms(),
            #[cfg(test)]
            now_override: None,
        });
        prepared.verified_grant = Some(grant);
        CandidatePreparationV2::Candidate(prepared)
    })
}

fn build_prepared_decision(
    plan: &EnforcementPlan,
    context: AuthorityDecisionContextV2,
    grant: Option<AuthorityGrantBindingV2>,
    actuator_identity_digest: Option<String>,
) -> Result<PreparedAuthorityDecisionV2, AuthorityRecordError> {
    if plan.target == PlanTarget::Candidate && context.protocol == AuthorityProtocol::Embeddings {
        return Err(AuthorityRecordError::InvalidDecision);
    }
    let dispatch_binding = ExactDispatchBindingV2 {
        request_body_digest: context.request_body_digest,
        target: plan.target,
        selected_supply_id: plan.selected_supply_id.clone(),
        requested_supply_id: context.requested_supply_id.clone(),
        route_id: context.route_id.clone(),
        method: context.method.clone(),
        path: context.path.clone(),
        protocol: context.protocol,
        task_class: context.task_class,
        workload_identity_digest: context.workload_identity_digest.clone(),
        app: context.app.clone(),
        resolved_tags: context.resolved_tags.clone(),
        bucket: plan.bucket,
    };
    let decision = AuthorityDecisionV2 {
        decision_id: context.decision_id,
        replaces_decision_id: None,
        configured_fallback_target: None,
        ts_ms: context.ts_ms,
        route_id: context.route_id,
        mode: plan.mode,
        protocol: context.protocol,
        task_class: context.task_class,
        workload_identity_digest: context.workload_identity_digest,
        app: context.app,
        resolved_tags: context.resolved_tags,
        requested_supply_id: context.requested_supply_id,
        reason: plan.reason,
        evidence_state: plan.evidence_state,
        selection_facts: selection_facts_for_plan(plan, context.kill_state)?,
        target: plan.target,
        intended_dispatch: u8::from(plan.target != PlanTarget::None),
        grant,
        selected_supply_id: plan.selected_supply_id.clone(),
        baseline_supply_id: plan.baseline_supply_id.clone(),
        actuator_identity_digest,
        actuator_config_digest: plan.actuator_digest.clone(),
        enforcement_config_digest: plan
            .config_digest
            .clone()
            .ok_or(AuthorityRecordError::InvalidDecision)?,
        route_config_digest: plan
            .route_digest
            .clone()
            .ok_or(AuthorityRecordError::InvalidDecision)?,
        model_rewritten: plan.model_rewritten,
    };
    decision.validate()?;
    Ok(PreparedAuthorityDecisionV2 {
        decision,
        dispatch_binding,
        verified_grant: None,
        authorization_revalidation: None,
    })
}

fn selection_facts_for_plan(
    plan: &EnforcementPlan,
    kill_state: KillReadResult,
) -> Result<AuthoritySelectionFactsV2, AuthorityRecordError> {
    match plan.reason {
        bowline_core::enforcement::SelectionReason::CandidateSelected => plan
            .bucket
            .map(AuthoritySelectionFactsV2::canonical_candidate)
            .ok_or(AuthorityRecordError::InvalidDecision),
        bowline_core::enforcement::SelectionReason::ObserveOnly
        | bowline_core::enforcement::SelectionReason::RecommendationOnly => Ok(
            AuthoritySelectionFactsV2::canonical_non_authority(kill_state),
        ),
        reason => {
            let fallback = AuthorityFallbackReasonV2::try_from(reason)?;
            let mut facts = AuthoritySelectionFactsV2::canonical_fallback(fallback);
            if fallback == AuthorityFallbackReasonV2::KillNotArmed {
                facts.kill_state = kill_state;
            }
            facts.bucket = plan.bucket;
            facts.validate_fallback(fallback)?;
            Ok(facts)
        }
    }
}

fn trusted_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(crate) struct RecordEnvelope {
    pub id: String,
    pub ts_ms: u64,
    pub run_id: Option<String>,
    pub sequence: Option<u64>,
    pub accounting_truncated: bool,
    pub protocol: ProtocolKind,
    pub observation_source: ObservationSource,
    pub coverage_status: CoverageStatus,
    pub coverage_reason: Option<String>,
    pub identity: WorkloadIdentity,
    pub decision: Decision,
}

pub(crate) struct ActualObservation {
    pub upstream: String,
    pub model: Option<String>,
    pub status: u16,
    pub streamed: bool,
    pub latency_ms: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub usage_source: UsageSource,
    pub est_cost_usd: Option<f64>,
    pub attribution: AttributionResult,
}

pub(crate) fn build_decision_record(
    envelope: RecordEnvelope,
    actual: ActualObservation,
) -> DecisionRecord {
    let attribution = actual.attribution;
    DecisionRecord {
        id: envelope.id,
        ts_ms: envelope.ts_ms,
        run_id: envelope.run_id,
        sequence: envelope.sequence,
        accounting_truncated: envelope.accounting_truncated,
        protocol: envelope.protocol,
        observation_source: envelope.observation_source,
        coverage_status: envelope.coverage_status,
        coverage_reason: envelope.coverage_reason,
        identity: envelope.identity,
        decision: envelope.decision,
        actual: ActualOutcome {
            upstream: actual.upstream,
            supply_id: attribution.supply_id,
            model: actual.model,
            status: actual.status,
            streamed: actual.streamed,
            latency_ms: actual.latency_ms,
            input_tokens: actual.input_tokens,
            output_tokens: actual.output_tokens,
            usage_source: actual.usage_source,
            est_cost_usd: actual.est_cost_usd,
            attribution_status: attribution.status,
            attribution_source: attribution.source,
            attribution_reference: attribution.reference,
            attribution_reason: attribution.reason,
        },
    }
}

pub(crate) fn apply_attribution_coverage(
    status: CoverageStatus,
    reason: Option<String>,
    attribution: &AttributionResult,
    require_dynamic_attribution: bool,
) -> (CoverageStatus, Option<String>) {
    if status != CoverageStatus::Supported {
        return (status, reason);
    }
    let acceptable = matches!(
        attribution.status,
        AttributionStatus::Attributed | AttributionStatus::StaticConfigured
    );
    if !require_dynamic_attribution || acceptable {
        (status, reason)
    } else {
        (
            CoverageStatus::IncompleteObservation,
            attribution.reason.clone(),
        )
    }
}

pub(crate) fn actual_cost(
    registry: &Registry,
    actual_supply_id: Option<&str>,
    model: Option<&str>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    owned_costs: &OwnedCostCatalog,
) -> Option<f64> {
    let entry = registry.resolve_model(actual_supply_id?, model?)?;
    let input_tokens = input_tokens.unwrap_or(0);
    let output_tokens = output_tokens.unwrap_or(0);

    if let Some(price) = &entry.price {
        Some(est_cost_usd(price, input_tokens, output_tokens))
    } else if entry.attributes.class == SupplyClass::Owned {
        owned_costs.cost_per_mtok(&entry.id).map(|cost_per_mtok| {
            ((input_tokens + output_tokens) as f64 / 1_000_000.0) * cost_per_mtok
        })
    } else {
        None
    }
}

#[cfg(test)]
mod candidate_protocol_tests {
    use super::*;
    use bowline_core::enforcement::{EvidenceState, RouteMode, SelectionReason};

    fn digest(value: u8) -> String {
        format!("sha256:{value:064x}")
    }

    #[test]
    fn candidate_preparation_rejects_embeddings_independently() {
        let plan = EnforcementPlan {
            target: PlanTarget::Candidate,
            mode: RouteMode::Enforce,
            reason: SelectionReason::CandidateSelected,
            evidence_state: EvidenceState::Presented,
            bucket: Some(7),
            selected_supply_id: Some("candidate".into()),
            baseline_supply_id: Some("baseline".into()),
            actuator_digest: Some(digest(1)),
            config_digest: Some(digest(2)),
            route_digest: Some(digest(3)),
            model_rewritten: true,
            grant_digest: Some(digest(4)),
            dispatch_count: 1,
        };
        let context = AuthorityDecisionContextV2 {
            decision_id: "embeddings-candidate".into(),
            ts_ms: 10,
            route_id: "route".into(),
            protocol: AuthorityProtocol::Embeddings,
            task_class: TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(5)),
            kill_state: KillReadResult::Armed,
            method: "POST".into(),
            path: "/v1/embeddings".into(),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            request_body_digest: [7; 32],
            requested_supply_id: None,
        };
        let grant = AuthorityGrantBindingV2 {
            grant_digest: digest(4),
            expires_at_ms: 100,
            economics_source_digest: digest(6),
            quality_source_digest: digest(7),
            opportunity_digest: digest(8),
        };

        assert!(build_prepared_decision(&plan, context, Some(grant), Some(digest(9))).is_err());
    }
}
