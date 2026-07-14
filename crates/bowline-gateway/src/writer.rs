use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::Context;
use bowline_core::{
    economics::{EconomicsError, EnforcedModeledDelta, EnforcedModeledDeltaStatus},
    enforcement::{FallbackMode, PlanTarget, SelectionReason, ValidatedEnforcement},
    ledger::{
        modeled_delta_applicable, validate_authority_pair_v2, AuthorityDecisionV2,
        AuthorityFallbackReasonV2, AuthorityLedgerV2, AuthorityOutcomeV2, AuthorityRecordV2,
        CandidateFailureClassV2, CircuitStateV2, CompletionStateV2, DecisionRecord, Ledger,
        RecoveryOutcome, SegmentedLedger, UsageSource, ValidatedCompleteAuthorityRunV2,
    },
    run::{
        AuthorityRunDigestsV2, AuthorityRunManifestV2, AuthorityRunStoreV2, RunDigests, RunError,
        RunLimits, RunStore,
    },
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::health::GatewayHealth;
#[cfg(test)]
use crate::observation::{
    test_prepared_authority_decision_v2, test_prepared_authority_decision_v2_with_revalidation,
};
use crate::observation::{
    AuthorizationRevalidationV2, ExactDispatchBindingV2, PreparedAuthorityDecisionV2,
};

#[cfg(test)]
use bowline_core::traffic::{CoverageStatus, ObservationSource, ProtocolKind};
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::path::Path;

const WRITER_CHANNEL: usize = 1024;
const FLUSH_BATCH: usize = 100;
const FLUSH_IDLE: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct ManagedWriterOptions {
    pub directory: PathBuf,
    pub policy_digest: String,
    pub registry_digest: String,
    pub attribution_digest: Option<String>,
    pub owned_cost_digest: Option<String>,
    pub passive_profile_digest: Option<String>,
    pub passive_input_digest: Option<String>,
    pub segment_bytes: u64,
    pub max_segments: u32,
    pub queue_capacity: usize,
}

impl ManagedWriterOptions {
    #[cfg(test)]
    fn test(directory: &Path, queue_capacity: usize) -> Self {
        Self {
            directory: directory.to_path_buf(),
            policy_digest: "sha256:policy".to_string(),
            registry_digest: "sha256:registry".to_string(),
            attribution_digest: None,
            owned_cost_digest: None,
            passive_profile_digest: None,
            passive_input_digest: None,
            segment_bytes: 64 * 1024,
            max_segments: 8,
            queue_capacity,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordContext {
    pub run_id: String,
    pub sequence: u64,
}

#[derive(Clone)]
pub struct ManagedWriter {
    inner: Arc<ManagedWriterInner>,
}

struct ManagedWriterInner {
    tx: mpsc::Sender<WriterMessage>,
    health: GatewayHealth,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

enum WriterMessage {
    Record(Box<DecisionRecord>),
    Shutdown(oneshot::Sender<Result<(), String>>),
}

#[derive(Debug, Error)]
pub enum ManagedWriterError {
    #[error("managed writer queue is full")]
    QueueFull,
    #[error("managed writer is closed")]
    Closed,
    #[error("record does not carry this writer's run ID and allocated sequence")]
    InvalidRecordContext,
    #[error("managed writer shutdown exceeded grace period")]
    ShutdownTimeout,
    #[error("managed writer thread failed: {0}")]
    Writer(String),
    #[error(transparent)]
    Run(#[from] RunError),
}

#[derive(Debug, Clone)]
pub struct AuthorityWriterOptions {
    pub directory: PathBuf,
    pub enforcement_digest: String,
    pub actuator_digests: Vec<String>,
    pub grant_digests: Vec<String>,
    pub queue_capacity: usize,
    pub max_records_bytes: u64,
}

pub struct DecisionHandle {
    payload: Option<DecisionHandlePayload>,
    owner: Arc<ManagedAuthorityWriterInner>,
}

#[derive(Debug)]
struct DecisionHandlePayload {
    run_id: String,
    decision_id: String,
    target: bowline_core::enforcement::PlanTarget,
    dispatch_binding: ExactDispatchBindingV2,
    verified_grant: Option<crate::enforcement_loader::VerifiedPromotionGrant>,
    authorization_revalidation: Option<AuthorizationRevalidationV2>,
    decision: AuthorityDecisionV2,
    recovered_fallback: bool,
}

impl std::fmt::Debug for DecisionHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecisionHandle")
            .field(
                "decision_id",
                &self.payload.as_ref().map(|value| &value.decision_id),
            )
            .finish_non_exhaustive()
    }
}

impl DecisionHandle {
    pub fn authorizes_candidate(&self) -> bool {
        self.payload.as_ref().is_some_and(|payload| {
            payload.target == bowline_core::enforcement::PlanTarget::Candidate
        })
    }

    pub fn decision_id(&self) -> &str {
        &self
            .payload
            .as_ref()
            .expect("live decision handle")
            .decision_id
    }

    pub fn decision(&self) -> &AuthorityDecisionV2 {
        &self
            .payload
            .as_ref()
            .expect("live decision handle")
            .decision
    }

    pub async fn authorize_dispatch(
        mut self,
        attempt: DispatchAttemptV2,
    ) -> Result<AuthorizedDispatchHandle, ManagedWriterError> {
        if let Err(error) = self.validate_dispatch_attempt(&attempt) {
            self.invalidate("dispatch attempt does not match flushed authority decision");
            return Err(error);
        }
        let payload = self.payload.as_ref().expect("live decision handle");
        let revalidation = payload.authorization_revalidation.clone();
        if let Some(revalidation) = revalidation {
            let kill_state = revalidation.kill_reader.read_kill_state().await;
            let now_ms = revalidation.now_ms();
            if kill_state != bowline_core::enforcement::KillReadResult::Armed
                || now_ms < revalidation.not_before_ms
                || now_ms > revalidation.expires_at_ms
            {
                self.invalidate("dispatch authorization kill or grant freshness check failed");
                return Err(ManagedWriterError::InvalidRecordContext);
            }
        }
        let authorization = {
            let recovered_fallback = payload.recovered_fallback;
            let mut lifecycle = self
                .owner
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lifecycle.closing {
                poison_authority_run_locked(
                    &self.owner.run,
                    &mut lifecycle,
                    "dispatch authorization raced with authority shutdown",
                    None,
                );
                Err(ManagedWriterError::Closed)
            } else if !lifecycle.transport_available {
                Err(ManagedWriterError::Closed)
            } else if !lifecycle.authority_complete && !recovered_fallback {
                Err(ManagedWriterError::InvalidRecordContext)
            } else {
                let authorized_dispatches = lifecycle
                    .authorized_dispatches
                    .checked_add(1)
                    .ok_or_else(|| {
                        ManagedWriterError::Writer(
                            "authority dispatch lifecycle overflow".to_string(),
                        )
                    })?;
                debug_assert!(
                    lifecycle.issued_decisions > 0,
                    "issued decision counter underflow"
                );
                lifecycle.issued_decisions = lifecycle.issued_decisions.saturating_sub(1);
                lifecycle.authorized_dispatches = authorized_dispatches;
                Ok(())
            }
        };
        if let Err(error) = authorization {
            self.invalidate("dispatch authorization rejected by authority lifecycle");
            return Err(error);
        }
        Ok(AuthorizedDispatchHandle {
            payload: self.payload.take().map(Box::new),
            owner: Arc::clone(&self.owner),
        })
    }

    fn validate_dispatch_attempt(
        &self,
        attempt: &DispatchAttemptV2,
    ) -> Result<(), ManagedWriterError> {
        let payload = self.payload.as_ref().expect("live decision handle");
        let binding = &payload.dispatch_binding;
        if (payload.target == bowline_core::enforcement::PlanTarget::Candidate
            && (payload.decision.protocol
                == bowline_core::enforcement::AuthorityProtocol::Embeddings
                || binding.protocol == bowline_core::enforcement::AuthorityProtocol::Embeddings
                || attempt.protocol == bowline_core::enforcement::AuthorityProtocol::Embeddings))
            || binding.request_body_digest != attempt.request_body_digest
            || binding.target != attempt.target
            || payload.target != attempt.target
            || binding.selected_supply_id != attempt.selected_supply_id
            || binding.requested_supply_id != attempt.requested_supply_id
            || binding.route_id != attempt.route_id
            || binding.method != attempt.method
            || binding.path != attempt.path
            || binding.protocol != attempt.protocol
            || binding.task_class != attempt.task_class
            || binding.workload_identity_digest != attempt.workload_identity_digest
            || binding.app != attempt.app
            || binding.resolved_tags != attempt.resolved_tags
            || binding.bucket != attempt.bucket
        {
            return Err(ManagedWriterError::InvalidRecordContext);
        }
        Ok(())
    }

    fn authorization_revalidation(&self) -> Option<AuthorizationRevalidationV2> {
        self.payload
            .as_ref()
            .and_then(|payload| payload.authorization_revalidation.clone())
    }

    async fn authorize_dispatch_without_revalidation(
        mut self,
        attempt: DispatchAttemptV2,
    ) -> Result<AuthorizedDispatchHandle, ManagedWriterError> {
        self.payload
            .as_mut()
            .expect("live decision handle")
            .authorization_revalidation = None;
        self.authorize_dispatch(attempt).await
    }

    /// Consumes the exact dispatch binding durably sealed into this decision. Production proxy
    /// integration uses this method so no duplicated caller reconstruction can drift one field.
    pub async fn authorize_bound_dispatch(
        self,
    ) -> Result<AuthorizedDispatchHandle, ManagedWriterError> {
        let attempt = self.bound_attempt();
        self.authorize_dispatch(attempt).await
    }

    fn bound_attempt(&self) -> DispatchAttemptV2 {
        let binding = &self
            .payload
            .as_ref()
            .expect("live decision handle")
            .dispatch_binding;
        DispatchAttemptV2 {
            request_body_digest: binding.request_body_digest,
            target: binding.target,
            selected_supply_id: binding.selected_supply_id.clone(),
            requested_supply_id: binding.requested_supply_id.clone(),
            route_id: binding.route_id.clone(),
            method: binding.method.clone(),
            path: binding.path.clone(),
            protocol: binding.protocol,
            task_class: binding.task_class,
            workload_identity_digest: binding.workload_identity_digest.clone(),
            app: binding.app.clone(),
            resolved_tags: binding.resolved_tags.clone(),
            bucket: binding.bucket,
        }
    }

    fn invalidate(&mut self, reason: &str) {
        if self.payload.take().is_some() {
            settle_outstanding_authority(&self.owner, AuthorityHandlePhase::Decision, Some(reason));
        }
    }
}

impl Drop for DecisionHandle {
    fn drop(&mut self) {
        self.invalidate("flushed authority decision handle was abandoned before dispatch");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchAttemptV2 {
    pub request_body_digest: [u8; 32],
    pub target: bowline_core::enforcement::PlanTarget,
    pub selected_supply_id: Option<String>,
    pub requested_supply_id: Option<String>,
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub protocol: bowline_core::enforcement::AuthorityProtocol,
    pub task_class: bowline_core::supply::TaskClass,
    pub workload_identity_digest: Option<String>,
    pub app: Option<String>,
    pub resolved_tags: Vec<String>,
    pub bucket: Option<u32>,
}

pub struct AuthorizedDispatchHandle {
    payload: Option<Box<DecisionHandlePayload>>,
    owner: Arc<ManagedAuthorityWriterInner>,
}

#[derive(Debug, Clone)]
pub struct AuthorityTerminalV2 {
    pub ts_ms: u64,
    pub circuit_after: CircuitStateV2,
    pub completion: CompletionStateV2,
    pub candidate_failure: Option<CandidateFailureClassV2>,
    pub status: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub usage_source: UsageSource,
}

impl std::fmt::Debug for AuthorizedDispatchHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedDispatchHandle")
            .field(
                "decision_id",
                &self.payload.as_ref().map(|value| &value.decision_id),
            )
            .finish_non_exhaustive()
    }
}

impl AuthorizedDispatchHandle {
    pub fn build_outcome(
        &self,
        terminal: AuthorityTerminalV2,
    ) -> Result<AuthorityOutcomeV2, ManagedWriterError> {
        let payload = self.payload.as_ref().ok_or(ManagedWriterError::Closed)?;
        let decision = &payload.decision;
        let fallback_reason = if decision.target == PlanTarget::Candidate
            || matches!(
                decision.mode,
                bowline_core::enforcement::RouteMode::Observe
                    | bowline_core::enforcement::RouteMode::Recommend
            ) {
            None
        } else {
            Some(
                AuthorityFallbackReasonV2::try_from(decision.reason)
                    .map_err(|_| ManagedWriterError::InvalidRecordContext)?,
            )
        };
        let mut outcome = AuthorityOutcomeV2 {
            decision_id: decision.decision_id.clone(),
            replaces_decision_id: decision.replaces_decision_id.clone(),
            ts_ms: terminal.ts_ms,
            route_id: decision.route_id.clone(),
            mode: decision.mode,
            protocol: decision.protocol,
            task_class: decision.task_class,
            workload_identity_digest: decision.workload_identity_digest.clone(),
            app: decision.app.clone(),
            resolved_tags: decision.resolved_tags.clone(),
            requested_supply_id: decision.requested_supply_id.clone(),
            selection_facts: decision.selection_facts.clone(),
            grant_digest: decision
                .grant
                .as_ref()
                .map(|grant| grant.grant_digest.clone()),
            grant_expires_at_ms: decision.grant.as_ref().map(|grant| grant.expires_at_ms),
            model_rewritten: decision.model_rewritten,
            selected_supply_id: decision.selected_supply_id.clone(),
            baseline_supply_id: decision.baseline_supply_id.clone(),
            actuator_identity_digest: decision.actuator_identity_digest.clone(),
            actuator_config_digest: decision.actuator_config_digest.clone(),
            enforcement_config_digest: decision.enforcement_config_digest.clone(),
            route_config_digest: decision.route_config_digest.clone(),
            target: decision.target,
            fallback_reason,
            circuit_before: decision.selection_facts.circuit_before,
            circuit_after: terminal.circuit_after,
            actual_dispatch: u8::from(decision.target != PlanTarget::None),
            completion: terminal.completion,
            candidate_failure: terminal.candidate_failure,
            status: terminal.status,
            input_tokens: terminal.input_tokens,
            output_tokens: terminal.output_tokens,
            usage_source: terminal.usage_source,
            observed_actual_cost_micros: None,
            approved_counterfactual_cost_micros: None,
            enforced_modeled_delta_micros: None,
        };
        if modeled_delta_applicable(&outcome) {
            if let Some(grant) = payload.verified_grant.as_ref() {
                let input = outcome
                    .input_tokens
                    .expect("applicability requires input tokens");
                let output = outcome
                    .output_tokens
                    .expect("applicability requires output tokens");
                let actual = grant
                    .candidate_rate_micros()
                    .cost_micros(input, output)
                    .map_err(|error| ManagedWriterError::Writer(error.to_string()))?;
                let counterfactual = grant
                    .actual_rate_micros()
                    .cost_micros(input, output)
                    .map_err(|error| ManagedWriterError::Writer(error.to_string()))?;
                outcome.observed_actual_cost_micros = Some(actual);
                outcome.approved_counterfactual_cost_micros = Some(counterfactual);
                outcome.enforced_modeled_delta_micros =
                    Some(i128::from(counterfactual) - i128::from(actual));
            }
        }
        outcome
            .validate()
            .map_err(|_| ManagedWriterError::InvalidRecordContext)?;
        validate_authority_pair_v2(decision, &outcome)
            .map_err(|_| ManagedWriterError::InvalidRecordContext)?;
        Ok(outcome)
    }

    fn complete(mut self) -> DecisionHandlePayload {
        let payload = *self
            .payload
            .take()
            .expect("live authorized dispatch handle");
        settle_outstanding_authority(&self.owner, AuthorityHandlePhase::AuthorizedDispatch, None);
        payload
    }
}

impl Drop for AuthorizedDispatchHandle {
    fn drop(&mut self) {
        if self.payload.take().is_some() {
            settle_outstanding_authority(
                &self.owner,
                AuthorityHandlePhase::AuthorizedDispatch,
                Some("authorized dispatch handle was abandoned before terminal persistence"),
            );
        }
    }
}

#[derive(Debug)]
pub struct CompletedAuthorityEvidenceV2 {
    run_id: String,
    decision: AuthorityDecisionV2,
    outcome: AuthorityOutcomeV2,
    verified_grant: Option<crate::enforcement_loader::VerifiedPromotionGrant>,
}

/// Produces modeled delta only from a durably completed decision, its original opaque grant, and
/// a separately validated clean authority run. No caller-supplied completeness flag or rate is
/// accepted. This remains modeled evidence, not provider-reconciled realized savings.
pub fn enforced_modeled_delta_from_verified(
    run: &ValidatedCompleteAuthorityRunV2,
    completed: &CompletedAuthorityEvidenceV2,
) -> Result<Option<EnforcedModeledDelta>, EconomicsError> {
    let decision = &completed.decision;
    let outcome = &completed.outcome;
    if run.run_id() != completed.run_id
        || decision.validate().is_err()
        || outcome.validate().is_err()
        || validate_authority_pair_v2(decision, outcome).is_err()
    {
        return Err(EconomicsError::InvalidEnforcedModeledDelta);
    }
    let Some(verified_grant) = completed.verified_grant.as_ref() else {
        return Ok(None);
    };
    let Some(grant) = decision.grant.as_ref() else {
        return Err(EconomicsError::InvalidEnforcedModeledDelta);
    };
    if grant.grant_digest != verified_grant.grant_digest()
        || grant.expires_at_ms != verified_grant.expires_at_ms()
        || grant.economics_source_digest != verified_grant.economics_source_digest()
        || grant.quality_source_digest != verified_grant.quality_source_digest()
        || grant.opportunity_digest != verified_grant.opportunity_digest()
        || decision.route_id != verified_grant.route_id()
        || decision.workload_identity_digest.as_deref()
            != Some(verified_grant.workload_identity_digest())
        || decision.task_class != verified_grant.task_class()
        || decision.protocol != verified_grant.protocol()
        || decision.selected_supply_id.as_deref() != Some(verified_grant.candidate_supply_id())
        || decision.baseline_supply_id.as_deref() != Some(verified_grant.actual_supply_id())
        || decision.enforcement_config_digest != verified_grant.config_digest()
        || decision.route_config_digest != verified_grant.route_digest()
        || decision.actuator_config_digest.as_deref() != Some(verified_grant.actuator_digest())
    {
        return Err(EconomicsError::InvalidEnforcedModeledDelta);
    }
    if !modeled_delta_applicable(outcome) {
        return Ok(None);
    }
    let (Some(input_tokens), Some(output_tokens)) = (outcome.input_tokens, outcome.output_tokens)
    else {
        return Ok(None);
    };
    let actual = verified_grant
        .candidate_rate_micros()
        .cost_micros(input_tokens, output_tokens)?;
    let counterfactual = verified_grant
        .actual_rate_micros()
        .cost_micros(input_tokens, output_tokens)?;
    let delta = i128::from(counterfactual) - i128::from(actual);
    if outcome.observed_actual_cost_micros != Some(actual)
        || outcome.approved_counterfactual_cost_micros != Some(counterfactual)
        || outcome.enforced_modeled_delta_micros != Some(delta)
    {
        return Err(EconomicsError::InvalidEnforcedModeledDelta);
    }
    Ok(Some(EnforcedModeledDelta {
        status: EnforcedModeledDeltaStatus::Available,
        observed_actual_cost_micros: actual,
        approved_counterfactual_cost_micros: counterfactual,
        enforced_modeled_delta_micros: delta,
    }))
}

#[derive(Clone)]
pub struct ManagedAuthorityWriter {
    inner: Arc<ManagedAuthorityWriterInner>,
}

pub enum CandidateDecisionReservation {
    Flushed(Box<CandidateDispatchReservation>),
    Rejected(ManagedWriterError),
    Recoverable {
        error: ManagedWriterError,
        recovery: ZeroAuthorityRecovery,
    },
}

pub struct CandidateDispatchReservation {
    writer: ManagedAuthorityWriter,
    candidate: Option<DecisionHandle>,
    replacement: Option<Box<PreparedAuthorityParts>>,
}

pub enum FinalDispatchAuthorization {
    Authorized(AuthorizedDispatchHandle),
    Fallback(ZeroAuthorityRecovery),
    Fatal(ManagedWriterError),
}

impl CandidateDispatchReservation {
    pub fn decision(&self) -> &AuthorityDecisionV2 {
        self.candidate
            .as_ref()
            .expect("live candidate reservation")
            .decision()
    }

    pub async fn authorize_final_dispatch(
        mut self,
        attempt: DispatchAttemptV2,
    ) -> FinalDispatchAuthorization {
        let candidate = self.candidate.take().expect("candidate consumed once");
        let replacement = self.replacement.take().expect("replacement consumed once");
        if let Err(error) = candidate.validate_dispatch_attempt(&attempt) {
            drop(candidate);
            return FinalDispatchAuthorization::Fatal(error);
        }
        if let Some(error) = self.writer.final_dispatch_lifecycle_error() {
            drop(candidate);
            return FinalDispatchAuthorization::Fatal(error);
        }
        let authority_lost = match candidate.authorization_revalidation() {
            Some(revalidation) => {
                let kill_state = revalidation.kill_reader.read_kill_state().await;
                let now_ms = revalidation.now_ms();
                kill_state != bowline_core::enforcement::KillReadResult::Armed
                    || now_ms < revalidation.not_before_ms
                    || now_ms > revalidation.expires_at_ms
            }
            None => false,
        };
        if authority_lost {
            return match self
                .writer
                .persist_pre_dispatch_rejection(candidate, replacement)
                .await
            {
                Ok(recovery) => FinalDispatchAuthorization::Fallback(recovery),
                Err(error) => FinalDispatchAuthorization::Fatal(error),
            };
        }
        match candidate
            .authorize_dispatch_without_revalidation(attempt)
            .await
        {
            Ok(authorized) => FinalDispatchAuthorization::Authorized(authorized),
            Err(error) => FinalDispatchAuthorization::Fatal(error),
        }
    }

    pub async fn authorize_final_bound_dispatch(self) -> FinalDispatchAuthorization {
        let attempt = self
            .candidate
            .as_ref()
            .expect("live candidate reservation")
            .bound_attempt();
        self.authorize_final_dispatch(attempt).await
    }

    pub async fn authorize_dispatch(
        self,
        attempt: DispatchAttemptV2,
    ) -> Result<AuthorizedDispatchHandle, ManagedWriterError> {
        match self.authorize_final_dispatch(attempt).await {
            FinalDispatchAuthorization::Authorized(handle) => Ok(handle),
            FinalDispatchAuthorization::Fallback(recovery) => {
                drop(recovery);
                Err(ManagedWriterError::InvalidRecordContext)
            }
            FinalDispatchAuthorization::Fatal(error) => Err(error),
        }
    }
}

pub struct ZeroAuthorityRecovery {
    writer: ManagedAuthorityWriter,
    replacement: Option<Box<PreparedAuthorityParts>>,
    active: bool,
}

impl ZeroAuthorityRecovery {
    pub async fn reserve_and_flush_replacement(
        mut self,
    ) -> Result<DecisionHandle, ManagedWriterError> {
        let replacement = self
            .replacement
            .take()
            .expect("recovery replacement is consumed exactly once");
        let result = self
            .writer
            .reserve_and_flush_decision_parts(*replacement, || {}, true, None)
            .await;
        self.release(None);
        result
    }

    fn release(&mut self, error: Option<&str>) {
        if self.active {
            settle_outstanding_authority(
                &self.writer.inner,
                AuthorityHandlePhase::Admission,
                error,
            );
            self.active = false;
        }
    }
}

impl Drop for ZeroAuthorityRecovery {
    fn drop(&mut self) {
        self.release(Some(
            "consumed authority recovery was abandoned before replacement reservation",
        ));
    }
}

#[derive(Debug)]
struct PreparedAuthorityParts {
    decision: AuthorityDecisionV2,
    dispatch_binding: ExactDispatchBindingV2,
    verified_grant: Option<crate::enforcement_loader::VerifiedPromotionGrant>,
    authorization_revalidation: Option<AuthorizationRevalidationV2>,
}

impl From<PreparedAuthorityDecisionV2> for PreparedAuthorityParts {
    fn from(prepared: PreparedAuthorityDecisionV2) -> Self {
        let (decision, dispatch_binding, verified_grant, authorization_revalidation) =
            prepared.into_parts();
        Self {
            decision,
            dispatch_binding,
            verified_grant,
            authorization_revalidation,
        }
    }
}

struct ManagedAuthorityWriterInner {
    tx: mpsc::Sender<AuthorityWriterMessage>,
    run: Arc<AuthorityRunStoreV2>,
    actuator_digests: BTreeSet<String>,
    grant_digests: BTreeSet<String>,
    lifecycle: Arc<Mutex<AuthorityLifecycleState>>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
    #[cfg(test)]
    recovery_consume_pause: Mutex<Option<RecoveryConsumePause>>,
    #[cfg(test)]
    post_candidate_flush_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    post_rejection_flush_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(test)]
struct RecoveryConsumePause {
    published: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

#[derive(Debug)]
struct AuthorityLifecycleState {
    closing: bool,
    authority_complete: bool,
    transport_available: bool,
    outstanding: u64,
    issued_decisions: u64,
    authorized_dispatches: u64,
    next_recovery_id: u64,
    max_pending_recoveries: usize,
    pending_recoveries: BTreeMap<u64, Box<PreparedAuthorityParts>>,
    recovery: RecoveryLifecycle,
    incomplete_persistence_fault: Option<IncompletePersistenceFault>,
}

#[derive(Debug)]
enum RecoveryLifecycle {
    None,
    Available {
        id: u64,
        replacement: Box<PreparedAuthorityParts>,
    },
    Consumed {
        id: u64,
    },
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum IncompletePersistenceFault {
    Dropped,
    WriterError,
    Flush,
}

impl AuthorityLifecycleState {
    fn new(max_pending_recoveries: usize) -> Self {
        Self {
            closing: false,
            authority_complete: true,
            transport_available: true,
            outstanding: 0,
            issued_decisions: 0,
            authorized_dispatches: 0,
            next_recovery_id: 0,
            max_pending_recoveries,
            pending_recoveries: BTreeMap::new(),
            recovery: RecoveryLifecycle::None,
            incomplete_persistence_fault: None,
        }
    }
}

enum AuthorityWriterMessage {
    Append {
        record: Box<AuthorityRecordV2>,
        recovery_id: Option<u64>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Shutdown(oneshot::Sender<Result<(), String>>),
}

pub fn spawn_managed_authority_writer(
    options: AuthorityWriterOptions,
) -> anyhow::Result<ManagedAuthorityWriter> {
    spawn_managed_authority_writer_inner(options, None, None)
}

#[cfg(test)]
pub(crate) fn spawn_transient_faulting_authority_writer(
    options: AuthorityWriterOptions,
    append_attempt: u64,
) -> anyhow::Result<ManagedAuthorityWriter> {
    spawn_managed_authority_writer_inner(
        options,
        None,
        Some(AuthorityWriterFault::Transient(append_attempt)),
    )
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
enum AuthorityWriterFault {
    Transient(u64),
    Persistent(u64),
    TransientThenPersistent {
        transient_attempt: u64,
        persistent_attempt: u64,
    },
}

fn spawn_managed_authority_writer_inner(
    options: AuthorityWriterOptions,
    pause: Option<std::sync::mpsc::Receiver<()>>,
    fault: Option<AuthorityWriterFault>,
) -> anyhow::Result<ManagedAuthorityWriter> {
    if options.queue_capacity == 0 {
        anyhow::bail!("authority writer queue capacity must be greater than zero");
    }
    let actuator_digests = normalized_authority_digest_set(options.actuator_digests, 64)?;
    let grant_digests = normalized_authority_digest_set(options.grant_digests, 256)?;
    let actuator_set_digest =
        authority_set_digest(b"bowline.authority.actuator-set.v2", &actuator_digests);
    let grant_set_digest = authority_set_digest(b"bowline.authority.grant-set.v2", &grant_digests);
    let run = Arc::new(AuthorityRunStoreV2::create(
        &options.directory,
        AuthorityRunDigestsV2 {
            enforcement: options.enforcement_digest,
            actuator_set: actuator_set_digest,
            grant_set: grant_set_digest,
        },
    )?);
    let snapshot = run.snapshot();
    let ledger = AuthorityLedgerV2::create(
        &options.directory,
        &snapshot.records_file,
        options.max_records_bytes,
    )?;
    run.flush()?;
    let (tx, rx) = mpsc::channel(options.queue_capacity);
    let lifecycle = Arc::new(Mutex::new(AuthorityLifecycleState::new(
        options.queue_capacity,
    )));
    let thread_run = Arc::clone(&run);
    let thread_lifecycle = Arc::clone(&lifecycle);
    let join = thread::Builder::new()
        .name("bowline-authority-ledger-writer".to_string())
        .spawn(move || {
            authority_writer_thread(ledger, thread_run, thread_lifecycle, rx, pause, fault)
        })
        .context("failed to spawn authority ledger writer thread")?;
    Ok(ManagedAuthorityWriter {
        inner: Arc::new(ManagedAuthorityWriterInner {
            tx,
            run,
            actuator_digests,
            grant_digests,
            lifecycle,
            join: Mutex::new(Some(join)),
            #[cfg(test)]
            recovery_consume_pause: Mutex::new(None),
            #[cfg(test)]
            post_candidate_flush_hook: Mutex::new(None),
            #[cfg(test)]
            post_rejection_flush_hook: Mutex::new(None),
        }),
    })
}

#[cfg(test)]
fn authority_test_options(
    directory: &std::path::Path,
    queue_capacity: usize,
) -> AuthorityWriterOptions {
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let digest = |value: u8| format!("sha256:{value:064x}");
    AuthorityWriterOptions {
        directory: directory.to_path_buf(),
        enforcement_digest: digest(8),
        actuator_digests: vec![digest(7)],
        grant_digests: vec![digest(2)],
        queue_capacity,
        max_records_bytes: 1024 * 1024,
    }
}

#[cfg(test)]
fn spawn_paused_authority_writer(
    directory: &std::path::Path,
    queue_capacity: usize,
) -> anyhow::Result<(ManagedAuthorityWriter, std::sync::mpsc::Sender<()>)> {
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = spawn_managed_authority_writer_inner(
        authority_test_options(directory, queue_capacity),
        Some(release_rx),
        None,
    )?;
    Ok((writer, release_tx))
}

#[cfg(test)]
fn spawn_faulting_authority_writer(
    directory: &std::path::Path,
    queue_capacity: usize,
) -> anyhow::Result<ManagedAuthorityWriter> {
    spawn_managed_authority_writer_inner(
        authority_test_options(directory, queue_capacity),
        None,
        Some(AuthorityWriterFault::Transient(1)),
    )
}

#[cfg(test)]
fn spawn_terminal_faulting_authority_writer(
    directory: &std::path::Path,
    queue_capacity: usize,
) -> anyhow::Result<ManagedAuthorityWriter> {
    spawn_managed_authority_writer_inner(
        authority_test_options(directory, queue_capacity),
        None,
        Some(AuthorityWriterFault::Persistent(2)),
    )
}

#[cfg(test)]
fn spawn_persistent_faulting_authority_writer(
    directory: &std::path::Path,
    queue_capacity: usize,
) -> anyhow::Result<ManagedAuthorityWriter> {
    spawn_managed_authority_writer_inner(
        authority_test_options(directory, queue_capacity),
        None,
        Some(AuthorityWriterFault::Persistent(1)),
    )
}

impl ManagedAuthorityWriter {
    fn final_dispatch_lifecycle_error(&self) -> Option<ManagedWriterError> {
        let lifecycle = self
            .inner
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if lifecycle.closing || !lifecycle.transport_available {
            Some(ManagedWriterError::Closed)
        } else if !lifecycle.authority_complete {
            Some(ManagedWriterError::InvalidRecordContext)
        } else {
            None
        }
    }

    async fn persist_pre_dispatch_rejection(
        &self,
        mut candidate: DecisionHandle,
        replacement: Box<PreparedAuthorityParts>,
    ) -> Result<ZeroAuthorityRecovery, ManagedWriterError> {
        if let Some(error) = self.final_dispatch_lifecycle_error() {
            candidate.invalidate("pre-dispatch rejection raced with authority lifecycle");
            return Err(error);
        }
        let payload = candidate
            .payload
            .as_ref()
            .ok_or(ManagedWriterError::InvalidRecordContext)?;
        if !Arc::ptr_eq(&candidate.owner, &self.inner)
            || payload.target != PlanTarget::Candidate
            || replacement.decision.replaces_decision_id.as_deref()
                != Some(payload.decision_id.as_str())
        {
            candidate.invalidate("pre-dispatch rejection binding mismatch");
            return Err(ManagedWriterError::InvalidRecordContext);
        }
        let decision = &payload.decision;
        let outcome = AuthorityOutcomeV2 {
            decision_id: decision.decision_id.clone(),
            replaces_decision_id: None,
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX)
                .max(decision.ts_ms),
            route_id: decision.route_id.clone(),
            mode: decision.mode,
            protocol: decision.protocol,
            task_class: decision.task_class,
            workload_identity_digest: decision.workload_identity_digest.clone(),
            app: decision.app.clone(),
            resolved_tags: decision.resolved_tags.clone(),
            requested_supply_id: decision.requested_supply_id.clone(),
            selection_facts: decision.selection_facts.clone(),
            grant_digest: decision
                .grant
                .as_ref()
                .map(|grant| grant.grant_digest.clone()),
            grant_expires_at_ms: decision.grant.as_ref().map(|grant| grant.expires_at_ms),
            model_rewritten: decision.model_rewritten,
            selected_supply_id: decision.selected_supply_id.clone(),
            baseline_supply_id: decision.baseline_supply_id.clone(),
            actuator_identity_digest: decision.actuator_identity_digest.clone(),
            actuator_config_digest: decision.actuator_config_digest.clone(),
            enforcement_config_digest: decision.enforcement_config_digest.clone(),
            route_config_digest: decision.route_config_digest.clone(),
            target: PlanTarget::Candidate,
            fallback_reason: None,
            circuit_before: decision.selection_facts.circuit_before,
            circuit_after: decision.selection_facts.circuit_before,
            actual_dispatch: 0,
            completion: CompletionStateV2::PreDispatchRejected,
            candidate_failure: None,
            status: None,
            input_tokens: None,
            output_tokens: None,
            usage_source: UsageSource::Missing,
            observed_actual_cost_micros: None,
            approved_counterfactual_cost_micros: None,
            enforced_modeled_delta_micros: None,
        };
        if outcome.validate().is_err() || validate_authority_pair_v2(decision, &outcome).is_err() {
            candidate.invalidate("pre-dispatch rejection outcome was invalid");
            return Err(ManagedWriterError::InvalidRecordContext);
        }
        let persistence = async {
            let permit = self
                .inner
                .tx
                .try_reserve()
                .map_err(map_authority_reserve_error)?;
            let sequence = self.inner.run.accept().map_err(ManagedWriterError::Run)?;
            let record = AuthorityRecordV2::outcome(sequence, outcome)
                .map_err(|error| ManagedWriterError::Writer(error.to_string()))?;
            let (reply_tx, reply_rx) = oneshot::channel();
            permit.send(AuthorityWriterMessage::Append {
                record: Box::new(record),
                recovery_id: None,
                reply: reply_tx,
            });
            reply_rx
                .await
                .map_err(|_| ManagedWriterError::Closed)?
                .map_err(ManagedWriterError::Writer)
        }
        .await;
        if let Err(error) = persistence {
            mark_authority_transport_unavailable(
                &self.inner.lifecycle,
                &self.inner.run,
                &format!("pre-dispatch rejection persistence failed: {error}"),
                None,
            );
            candidate.payload.take();
            settle_outstanding_authority(&self.inner, AuthorityHandlePhase::Decision, None);
            return Err(error);
        }
        #[cfg(test)]
        if let Some(hook) = self.inner.post_rejection_flush_hook.lock().unwrap().take() {
            hook();
        }
        if let Some(error) = self.final_dispatch_lifecycle_error() {
            candidate.payload.take();
            settle_outstanding_authority(&self.inner, AuthorityHandlePhase::Decision, None);
            return Err(error);
        }
        candidate.payload.take();
        {
            let mut lifecycle = self
                .inner
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            debug_assert!(lifecycle.issued_decisions > 0);
            lifecycle.issued_decisions = lifecycle.issued_decisions.saturating_sub(1);
        }
        Ok(ZeroAuthorityRecovery {
            writer: self.clone(),
            replacement: Some(replacement),
            active: true,
        })
    }

    pub async fn reserve_and_flush_decision(
        &self,
        prepared: PreparedAuthorityDecisionV2,
    ) -> Result<DecisionHandle, ManagedWriterError> {
        self.reserve_and_flush_decision_inner(prepared, || {}).await
    }

    pub async fn reserve_candidate_decision_or_recovery(
        &self,
        validated: &ValidatedEnforcement,
        candidate: PreparedAuthorityDecisionV2,
        replacement: PreparedAuthorityDecisionV2,
    ) -> CandidateDecisionReservation {
        let mut candidate = PreparedAuthorityParts::from(candidate);
        let replacement = PreparedAuthorityParts::from(replacement);
        let Some(configured_fallback_target) = validated
            .route(&candidate.decision.route_id)
            .and_then(|route| match route.fallback {
                Some(FallbackMode::Bypass) => Some(PlanTarget::Original),
                Some(FallbackMode::FailClosed) => Some(PlanTarget::None),
                None => None,
            })
        else {
            return CandidateDecisionReservation::Rejected(
                ManagedWriterError::InvalidRecordContext,
            );
        };
        candidate.decision.configured_fallback_target = Some(configured_fallback_target);
        let candidate_bindings_match = candidate
            .decision
            .actuator_config_digest
            .as_ref()
            .is_some_and(|digest| self.inner.actuator_digests.contains(digest))
            && candidate
                .decision
                .grant
                .as_ref()
                .is_some_and(|grant| self.inner.grant_digests.contains(&grant.grant_digest));
        if validate_candidate_recovery_pair(validated, &candidate, &replacement).is_err()
            || candidate.decision.enforcement_config_digest
                != self.inner.run.snapshot().enforcement_digest
            || !candidate_bindings_match
        {
            return CandidateDecisionReservation::Rejected(
                ManagedWriterError::InvalidRecordContext,
            );
        }
        let recovery_id = {
            let mut lifecycle = self
                .inner
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lifecycle.closing
                || !lifecycle.authority_complete
                || !lifecycle.transport_available
                || !matches!(lifecycle.recovery, RecoveryLifecycle::None)
                || lifecycle.pending_recoveries.len() >= lifecycle.max_pending_recoveries
            {
                return CandidateDecisionReservation::Rejected(
                    ManagedWriterError::InvalidRecordContext,
                );
            }
            let Some(recovery_id) = lifecycle.next_recovery_id.checked_add(1) else {
                lifecycle.recovery = RecoveryLifecycle::Disabled;
                lifecycle.pending_recoveries.clear();
                return CandidateDecisionReservation::Rejected(ManagedWriterError::Writer(
                    "authority recovery generation overflow".into(),
                ));
            };
            lifecycle.next_recovery_id = recovery_id;
            lifecycle
                .pending_recoveries
                .insert(recovery_id, Box::new(replacement));
            recovery_id
        };
        match self
            .reserve_and_flush_decision_parts(candidate, || {}, false, Some(recovery_id))
            .await
        {
            Ok(handle) => {
                let replacement = {
                    let mut lifecycle = self
                        .inner
                        .lifecycle
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    lifecycle.pending_recoveries.remove(&recovery_id)
                };
                let Some(mut replacement) = replacement else {
                    drop(handle);
                    return CandidateDecisionReservation::Rejected(
                        ManagedWriterError::InvalidRecordContext,
                    );
                };
                replacement.decision.replaces_decision_id =
                    Some(handle.decision().decision_id.clone());
                #[cfg(test)]
                if let Some(hook) = self.inner.post_candidate_flush_hook.lock().unwrap().take() {
                    hook();
                }
                CandidateDecisionReservation::Flushed(Box::new(CandidateDispatchReservation {
                    writer: self.clone(),
                    candidate: Some(handle),
                    replacement: Some(replacement),
                }))
            }
            Err(error) => {
                #[cfg(test)]
                self.pause_before_recovery_consume().await;
                let replacement = {
                    let mut lifecycle = self
                        .inner
                        .lifecycle
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let open = !lifecycle.closing && lifecycle.transport_available;
                    match std::mem::replace(&mut lifecycle.recovery, RecoveryLifecycle::Disabled) {
                        RecoveryLifecycle::Available { id, replacement }
                            if open && id == recovery_id =>
                        {
                            let Some(outstanding) = lifecycle.outstanding.checked_add(1) else {
                                lifecycle.recovery = RecoveryLifecycle::Disabled;
                                return CandidateDecisionReservation::Rejected(
                                    ManagedWriterError::Writer(
                                        "authority recovery lifecycle overflow".into(),
                                    ),
                                );
                            };
                            lifecycle.outstanding = outstanding;
                            lifecycle.recovery = RecoveryLifecycle::Consumed { id };
                            Some(replacement)
                        }
                        state => {
                            lifecycle.recovery = match state {
                                RecoveryLifecycle::Consumed { .. }
                                | RecoveryLifecycle::Disabled
                                | RecoveryLifecycle::None => state,
                                available @ RecoveryLifecycle::Available { .. } => available,
                            };
                            None
                        }
                    }
                };
                match replacement {
                    Some(replacement) => CandidateDecisionReservation::Recoverable {
                        error,
                        recovery: ZeroAuthorityRecovery {
                            writer: self.clone(),
                            replacement: Some(replacement),
                            active: true,
                        },
                    },
                    None => CandidateDecisionReservation::Rejected(error),
                }
            }
        }
    }

    async fn reserve_and_flush_decision_inner<F>(
        &self,
        prepared: PreparedAuthorityDecisionV2,
        post_flush: F,
    ) -> Result<DecisionHandle, ManagedWriterError>
    where
        F: FnOnce(),
    {
        self.reserve_and_flush_decision_mode(prepared, post_flush, false)
            .await
    }

    async fn reserve_and_flush_decision_mode<F>(
        &self,
        prepared: PreparedAuthorityDecisionV2,
        post_flush: F,
        allow_recovered_fallback: bool,
    ) -> Result<DecisionHandle, ManagedWriterError>
    where
        F: FnOnce(),
    {
        self.reserve_and_flush_decision_parts(
            PreparedAuthorityParts::from(prepared),
            post_flush,
            allow_recovered_fallback,
            None,
        )
        .await
    }

    async fn reserve_and_flush_decision_parts<F>(
        &self,
        prepared: PreparedAuthorityParts,
        post_flush: F,
        allow_recovered_fallback: bool,
        recovery_id: Option<u64>,
    ) -> Result<DecisionHandle, ManagedWriterError>
    where
        F: FnOnce(),
    {
        let PreparedAuthorityParts {
            decision,
            dispatch_binding,
            verified_grant,
            authorization_revalidation,
        } = prepared;
        decision
            .validate()
            .map_err(|error| ManagedWriterError::Writer(error.to_string()))?;
        let manifest = self.inner.run.snapshot();
        let candidate_bindings_match = if decision.grants_candidate_authority() {
            decision
                .actuator_config_digest
                .as_ref()
                .is_some_and(|digest| self.inner.actuator_digests.contains(digest))
                && decision
                    .grant
                    .as_ref()
                    .is_some_and(|grant| self.inner.grant_digests.contains(&grant.grant_digest))
        } else {
            true
        };
        if decision.enforcement_config_digest != manifest.enforcement_digest
            || !candidate_bindings_match
        {
            self.mark_authority_error("authority decision is outside manifest bindings", None);
            return Err(ManagedWriterError::InvalidRecordContext);
        }
        let mut admission =
            AuthorityAdmissionGuard::begin(Arc::clone(&self.inner), allow_recovered_fallback)?;
        let permit = match self.inner.tx.try_reserve() {
            Ok(permit) => permit,
            Err(reserve_error) => {
                let transport_unavailable =
                    matches!(reserve_error, mpsc::error::TrySendError::Closed(()));
                let error = map_authority_reserve_error(reserve_error);
                if transport_unavailable {
                    mark_authority_transport_unavailable(
                        &self.inner.lifecycle,
                        &self.inner.run,
                        &error.to_string(),
                        None,
                    );
                } else {
                    self.mark_authority_error_with_recovery(&error.to_string(), None, recovery_id);
                    if recovery_id.is_some() {
                        admission.failure_already_recorded();
                    }
                }
                return Err(error);
            }
        };
        let sequence = match self.inner.run.accept() {
            Ok(sequence) => sequence,
            Err(error) => {
                self.mark_authority_error_with_recovery(&error.to_string(), None, recovery_id);
                if recovery_id.is_some() {
                    admission.failure_already_recorded();
                }
                return Err(error.into());
            }
        };
        let payload = DecisionHandlePayload {
            run_id: self.inner.run.snapshot().run_id,
            decision_id: decision.decision_id.clone(),
            target: decision.target,
            dispatch_binding,
            verified_grant,
            authorization_revalidation,
            decision: decision.clone(),
            recovered_fallback: allow_recovered_fallback,
        };
        let record = AuthorityRecordV2::decision(sequence, decision).map_err(|error| {
            self.mark_authority_error_with_recovery(
                &error.to_string(),
                Some(sequence),
                recovery_id,
            );
            if recovery_id.is_some() {
                admission.failure_already_recorded();
            }
            ManagedWriterError::Writer(error.to_string())
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        permit.send(AuthorityWriterMessage::Append {
            record: Box::new(record),
            recovery_id,
            reply: reply_tx,
        });
        let append_result = match reply_rx.await {
            Ok(result) => result,
            Err(_) => {
                mark_authority_transport_unavailable(
                    &self.inner.lifecycle,
                    &self.inner.run,
                    "authority writer reply channel closed",
                    Some(sequence),
                );
                return Err(ManagedWriterError::Closed);
            }
        };
        if let Err(error) = append_result {
            if recovery_id.is_some() {
                admission.failure_already_recorded();
            }
            return Err(ManagedWriterError::Writer(error));
        }
        post_flush();
        admission.issue_handle(payload, allow_recovered_fallback, recovery_id)
    }

    pub async fn append_and_flush_outcome(
        &self,
        handle: AuthorizedDispatchHandle,
        outcome: AuthorityOutcomeV2,
    ) -> Result<CompletedAuthorityEvidenceV2, ManagedWriterError> {
        let payload = handle
            .payload
            .as_ref()
            .expect("live authorized dispatch handle");
        if !Arc::ptr_eq(&handle.owner, &self.inner)
            || payload.run_id != self.inner.run.snapshot().run_id
            || payload.decision_id != outcome.decision_id
            || payload.target != outcome.target
            || validate_authority_pair_v2(&payload.decision, &outcome).is_err()
        {
            self.mark_authority_error("terminal does not match flushed decision handle", None);
            return Err(ManagedWriterError::InvalidRecordContext);
        }
        outcome
            .validate()
            .map_err(|error| ManagedWriterError::Writer(error.to_string()))?;
        if authority_lifecycle_blocks_append(&self.inner, payload.recovered_fallback) {
            self.mark_authority_error("writer is shutting down", None);
            return Err(ManagedWriterError::Closed);
        }
        let permit = match self.inner.tx.try_reserve() {
            Ok(permit) => permit,
            Err(reserve_error) => {
                let transport_unavailable =
                    matches!(reserve_error, mpsc::error::TrySendError::Closed(()));
                let error = map_authority_reserve_error(reserve_error);
                if transport_unavailable {
                    mark_authority_transport_unavailable(
                        &self.inner.lifecycle,
                        &self.inner.run,
                        &error.to_string(),
                        None,
                    );
                } else {
                    self.mark_authority_error(&error.to_string(), None);
                }
                return Err(error);
            }
        };
        let sequence = match self.inner.run.accept() {
            Ok(sequence) => sequence,
            Err(error) => {
                self.mark_authority_error(&error.to_string(), None);
                return Err(error.into());
            }
        };
        let completed_outcome = outcome.clone();
        let record = AuthorityRecordV2::outcome(sequence, outcome).map_err(|error| {
            self.mark_authority_error(&error.to_string(), Some(sequence));
            ManagedWriterError::Writer(error.to_string())
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        permit.send(AuthorityWriterMessage::Append {
            record: Box::new(record),
            recovery_id: None,
            reply: reply_tx,
        });
        let append_result = match reply_rx.await {
            Ok(result) => result,
            Err(_) => {
                mark_authority_transport_unavailable(
                    &self.inner.lifecycle,
                    &self.inner.run,
                    "authority writer reply channel closed",
                    Some(sequence),
                );
                return Err(ManagedWriterError::Closed);
            }
        };
        append_result.map_err(ManagedWriterError::Writer)?;
        let payload = handle.complete();
        if completed_outcome.completion == CompletionStateV2::Cancelled {
            self.mark_authority_error("authority dispatch was cancelled after decision", None);
            return Err(ManagedWriterError::Writer(
                "authority dispatch cancellation made the run incomplete".to_string(),
            ));
        }
        Ok(CompletedAuthorityEvidenceV2 {
            run_id: payload.run_id,
            decision: payload.decision,
            outcome: completed_outcome,
            verified_grant: payload.verified_grant,
        })
    }

    pub fn manifest_snapshot(&self) -> AuthorityRunManifestV2 {
        self.inner.run.snapshot()
    }

    pub fn manifest_path(&self) -> &std::path::Path {
        self.inner.run.manifest_path()
    }

    pub async fn shutdown(&self, grace: Duration) -> Result<(), ManagedWriterError> {
        {
            let mut lifecycle = self
                .inner
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lifecycle.closing {
                return Ok(());
            }
            lifecycle.closing = true;
            disable_unconsumed_recovery(&mut lifecycle);
            if lifecycle.outstanding != 0 {
                poison_authority_run_locked(
                    &self.inner.run,
                    &mut lifecycle,
                    "authority shutdown observed an outstanding decision or dispatch handle",
                    None,
                );
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let shutdown = async {
            self.inner
                .tx
                .send(AuthorityWriterMessage::Shutdown(reply_tx))
                .await
                .map_err(|_| ManagedWriterError::Closed)?;
            reply_rx
                .await
                .map_err(|_| ManagedWriterError::Closed)?
                .map_err(ManagedWriterError::Writer)
        };
        tokio::time::timeout(grace, shutdown)
            .await
            .map_err(|_| ManagedWriterError::ShutdownTimeout)??;
        if let Some(join) = self
            .inner
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            join.join()
                .map_err(|_| ManagedWriterError::Writer("writer thread panicked".to_string()))?;
        }
        Ok(())
    }

    fn mark_authority_error(&self, reason: &str, sequence: Option<u64>) {
        self.mark_authority_error_with_recovery(reason, sequence, None);
    }

    #[cfg(test)]
    fn install_recovery_consume_pause(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (published_tx, published_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        *self.inner.recovery_consume_pause.lock().unwrap() = Some(RecoveryConsumePause {
            published: published_tx,
            resume: resume_rx,
        });
        (published_rx, resume_tx)
    }

    #[cfg(test)]
    pub(crate) fn install_post_candidate_flush_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.inner.post_candidate_flush_hook.lock().unwrap() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn install_post_rejection_flush_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.inner.post_rejection_flush_hook.lock().unwrap() = Some(Box::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn install_post_rejection_closing_hook(&self) {
        let lifecycle = Arc::clone(&self.inner.lifecycle);
        self.install_post_rejection_flush_hook(move || {
            let mut lifecycle = lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            lifecycle.closing = true;
            lifecycle.authority_complete = false;
        });
    }

    #[cfg(test)]
    async fn pause_before_recovery_consume(&self) {
        let pause = self.inner.recovery_consume_pause.lock().unwrap().take();
        if let Some(pause) = pause {
            let _ = pause.published.send(());
            let _ = pause.resume.await;
        }
    }

    fn mark_authority_error_with_recovery(
        &self,
        reason: &str,
        sequence: Option<u64>,
        recovery_id: Option<u64>,
    ) {
        if let Some(recovery_id) = recovery_id {
            publish_candidate_failure_recovery(
                &self.inner.lifecycle,
                &self.inner.run,
                reason,
                sequence,
                recovery_id,
            );
        } else {
            poison_authority_run(&self.inner.lifecycle, &self.inner.run, reason, sequence);
        }
    }
}

fn validate_candidate_recovery_pair(
    validated: &ValidatedEnforcement,
    candidate: &PreparedAuthorityParts,
    replacement: &PreparedAuthorityParts,
) -> Result<(), ManagedWriterError> {
    let candidate_decision = &candidate.decision;
    let replacement_decision = &replacement.decision;
    candidate_decision
        .validate()
        .map_err(|_| ManagedWriterError::InvalidRecordContext)?;
    replacement_decision
        .validate()
        .map_err(|_| ManagedWriterError::InvalidRecordContext)?;
    let route = validated
        .route(&candidate_decision.route_id)
        .ok_or(ManagedWriterError::InvalidRecordContext)?;
    let expected_target = match route.fallback {
        Some(FallbackMode::Bypass) => PlanTarget::Original,
        Some(FallbackMode::FailClosed) => PlanTarget::None,
        None => return Err(ManagedWriterError::InvalidRecordContext),
    };
    let expected_selected_supply = match expected_target {
        PlanTarget::Original => candidate_decision.baseline_supply_id.as_ref(),
        PlanTarget::None => None,
        PlanTarget::Candidate => return Err(ManagedWriterError::InvalidRecordContext),
    };
    let candidate_binding = &candidate.dispatch_binding;
    let replacement_binding = &replacement.dispatch_binding;
    let exact_request = candidate_binding.request_body_digest
        == replacement_binding.request_body_digest
        && candidate_binding.requested_supply_id == replacement_binding.requested_supply_id
        && candidate_binding.route_id == replacement_binding.route_id
        && candidate_binding.method == replacement_binding.method
        && candidate_binding.path == replacement_binding.path
        && candidate_binding.protocol == replacement_binding.protocol
        && candidate_binding.workload_identity_digest
            == replacement_binding.workload_identity_digest
        && candidate_binding.app == replacement_binding.app
        && candidate_binding.resolved_tags == replacement_binding.resolved_tags
        && candidate_binding.bucket == replacement_binding.bucket;
    let exact_decision = candidate_decision.decision_id != replacement_decision.decision_id
        && candidate_decision.ts_ms == replacement_decision.ts_ms
        && candidate_decision.route_id == replacement_decision.route_id
        && candidate_decision.mode == replacement_decision.mode
        && candidate_decision.protocol == replacement_decision.protocol
        && candidate_decision.task_class == replacement_decision.task_class
        && candidate_decision.workload_identity_digest
            == replacement_decision.workload_identity_digest
        && candidate_decision.app == replacement_decision.app
        && candidate_decision.resolved_tags == replacement_decision.resolved_tags
        && candidate_decision.requested_supply_id == replacement_decision.requested_supply_id
        && candidate_decision.baseline_supply_id == replacement_decision.baseline_supply_id
        && candidate_decision.enforcement_config_digest
            == replacement_decision.enforcement_config_digest
        && candidate_decision.route_config_digest == replacement_decision.route_config_digest;
    let exact_validated_config = candidate_decision.enforcement_config_digest
        == validated.normalized_digest()
        && validated
            .route_digest(&candidate_decision.route_id)
            .as_deref()
            == Some(candidate_decision.route_config_digest.as_str())
        && candidate_decision.actuator_config_digest.as_deref()
            == route
                .promoted_supply_id
                .as_deref()
                .and_then(|supply_id| validated.actuator_digest(supply_id))
                .as_deref();
    let exact_fallback = candidate_decision.grants_candidate_authority()
        && replacement_decision.replaces_decision_id.is_none()
        && replacement_decision.reason == SelectionReason::CandidateUnavailable
        && replacement_decision.target == expected_target
        && replacement_decision.intended_dispatch
            == u8::from(expected_target == PlanTarget::Original)
        && replacement_decision.selected_supply_id.as_ref() == expected_selected_supply
        && replacement_decision.grant.is_none()
        && replacement_decision.actuator_identity_digest.is_none()
        && replacement_decision.actuator_config_digest.is_none()
        && !replacement_decision.model_rewritten
        && candidate_binding.target == PlanTarget::Candidate
        && replacement_binding.target == expected_target
        && replacement_binding.selected_supply_id.as_ref() == expected_selected_supply
        && replacement_decision.selection_facts.bucket == candidate_decision.selection_facts.bucket;
    if exact_request && exact_decision && exact_validated_config && exact_fallback {
        Ok(())
    } else {
        Err(ManagedWriterError::InvalidRecordContext)
    }
}

struct AuthorityAdmissionGuard {
    owner: Arc<ManagedAuthorityWriterInner>,
    active: bool,
    failure_already_recorded: bool,
}

impl AuthorityAdmissionGuard {
    fn begin(
        owner: Arc<ManagedAuthorityWriterInner>,
        allow_recovered_fallback: bool,
    ) -> Result<Self, ManagedWriterError> {
        {
            let mut lifecycle = owner
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lifecycle.closing {
                return Err(ManagedWriterError::Closed);
            }
            if !lifecycle.transport_available {
                return Err(ManagedWriterError::Closed);
            }
            if !lifecycle.authority_complete && !allow_recovered_fallback {
                return Err(ManagedWriterError::InvalidRecordContext);
            }
            lifecycle.outstanding = lifecycle
                .outstanding
                .checked_add(1)
                .ok_or_else(|| ManagedWriterError::Writer("authority lifecycle overflow".into()))?;
        }
        Ok(Self {
            owner,
            active: true,
            failure_already_recorded: false,
        })
    }

    fn failure_already_recorded(&mut self) {
        self.failure_already_recorded = true;
    }

    fn issue_handle(
        mut self,
        payload: DecisionHandlePayload,
        allow_recovered_fallback: bool,
        recovery_id: Option<u64>,
    ) -> Result<DecisionHandle, ManagedWriterError> {
        let result = {
            let mut lifecycle = self
                .owner
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lifecycle.closing || !lifecycle.transport_available {
                Err(ManagedWriterError::Closed)
            } else if !lifecycle.authority_complete && !allow_recovered_fallback {
                if recovery_id.is_some() {
                    self.failure_already_recorded = true;
                }
                Err(ManagedWriterError::InvalidRecordContext)
            } else if recovery_id.is_some_and(|id| {
                !matches!(lifecycle.recovery, RecoveryLifecycle::None)
                    || !lifecycle.pending_recoveries.contains_key(&id)
            }) {
                self.failure_already_recorded = true;
                Err(ManagedWriterError::InvalidRecordContext)
            } else {
                lifecycle.issued_decisions =
                    lifecycle.issued_decisions.checked_add(1).ok_or_else(|| {
                        ManagedWriterError::Writer(
                            "authority issued-decision lifecycle overflow".to_string(),
                        )
                    })?;
                self.active = false;
                Ok(())
            }
        };
        result?;
        Ok(DecisionHandle {
            payload: Some(payload),
            owner: Arc::clone(&self.owner),
        })
    }
}

impl Drop for AuthorityAdmissionGuard {
    fn drop(&mut self) {
        if self.active {
            settle_outstanding_authority(
                &self.owner,
                AuthorityHandlePhase::Admission,
                (!self.failure_already_recorded).then_some(
                    "authority decision admission was abandoned before durable acknowledgement",
                ),
            );
        }
    }
}

fn authority_lifecycle_blocks_append(
    owner: &ManagedAuthorityWriterInner,
    allow_recovered_fallback: bool,
) -> bool {
    let lifecycle = owner
        .lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    lifecycle.closing
        || !lifecycle.transport_available
        || (!lifecycle.authority_complete && !allow_recovered_fallback)
}

#[derive(Clone, Copy)]
enum AuthorityHandlePhase {
    Admission,
    Decision,
    AuthorizedDispatch,
}

fn settle_outstanding_authority(
    owner: &ManagedAuthorityWriterInner,
    phase: AuthorityHandlePhase,
    error: Option<&str>,
) {
    let mut lifecycle = owner
        .lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(error) = error {
        poison_authority_run_locked(&owner.run, &mut lifecycle, error, None);
    }
    debug_assert!(
        lifecycle.outstanding > 0,
        "outstanding authority counter underflow"
    );
    lifecycle.outstanding = lifecycle.outstanding.saturating_sub(1);
    match phase {
        AuthorityHandlePhase::Admission => {}
        AuthorityHandlePhase::Decision => {
            debug_assert!(
                lifecycle.issued_decisions > 0,
                "issued decision counter underflow"
            );
            lifecycle.issued_decisions = lifecycle.issued_decisions.saturating_sub(1);
        }
        AuthorityHandlePhase::AuthorizedDispatch => {
            debug_assert!(
                lifecycle.authorized_dispatches > 0,
                "authorized dispatch counter underflow"
            );
            lifecycle.authorized_dispatches = lifecycle.authorized_dispatches.saturating_sub(1);
        }
    }
}

fn poison_authority_run(
    lifecycle: &Mutex<AuthorityLifecycleState>,
    run: &AuthorityRunStoreV2,
    reason: &str,
    sequence: Option<u64>,
) {
    let mut lifecycle = lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    poison_authority_run_locked(run, &mut lifecycle, reason, sequence);
}

fn poison_authority_run_locked(
    run: &AuthorityRunStoreV2,
    lifecycle: &mut AuthorityLifecycleState,
    reason: &str,
    sequence: Option<u64>,
) {
    persist_incomplete_authority_locked(run, lifecycle, reason, sequence);
    disable_unconsumed_recovery(lifecycle);
}

fn publish_candidate_failure_recovery(
    lifecycle: &Mutex<AuthorityLifecycleState>,
    run: &AuthorityRunStoreV2,
    reason: &str,
    sequence: Option<u64>,
    recovery_id: u64,
) {
    let mut lifecycle = lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let may_publish = lifecycle.authority_complete
        && lifecycle.transport_available
        && !lifecycle.closing
        && matches!(lifecycle.recovery, RecoveryLifecycle::None)
        && lifecycle.pending_recoveries.contains_key(&recovery_id);
    if !may_publish {
        if let Some(sequence) = sequence {
            let _ = run.dropped(sequence);
        }
        return;
    }
    let persisted = persist_incomplete_authority_locked(run, &mut lifecycle, reason, sequence);
    let replacement = lifecycle.pending_recoveries.remove(&recovery_id);
    lifecycle.pending_recoveries.clear();
    lifecycle.recovery = match replacement {
        Some(replacement) if persisted => RecoveryLifecycle::Available {
            id: recovery_id,
            replacement,
        },
        _ => RecoveryLifecycle::Disabled,
    };
}

fn persist_incomplete_authority_locked(
    run: &AuthorityRunStoreV2,
    lifecycle: &mut AuthorityLifecycleState,
    reason: &str,
    sequence: Option<u64>,
) -> bool {
    lifecycle.authority_complete = false;
    let dropped_persisted = sequence.is_none_or(|sequence| {
        lifecycle.incomplete_persistence_fault != Some(IncompletePersistenceFault::Dropped)
            && run.dropped(sequence).is_ok()
    });
    let writer_error_persisted =
        lifecycle.incomplete_persistence_fault != Some(IncompletePersistenceFault::WriterError);
    run.set_writer_error(reason);
    let flush_persisted = lifecycle.incomplete_persistence_fault
        != Some(IncompletePersistenceFault::Flush)
        && run.flush().is_ok();
    let persisted = dropped_persisted && writer_error_persisted && flush_persisted;
    if !persisted {
        lifecycle.transport_available = false;
    }
    persisted
}

fn disable_unconsumed_recovery(lifecycle: &mut AuthorityLifecycleState) {
    lifecycle.pending_recoveries.clear();
    let recovery = std::mem::replace(&mut lifecycle.recovery, RecoveryLifecycle::Disabled);
    lifecycle.recovery = match recovery {
        RecoveryLifecycle::Consumed { id } => RecoveryLifecycle::Consumed { id },
        RecoveryLifecycle::None => RecoveryLifecycle::None,
        _ => RecoveryLifecycle::Disabled,
    };
}

fn mark_authority_transport_unavailable(
    lifecycle: &Mutex<AuthorityLifecycleState>,
    run: &AuthorityRunStoreV2,
    reason: &str,
    sequence: Option<u64>,
) {
    let mut lifecycle = lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    lifecycle.authority_complete = false;
    lifecycle.transport_available = false;
    disable_unconsumed_recovery(&mut lifecycle);
    if let Some(sequence) = sequence {
        let _ = run.dropped(sequence);
    }
    run.set_writer_error(reason);
    let _ = run.flush();
}

fn normalized_authority_digest_set(
    values: Vec<String>,
    maximum: usize,
) -> anyhow::Result<BTreeSet<String>> {
    let input_len = values.len();
    if input_len > maximum || values.iter().any(|value| !valid_authority_digest(value)) {
        anyhow::bail!("invalid authority digest set");
    }
    let set = values.into_iter().collect::<BTreeSet<_>>();
    if set.len() != input_len {
        anyhow::bail!("invalid authority digest set");
    }
    Ok(set)
}

fn authority_set_digest(domain: &[u8], values: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn valid_authority_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn map_authority_reserve_error(error: mpsc::error::TrySendError<()>) -> ManagedWriterError {
    match error {
        mpsc::error::TrySendError::Full(()) => ManagedWriterError::QueueFull,
        mpsc::error::TrySendError::Closed(()) => ManagedWriterError::Closed,
    }
}

fn authority_writer_thread(
    mut ledger: AuthorityLedgerV2,
    run: Arc<AuthorityRunStoreV2>,
    lifecycle: Arc<Mutex<AuthorityLifecycleState>>,
    mut rx: mpsc::Receiver<AuthorityWriterMessage>,
    pause: Option<std::sync::mpsc::Receiver<()>>,
    fault: Option<AuthorityWriterFault>,
) {
    if let Some(release) = pause {
        let _ = release.recv();
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            mark_authority_transport_unavailable(
                &lifecycle,
                &run,
                &format!("failed to start writer runtime: {error}"),
                None,
            );
            let _ = run.finish(false, None, None);
            return;
        }
    };
    runtime.block_on(async move {
        let mut requested_shutdown = false;
        let mut append_attempt = 0u64;
        while let Some(message) = rx.recv().await {
            match message {
                AuthorityWriterMessage::Append {
                    record,
                    recovery_id,
                    reply,
                } => {
                    let sequence = record.sequence();
                    let result = process_authority_record(
                        &mut ledger,
                        &run,
                        *record,
                        &mut append_attempt,
                        fault,
                    );
                    if let Err(error) = &result {
                        match error {
                            AuthorityRecordFailure::Transient(_) => {
                                if let Some(recovery_id) = recovery_id {
                                    publish_candidate_failure_recovery(
                                        &lifecycle,
                                        &run,
                                        &error.to_string(),
                                        Some(sequence),
                                        recovery_id,
                                    )
                                } else {
                                    poison_authority_run(
                                        &lifecycle,
                                        &run,
                                        &error.to_string(),
                                        Some(sequence),
                                    )
                                }
                            }
                            AuthorityRecordFailure::Transport(_) => {
                                mark_authority_transport_unavailable(
                                    &lifecycle,
                                    &run,
                                    &error.to_string(),
                                    Some(sequence),
                                )
                            }
                        }
                    }
                    let _ = reply.send(result.map_err(|error| error.to_string()));
                }
                AuthorityWriterMessage::Shutdown(reply) => {
                    rx.close();
                    while let Some(AuthorityWriterMessage::Append {
                        record,
                        recovery_id,
                        reply,
                    }) = rx.recv().await
                    {
                        let sequence = record.sequence();
                        let result = process_authority_record(
                            &mut ledger,
                            &run,
                            *record,
                            &mut append_attempt,
                            fault,
                        );
                        if let Err(error) = &result {
                            match error {
                                AuthorityRecordFailure::Transient(_) => {
                                    if let Some(recovery_id) = recovery_id {
                                        publish_candidate_failure_recovery(
                                            &lifecycle,
                                            &run,
                                            &error.to_string(),
                                            Some(sequence),
                                            recovery_id,
                                        )
                                    } else {
                                        poison_authority_run(
                                            &lifecycle,
                                            &run,
                                            &error.to_string(),
                                            Some(sequence),
                                        )
                                    }
                                }
                                AuthorityRecordFailure::Transport(_) => {
                                    mark_authority_transport_unavailable(
                                        &lifecycle,
                                        &run,
                                        &error.to_string(),
                                        Some(sequence),
                                    )
                                }
                            }
                        }
                        let _ = reply.send(result.map_err(|error| error.to_string()));
                    }
                    let result = ledger.integrity().map_err(anyhow::Error::from).and_then(
                        |(bytes, digest)| {
                            run.finish(true, Some(bytes), Some(digest))
                                .map_err(anyhow::Error::from)
                        },
                    );
                    let _ = reply.send(result.map_err(|error| error.to_string()));
                    requested_shutdown = true;
                    break;
                }
            }
        }
        if !requested_shutdown {
            let integrity = ledger.integrity().ok();
            let (bytes, digest) = integrity
                .map(|(bytes, digest)| (Some(bytes), Some(digest)))
                .unwrap_or((None, None));
            let _ = run.finish(false, bytes, digest);
        }
    });
}

#[derive(Debug, Error)]
enum AuthorityRecordFailure {
    #[error("{0}")]
    Transient(String),
    #[error("{0}")]
    Transport(String),
}

fn process_authority_record(
    ledger: &mut AuthorityLedgerV2,
    run: &AuthorityRunStoreV2,
    record: AuthorityRecordV2,
    append_attempt: &mut u64,
    fault: Option<AuthorityWriterFault>,
) -> Result<(), AuthorityRecordFailure> {
    let sequence = record.sequence();
    *append_attempt = append_attempt.saturating_add(1);
    if matches!(fault, Some(AuthorityWriterFault::Transient(attempt)) if attempt == *append_attempt)
        || matches!(
            fault,
            Some(AuthorityWriterFault::TransientThenPersistent {
                transient_attempt,
                ..
            }) if transient_attempt == *append_attempt
        )
    {
        return Err(AuthorityRecordFailure::Transient(
            "injected transient authority append failure".into(),
        ));
    }
    ledger
        .append(&record)
        .map_err(|error| AuthorityRecordFailure::Transport(error.to_string()))?;
    if matches!(fault, Some(AuthorityWriterFault::Persistent(attempt)) if attempt == *append_attempt)
        || matches!(
            fault,
            Some(AuthorityWriterFault::TransientThenPersistent {
                persistent_attempt,
                ..
            }) if persistent_attempt == *append_attempt
        )
    {
        return Err(AuthorityRecordFailure::Transport(
            "injected persistent authority durable flush failure".into(),
        ));
    }
    ledger
        .flush()
        .map_err(|error| AuthorityRecordFailure::Transport(error.to_string()))?;
    run.recorded(sequence)
        .map_err(|error| AuthorityRecordFailure::Transport(error.to_string()))?;
    run.flush()
        .map_err(|error| AuthorityRecordFailure::Transport(error.to_string()))?;
    Ok(())
}

pub fn spawn_managed_writer(options: ManagedWriterOptions) -> anyhow::Result<ManagedWriter> {
    spawn_managed_writer_inner(options, None)
}

#[cfg(test)]
fn spawn_paused_managed_writer(
    directory: &Path,
    queue_capacity: usize,
) -> anyhow::Result<(ManagedWriter, std::sync::mpsc::Sender<()>)> {
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = spawn_managed_writer_inner(
        ManagedWriterOptions::test(directory, queue_capacity),
        Some(release_rx),
    )?;
    Ok((writer, release_tx))
}

fn spawn_managed_writer_inner(
    options: ManagedWriterOptions,
    pause: Option<std::sync::mpsc::Receiver<()>>,
) -> anyhow::Result<ManagedWriter> {
    if options.queue_capacity == 0 {
        anyhow::bail!("managed writer queue capacity must be greater than zero");
    }
    let run = Arc::new(RunStore::create(
        &options.directory,
        RunDigests {
            policy: options.policy_digest,
            registry: options.registry_digest,
            attribution: options.attribution_digest,
            owned_cost: options.owned_cost_digest,
            passive_profile: options.passive_profile_digest,
            passive_input: options.passive_input_digest,
        },
        RunLimits {
            segment_bytes: options.segment_bytes,
            max_segments: options.max_segments,
        },
    )?);
    let canonical_directory = std::fs::canonicalize(&options.directory)
        .context("failed to resolve managed ledger directory")?;
    let ledger = SegmentedLedger::open(
        &canonical_directory,
        &run.run_id(),
        options.segment_bytes,
        options.max_segments,
    )?;
    for filename in ledger.segment_filenames() {
        run.add_segment(filename.clone())?;
    }
    run.flush()?;
    let health = GatewayHealth::new(Arc::clone(&run), options.queue_capacity);
    let (tx, rx) = mpsc::channel(options.queue_capacity);
    let thread_health = health.clone();
    let join = thread::Builder::new()
        .name("bowline-managed-ledger-writer".to_string())
        .spawn(move || managed_writer_thread(ledger, run, thread_health, rx, pause))
        .context("failed to spawn managed ledger writer thread")?;
    Ok(ManagedWriter {
        inner: Arc::new(ManagedWriterInner {
            tx,
            health,
            join: Mutex::new(Some(join)),
        }),
    })
}

impl ManagedWriter {
    pub fn accept_request(&self) -> Result<RecordContext, ManagedWriterError> {
        if self.inner.health.is_shutting_down() {
            return Err(ManagedWriterError::Closed);
        }
        Ok(RecordContext {
            run_id: self.inner.health.run().run_id(),
            sequence: self.inner.health.run().accept()?,
        })
    }

    pub fn try_record(&self, record: DecisionRecord) -> Result<(), ManagedWriterError> {
        let sequence = record
            .sequence
            .ok_or(ManagedWriterError::InvalidRecordContext)?;
        if record.run_id.as_deref() != Some(&self.inner.health.run().run_id()) {
            return Err(ManagedWriterError::InvalidRecordContext);
        }
        if self.inner.health.is_shutting_down() {
            self.disclose_drop(sequence, "writer is shutting down");
            return Err(ManagedWriterError::Closed);
        }
        match self
            .inner
            .tx
            .try_send(WriterMessage::Record(Box::new(record)))
        {
            Ok(()) => {
                self.inner.health.increment_queue_depth();
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.disclose_drop(sequence, "writer queue is full");
                Err(ManagedWriterError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.disclose_drop(sequence, "writer channel is closed");
                Err(ManagedWriterError::Closed)
            }
        }
    }

    pub fn health(&self) -> GatewayHealth {
        self.inner.health.clone()
    }

    pub async fn shutdown(&self, grace: Duration) -> Result<(), ManagedWriterError> {
        if !self.inner.health.begin_shutdown() {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let shutdown = async {
            self.inner
                .tx
                .send(WriterMessage::Shutdown(reply_tx))
                .await
                .map_err(|_| ManagedWriterError::Closed)?;
            reply_rx
                .await
                .map_err(|_| ManagedWriterError::Closed)?
                .map_err(ManagedWriterError::Writer)
        };
        tokio::time::timeout(grace, shutdown)
            .await
            .map_err(|_| ManagedWriterError::ShutdownTimeout)??;
        if let Some(join) = self
            .inner
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            join.join()
                .map_err(|_| ManagedWriterError::Writer("writer thread panicked".to_string()))?;
        }
        Ok(())
    }

    fn disclose_drop(&self, sequence: u64, reason: &str) {
        let run = self.inner.health.run();
        let _ = run.dropped(sequence);
        run.set_writer_error(reason);
        let _ = run.flush();
    }
}

fn managed_writer_thread(
    mut ledger: SegmentedLedger,
    run: Arc<RunStore>,
    health: GatewayHealth,
    mut rx: mpsc::Receiver<WriterMessage>,
    pause: Option<std::sync::mpsc::Receiver<()>>,
) {
    if let Some(release) = pause {
        let _ = release.recv();
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            run.set_writer_error(format!("failed to start writer runtime: {error}"));
            let _ = run.finish(false);
            return;
        }
    };
    runtime.block_on(async move {
        let mut clean_shutdown = false;
        loop {
            match tokio::time::timeout(FLUSH_IDLE, rx.recv()).await {
                Ok(Some(WriterMessage::Record(record))) => {
                    process_managed_record(&mut ledger, &run, &health, *record);
                }
                Ok(Some(WriterMessage::Shutdown(reply))) => {
                    rx.close();
                    while let Some(message) = rx.recv().await {
                        if let WriterMessage::Record(record) = message {
                            process_managed_record(&mut ledger, &run, &health, *record);
                        }
                    }
                    let result = flush_managed(&mut ledger, &run)
                        .and_then(|()| {
                            let (inventory, digest) = ledger.integrity_inventory()?;
                            run.bind_integrity(inventory, digest)?;
                            Ok(())
                        })
                        .and_then(|()| run.finish(true).map_err(anyhow::Error::from));
                    clean_shutdown = result.is_ok();
                    let _ = reply.send(result.map_err(|error| error.to_string()));
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    if let Err(error) = flush_managed(&mut ledger, &run) {
                        run.set_writer_error(error.to_string());
                    }
                }
            }
        }
        if !clean_shutdown {
            let _ = flush_managed(&mut ledger, &run);
            let _ = run.finish(false);
        }
    });
}

fn process_managed_record(
    ledger: &mut SegmentedLedger,
    run: &RunStore,
    health: &GatewayHealth,
    record: DecisionRecord,
) {
    health.decrement_queue_depth();
    let Some(sequence) = record.sequence else {
        run.set_writer_error("queued record missing sequence");
        return;
    };
    match ledger.append(&record) {
        Ok(()) => {
            if let Err(error) = run.recorded(sequence) {
                run.set_writer_error(error.to_string());
            }
            for filename in ledger.segment_filenames() {
                if let Err(error) = run.add_segment(filename.clone()) {
                    run.set_writer_error(error.to_string());
                }
            }
        }
        Err(error) => {
            let _ = run.dropped(sequence);
            run.set_writer_error(error.to_string());
        }
    }
}

fn flush_managed(ledger: &mut SegmentedLedger, run: &RunStore) -> anyhow::Result<()> {
    ledger.flush()?;
    run.flush()?;
    Ok(())
}

#[derive(Clone)]
pub struct LedgerWriter {
    pub tx: mpsc::Sender<DecisionRecord>,
}

pub fn spawn_writer(dir: PathBuf) -> anyhow::Result<(LedgerWriter, RecoveryOutcome)> {
    let (ledger, recovery) = Ledger::open(&dir)
        .with_context(|| format!("failed to open decision ledger at {}", dir.display()))?;
    let writer = spawn_opened_writer(ledger)?;

    Ok((writer, recovery))
}

pub(crate) fn open_writer_if_recording_enabled(
    dir: PathBuf,
) -> anyhow::Result<(Option<LedgerWriter>, RecoveryOutcome)> {
    let (ledger, recovery) = Ledger::open(&dir)
        .with_context(|| format!("failed to open decision ledger at {}", dir.display()))?;
    if recovery.blocks_append() {
        return Ok((None, recovery));
    }

    Ok((Some(spawn_opened_writer(ledger)?), recovery))
}

fn spawn_opened_writer(ledger: Ledger) -> anyhow::Result<LedgerWriter> {
    let (tx, rx) = mpsc::channel(WRITER_CHANNEL);

    thread::Builder::new()
        .name("bowline-ledger-writer".to_string())
        .spawn(move || writer_thread(ledger, rx))
        .context("failed to spawn ledger writer thread")?;

    Ok(LedgerWriter { tx })
}

fn writer_thread(mut ledger: Ledger, mut rx: mpsc::Receiver<DecisionRecord>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(error = %err, "failed to start ledger writer runtime");
            return;
        }
    };

    runtime.block_on(async move {
        let mut batch = Vec::with_capacity(FLUSH_BATCH);

        loop {
            if batch.is_empty() {
                match rx.recv().await {
                    Some(record) => batch.push(record),
                    None => break,
                }
            }

            while batch.len() < FLUSH_BATCH {
                match tokio::time::timeout(FLUSH_IDLE, rx.recv()).await {
                    Ok(Some(record)) => batch.push(record),
                    Ok(None) => {
                        flush_batch(&mut ledger, &mut batch);
                        return;
                    }
                    Err(_) => break,
                }
            }

            flush_batch(&mut ledger, &mut batch);
        }

        flush_batch(&mut ledger, &mut batch);
    });
}

fn flush_batch(ledger: &mut Ledger, batch: &mut Vec<DecisionRecord>) {
    if batch.is_empty() {
        return;
    }

    for record in batch.drain(..) {
        if let Err(err) = ledger.append(&record) {
            tracing::warn!(error = %err, record_id = %record.id, "failed to append decision record");
        }
    }

    if let Err(err) = ledger.flush() {
        tracing::warn!(error = %err, "failed to flush decision ledger");
    }
}

#[cfg(test)]
mod tests {
    use bowline_core::{
        decision::Decision,
        ledger::{ActualOutcome, Ledger, UsageSource},
        policy::WorkloadIdentity,
        supply::TaskClass,
    };

    use super::*;

    fn digest(value: u8) -> String {
        format!("sha256:{value:064x}")
    }

    #[tokio::test]
    async fn modeled_delta_requires_descriptor_verified_run_token_and_exact_run_match() {
        let first = tempfile::tempdir().unwrap();
        let writer =
            spawn_managed_authority_writer(authority_test_options(first.path(), 2)).unwrap();
        let handle = writer
            .reserve_and_flush_decision(authority_decision("candidate"))
            .await
            .unwrap();
        let completed = writer
            .append_and_flush_outcome(
                handle
                    .authorize_dispatch(authority_dispatch_attempt())
                    .await
                    .unwrap(),
                authority_outcome("candidate"),
            )
            .await
            .unwrap();
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let verified =
            AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
        assert!(
            enforced_modeled_delta_from_verified(verified.complete(), &completed)
                .unwrap()
                .is_none()
        );

        let second = tempfile::tempdir().unwrap();
        let other_writer =
            spawn_managed_authority_writer(authority_test_options(second.path(), 2)).unwrap();
        let handle = other_writer
            .reserve_and_flush_decision(authority_decision("candidate"))
            .await
            .unwrap();
        other_writer
            .append_and_flush_outcome(
                handle
                    .authorize_dispatch(authority_dispatch_attempt())
                    .await
                    .unwrap(),
                authority_outcome("candidate"),
            )
            .await
            .unwrap();
        other_writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let other =
            AuthorityLedgerV2::read_validated_authority_run(other_writer.manifest_path()).unwrap();
        assert!(enforced_modeled_delta_from_verified(other.complete(), &completed).is_err());
    }

    #[tokio::test]
    async fn modeled_delta_http_status_matrix_is_unavailable_outside_complete_observed_2xx() {
        let verified_grant =
            crate::proxy::proxy_controlled_matrix_tests::modeled_delta_verified_grant_fixture();
        let statuses = [
            101, 300, 301, 302, 304, 307, 308, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503,
            599, 200, 204, 299,
        ];
        for status in statuses {
            let tempdir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let writer = spawn_managed_authority_writer(AuthorityWriterOptions {
                directory: tempdir.path().to_path_buf(),
                enforcement_digest: verified_grant.config_digest().into(),
                actuator_digests: vec![verified_grant.actuator_digest().into()],
                grant_digests: vec![verified_grant.grant_digest().into()],
                queue_capacity: 2,
                max_records_bytes: 1024 * 1024,
            })
            .unwrap();
            let mut decision = raw_authority_decision(&format!("status-{status}"));
            decision.route_id = verified_grant.route_id().into();
            decision.protocol = verified_grant.protocol();
            decision.task_class = verified_grant.task_class();
            decision.workload_identity_digest =
                Some(verified_grant.workload_identity_digest().into());
            decision.selected_supply_id = Some(verified_grant.candidate_supply_id().into());
            decision.baseline_supply_id = Some(verified_grant.actual_supply_id().into());
            decision.grant = Some(bowline_core::ledger::AuthorityGrantBindingV2 {
                grant_digest: verified_grant.grant_digest().into(),
                expires_at_ms: verified_grant.expires_at_ms(),
                economics_source_digest: verified_grant.economics_source_digest().into(),
                quality_source_digest: verified_grant.quality_source_digest().into(),
                opportunity_digest: verified_grant.opportunity_digest().into(),
            });
            decision.enforcement_config_digest = verified_grant.config_digest().into();
            decision.route_config_digest = verified_grant.route_digest().into();
            decision.actuator_config_digest = Some(verified_grant.actuator_digest().into());
            let handle = writer
                .reserve_and_flush_decision(test_prepared_authority_decision_v2(decision))
                .await
                .unwrap();
            let mut attempt = authority_dispatch_attempt();
            attempt.route_id = verified_grant.route_id().into();
            attempt.protocol = verified_grant.protocol();
            attempt.task_class = verified_grant.task_class();
            attempt.workload_identity_digest =
                Some(verified_grant.workload_identity_digest().into());
            attempt.selected_supply_id = Some(verified_grant.candidate_supply_id().into());
            let mut authorized = handle.authorize_dispatch(attempt).await.unwrap();
            authorized.payload.as_mut().unwrap().verified_grant = Some(verified_grant.clone());
            let failure = if matches!(status, 401 | 403) {
                Some(CandidateFailureClassV2::Authentication)
            } else if (500..=599).contains(&status) {
                Some(CandidateFailureClassV2::Server)
            } else {
                None
            };
            let outcome = authorized
                .build_outcome(AuthorityTerminalV2 {
                    ts_ms: 20,
                    circuit_after: if failure.is_some() {
                        CircuitStateV2::Open
                    } else {
                        CircuitStateV2::Closed
                    },
                    completion: if failure.is_some() {
                        CompletionStateV2::Failed
                    } else {
                        CompletionStateV2::Succeeded
                    },
                    candidate_failure: failure,
                    status: Some(status),
                    input_tokens: Some(10),
                    output_tokens: Some(20),
                    usage_source: UsageSource::Observed,
                })
                .unwrap();
            let costs = (
                outcome.observed_actual_cost_micros,
                outcome.approved_counterfactual_cost_micros,
                outcome.enforced_modeled_delta_micros,
            );
            if (200..=299).contains(&status) {
                assert!(
                    matches!(costs, (Some(_), Some(_), Some(_))),
                    "status {status}"
                );
            } else {
                assert_eq!(costs, (None, None, None), "status {status}");
            }
            let completed = writer
                .append_and_flush_outcome(authorized, outcome)
                .await
                .unwrap();
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
            let run =
                AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
            let recomputed =
                enforced_modeled_delta_from_verified(run.complete(), &completed).unwrap();
            assert_eq!(recomputed.is_some(), (200..=299).contains(&status));
        }
    }

    #[tokio::test]
    async fn partial_observed_usage_is_durable_without_modeled_delta() {
        let verified_grant =
            crate::proxy::proxy_controlled_matrix_tests::modeled_delta_verified_grant_fixture();
        for (id, input_tokens, output_tokens) in [
            ("input-only", Some(10), None),
            ("output-only", None, Some(20)),
        ] {
            let tempdir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let writer = spawn_managed_authority_writer(AuthorityWriterOptions {
                directory: tempdir.path().to_path_buf(),
                enforcement_digest: verified_grant.config_digest().into(),
                actuator_digests: vec![verified_grant.actuator_digest().into()],
                grant_digests: vec![verified_grant.grant_digest().into()],
                queue_capacity: 2,
                max_records_bytes: 1024 * 1024,
            })
            .unwrap();
            let mut decision = raw_authority_decision(id);
            decision.route_id = verified_grant.route_id().into();
            decision.protocol = verified_grant.protocol();
            decision.task_class = verified_grant.task_class();
            decision.workload_identity_digest =
                Some(verified_grant.workload_identity_digest().into());
            decision.selected_supply_id = Some(verified_grant.candidate_supply_id().into());
            decision.baseline_supply_id = Some(verified_grant.actual_supply_id().into());
            decision.grant = Some(bowline_core::ledger::AuthorityGrantBindingV2 {
                grant_digest: verified_grant.grant_digest().into(),
                expires_at_ms: verified_grant.expires_at_ms(),
                economics_source_digest: verified_grant.economics_source_digest().into(),
                quality_source_digest: verified_grant.quality_source_digest().into(),
                opportunity_digest: verified_grant.opportunity_digest().into(),
            });
            decision.enforcement_config_digest = verified_grant.config_digest().into();
            decision.route_config_digest = verified_grant.route_digest().into();
            decision.actuator_config_digest = Some(verified_grant.actuator_digest().into());
            let handle = writer
                .reserve_and_flush_decision(test_prepared_authority_decision_v2(decision))
                .await
                .unwrap();
            let mut attempt = authority_dispatch_attempt();
            attempt.route_id = verified_grant.route_id().into();
            attempt.protocol = verified_grant.protocol();
            attempt.task_class = verified_grant.task_class();
            attempt.workload_identity_digest =
                Some(verified_grant.workload_identity_digest().into());
            attempt.selected_supply_id = Some(verified_grant.candidate_supply_id().into());
            let mut authorized = handle.authorize_dispatch(attempt).await.unwrap();
            authorized.payload.as_mut().unwrap().verified_grant = Some(verified_grant.clone());
            let outcome = authorized
                .build_outcome(AuthorityTerminalV2 {
                    ts_ms: 20,
                    circuit_after: CircuitStateV2::Closed,
                    completion: CompletionStateV2::Succeeded,
                    candidate_failure: None,
                    status: Some(200),
                    input_tokens,
                    output_tokens,
                    usage_source: UsageSource::Observed,
                })
                .unwrap();
            assert_eq!(outcome.input_tokens, input_tokens);
            assert_eq!(outcome.output_tokens, output_tokens);
            assert_eq!(outcome.observed_actual_cost_micros, None);
            assert_eq!(outcome.approved_counterfactual_cost_micros, None);
            assert_eq!(outcome.enforced_modeled_delta_micros, None);
            let completed = writer
                .append_and_flush_outcome(authorized, outcome)
                .await
                .unwrap();
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
            let run =
                AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
            let AuthorityRecordV2::Outcome {
                outcome: persisted, ..
            } = &run.records()[1]
            else {
                panic!("missing persisted outcome")
            };
            assert_eq!(persisted.input_tokens, input_tokens);
            assert_eq!(persisted.output_tokens, output_tokens);
            assert!(
                enforced_modeled_delta_from_verified(run.complete(), &completed)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn writer_flushes_record_off_thread() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let (writer, recovery) = spawn_writer(tempdir.path().to_path_buf()).expect("writer starts");
        assert!(matches!(recovery, RecoveryOutcome::Absent));

        writer.tx.try_send(record()).expect("record accepted");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let (records, _) = Ledger::read_all(tempdir.path()).expect("ledger readable");
            if records.len() == 1 {
                assert_eq!(records[0].id, "record-1");
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for writer flush"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn managed_writer_saturation_is_counted_and_unready() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let (writer, release) =
            spawn_paused_managed_writer(tempdir.path(), 1).expect("managed writer starts paused");

        let first = writer.accept_request().expect("first request accepted");
        writer
            .try_record(record_for(first))
            .expect("first record queued");
        let second = writer.accept_request().expect("second request accepted");
        let error = writer
            .try_record(record_for(second))
            .expect_err("full queue must disclose drop");

        assert!(matches!(error, ManagedWriterError::QueueFull));
        let snapshot = writer.health().snapshot();
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.recorded, 0);
        assert_eq!(snapshot.dropped, 1);
        assert!(!snapshot.ready);

        release.send(()).expect("writer released");
        writer
            .shutdown(Duration::from_secs(2))
            .await
            .expect("writer drains after release");
    }

    #[tokio::test]
    async fn managed_writer_shutdown_drains_and_syncs_every_queued_record() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let writer = spawn_managed_writer(ManagedWriterOptions::test(tempdir.path(), 16))
            .expect("managed writer starts");

        for _ in 0..10 {
            let context = writer.accept_request().expect("request accepted");
            writer
                .try_record(record_for(context))
                .expect("record queued");
        }
        writer
            .shutdown(Duration::from_secs(2))
            .await
            .expect("writer drains");
        let snapshot = writer.health().snapshot();
        assert_eq!(
            (snapshot.accepted, snapshot.recorded, snapshot.dropped),
            (10, 10, 0)
        );
        assert!(snapshot.clean_shutdown);
        let (records, outcomes) =
            SegmentedLedger::read_run(tempdir.path(), &snapshot.run_id).expect("segments readable");
        assert_eq!(records.len(), 10);
        assert!(outcomes
            .iter()
            .all(|outcome| matches!(outcome, RecoveryOutcome::Clean { .. })));
    }

    #[tokio::test]
    async fn authoritative_run_rejects_segment_deletion_addition_reorder_and_redistribution() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let ledger_dir = std::fs::canonicalize(tempdir.path())
            .unwrap()
            .join("ledger");
        let mut options = ManagedWriterOptions::test(&ledger_dir, 16);
        options.segment_bytes = 1_400;
        options.max_segments = 16;
        let writer = spawn_managed_writer(options).expect("managed writer starts");
        for _ in 0..10 {
            let context = writer.accept_request().expect("request accepted");
            writer
                .try_record(record_for(context))
                .expect("record queued");
        }
        writer
            .shutdown(Duration::from_secs(2))
            .await
            .expect("writer drains");
        let directory = ledger_dir;
        let manifest = writer.health().run().snapshot();
        assert!(manifest.segments.len() > 1, "fixture must rotate");
        assert_eq!(
            SegmentedLedger::read_authoritative_run(&directory, &manifest)
                .expect("bound run reads")
                .len(),
            10
        );

        let first = directory.join(&manifest.segments[0]);
        let first_bytes = std::fs::read(&first).unwrap();
        std::fs::remove_file(&first).unwrap();
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_err());
        std::fs::write(&first, &first_bytes).unwrap();

        let extra = directory.join(format!(
            "run-{}-{:06}.bwl",
            manifest.run_id,
            manifest.segments.len()
        ));
        std::fs::write(&extra, b"BWL1\n").unwrap();
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_err());
        std::fs::remove_file(extra).unwrap();

        let mut reordered = manifest.clone();
        reordered.segments.swap(0, 1);
        assert!(SegmentedLedger::read_authoritative_run(&directory, &reordered).is_err());

        let second = directory.join(&manifest.segments[1]);
        let second_bytes = std::fs::read(&second).unwrap();
        std::fs::write(&first, &second_bytes).unwrap();
        std::fs::write(&second, &first_bytes).unwrap();
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_err());
    }

    #[tokio::test]
    async fn authority_writer_reserves_capacity_before_sequence_and_handle() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let (writer, release) = spawn_paused_authority_writer(tempdir.path(), 1)
            .expect("authority writer starts paused");
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            first_writer
                .reserve_and_flush_decision(authority_decision("decision-1"))
                .await
        });
        while writer.manifest_snapshot().accepted == 0 {
            tokio::task::yield_now().await;
        }
        let error = writer
            .reserve_and_flush_decision(authority_decision("decision-2"))
            .await
            .expect_err("full queue returns no handle or sequence");
        assert!(matches!(error, ManagedWriterError::QueueFull));
        assert_eq!(writer.manifest_snapshot().accepted, 1);
        assert!(!writer.manifest_snapshot().writer_healthy);
        release.send(()).unwrap();
        assert!(
            first.await.unwrap().is_err(),
            "an incomplete run cannot issue authority"
        );
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn decision_admission_and_shutdown_share_one_atomic_lifecycle_boundary() {
        let tempdir = tempfile::tempdir().unwrap();
        let (writer, release) = spawn_paused_authority_writer(tempdir.path(), 2).unwrap();
        let admitting_writer = writer.clone();
        let admission = tokio::spawn(async move {
            admitting_writer
                .reserve_and_flush_decision(authority_decision("racing"))
                .await
        });
        while writer.manifest_snapshot().accepted == 0 {
            tokio::task::yield_now().await;
        }

        let closing_writer = writer.clone();
        let closing =
            tokio::spawn(async move { closing_writer.shutdown(Duration::from_secs(2)).await });
        while writer.manifest_snapshot().writer_healthy {
            tokio::task::yield_now().await;
        }
        release.send(()).unwrap();
        assert!(admission.await.unwrap().is_err());
        closing.await.unwrap().unwrap();
        assert!(!writer.manifest_snapshot().clean_shutdown);

        let accepted = writer.manifest_snapshot().accepted;
        assert!(matches!(
            writer
                .reserve_and_flush_decision(authority_decision("after-close"))
                .await,
            Err(ManagedWriterError::Closed)
        ));
        assert_eq!(writer.manifest_snapshot().accepted, accepted);
    }

    #[tokio::test]
    async fn shutdown_winning_before_dispatch_authorization_rejects_the_handle() {
        let tempdir = tempfile::tempdir().unwrap();
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
        let handle = writer
            .reserve_and_flush_decision(authority_decision("shutdown-first"))
            .await
            .unwrap();

        writer.shutdown(Duration::from_secs(2)).await.unwrap();

        assert!(matches!(
            handle
                .authorize_dispatch(authority_dispatch_attempt())
                .await,
            Err(ManagedWriterError::Closed)
        ));
        assert!(!writer.manifest_snapshot().writer_healthy);
        assert!(!writer.manifest_snapshot().clean_shutdown);
    }

    #[tokio::test]
    async fn poison_winning_before_dispatch_authorization_rejects_the_handle() {
        let tempdir = tempfile::tempdir().unwrap();
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
        let handle = writer
            .reserve_and_flush_decision(authority_decision("poison-first"))
            .await
            .unwrap();

        writer.mark_authority_error("injected poison", None);

        assert!(matches!(
            handle
                .authorize_dispatch(authority_dispatch_attempt())
                .await,
            Err(ManagedWriterError::InvalidRecordContext)
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(!writer.manifest_snapshot().clean_shutdown);
    }

    #[tokio::test]
    async fn dispatch_authorization_winning_before_shutdown_remains_outstanding() {
        let tempdir = tempfile::tempdir().unwrap();
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
        let handle = writer
            .reserve_and_flush_decision(authority_decision("authorize-first"))
            .await
            .unwrap();

        let authorized = handle
            .authorize_dispatch(authority_dispatch_attempt())
            .await
            .unwrap();
        {
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert_eq!(lifecycle.issued_decisions, 0);
            assert_eq!(lifecycle.authorized_dispatches, 1);
            assert_eq!(lifecycle.outstanding, 1);
        }
        writer.shutdown(Duration::from_secs(2)).await.unwrap();

        assert!(!writer.manifest_snapshot().writer_healthy);
        assert!(!writer.manifest_snapshot().clean_shutdown);
        drop(authorized);
    }

    #[tokio::test]
    async fn unhealthy_run_issues_neither_candidate_nor_zero_authority_handle() {
        for prepared in [
            authority_decision("candidate-after-poison"),
            zero_authority_decision("zero-after-poison"),
        ] {
            let tempdir = tempfile::tempdir().unwrap();
            let writer =
                spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
            writer.mark_authority_error("injected poison", None);

            assert!(writer.reserve_and_flush_decision(prepared).await.is_err());
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
            assert!(!writer.manifest_snapshot().writer_healthy);
        }
    }

    #[tokio::test]
    async fn zero_authority_post_flush_poison_emits_no_handle() {
        let tempdir = tempfile::tempdir().unwrap();
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();

        let result = writer
            .reserve_and_flush_decision_inner(zero_authority_decision("zero-post-flush"), || {
                writer.mark_authority_error("post-flush poison", None);
            })
            .await;

        assert!(matches!(
            result,
            Err(ManagedWriterError::InvalidRecordContext)
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let manifest = writer.manifest_snapshot();
        assert_eq!(manifest.recorded, 1);
        assert!(!manifest.writer_healthy);
        assert!(!manifest.clean_shutdown);
        let lifecycle = writer.inner.lifecycle.lock().unwrap();
        assert_eq!(lifecycle.issued_decisions, 0);
        assert_eq!(lifecycle.authorized_dispatches, 0);
        assert_eq!(lifecycle.outstanding, 0);
    }

    #[tokio::test]
    async fn authority_flush_failure_returns_no_handle_and_marks_run_incomplete() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let writer = spawn_persistent_faulting_authority_writer(tempdir.path(), 2)
            .expect("authority writer starts");
        let error = writer
            .reserve_and_flush_decision(authority_decision("decision-1"))
            .await
            .expect_err("failed durable flush cannot create handle");
        assert!(matches!(error, ManagedWriterError::Writer(_)));
        let snapshot = writer.manifest_snapshot();
        assert!(!snapshot.writer_healthy);
        assert_eq!(
            (snapshot.accepted, snapshot.recorded, snapshot.dropped),
            (1, 0, 1)
        );
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(!writer.manifest_snapshot().clean_shutdown);
    }

    #[tokio::test]
    async fn failed_candidate_flush_poison_prevents_zero_authority_handle_issuance() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let writer =
            spawn_faulting_authority_writer(tempdir.path(), 2).expect("authority writer starts");
        assert!(writer
            .reserve_and_flush_decision(authority_decision("candidate"))
            .await
            .is_err());
        let replacement_error = writer
            .reserve_and_flush_decision(zero_authority_decision("replacement"))
            .await
            .expect_err("poisoned authority run cannot issue a replacement handle");
        assert!(matches!(
            replacement_error,
            ManagedWriterError::InvalidRecordContext
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let manifest = writer.manifest_snapshot();
        assert_eq!(
            (manifest.accepted, manifest.recorded, manifest.dropped),
            (1, 0, 1)
        );
        assert!(!manifest.clean_shutdown);
    }

    #[tokio::test]
    async fn failed_candidate_flush_issues_one_scoped_zero_authority_recovery() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            tempdir.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .expect("authority writer starts");
        let CandidateDecisionReservation::Recoverable { recovery, .. } = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate"),
                recovery_replacement_decision(&validated, "replacement"),
            )
            .await
        else {
            panic!("failed candidate flush must return scoped recovery")
        };
        {
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert_eq!(lifecycle.issued_decisions, 0);
            assert_eq!(lifecycle.authorized_dispatches, 0);
            assert_eq!(lifecycle.outstanding, 1);
            assert!(!lifecycle.authority_complete);
            assert!(lifecycle.transport_available);
        }
        assert!(matches!(
            writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-replay"),
                    recovery_replacement_decision(&validated, "replacement-replay"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        let replacement = recovery
            .reserve_and_flush_replacement()
            .await
            .expect("replacement decision flushes despite incomplete authority run");
        assert!(!replacement.authorizes_candidate());
        assert_eq!(writer.manifest_snapshot().recorded, 1);
        let authorized = replacement
            .authorize_dispatch(zero_authority_dispatch_attempt())
            .await
            .expect("durably flushed replacement authorizes only original dispatch");
        {
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert_eq!(lifecycle.authorized_dispatches, 1);
            assert_eq!(lifecycle.outstanding, 1);
        }
        writer
            .append_and_flush_outcome(
                authorized,
                zero_authority_outcome(&validated, "replacement"),
            )
            .await
            .expect("exact recovered fallback terminal remains appendable");
        {
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert_eq!(lifecycle.authorized_dispatches, 0);
            assert_eq!(lifecycle.outstanding, 0);
        }
        assert!(matches!(
            writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-after-incomplete"),
                    recovery_replacement_decision(&validated, "replacement-after-incomplete"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(!writer.manifest_snapshot().writer_healthy);
        assert_eq!(
            (
                writer.manifest_snapshot().accepted,
                writer.manifest_snapshot().recorded,
                writer.manifest_snapshot().dropped,
            ),
            (3, 2, 1)
        );
        assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
    }

    #[tokio::test]
    async fn recovered_replacement_flush_failure_issues_no_handle_or_target() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::TransientThenPersistent {
                transient_attempt: 1,
                persistent_attempt: 2,
            },
        )
        .unwrap();
        let CandidateDecisionReservation::Recoverable { recovery, .. } = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-replacement-fails"),
                recovery_replacement_decision(&validated, "replacement-flush-fails"),
            )
            .await
        else {
            panic!("candidate failure must own exact recovery")
        };

        assert!(matches!(
            recovery.reserve_and_flush_replacement().await,
            Err(ManagedWriterError::Writer(_))
        ));
        {
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert!(!lifecycle.authority_complete);
            assert!(!lifecycle.transport_available);
            assert_eq!(lifecycle.issued_decisions, 0);
            assert_eq!(lifecycle.authorized_dispatches, 0);
            assert_eq!(lifecycle.outstanding, 0);
        }
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn successful_candidate_reservations_remain_enabled_after_each_flush() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();

        for id in ["candidate-success-1", "candidate-success-2"] {
            let CandidateDecisionReservation::Flushed(handle) = writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, id),
                    recovery_replacement_decision(&validated, &format!("replacement-{id}")),
                )
                .await
            else {
                panic!("each successful candidate reservation must issue its own handle")
            };
            complete_candidate_handle(&writer, &validated, handle, id).await;
        }

        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn two_pending_candidate_successes_both_issue_handles() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let (writer, release) = spawn_paused_authority_writer_for(directory.path(), &validated)
            .expect("paused authority writer starts");

        let first_writer = writer.clone();
        let first_validated = validated.clone();
        let first = tokio::spawn(async move {
            first_writer
                .reserve_candidate_decision_or_recovery(
                    &first_validated,
                    recovery_candidate_decision(&first_validated, "candidate-pending-1"),
                    recovery_replacement_decision(&first_validated, "replacement-pending-1"),
                )
                .await
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        let second_writer = writer.clone();
        let second_validated = validated.clone();
        let second = tokio::spawn(async move {
            second_writer
                .reserve_candidate_decision_or_recovery(
                    &second_validated,
                    recovery_candidate_decision(&second_validated, "candidate-pending-2"),
                    recovery_replacement_decision(&second_validated, "replacement-pending-2"),
                )
                .await
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(!first.is_finished());
        assert!(
            !second.is_finished(),
            "overlap alone must not reject the second candidate reservation"
        );

        release.send(()).unwrap();
        let CandidateDecisionReservation::Flushed(first_handle) = first.await.unwrap() else {
            panic!("first pending success must issue")
        };
        let CandidateDecisionReservation::Flushed(second_handle) = second.await.unwrap() else {
            panic!("second pending success must issue")
        };
        complete_candidate_handle(&writer, &validated, first_handle, "candidate-pending-1").await;
        complete_candidate_handle(&writer, &validated, second_handle, "candidate-pending-2").await;
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn first_pending_failure_owns_recovery_and_disables_other_pending_callback() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let writer = spawn_managed_authority_writer_inner(
            recovery_writer_options(directory.path(), &validated),
            Some(release_rx),
            Some(AuthorityWriterFault::Transient(1)),
        )
        .unwrap();
        let (published, resume) = writer.install_recovery_consume_pause();

        let first_writer = writer.clone();
        let first_validated = validated.clone();
        let first = tokio::spawn(async move {
            first_writer
                .reserve_candidate_decision_or_recovery(
                    &first_validated,
                    recovery_candidate_decision(&first_validated, "candidate-fails-first"),
                    recovery_replacement_decision(&first_validated, "replacement-fails-first"),
                )
                .await
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        let second_writer = writer.clone();
        let second_validated = validated.clone();
        let second = tokio::spawn(async move {
            second_writer
                .reserve_candidate_decision_or_recovery(
                    &second_validated,
                    recovery_candidate_decision(&second_validated, "candidate-after-failure"),
                    recovery_replacement_decision(&second_validated, "replacement-after-failure"),
                )
                .await
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(!second.is_finished());

        release_tx.send(()).unwrap();
        published.await.unwrap();
        assert!(matches!(
            second.await.unwrap(),
            CandidateDecisionReservation::Rejected(_)
        ));
        assert!(matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Available { .. }
        ));
        resume.send(()).unwrap();
        let CandidateDecisionReservation::Recoverable { recovery, .. } = first.await.unwrap()
        else {
            panic!("first actual failure must own the sole recovery")
        };
        let replacement = recovery.reserve_and_flush_replacement().await.unwrap();
        complete_zero_authority_handle(&writer, &validated, replacement, "replacement-fails-first")
            .await;
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn earlier_success_handle_rejects_dispatch_after_later_candidate_failure() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(2),
        )
        .unwrap();
        let CandidateDecisionReservation::Flushed(success_handle) = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-callback-wins"),
                recovery_replacement_decision(&validated, "replacement-callback-wins"),
            )
            .await
        else {
            panic!("first callback must issue before the later failure")
        };
        let CandidateDecisionReservation::Recoverable { recovery, .. } = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-fails-later"),
                recovery_replacement_decision(&validated, "replacement-fails-later"),
            )
            .await
        else {
            panic!("later first actual failure must still own recovery")
        };
        assert!(matches!(
            success_handle
                .authorize_dispatch(authority_dispatch_attempt())
                .await,
            Err(ManagedWriterError::InvalidRecordContext)
        ));
        let replacement = recovery.reserve_and_flush_replacement().await.unwrap();
        complete_zero_authority_handle(&writer, &validated, replacement, "replacement-fails-later")
            .await;
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn pending_candidate_recoveries_are_bounded_by_writer_queue_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let (writer, release) = spawn_paused_authority_writer_for(directory.path(), &validated)
            .expect("paused authority writer starts");
        let mut pending = Vec::new();
        for index in 0..2 {
            let pending_writer = writer.clone();
            let pending_validated = validated.clone();
            pending.push(tokio::spawn(async move {
                pending_writer
                    .reserve_candidate_decision_or_recovery(
                        &pending_validated,
                        recovery_candidate_decision(
                            &pending_validated,
                            &format!("candidate-bound-{index}"),
                        ),
                        recovery_replacement_decision(
                            &pending_validated,
                            &format!("replacement-bound-{index}"),
                        ),
                    )
                    .await
            }));
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
        }
        assert!(pending.iter().all(|reservation| !reservation.is_finished()));
        assert!(matches!(
            writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-bound-overflow"),
                    recovery_replacement_decision(&validated, "replacement-bound-overflow"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));

        release.send(()).unwrap();
        for (index, reservation) in pending.into_iter().enumerate() {
            let CandidateDecisionReservation::Flushed(handle) = reservation.await.unwrap() else {
                panic!("bounded pending candidate must issue")
            };
            complete_candidate_handle(
                &writer,
                &validated,
                handle,
                &format!("candidate-bound-{index}"),
            )
            .await;
        }
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_after_recovery_publish_before_consume_rejects_capability() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .unwrap();
        let (published, resume) = writer.install_recovery_consume_pause();
        let reservation_writer = writer.clone();
        let reservation_validated = validated.clone();
        let reservation = tokio::spawn(async move {
            reservation_writer
                .reserve_candidate_decision_or_recovery(
                    &reservation_validated,
                    recovery_candidate_decision(&reservation_validated, "candidate-shutdown-race"),
                    recovery_replacement_decision(
                        &reservation_validated,
                        "replacement-shutdown-race",
                    ),
                )
                .await
        });
        published.await.unwrap();
        assert!(matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Available { .. }
        ));

        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        resume.send(()).unwrap();
        assert!(matches!(
            reservation.await.unwrap(),
            CandidateDecisionReservation::Rejected(_)
        ));
    }

    #[tokio::test]
    async fn ordinary_poison_after_recovery_publish_before_consume_rejects_capability() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .unwrap();
        let (published, resume) = writer.install_recovery_consume_pause();
        let reservation_writer = writer.clone();
        let reservation_validated = validated.clone();
        let reservation = tokio::spawn(async move {
            reservation_writer
                .reserve_candidate_decision_or_recovery(
                    &reservation_validated,
                    recovery_candidate_decision(&reservation_validated, "candidate-poison-race"),
                    recovery_replacement_decision(
                        &reservation_validated,
                        "replacement-poison-race",
                    ),
                )
                .await
        });
        published.await.unwrap();

        writer.mark_authority_error("ordinary poison after recovery publish", None);
        resume.send(()).unwrap();
        assert!(matches!(
            reservation.await.unwrap(),
            CandidateDecisionReservation::Rejected(_)
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn transport_failure_after_recovery_publish_before_consume_rejects_capability() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .unwrap();
        let (published, resume) = writer.install_recovery_consume_pause();
        let reservation_writer = writer.clone();
        let reservation_validated = validated.clone();
        let reservation = tokio::spawn(async move {
            reservation_writer
                .reserve_candidate_decision_or_recovery(
                    &reservation_validated,
                    recovery_candidate_decision(&reservation_validated, "candidate-transport-race"),
                    recovery_replacement_decision(
                        &reservation_validated,
                        "replacement-transport-race",
                    ),
                )
                .await
        });
        published.await.unwrap();

        mark_authority_transport_unavailable(
            &writer.inner.lifecycle,
            &writer.inner.run,
            "transport failed after recovery publish",
            None,
        );
        resume.send(()).unwrap();
        assert!(matches!(
            reservation.await.unwrap(),
            CandidateDecisionReservation::Rejected(_)
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn wrong_recovery_generation_after_publish_rejects_as_stale() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .unwrap();
        let (published, resume) = writer.install_recovery_consume_pause();
        let reservation_writer = writer.clone();
        let reservation_validated = validated.clone();
        let reservation = tokio::spawn(async move {
            reservation_writer
                .reserve_candidate_decision_or_recovery(
                    &reservation_validated,
                    recovery_candidate_decision(&reservation_validated, "candidate-stale-id"),
                    recovery_replacement_decision(&reservation_validated, "replacement-stale-id"),
                )
                .await
        });
        published.await.unwrap();
        {
            let mut lifecycle = writer.inner.lifecycle.lock().unwrap();
            let recovery = std::mem::replace(&mut lifecycle.recovery, RecoveryLifecycle::Disabled);
            let RecoveryLifecycle::Available { id, replacement } = recovery else {
                panic!("candidate failure must publish exact recovery")
            };
            lifecycle.recovery = RecoveryLifecycle::Available {
                id: id + 1,
                replacement,
            };
        }

        resume.send(()).unwrap();
        assert!(matches!(
            reservation.await.unwrap(),
            CandidateDecisionReservation::Rejected(_)
        ));
        assert!(matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Available { .. }
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn consumed_recovery_remains_one_shot_when_shutdown_follows() {
        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .unwrap();
        let CandidateDecisionReservation::Recoverable { recovery, .. } = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-consume-wins"),
                recovery_replacement_decision(&validated, "replacement-consume-wins"),
            )
            .await
        else {
            panic!("first exact recovery must consume")
        };
        assert!(matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Consumed { .. }
        ));
        assert_eq!(writer.inner.lifecycle.lock().unwrap().outstanding, 1);

        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Consumed { .. }
        ));
        assert!(!writer.inner.lifecycle.lock().unwrap().authority_complete);
        assert!(matches!(
            writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-replay-after-consume"),
                    recovery_replacement_decision(&validated, "replacement-replay-after-consume",),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        assert!(matches!(
            recovery.reserve_and_flush_replacement().await,
            Err(ManagedWriterError::Closed)
        ));
    }

    #[test]
    fn recovery_pair_rejects_wrong_fallback_reason_request_and_config_bindings() {
        let bypass = recovery_validated("bypass");
        let fail_closed = recovery_validated("fail-closed");

        let rejects = |validated: &bowline_core::enforcement::ValidatedEnforcement,
                       mutate: fn(&mut PreparedAuthorityParts)| {
            let candidate =
                PreparedAuthorityParts::from(recovery_candidate_decision(validated, "candidate"));
            let mut replacement = PreparedAuthorityParts::from(recovery_replacement_decision(
                validated,
                "replacement",
            ));
            mutate(&mut replacement);
            assert!(validate_candidate_recovery_pair(validated, &candidate, &replacement).is_err());
        };

        rejects(&fail_closed, |replacement| {
            replacement.decision.target = PlanTarget::Original;
            replacement.decision.intended_dispatch = 1;
            replacement.decision.selected_supply_id = Some("baseline".into());
            replacement.dispatch_binding.target = PlanTarget::Original;
            replacement.dispatch_binding.selected_supply_id = Some("baseline".into());
        });
        rejects(&bypass, |replacement| {
            replacement.decision.target = PlanTarget::None;
            replacement.decision.intended_dispatch = 0;
            replacement.decision.selected_supply_id = None;
            replacement.dispatch_binding.target = PlanTarget::None;
            replacement.dispatch_binding.selected_supply_id = None;
        });
        rejects(&bypass, |replacement| {
            replacement.decision.route_id = "other-route".into();
            replacement.dispatch_binding.route_id = "other-route".into();
        });
        rejects(&bypass, |replacement| {
            replacement.decision.reason = SelectionReason::CircuitOpen;
            let mut facts = bowline_core::ledger::AuthoritySelectionFactsV2::canonical_fallback(
                bowline_core::ledger::AuthorityFallbackReasonV2::CircuitOpen,
            );
            facts.bucket = Some(1);
            replacement.decision.selection_facts = facts;
        });
        rejects(&bypass, |replacement| {
            replacement.dispatch_binding.request_body_digest = [8; 32];
        });
        rejects(&bypass, |replacement| {
            replacement.decision.enforcement_config_digest = digest(8);
        });
        rejects(&bypass, |replacement| {
            replacement.decision.selection_facts.bucket = Some(2);
            replacement.dispatch_binding.bucket = Some(2);
        });
    }

    #[tokio::test]
    async fn unavailable_transport_rejects_scoped_replacement_and_every_dispatch_handle() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            tempdir.path(),
            2,
            &validated,
            AuthorityWriterFault::Persistent(1),
        )
        .expect("authority writer starts");
        assert!(matches!(
            writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate"),
                    recovery_replacement_decision(&validated, "replacement"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        let snapshot = writer.manifest_snapshot();
        assert_eq!((snapshot.accepted, snapshot.recorded), (1, 0));
        {
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert!(!lifecycle.authority_complete);
            assert!(!lifecycle.transport_available);
            assert_eq!(lifecycle.outstanding, 0);
        }
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn incomplete_persistence_failure_disables_recovery_and_transport() {
        for fault in [
            IncompletePersistenceFault::Dropped,
            IncompletePersistenceFault::WriterError,
            IncompletePersistenceFault::Flush,
        ] {
            let tempdir = tempfile::tempdir().expect("tempdir created");
            let validated = recovery_validated("bypass");
            let writer = spawn_faulting_authority_writer_for(
                tempdir.path(),
                2,
                &validated,
                AuthorityWriterFault::Transient(1),
            )
            .expect("authority writer starts");
            writer
                .inner
                .lifecycle
                .lock()
                .unwrap()
                .incomplete_persistence_fault = Some(fault);
            assert!(matches!(
                writer
                    .reserve_candidate_decision_or_recovery(
                        &validated,
                        recovery_candidate_decision(&validated, "candidate"),
                        recovery_replacement_decision(&validated, "replacement"),
                    )
                    .await,
                CandidateDecisionReservation::Rejected(_)
            ));
            {
                let lifecycle = writer.inner.lifecycle.lock().unwrap();
                assert!(!lifecycle.authority_complete);
                assert!(!lifecycle.transport_available);
                assert!(matches!(lifecycle.recovery, RecoveryLifecycle::Disabled));
                assert_eq!(lifecycle.issued_decisions, 0);
                assert_eq!(lifecycle.authorized_dispatches, 0);
            }
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn preexisting_incomplete_mismatch_and_abandonment_never_mint_recovery() {
        let validated = recovery_validated("bypass");

        let validation_dir = tempfile::tempdir().unwrap();
        let validation = spawn_authority_writer_for(validation_dir.path(), &validated).unwrap();
        let mut invalid_parts = PreparedAuthorityParts::from(recovery_candidate_decision(
            &validated,
            "candidate-invalid-grant",
        ));
        invalid_parts.decision.grant.as_mut().unwrap().grant_digest = digest(9);
        let invalid_candidate = test_prepared_authority_decision_v2(invalid_parts.decision);
        assert!(matches!(
            validation
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    invalid_candidate,
                    recovery_replacement_decision(&validated, "replacement-invalid-grant"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        {
            let lifecycle = validation.inner.lifecycle.lock().unwrap();
            assert!(lifecycle.authority_complete);
            assert!(matches!(lifecycle.recovery, RecoveryLifecycle::None));
        }
        validation.shutdown(Duration::from_secs(2)).await.unwrap();

        let poisoned_dir = tempfile::tempdir().unwrap();
        let poisoned = spawn_authority_writer_for(poisoned_dir.path(), &validated).unwrap();
        poisoned.mark_authority_error("ordinary poison", None);
        assert!(matches!(
            poisoned
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-poisoned"),
                    recovery_replacement_decision(&validated, "replacement-poisoned"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        assert!(!matches!(
            poisoned.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Available { .. }
        ));
        poisoned.shutdown(Duration::from_secs(2)).await.unwrap();

        let mismatch_dir = tempfile::tempdir().unwrap();
        let mismatch = spawn_authority_writer_for(mismatch_dir.path(), &validated).unwrap();
        let CandidateDecisionReservation::Flushed(handle) = mismatch
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-mismatch"),
                recovery_replacement_decision(&validated, "replacement-mismatch"),
            )
            .await
        else {
            panic!("candidate decision must flush")
        };
        let mut attempt = authority_dispatch_attempt();
        attempt.request_body_digest = [9; 32];
        assert!(handle.authorize_dispatch(attempt).await.is_err());
        assert!(matches!(
            mismatch
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-after-mismatch"),
                    recovery_replacement_decision(&validated, "replacement-after-mismatch"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        mismatch.shutdown(Duration::from_secs(2)).await.unwrap();

        let abandoned_dir = tempfile::tempdir().unwrap();
        let abandoned = spawn_authority_writer_for(abandoned_dir.path(), &validated).unwrap();
        let CandidateDecisionReservation::Flushed(handle) = abandoned
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-abandoned"),
                recovery_replacement_decision(&validated, "replacement-abandoned"),
            )
            .await
        else {
            panic!("candidate decision must flush")
        };
        drop(handle);
        assert!(matches!(
            abandoned
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-after-abandon"),
                    recovery_replacement_decision(&validated, "replacement-after-abandon"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        abandoned.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn unrelated_poison_while_candidate_is_pending_never_mints_recovery() {
        let validated = recovery_validated("bypass");
        let directory = tempfile::tempdir().unwrap();
        let (writer, release) =
            spawn_paused_authority_writer_for(directory.path(), &validated).unwrap();
        let reservation_writer = writer.clone();
        let reservation_validated = validated.clone();
        let reservation = tokio::spawn(async move {
            reservation_writer
                .reserve_candidate_decision_or_recovery(
                    &reservation_validated,
                    recovery_candidate_decision(&reservation_validated, "candidate-race"),
                    recovery_replacement_decision(&reservation_validated, "replacement-race"),
                )
                .await
        });

        for _ in 0..100 {
            if writer
                .inner
                .lifecycle
                .lock()
                .unwrap()
                .pending_recoveries
                .len()
                == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            writer
                .inner
                .lifecycle
                .lock()
                .unwrap()
                .pending_recoveries
                .len(),
            1
        );

        writer.mark_authority_error("unrelated concurrent poison", None);
        assert!(!matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Available { .. } | RecoveryLifecycle::Consumed { .. }
        ));
        assert!(writer
            .inner
            .lifecycle
            .lock()
            .unwrap()
            .pending_recoveries
            .is_empty());

        release.send(()).unwrap();
        assert!(matches!(
            reservation.await.unwrap(),
            CandidateDecisionReservation::Rejected(_)
        ));
        assert!(!matches!(
            writer.inner.lifecycle.lock().unwrap().recovery,
            RecoveryLifecycle::Available { .. }
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_candidate_terminal_never_mints_recovery() {
        let validated = recovery_validated("bypass");
        let directory = tempfile::tempdir().unwrap();
        let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();
        let CandidateDecisionReservation::Flushed(handle) = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate-cancelled"),
                recovery_replacement_decision(&validated, "replacement-cancelled"),
            )
            .await
        else {
            panic!("candidate decision must flush")
        };
        let authorized = handle
            .authorize_dispatch(authority_dispatch_attempt())
            .await
            .unwrap();
        assert!(writer
            .append_and_flush_outcome(
                authorized,
                recovery_cancelled_outcome(&validated, "candidate-cancelled"),
            )
            .await
            .is_err());
        assert!(matches!(
            writer
                .reserve_candidate_decision_or_recovery(
                    &validated,
                    recovery_candidate_decision(&validated, "candidate-after-cancel"),
                    recovery_replacement_decision(&validated, "replacement-after-cancel"),
                )
                .await,
            CandidateDecisionReservation::Rejected(_)
        ));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn closing_blocks_scoped_zero_authority_recovery() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            tempdir.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .expect("authority writer starts");
        let CandidateDecisionReservation::Recoverable { recovery, .. } = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate"),
                recovery_replacement_decision(&validated, "replacement"),
            )
            .await
        else {
            panic!("candidate must fail transiently")
        };
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            recovery.reserve_and_flush_replacement().await,
            Err(ManagedWriterError::Closed)
        ));
    }

    #[tokio::test]
    async fn scoped_recovery_supports_local_none_terminal_without_upstream_dispatch() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let validated = recovery_validated("fail-closed");
        let writer = spawn_faulting_authority_writer_for(
            tempdir.path(),
            2,
            &validated,
            AuthorityWriterFault::Transient(1),
        )
        .expect("authority writer starts");
        let CandidateDecisionReservation::Recoverable { recovery, .. } = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                recovery_candidate_decision(&validated, "candidate"),
                recovery_replacement_decision(&validated, "local"),
            )
            .await
        else {
            panic!("candidate must fail transiently")
        };
        let handle = recovery
            .reserve_and_flush_replacement()
            .await
            .expect("local zero-authority decision flushes");
        let terminal = handle
            .authorize_dispatch(zero_none_dispatch_attempt())
            .await
            .expect("exact no-target terminal capability is issued");
        writer
            .append_and_flush_outcome(terminal, zero_none_outcome(&validated, "local"))
            .await
            .expect("local zero-dispatch terminal appends");
        let snapshot = writer.manifest_snapshot();
        assert_eq!(
            (snapshot.accepted, snapshot.recorded, snapshot.dropped),
            (3, 2, 1)
        );
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err());
    }

    #[tokio::test]
    async fn terminal_flush_failure_marks_the_authority_run_incomplete() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let writer = spawn_terminal_faulting_authority_writer(tempdir.path(), 2)
            .expect("authority writer starts");
        let handle = writer
            .reserve_and_flush_decision(authority_decision("candidate"))
            .await
            .expect("candidate decision is durable");
        let error = writer
            .append_and_flush_outcome(
                handle
                    .authorize_dispatch(authority_dispatch_attempt())
                    .await
                    .unwrap(),
                authority_outcome("candidate"),
            )
            .await
            .expect_err("terminal flush failure is disclosed");
        assert!(matches!(error, ManagedWriterError::Writer(_)));
        assert!(!writer.manifest_snapshot().writer_healthy);
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(!writer.manifest_snapshot().clean_shutdown);
    }

    #[tokio::test]
    async fn terminal_admission_rejects_every_one_field_pair_contradiction_before_append() {
        let base = authority_outcome("candidate");
        let mut outcomes = Vec::new();
        macro_rules! tamper {
            ($field:ident, $value:expr) => {{
                let mut value = base.clone();
                value.$field = $value;
                outcomes.push(value);
            }};
        }
        tamper!(route_id, "other-route".into());
        tamper!(mode, bowline_core::enforcement::RouteMode::CanaryEnforce);
        tamper!(
            protocol,
            bowline_core::enforcement::AuthorityProtocol::Responses
        );
        tamper!(task_class, bowline_core::supply::TaskClass::Mechanical);
        tamper!(workload_identity_digest, Some(digest(20)));
        tamper!(app, Some("other-app".into()));
        tamper!(resolved_tags, vec!["other".into()]);
        tamper!(requested_supply_id, Some("other-requested".into()));
        tamper!(grant_digest, Some(digest(21)));
        tamper!(grant_expires_at_ms, Some(101));
        tamper!(model_rewritten, true);
        tamper!(selected_supply_id, Some("other-candidate".into()));
        tamper!(baseline_supply_id, Some("other-baseline".into()));
        tamper!(actuator_identity_digest, Some(digest(22)));
        tamper!(actuator_config_digest, Some(digest(23)));
        tamper!(enforcement_config_digest, digest(24));
        tamper!(route_config_digest, digest(25));
        tamper!(
            circuit_before,
            bowline_core::ledger::CircuitStateV2::HalfOpen
        );
        tamper!(circuit_after, bowline_core::ledger::CircuitStateV2::Open);
        tamper!(actual_dispatch, 0);
        tamper!(
            completion,
            bowline_core::ledger::CompletionStateV2::Cancelled
        );
        tamper!(
            candidate_failure,
            Some(bowline_core::ledger::CandidateFailureClassV2::Connect)
        );
        let mut selection = base.selection_facts.clone();
        selection.bucket = Some(2);
        tamper!(selection_facts, selection);

        for (index, outcome) in outcomes.into_iter().enumerate() {
            let tempdir = tempfile::tempdir().unwrap();
            let writer =
                spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
            let handle = writer
                .reserve_and_flush_decision(authority_decision("candidate"))
                .await
                .unwrap();
            let result = writer
                .append_and_flush_outcome(
                    handle
                        .authorize_dispatch(authority_dispatch_attempt())
                        .await
                        .unwrap(),
                    outcome,
                )
                .await;
            assert!(result.is_err(), "tamper {index} yielded completed evidence");
            assert!(!writer.manifest_snapshot().writer_healthy);
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_terminal_is_durable_but_incomplete_while_failed_is_complete_evidence() {
        let cancelled_dir = tempfile::tempdir().unwrap();
        let cancelled_writer =
            spawn_managed_authority_writer(authority_test_options(cancelled_dir.path(), 2))
                .unwrap();
        let handle = cancelled_writer
            .reserve_and_flush_decision(authority_decision("cancelled"))
            .await
            .unwrap();
        let mut cancelled = authority_outcome("cancelled");
        cancelled.completion = CompletionStateV2::Cancelled;
        cancelled.input_tokens = None;
        cancelled.output_tokens = None;
        cancelled.usage_source = UsageSource::Missing;
        cancelled.observed_actual_cost_micros = None;
        cancelled.approved_counterfactual_cost_micros = None;
        cancelled.enforced_modeled_delta_micros = None;
        let result = cancelled_writer
            .append_and_flush_outcome(
                handle
                    .authorize_dispatch(authority_dispatch_attempt())
                    .await
                    .unwrap(),
                cancelled,
            )
            .await;
        assert!(result.is_err());
        cancelled_writer
            .shutdown(Duration::from_secs(2))
            .await
            .unwrap();
        let cancelled_manifest = cancelled_writer.manifest_snapshot();
        assert_eq!(cancelled_manifest.recorded, 2);
        assert!(!cancelled_manifest.writer_healthy);
        assert!(!cancelled_manifest.clean_shutdown);
        assert!(
            AuthorityLedgerV2::read_validated_authority_run(cancelled_writer.manifest_path())
                .is_err()
        );

        let failed_dir = tempfile::tempdir().unwrap();
        let failed_writer =
            spawn_managed_authority_writer(authority_test_options(failed_dir.path(), 2)).unwrap();
        let handle = failed_writer
            .reserve_and_flush_decision(authority_decision("failed"))
            .await
            .unwrap();
        let mut failed = authority_outcome("failed");
        failed.completion = CompletionStateV2::Failed;
        failed.candidate_failure = Some(bowline_core::ledger::CandidateFailureClassV2::Connect);
        failed.status = None;
        failed.input_tokens = None;
        failed.output_tokens = None;
        failed.usage_source = UsageSource::Missing;
        failed.observed_actual_cost_micros = None;
        failed.approved_counterfactual_cost_micros = None;
        failed.enforced_modeled_delta_micros = None;
        failed.circuit_after = bowline_core::ledger::CircuitStateV2::Open;
        let completed = failed_writer
            .append_and_flush_outcome(
                handle
                    .authorize_dispatch(authority_dispatch_attempt())
                    .await
                    .unwrap(),
                failed,
            )
            .await
            .unwrap();
        failed_writer
            .shutdown(Duration::from_secs(2))
            .await
            .unwrap();
        let failed_manifest = failed_writer.manifest_snapshot();
        assert!(failed_manifest.writer_healthy);
        assert!(failed_manifest.clean_shutdown);
        let verified =
            AuthorityLedgerV2::read_validated_authority_run(failed_writer.manifest_path()).unwrap();
        assert!(
            enforced_modeled_delta_from_verified(verified.complete(), &completed)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn dispatch_authorization_rereads_kill_and_rechecks_freshness() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::{AtomicU64, Ordering};

        fn reader(root: &std::path::Path, state: &[u8]) -> BoundedKillStateReader {
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("kill");
            std::fs::write(&path, state).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let root = std::fs::canonicalize(root).unwrap();
            BoundedKillStateReader::new(KillStateReader::open(&root, "kill").unwrap(), 1)
        }

        for case in ["expired", "bypass", "malformed", "queue"] {
            let tempdir = tempfile::tempdir().unwrap();
            let kill_dir = tempfile::tempdir().unwrap();
            let kill_reader = reader(kill_dir.path(), b"armed\n");
            let now = Arc::new(AtomicU64::new(50));
            let prepared = test_prepared_authority_decision_v2_with_revalidation(
                raw_authority_decision(case),
                kill_reader.clone(),
                0,
                100,
                Arc::clone(&now),
            );
            let writer =
                spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
            let handle = writer.reserve_and_flush_decision(prepared).await.unwrap();
            match case {
                "expired" => now.store(101, Ordering::Release),
                "bypass" => std::fs::write(kill_dir.path().join("kill"), b"bypass\n").unwrap(),
                "malformed" => std::fs::write(kill_dir.path().join("kill"), b"invalid\n").unwrap(),
                "queue" => kill_reader.shutdown(),
                _ => unreachable!(),
            }
            let error = handle
                .authorize_dispatch(authority_dispatch_attempt())
                .await
                .unwrap_err();
            assert!(matches!(error, ManagedWriterError::InvalidRecordContext));
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
            assert!(!writer.manifest_snapshot().writer_healthy);
            assert!(!writer.manifest_snapshot().clean_shutdown);
            assert!(
                AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).is_err()
            );
        }

        let tempdir = tempfile::tempdir().unwrap();
        let kill_dir = tempfile::tempdir().unwrap();
        let kill_reader = reader(kill_dir.path(), b"armed\n");
        let now = Arc::new(AtomicU64::new(50));
        let prepared = test_prepared_authority_decision_v2_with_revalidation(
            raw_authority_decision("fresh"),
            kill_reader,
            0,
            100,
            now,
        );
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
        let handle = writer.reserve_and_flush_decision(prepared).await.unwrap();
        let authorized = handle
            .authorize_dispatch(authority_dispatch_attempt())
            .await
            .unwrap();
        writer
            .append_and_flush_outcome(authorized, authority_outcome("fresh"))
            .await
            .unwrap();
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(writer.manifest_snapshot().writer_healthy);
        assert!(writer.manifest_snapshot().clean_shutdown);
    }

    #[tokio::test]
    async fn final_revalidation_persists_rejection_before_exact_fallback() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::{AtomicU64, Ordering};

        fn reader(root: &std::path::Path) -> BoundedKillStateReader {
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("kill");
            std::fs::write(&path, b"armed\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let root = std::fs::canonicalize(root).unwrap();
            BoundedKillStateReader::new(KillStateReader::open(&root, "kill").unwrap(), 2)
        }

        let cases = [
            ("bypass", "kill-bypass"),
            ("bypass", "malformed"),
            ("bypass", "expired"),
            ("bypass", "clock-rollback"),
            ("bypass", "unreadable"),
            ("bypass", "reader-shutdown"),
            ("fail-closed", "kill-bypass"),
            ("fail-closed", "malformed"),
            ("fail-closed", "expired"),
            ("fail-closed", "clock-rollback"),
            ("fail-closed", "unreadable"),
            ("fail-closed", "reader-shutdown"),
        ];
        assert_eq!(
            cases.len(),
            12,
            "six authority-loss modes must run under both configured fallbacks"
        );
        for (fallback, case) in cases {
            let directory = tempfile::tempdir().unwrap();
            let kill_directory = tempfile::tempdir().unwrap();
            let kill_reader = reader(kill_directory.path());
            let now = Arc::new(AtomicU64::new(50));
            let validated = recovery_validated(fallback);
            let candidate = recovery_candidate_decision_with_revalidation(
                &validated,
                &format!("candidate-{case}"),
                kill_reader.clone(),
                25,
                100,
                Arc::clone(&now),
            );
            let replacement =
                recovery_replacement_decision(&validated, &format!("replacement-{case}"));
            let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();
            let CandidateDecisionReservation::Flushed(reservation) = writer
                .reserve_candidate_decision_or_recovery(&validated, candidate, replacement)
                .await
            else {
                panic!("candidate decision must flush")
            };

            match case {
                "kill-bypass" => {
                    std::fs::write(kill_directory.path().join("kill"), b"bypass\n").unwrap()
                }
                "malformed" => {
                    std::fs::write(kill_directory.path().join("kill"), b"invalid\n").unwrap()
                }
                "expired" => now.store(101, Ordering::Release),
                "clock-rollback" => now.store(24, Ordering::Release),
                "unreadable" => std::fs::remove_file(kill_directory.path().join("kill")).unwrap(),
                "reader-shutdown" => kill_reader.shutdown(),
                _ => unreachable!(),
            }

            let FinalDispatchAuthorization::Fallback(recovery) = reservation
                .authorize_final_dispatch(authority_dispatch_attempt())
                .await
            else {
                panic!("ordinary authority loss must return exact fallback")
            };
            let replacement = recovery
                .reserve_and_flush_replacement()
                .await
                .expect("linked replacement decision flushes");
            if fallback == "bypass" {
                complete_zero_authority_handle(
                    &writer,
                    &validated,
                    replacement,
                    &format!("replacement-{case}"),
                )
                .await;
            } else {
                let replaces_decision_id = replacement.decision().replaces_decision_id.clone();
                let authorized = replacement
                    .authorize_dispatch(zero_none_dispatch_attempt())
                    .await
                    .unwrap();
                let mut outcome = zero_none_outcome(&validated, &format!("replacement-{case}"));
                outcome.replaces_decision_id = replaces_decision_id;
                writer
                    .append_and_flush_outcome(authorized, outcome)
                    .await
                    .unwrap();
            }
            writer.shutdown(Duration::from_secs(2)).await.unwrap();
            let validated_run =
                AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path())
                    .expect("fully persisted rejection and fallback remains complete");
            assert_eq!(validated_run.records().len(), 4);
        }
    }

    #[tokio::test]
    async fn final_revalidation_floors_rejection_time_at_the_candidate_decision() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::AtomicU64;

        let directory = tempfile::tempdir().unwrap();
        let kill_directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            kill_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let kill_path = kill_directory.path().join("kill");
        std::fs::write(&kill_path, b"armed\n").unwrap();
        std::fs::set_permissions(&kill_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let kill_reader = BoundedKillStateReader::new(
            KillStateReader::open(
                &std::fs::canonicalize(kill_directory.path()).unwrap(),
                "kill",
            )
            .unwrap(),
            1,
        );
        let validated = recovery_validated("bypass");
        let now = Arc::new(AtomicU64::new(50));
        let mut candidate_decision = raw_authority_decision("candidate-future");
        candidate_decision.ts_ms = u64::MAX;
        candidate_decision.grant.as_mut().unwrap().expires_at_ms = u64::MAX;
        candidate_decision.enforcement_config_digest = validated.normalized_digest().into();
        candidate_decision.route_config_digest = validated.route_digest("route").unwrap();
        candidate_decision.actuator_config_digest =
            Some(validated.actuator_digest("candidate").unwrap());
        let candidate = test_prepared_authority_decision_v2_with_revalidation(
            candidate_decision,
            kill_reader,
            0,
            100,
            now,
        );
        let mut replacement = raw_authority_decision("replacement-future");
        replacement.ts_ms = u64::MAX;
        replacement.reason = bowline_core::enforcement::SelectionReason::CandidateUnavailable;
        replacement.evidence_state = bowline_core::enforcement::EvidenceState::Unverified;
        replacement.target = bowline_core::enforcement::PlanTarget::Original;
        replacement.intended_dispatch = 1;
        let mut facts = bowline_core::ledger::AuthoritySelectionFactsV2::canonical_fallback(
            bowline_core::ledger::AuthorityFallbackReasonV2::CandidateUnavailable,
        );
        facts.bucket = Some(1);
        replacement.selection_facts = facts;
        replacement.grant = None;
        replacement.selected_supply_id = replacement.baseline_supply_id.clone();
        replacement.actuator_identity_digest = None;
        replacement.actuator_config_digest = None;
        replacement.enforcement_config_digest = validated.normalized_digest().into();
        replacement.route_config_digest = validated.route_digest("route").unwrap();
        let replacement_decision = test_prepared_authority_decision_v2(replacement);
        let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();
        let CandidateDecisionReservation::Flushed(reservation) = writer
            .reserve_candidate_decision_or_recovery(&validated, candidate, replacement_decision)
            .await
        else {
            panic!("candidate decision must flush")
        };
        std::fs::write(kill_path, b"bypass\n").unwrap();

        let FinalDispatchAuthorization::Fallback(recovery) = reservation
            .authorize_final_dispatch(authority_dispatch_attempt())
            .await
        else {
            panic!("clock rollback cannot turn durable ordinary fallback into a fatal error")
        };
        let replacement = recovery.reserve_and_flush_replacement().await.unwrap();
        let replaces_decision_id = replacement.decision().replaces_decision_id.clone();
        let authorized = replacement
            .authorize_dispatch(zero_authority_dispatch_attempt())
            .await
            .unwrap();
        let mut outcome = zero_authority_outcome(&validated, "replacement-future");
        outcome.ts_ms = u64::MAX;
        outcome.replaces_decision_id = replaces_decision_id;
        writer
            .append_and_flush_outcome(authorized, outcome)
            .await
            .unwrap();
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let run = AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
        let AuthorityRecordV2::Outcome {
            outcome: rejection, ..
        } = &run.records()[1]
        else {
            panic!("second record must be the candidate rejection")
        };
        assert_eq!(rejection.ts_ms, u64::MAX);
    }

    #[tokio::test]
    async fn final_revalidation_shutdown_after_rejection_flush_does_not_expose_fallback() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::AtomicU64;

        let directory = tempfile::tempdir().unwrap();
        let kill_directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            kill_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let kill_path = kill_directory.path().join("kill");
        std::fs::write(&kill_path, b"armed\n").unwrap();
        std::fs::set_permissions(&kill_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let kill_reader = BoundedKillStateReader::new(
            KillStateReader::open(
                &std::fs::canonicalize(kill_directory.path()).unwrap(),
                "kill",
            )
            .unwrap(),
            1,
        );
        let validated = recovery_validated("bypass");
        let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();
        let candidate = recovery_candidate_decision_with_revalidation(
            &validated,
            "candidate-shutdown-race",
            kill_reader,
            0,
            100,
            Arc::new(AtomicU64::new(50)),
        );
        let replacement = recovery_replacement_decision(&validated, "replacement-shutdown-race");
        let CandidateDecisionReservation::Flushed(reservation) = writer
            .reserve_candidate_decision_or_recovery(&validated, candidate, replacement)
            .await
        else {
            panic!("candidate decision must flush")
        };
        let lifecycle = Arc::clone(&writer.inner.lifecycle);
        writer.install_post_rejection_flush_hook(move || {
            let mut lifecycle = lifecycle.lock().unwrap();
            lifecycle.closing = true;
            lifecycle.authority_complete = false;
        });
        std::fs::write(kill_path, b"bypass\n").unwrap();

        assert!(matches!(
            reservation
                .authorize_final_dispatch(authority_dispatch_attempt())
                .await,
            FinalDispatchAuthorization::Fatal(ManagedWriterError::Closed)
        ));
        let lifecycle = writer.inner.lifecycle.lock().unwrap();
        assert_eq!(lifecycle.outstanding, 0);
        assert_eq!(lifecycle.issued_decisions, 0);
        assert_eq!(lifecycle.authorized_dispatches, 0);
    }

    #[tokio::test]
    async fn final_revalidation_persistence_failure_is_fatal_and_mints_no_fallback() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::AtomicU64;

        let directory = tempfile::tempdir().unwrap();
        let kill_directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            kill_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let kill_path = kill_directory.path().join("kill");
        std::fs::write(&kill_path, b"armed\n").unwrap();
        std::fs::set_permissions(&kill_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let kill_root = std::fs::canonicalize(kill_directory.path()).unwrap();
        let kill_reader =
            BoundedKillStateReader::new(KillStateReader::open(&kill_root, "kill").unwrap(), 1);
        let validated = recovery_validated("bypass");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Persistent(2),
        )
        .unwrap();
        let candidate = recovery_candidate_decision_with_revalidation(
            &validated,
            "candidate-fatal",
            kill_reader,
            0,
            100,
            Arc::new(AtomicU64::new(50)),
        );
        let replacement = recovery_replacement_decision(&validated, "replacement-fatal");
        let CandidateDecisionReservation::Flushed(reservation) = writer
            .reserve_candidate_decision_or_recovery(&validated, candidate, replacement)
            .await
        else {
            panic!("candidate decision must flush")
        };
        std::fs::write(kill_path, b"bypass\n").unwrap();
        assert!(matches!(
            reservation
                .authorize_final_dispatch(authority_dispatch_attempt())
                .await,
            FinalDispatchAuthorization::Fatal(ManagedWriterError::Writer(_))
        ));
        let lifecycle = writer.inner.lifecycle.lock().unwrap();
        assert!(!lifecycle.authority_complete);
        assert!(!lifecycle.transport_available);
        assert_eq!(lifecycle.authorized_dispatches, 0);
    }

    #[tokio::test]
    async fn final_revalidation_closing_transport_and_replacement_failure_disable_dispatch() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::AtomicU64;

        fn prepared(
            validated: &bowline_core::enforcement::ValidatedEnforcement,
            id: &str,
        ) -> (
            tempfile::TempDir,
            PreparedAuthorityDecisionV2,
            PreparedAuthorityDecisionV2,
        ) {
            let kill = tempfile::tempdir().unwrap();
            std::fs::set_permissions(kill.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = kill.path().join("kill");
            std::fs::write(&path, b"armed\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let reader = BoundedKillStateReader::new(
                KillStateReader::open(&std::fs::canonicalize(kill.path()).unwrap(), "kill")
                    .unwrap(),
                1,
            );
            (
                kill,
                recovery_candidate_decision_with_revalidation(
                    validated,
                    &format!("candidate-{id}"),
                    reader,
                    0,
                    100,
                    Arc::new(AtomicU64::new(50)),
                ),
                recovery_replacement_decision(validated, &format!("replacement-{id}")),
            )
        }

        for fatal in ["closing", "transport"] {
            let directory = tempfile::tempdir().unwrap();
            let validated = recovery_validated("bypass");
            let (_kill, candidate, replacement) = prepared(&validated, fatal);
            let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();
            let CandidateDecisionReservation::Flushed(reservation) = writer
                .reserve_candidate_decision_or_recovery(&validated, candidate, replacement)
                .await
            else {
                panic!("candidate flushes")
            };
            {
                let mut lifecycle = writer.inner.lifecycle.lock().unwrap();
                if fatal == "closing" {
                    lifecycle.closing = true;
                } else {
                    lifecycle.transport_available = false;
                }
            }
            assert!(matches!(
                reservation
                    .authorize_final_dispatch(authority_dispatch_attempt())
                    .await,
                FinalDispatchAuthorization::Fatal(_)
            ));
            let lifecycle = writer.inner.lifecycle.lock().unwrap();
            assert_eq!(lifecycle.authorized_dispatches, 0);
        }

        let directory = tempfile::tempdir().unwrap();
        let validated = recovery_validated("bypass");
        let (kill, candidate, replacement) = prepared(&validated, "replacement-fault");
        let writer = spawn_faulting_authority_writer_for(
            directory.path(),
            2,
            &validated,
            AuthorityWriterFault::Persistent(3),
        )
        .unwrap();
        let CandidateDecisionReservation::Flushed(reservation) = writer
            .reserve_candidate_decision_or_recovery(&validated, candidate, replacement)
            .await
        else {
            panic!("candidate flushes")
        };
        std::fs::write(kill.path().join("kill"), b"bypass\n").unwrap();
        let FinalDispatchAuthorization::Fallback(recovery) = reservation
            .authorize_final_dispatch(authority_dispatch_attempt())
            .await
        else {
            panic!("ordinary loss exposes fallback only after rejection persistence")
        };
        assert!(matches!(
            recovery.reserve_and_flush_replacement().await,
            Err(ManagedWriterError::Writer(_))
        ));
        let lifecycle = writer.inner.lifecycle.lock().unwrap();
        assert!(!lifecycle.transport_available);
        assert_eq!(lifecycle.authorized_dispatches, 0);
        assert_eq!(lifecycle.outstanding, 0);
    }

    #[tokio::test]
    async fn final_revalidation_fatal_matrix_covers_both_configured_fallbacks() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::AtomicU64;

        for fallback in ["bypass", "fail-closed"] {
            for fatal in [
                "closing",
                "transport",
                "rejection-persistence",
                "replacement-persistence",
                "post-rejection-race",
            ] {
                let directory = tempfile::tempdir().unwrap();
                let kill = tempfile::tempdir().unwrap();
                std::fs::set_permissions(kill.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                let kill_path = kill.path().join("kill");
                std::fs::write(&kill_path, b"armed\n").unwrap();
                std::fs::set_permissions(&kill_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                let kill_reader = BoundedKillStateReader::new(
                    KillStateReader::open(&std::fs::canonicalize(kill.path()).unwrap(), "kill")
                        .unwrap(),
                    1,
                );
                let validated = recovery_validated(fallback);
                let id = format!("{fallback}-{fatal}");
                let candidate = recovery_candidate_decision_with_revalidation(
                    &validated,
                    &format!("candidate-{id}"),
                    kill_reader,
                    0,
                    100,
                    Arc::new(AtomicU64::new(50)),
                );
                let replacement =
                    recovery_replacement_decision(&validated, &format!("replacement-{id}"));
                let writer = match fatal {
                    "rejection-persistence" => spawn_faulting_authority_writer_for(
                        directory.path(),
                        2,
                        &validated,
                        AuthorityWriterFault::Persistent(2),
                    )
                    .unwrap(),
                    "replacement-persistence" => spawn_faulting_authority_writer_for(
                        directory.path(),
                        2,
                        &validated,
                        AuthorityWriterFault::Persistent(3),
                    )
                    .unwrap(),
                    _ => spawn_authority_writer_for(directory.path(), &validated).unwrap(),
                };
                let CandidateDecisionReservation::Flushed(reservation) = writer
                    .reserve_candidate_decision_or_recovery(&validated, candidate, replacement)
                    .await
                else {
                    panic!("{id} candidate decision must flush")
                };
                match fatal {
                    "closing" | "transport" => {
                        let mut lifecycle = writer.inner.lifecycle.lock().unwrap();
                        if fatal == "closing" {
                            lifecycle.closing = true;
                        } else {
                            lifecycle.transport_available = false;
                        }
                    }
                    "post-rejection-race" => writer.install_post_rejection_closing_hook(),
                    "rejection-persistence" | "replacement-persistence" => {}
                    _ => unreachable!(),
                }
                if !matches!(fatal, "closing" | "transport") {
                    std::fs::write(&kill_path, b"bypass\n").unwrap();
                }
                if fatal == "replacement-persistence" {
                    let FinalDispatchAuthorization::Fallback(recovery) = reservation
                        .authorize_final_dispatch(authority_dispatch_attempt())
                        .await
                    else {
                        panic!("{id} must expose replacement only after rejection persistence")
                    };
                    assert!(matches!(
                        recovery.reserve_and_flush_replacement().await,
                        Err(ManagedWriterError::Writer(_))
                    ));
                } else {
                    assert!(matches!(
                        reservation
                            .authorize_final_dispatch(authority_dispatch_attempt())
                            .await,
                        FinalDispatchAuthorization::Fatal(_)
                    ));
                }
                let lifecycle = writer.inner.lifecycle.lock().unwrap();
                assert_eq!(lifecycle.authorized_dispatches, 0, "{id}");
                assert_eq!(lifecycle.issued_decisions, 0, "{id}");
            }
        }
    }

    #[tokio::test]
    async fn final_revalidation_overlapping_reservations_keep_exact_replacement_generation() {
        use crate::enforcement_loader::{BoundedKillStateReader, KillStateReader};
        use std::sync::atomic::AtomicU64;

        fn reader(root: &std::path::Path) -> BoundedKillStateReader {
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.join("kill");
            std::fs::write(&path, b"armed\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            BoundedKillStateReader::new(
                KillStateReader::open(&std::fs::canonicalize(root).unwrap(), "kill").unwrap(),
                2,
            )
        }

        let directory = tempfile::tempdir().unwrap();
        let first_kill = tempfile::tempdir().unwrap();
        let second_kill = tempfile::tempdir().unwrap();
        let first_reader = reader(first_kill.path());
        let second_reader = reader(second_kill.path());
        let validated = recovery_validated("bypass");
        let writer = spawn_authority_writer_for(directory.path(), &validated).unwrap();
        let now = Arc::new(AtomicU64::new(50));
        let reserve =
            |candidate_id: &str, replacement_id: &str, kill_reader: BoundedKillStateReader| {
                (
                    recovery_candidate_decision_with_revalidation(
                        &validated,
                        candidate_id,
                        kill_reader,
                        0,
                        100,
                        Arc::clone(&now),
                    ),
                    recovery_replacement_decision(&validated, replacement_id),
                )
            };
        let (first_candidate, first_replacement) =
            reserve("candidate-first", "replacement-first", first_reader);
        let (second_candidate, second_replacement) =
            reserve("candidate-second", "replacement-second", second_reader);
        let CandidateDecisionReservation::Flushed(first) = writer
            .reserve_candidate_decision_or_recovery(&validated, first_candidate, first_replacement)
            .await
        else {
            panic!("first candidate flushes")
        };
        let CandidateDecisionReservation::Flushed(second) = writer
            .reserve_candidate_decision_or_recovery(
                &validated,
                second_candidate,
                second_replacement,
            )
            .await
        else {
            panic!("second candidate flushes")
        };
        std::fs::write(first_kill.path().join("kill"), b"bypass\n").unwrap();
        let FinalDispatchAuthorization::Fallback(recovery) = first
            .authorize_final_dispatch(authority_dispatch_attempt())
            .await
        else {
            panic!("first candidate must fall back")
        };
        let replacement = recovery.reserve_and_flush_replacement().await.unwrap();
        assert_eq!(
            replacement.decision().replaces_decision_id.as_deref(),
            Some("candidate-first")
        );
        complete_zero_authority_handle(&writer, &validated, replacement, "replacement-first").await;
        let FinalDispatchAuthorization::Authorized(second) = second
            .authorize_final_dispatch(authority_dispatch_attempt())
            .await
        else {
            panic!("second candidate remains authorized")
        };
        let mut outcome = authority_outcome("candidate-second");
        outcome.enforcement_config_digest = validated.normalized_digest().into();
        outcome.route_config_digest = validated.route_digest("route").unwrap();
        outcome.actuator_config_digest = Some(validated.actuator_digest("candidate").unwrap());
        writer
            .append_and_flush_outcome(second, outcome)
            .await
            .unwrap();
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        let run = AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path()).unwrap();
        assert_eq!(run.records().len(), 6);
    }

    #[tokio::test]
    async fn candidate_decision_must_belong_to_manifest_actuator_and_grant_sets() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let mut options = authority_test_options(tempdir.path(), 2);
        options.actuator_digests = vec![format!("sha256:{:064x}", 99)];
        options.grant_digests = vec![format!("sha256:{:064x}", 100)];
        let writer = spawn_managed_authority_writer(options).unwrap();
        let error = writer
            .reserve_and_flush_decision(authority_decision("candidate"))
            .await
            .expect_err("candidate facts outside manifest sets cannot issue a handle");
        assert!(matches!(error, ManagedWriterError::InvalidRecordContext));
        assert_eq!(writer.manifest_snapshot().accepted, 0);
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn exact_dispatch_authorization_rejects_embeddings_candidate() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
        let mut handle = writer
            .reserve_and_flush_decision(authority_decision("embeddings-candidate"))
            .await
            .unwrap();
        let payload = handle.payload.as_mut().unwrap();
        payload.decision.protocol = bowline_core::enforcement::AuthorityProtocol::Embeddings;
        payload.dispatch_binding.protocol =
            bowline_core::enforcement::AuthorityProtocol::Embeddings;
        let mut attempt = authority_dispatch_attempt();
        attempt.protocol = bowline_core::enforcement::AuthorityProtocol::Embeddings;

        let error = handle
            .authorize_dispatch(attempt)
            .await
            .expect_err("Embeddings candidate must fail closed at exact dispatch authorization");
        assert!(matches!(error, ManagedWriterError::InvalidRecordContext));
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
    }

    #[tokio::test]
    async fn opaque_authorized_handle_builds_and_flushes_exact_terminal() {
        let tempdir = tempfile::tempdir().unwrap();
        let writer =
            spawn_managed_authority_writer(authority_test_options(tempdir.path(), 2)).unwrap();
        let handle = writer
            .reserve_and_flush_decision(authority_decision("terminal-builder"))
            .await
            .unwrap();
        let authorized = handle
            .authorize_dispatch(authority_dispatch_attempt())
            .await
            .unwrap();
        let outcome = authorized
            .build_outcome(AuthorityTerminalV2 {
                ts_ms: 20,
                circuit_after: CircuitStateV2::Closed,
                completion: CompletionStateV2::Succeeded,
                candidate_failure: None,
                status: Some(200),
                input_tokens: None,
                output_tokens: None,
                usage_source: UsageSource::Missing,
            })
            .unwrap();
        writer
            .append_and_flush_outcome(authorized, outcome)
            .await
            .unwrap();
        writer.shutdown(Duration::from_secs(2)).await.unwrap();
        assert!(writer.manifest_snapshot().clean_shutdown);
    }

    #[test]
    fn authority_manifest_digest_sets_reject_duplicates() {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let mut options = authority_test_options(tempdir.path(), 2);
        options
            .actuator_digests
            .push(options.actuator_digests[0].clone());
        assert!(spawn_managed_authority_writer(options).is_err());
    }

    fn authority_decision(id: &str) -> PreparedAuthorityDecisionV2 {
        test_prepared_authority_decision_v2(raw_authority_decision(id))
    }

    fn recovery_validated(fallback: &str) -> bowline_core::enforcement::ValidatedEnforcement {
        let yaml = format!(
            r#"
version: 1
global_candidate_in_flight: 2
kill_switch: {{trust_root: /var/lib/bowline/kill, relative_path: state}}
actuators:
  - supply_id: candidate
    base_url: https://inference.example.test/v1
    authorization_env: BOWLINE_ACTUATOR_TOKEN
    health_path: /models
    remote_acknowledged: true
    connect_timeout_ms: 100
    response_header_timeout_ms: 100
    stream_idle_timeout_ms: 100
    concurrency: 2
    probe_timeout_ms: 100
    probe_max_bytes: 1024
    breaker_consecutive_failures: 2
    breaker_cooldown_ms: 100
routes:
  - route_id: route
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    workload: {{app: support, resolved_tags: [production]}}
    mode: canary-enforce
    rollout_ppm: 1
    promoted_supply_id: candidate
    actual_supply_id: baseline
    task_class: heavy-lifting
    model_authority: rewrite-to-canonical
    fallback: {fallback}
    promotion:
      economics_bundle_path: evidence/economics
      economics_report_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      opportunity_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      quality_run_path: evidence/quality/run-1
      authorization_path: evidence/authorization/route.json
      quality_run_id: quality-1
      quality_report_digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      policy_digest: sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
      registry_digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
      owned_cost_digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      max_economics_age_ms: 1000
      expires_at_ms: 2000000000000
"#
        );
        bowline_core::enforcement::EnforcementConfigV1::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap()
    }

    fn recovery_writer_options(
        directory: &std::path::Path,
        validated: &bowline_core::enforcement::ValidatedEnforcement,
    ) -> AuthorityWriterOptions {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        AuthorityWriterOptions {
            directory: directory.to_path_buf(),
            enforcement_digest: validated.normalized_digest().into(),
            actuator_digests: vec![validated.actuator_digest("candidate").unwrap()],
            grant_digests: vec![digest(2)],
            queue_capacity: 2,
            max_records_bytes: 1024 * 1024,
        }
    }

    fn spawn_faulting_authority_writer_for(
        directory: &std::path::Path,
        queue_capacity: usize,
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        fault: AuthorityWriterFault,
    ) -> anyhow::Result<ManagedAuthorityWriter> {
        let mut options = recovery_writer_options(directory, validated);
        options.queue_capacity = queue_capacity;
        spawn_managed_authority_writer_inner(options, None, Some(fault))
    }

    fn spawn_authority_writer_for(
        directory: &std::path::Path,
        validated: &bowline_core::enforcement::ValidatedEnforcement,
    ) -> anyhow::Result<ManagedAuthorityWriter> {
        spawn_managed_authority_writer_inner(
            recovery_writer_options(directory, validated),
            None,
            None,
        )
    }

    fn spawn_paused_authority_writer_for(
        directory: &std::path::Path,
        validated: &bowline_core::enforcement::ValidatedEnforcement,
    ) -> anyhow::Result<(ManagedAuthorityWriter, std::sync::mpsc::Sender<()>)> {
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let writer = spawn_managed_authority_writer_inner(
            recovery_writer_options(directory, validated),
            Some(release_rx),
            None,
        )?;
        Ok((writer, release_tx))
    }

    fn recovery_candidate_decision(
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        id: &str,
    ) -> PreparedAuthorityDecisionV2 {
        let mut decision = raw_authority_decision(id);
        decision.enforcement_config_digest = validated.normalized_digest().into();
        decision.route_config_digest = validated.route_digest("route").unwrap();
        decision.actuator_config_digest = Some(validated.actuator_digest("candidate").unwrap());
        test_prepared_authority_decision_v2(decision)
    }

    fn recovery_candidate_decision_with_revalidation(
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        id: &str,
        kill_reader: crate::enforcement_loader::BoundedKillStateReader,
        not_before_ms: u64,
        expires_at_ms: u64,
        now_override: Arc<std::sync::atomic::AtomicU64>,
    ) -> PreparedAuthorityDecisionV2 {
        let mut decision = raw_authority_decision(id);
        decision.enforcement_config_digest = validated.normalized_digest().into();
        decision.route_config_digest = validated.route_digest("route").unwrap();
        decision.actuator_config_digest = Some(validated.actuator_digest("candidate").unwrap());
        test_prepared_authority_decision_v2_with_revalidation(
            decision,
            kill_reader,
            not_before_ms,
            expires_at_ms,
            now_override,
        )
    }

    fn recovery_replacement_decision(
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        id: &str,
    ) -> PreparedAuthorityDecisionV2 {
        let mut decision = raw_authority_decision(id);
        decision.reason = bowline_core::enforcement::SelectionReason::CandidateUnavailable;
        decision.evidence_state = bowline_core::enforcement::EvidenceState::Unverified;
        decision.target = match validated.route("route").unwrap().fallback.unwrap() {
            bowline_core::enforcement::FallbackMode::Bypass => {
                bowline_core::enforcement::PlanTarget::Original
            }
            bowline_core::enforcement::FallbackMode::FailClosed => {
                bowline_core::enforcement::PlanTarget::None
            }
        };
        decision.intended_dispatch =
            u8::from(decision.target == bowline_core::enforcement::PlanTarget::Original);
        let mut facts = bowline_core::ledger::AuthoritySelectionFactsV2::canonical_fallback(
            bowline_core::ledger::AuthorityFallbackReasonV2::CandidateUnavailable,
        );
        facts.bucket = Some(1);
        decision.selection_facts = facts;
        decision.grant = None;
        decision.selected_supply_id = (decision.target
            == bowline_core::enforcement::PlanTarget::Original)
            .then(|| "baseline".into());
        decision.actuator_identity_digest = None;
        decision.actuator_config_digest = None;
        decision.enforcement_config_digest = validated.normalized_digest().into();
        decision.route_config_digest = validated.route_digest("route").unwrap();
        test_prepared_authority_decision_v2(decision)
    }

    async fn complete_candidate_handle(
        writer: &ManagedAuthorityWriter,
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        handle: Box<CandidateDispatchReservation>,
        id: &str,
    ) {
        let authorized = handle
            .authorize_dispatch(authority_dispatch_attempt())
            .await
            .expect("candidate handle authorizes its exact dispatch");
        let mut outcome = authority_outcome(id);
        outcome.enforcement_config_digest = validated.normalized_digest().into();
        outcome.route_config_digest = validated.route_digest("route").unwrap();
        outcome.actuator_config_digest = Some(validated.actuator_digest("candidate").unwrap());
        writer
            .append_and_flush_outcome(authorized, outcome)
            .await
            .expect("candidate terminal flushes");
    }

    async fn complete_zero_authority_handle(
        writer: &ManagedAuthorityWriter,
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        handle: DecisionHandle,
        id: &str,
    ) {
        let replaces_decision_id = handle.decision().replaces_decision_id.clone();
        let authorized = handle
            .authorize_dispatch(zero_authority_dispatch_attempt())
            .await
            .expect("replacement handle authorizes its exact original dispatch");
        let mut outcome = zero_authority_outcome(validated, id);
        outcome.replaces_decision_id = replaces_decision_id;
        writer
            .append_and_flush_outcome(authorized, outcome)
            .await
            .expect("replacement terminal flushes");
    }

    fn raw_authority_decision(id: &str) -> AuthorityDecisionV2 {
        let digest = |value: u8| format!("sha256:{value:064x}");
        AuthorityDecisionV2 {
            decision_id: id.into(),
            replaces_decision_id: None,
            configured_fallback_target: None,
            ts_ms: 10,
            route_id: "route".into(),
            mode: bowline_core::enforcement::RouteMode::Enforce,
            protocol: bowline_core::enforcement::AuthorityProtocol::ChatCompletions,
            task_class: bowline_core::supply::TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(1)),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            requested_supply_id: None,
            reason: bowline_core::enforcement::SelectionReason::CandidateSelected,
            evidence_state: bowline_core::enforcement::EvidenceState::Presented,
            selection_facts: bowline_core::ledger::AuthoritySelectionFactsV2::canonical_candidate(
                1,
            ),
            target: bowline_core::enforcement::PlanTarget::Candidate,
            intended_dispatch: 1,
            grant: Some(bowline_core::ledger::AuthorityGrantBindingV2 {
                grant_digest: digest(2),
                expires_at_ms: 100,
                economics_source_digest: digest(3),
                quality_source_digest: digest(4),
                opportunity_digest: digest(5),
            }),
            selected_supply_id: Some("candidate".into()),
            baseline_supply_id: Some("baseline".into()),
            actuator_identity_digest: Some(digest(6)),
            actuator_config_digest: Some(digest(7)),
            enforcement_config_digest: digest(8),
            route_config_digest: digest(9),
            model_rewritten: false,
        }
    }

    fn zero_authority_decision(id: &str) -> PreparedAuthorityDecisionV2 {
        let mut decision = raw_authority_decision(id);
        decision.reason = bowline_core::enforcement::SelectionReason::CandidateUnavailable;
        decision.evidence_state = bowline_core::enforcement::EvidenceState::Unverified;
        decision.target = bowline_core::enforcement::PlanTarget::Original;
        decision.intended_dispatch = 1;
        decision.selection_facts =
            bowline_core::ledger::AuthoritySelectionFactsV2::canonical_fallback(
                bowline_core::ledger::AuthorityFallbackReasonV2::CandidateUnavailable,
            );
        decision.grant = None;
        decision.selected_supply_id = decision.baseline_supply_id.clone();
        decision.actuator_identity_digest = None;
        decision.actuator_config_digest = None;
        test_prepared_authority_decision_v2(decision)
    }

    fn authority_outcome(id: &str) -> AuthorityOutcomeV2 {
        AuthorityOutcomeV2 {
            decision_id: id.into(),
            replaces_decision_id: None,
            ts_ms: 20,
            route_id: "route".into(),
            mode: bowline_core::enforcement::RouteMode::Enforce,
            protocol: bowline_core::enforcement::AuthorityProtocol::ChatCompletions,
            task_class: bowline_core::supply::TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(1)),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            requested_supply_id: None,
            selection_facts: bowline_core::ledger::AuthoritySelectionFactsV2::canonical_candidate(
                1,
            ),
            grant_digest: Some(digest(2)),
            grant_expires_at_ms: Some(100),
            model_rewritten: false,
            selected_supply_id: Some("candidate".into()),
            baseline_supply_id: Some("baseline".into()),
            actuator_identity_digest: Some(digest(6)),
            actuator_config_digest: Some(digest(7)),
            enforcement_config_digest: digest(8),
            route_config_digest: digest(9),
            target: bowline_core::enforcement::PlanTarget::Candidate,
            fallback_reason: None,
            circuit_before: bowline_core::ledger::CircuitStateV2::Closed,
            circuit_after: bowline_core::ledger::CircuitStateV2::Closed,
            actual_dispatch: 1,
            completion: bowline_core::ledger::CompletionStateV2::Succeeded,
            candidate_failure: None,
            status: Some(200),
            input_tokens: Some(1),
            output_tokens: Some(1),
            usage_source: bowline_core::ledger::UsageSource::Observed,
            observed_actual_cost_micros: Some(1),
            approved_counterfactual_cost_micros: Some(2),
            enforced_modeled_delta_micros: Some(1),
        }
    }

    fn authority_dispatch_attempt() -> DispatchAttemptV2 {
        DispatchAttemptV2 {
            request_body_digest: [7; 32],
            target: bowline_core::enforcement::PlanTarget::Candidate,
            selected_supply_id: Some("candidate".into()),
            requested_supply_id: None,
            route_id: "route".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            protocol: bowline_core::enforcement::AuthorityProtocol::ChatCompletions,
            task_class: bowline_core::supply::TaskClass::HeavyLifting,
            workload_identity_digest: Some(digest(1)),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            bucket: Some(1),
        }
    }

    fn zero_authority_dispatch_attempt() -> DispatchAttemptV2 {
        let mut attempt = authority_dispatch_attempt();
        attempt.target = bowline_core::enforcement::PlanTarget::Original;
        attempt.selected_supply_id = Some("baseline".into());
        attempt.bucket = Some(1);
        attempt
    }

    fn zero_authority_outcome(
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        id: &str,
    ) -> AuthorityOutcomeV2 {
        let mut outcome = authority_outcome(id);
        outcome.selection_facts =
            bowline_core::ledger::AuthoritySelectionFactsV2::canonical_fallback(
                bowline_core::ledger::AuthorityFallbackReasonV2::CandidateUnavailable,
            );
        outcome.selection_facts.bucket = Some(1);
        outcome.grant_digest = None;
        outcome.grant_expires_at_ms = None;
        outcome.selected_supply_id = Some("baseline".into());
        outcome.actuator_identity_digest = None;
        outcome.actuator_config_digest = None;
        outcome.target = bowline_core::enforcement::PlanTarget::Original;
        outcome.fallback_reason =
            Some(bowline_core::ledger::AuthorityFallbackReasonV2::CandidateUnavailable);
        outcome.input_tokens = None;
        outcome.output_tokens = None;
        outcome.usage_source = bowline_core::ledger::UsageSource::Missing;
        outcome.observed_actual_cost_micros = None;
        outcome.approved_counterfactual_cost_micros = None;
        outcome.enforced_modeled_delta_micros = None;
        outcome.enforcement_config_digest = validated.normalized_digest().into();
        outcome.route_config_digest = validated.route_digest("route").unwrap();
        outcome
    }

    fn zero_none_dispatch_attempt() -> DispatchAttemptV2 {
        let mut attempt = zero_authority_dispatch_attempt();
        attempt.target = bowline_core::enforcement::PlanTarget::None;
        attempt.selected_supply_id = None;
        attempt
    }

    fn zero_none_outcome(
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        id: &str,
    ) -> AuthorityOutcomeV2 {
        let mut outcome = zero_authority_outcome(validated, id);
        outcome.selected_supply_id = None;
        outcome.target = bowline_core::enforcement::PlanTarget::None;
        outcome.actual_dispatch = 0;
        outcome.completion = bowline_core::ledger::CompletionStateV2::Local;
        outcome.status = None;
        outcome
    }

    fn recovery_cancelled_outcome(
        validated: &bowline_core::enforcement::ValidatedEnforcement,
        id: &str,
    ) -> AuthorityOutcomeV2 {
        let mut outcome = authority_outcome(id);
        outcome.enforcement_config_digest = validated.normalized_digest().into();
        outcome.route_config_digest = validated.route_digest("route").unwrap();
        outcome.actuator_config_digest = Some(validated.actuator_digest("candidate").unwrap());
        outcome.completion = bowline_core::ledger::CompletionStateV2::Cancelled;
        outcome.candidate_failure = None;
        outcome.status = None;
        outcome.input_tokens = None;
        outcome.output_tokens = None;
        outcome.usage_source = bowline_core::ledger::UsageSource::Missing;
        outcome.observed_actual_cost_micros = None;
        outcome.approved_counterfactual_cost_micros = None;
        outcome.enforced_modeled_delta_micros = None;
        outcome
    }

    fn record_for(context: RecordContext) -> DecisionRecord {
        let mut record = record();
        record.run_id = Some(context.run_id);
        record.sequence = Some(context.sequence);
        record
    }

    fn record() -> DecisionRecord {
        DecisionRecord {
            id: "record-1".to_string(),
            ts_ms: 1,
            run_id: None,
            sequence: None,
            accounting_truncated: false,
            protocol: ProtocolKind::ChatCompletions,
            observation_source: ObservationSource::Inline,
            coverage_status: CoverageStatus::Supported,
            coverage_reason: None,
            identity: WorkloadIdentity {
                api_key_digest: None,
                route: "/v1/chat/completions".to_string(),
                app: Some("support-bot".to_string()),
                tags: vec!["customer-data".to_string()],
            },
            decision: Decision {
                policy_digest: "sha256:test".to_string(),
                task_class: TaskClass::HeavyLifting,
                feasible_ids: vec!["local/echo".to_string()],
                floor: 0.55,
                shadow: None,
            },
            actual: ActualOutcome {
                upstream: "http://127.0.0.1:1".to_string(),
                supply_id: None,
                model: Some("echo".to_string()),
                status: 200,
                streamed: false,
                latency_ms: 1,
                input_tokens: Some(7),
                output_tokens: Some(5),
                usage_source: UsageSource::Observed,
                est_cost_usd: Some(0.01),
                attribution_status: bowline_core::attribution::AttributionStatus::StaticConfigured,
                attribution_source: bowline_core::attribution::AttributionSource::LegacyConfigured,
                attribution_reference: None,
                attribution_reason: None,
            },
        }
    }
}
