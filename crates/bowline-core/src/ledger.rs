use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::attribution::{AttributionRef, AttributionSource, AttributionStatus};
use crate::decision::Decision;
use crate::enforcement::{
    AuthorityProtocol, EvidenceState, KillReadResult, PlanTarget, RouteMode, SelectionReason,
};
use crate::policy::WorkloadIdentity;
use crate::run::{
    load_authority_manifest_at, AuthorityRunManifestV2, RunError, RunManifest, RunSegment,
};
use crate::supply::TaskClass;
use crate::traffic::{CoverageStatus, ObservationSource, ProtocolKind};

const LEDGER_FILE: &str = "decisions.bwl";
const MAGIC: &[u8; 5] = b"BWL1\n";
const AUTHORITY_MAGIC: &[u8; 5] = b"BWA2\n";
const FRAME_HEADER_LEN: usize = 8;
pub const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SEGMENTS: u32 = 1024;
const MAX_SEGMENT_FILENAME_BYTES: usize = 128;
// 4,096 runs × (1,024 segments + one manifest), plus lock/legacy-file headroom.
const MAX_LEDGER_DIRECTORY_ENTRIES_SCAN: usize = 4_200_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActualOutcome {
    pub upstream: String,
    #[serde(default)]
    pub supply_id: Option<String>,
    pub model: Option<String>,
    pub status: u16,
    pub streamed: bool,
    pub latency_ms: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub usage_source: UsageSource,
    pub est_cost_usd: Option<f64>,
    #[serde(default)]
    pub attribution_status: AttributionStatus,
    #[serde(default)]
    pub attribution_source: AttributionSource,
    #[serde(default)]
    pub attribution_reference: Option<AttributionRef>,
    #[serde(default)]
    pub attribution_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsageSource {
    Observed,
    Estimated,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrantBindingV2 {
    pub grant_digest: String,
    pub expires_at_ms: u64,
    pub economics_source_digest: String,
    pub quality_source_digest: String,
    pub opportunity_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityFallbackReasonV2 {
    KillNotArmed,
    RouteMismatch,
    UntrustedIdentity,
    UnsupportedShape,
    GrantMissing,
    GrantMismatch,
    GrantStale,
    WorkloadMismatch,
    AllowlistMiss,
    RolloutMiss,
    PinnedModelMismatch,
    CircuitOpen,
    AdmissionSaturated,
    CandidateUnavailable,
    ActuatorUnavailable,
}

impl TryFrom<SelectionReason> for AuthorityFallbackReasonV2 {
    type Error = AuthorityRecordError;

    fn try_from(value: SelectionReason) -> Result<Self, Self::Error> {
        Ok(match value {
            SelectionReason::KillNotArmed => Self::KillNotArmed,
            SelectionReason::RouteMismatch => Self::RouteMismatch,
            SelectionReason::UntrustedIdentity => Self::UntrustedIdentity,
            SelectionReason::UnsupportedShape => Self::UnsupportedShape,
            SelectionReason::GrantMissing => Self::GrantMissing,
            SelectionReason::GrantMismatch => Self::GrantMismatch,
            SelectionReason::GrantStale => Self::GrantStale,
            SelectionReason::WorkloadMismatch => Self::WorkloadMismatch,
            SelectionReason::AllowlistMiss => Self::AllowlistMiss,
            SelectionReason::RolloutMiss => Self::RolloutMiss,
            SelectionReason::PinnedModelMismatch => Self::PinnedModelMismatch,
            SelectionReason::CircuitOpen => Self::CircuitOpen,
            SelectionReason::AdmissionSaturated => Self::AdmissionSaturated,
            SelectionReason::CandidateUnavailable => Self::CandidateUnavailable,
            SelectionReason::ActuatorUnavailable => Self::ActuatorUnavailable,
            SelectionReason::ObserveOnly
            | SelectionReason::RecommendationOnly
            | SelectionReason::CandidateSelected => {
                return Err(AuthorityRecordError::InvalidDecision);
            }
        })
    }
}

impl From<AuthorityFallbackReasonV2> for SelectionReason {
    fn from(value: AuthorityFallbackReasonV2) -> Self {
        match value {
            AuthorityFallbackReasonV2::KillNotArmed => Self::KillNotArmed,
            AuthorityFallbackReasonV2::RouteMismatch => Self::RouteMismatch,
            AuthorityFallbackReasonV2::UntrustedIdentity => Self::UntrustedIdentity,
            AuthorityFallbackReasonV2::UnsupportedShape => Self::UnsupportedShape,
            AuthorityFallbackReasonV2::GrantMissing => Self::GrantMissing,
            AuthorityFallbackReasonV2::GrantMismatch => Self::GrantMismatch,
            AuthorityFallbackReasonV2::GrantStale => Self::GrantStale,
            AuthorityFallbackReasonV2::WorkloadMismatch => Self::WorkloadMismatch,
            AuthorityFallbackReasonV2::AllowlistMiss => Self::AllowlistMiss,
            AuthorityFallbackReasonV2::RolloutMiss => Self::RolloutMiss,
            AuthorityFallbackReasonV2::PinnedModelMismatch => Self::PinnedModelMismatch,
            AuthorityFallbackReasonV2::CircuitOpen => Self::CircuitOpen,
            AuthorityFallbackReasonV2::AdmissionSaturated => Self::AdmissionSaturated,
            AuthorityFallbackReasonV2::CandidateUnavailable => Self::CandidateUnavailable,
            AuthorityFallbackReasonV2::ActuatorUnavailable => Self::ActuatorUnavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySelectionFactsV2 {
    pub kill_state: KillReadResult,
    pub route_matched: bool,
    pub identity_trusted: bool,
    pub shape_supported: bool,
    pub grant_present: bool,
    pub grant_matched: bool,
    pub grant_fresh: bool,
    pub workload_matched: bool,
    pub allowlist_matched: bool,
    pub rollout_selected: bool,
    pub bucket: Option<u32>,
    pub pinned_model_matched: bool,
    pub candidate_availability: Option<crate::enforcement::CandidateAvailability>,
    pub actuator_available: Option<bool>,
    pub circuit_before: CircuitStateV2,
}

impl AuthoritySelectionFactsV2 {
    pub fn canonical_fallback(reason: AuthorityFallbackReasonV2) -> Self {
        let mut facts = Self {
            kill_state: KillReadResult::Armed,
            route_matched: false,
            identity_trusted: false,
            shape_supported: false,
            grant_present: false,
            grant_matched: false,
            grant_fresh: false,
            workload_matched: false,
            allowlist_matched: false,
            rollout_selected: false,
            bucket: None,
            pinned_model_matched: false,
            candidate_availability: None,
            actuator_available: None,
            circuit_before: CircuitStateV2::NotApplicable,
        };
        if reason == AuthorityFallbackReasonV2::KillNotArmed {
            facts.kill_state = KillReadResult::Bypass;
            return facts;
        }
        facts.route_matched = reason != AuthorityFallbackReasonV2::RouteMismatch;
        if !facts.route_matched {
            return facts;
        }
        facts.identity_trusted = reason != AuthorityFallbackReasonV2::UntrustedIdentity;
        if !facts.identity_trusted {
            return facts;
        }
        facts.shape_supported = reason != AuthorityFallbackReasonV2::UnsupportedShape;
        if !facts.shape_supported {
            return facts;
        }
        facts.grant_present = reason != AuthorityFallbackReasonV2::GrantMissing;
        if !facts.grant_present {
            return facts;
        }
        facts.grant_matched = reason != AuthorityFallbackReasonV2::GrantMismatch;
        if !facts.grant_matched {
            return facts;
        }
        facts.grant_fresh = reason != AuthorityFallbackReasonV2::GrantStale;
        if !facts.grant_fresh {
            return facts;
        }
        facts.workload_matched = reason != AuthorityFallbackReasonV2::WorkloadMismatch;
        if !facts.workload_matched {
            return facts;
        }
        facts.allowlist_matched = reason != AuthorityFallbackReasonV2::AllowlistMiss;
        if !facts.allowlist_matched {
            return facts;
        }
        facts.bucket = Some(0);
        facts.rollout_selected = reason != AuthorityFallbackReasonV2::RolloutMiss;
        if !facts.rollout_selected {
            return facts;
        }
        facts.pinned_model_matched = reason != AuthorityFallbackReasonV2::PinnedModelMismatch;
        if !facts.pinned_model_matched {
            return facts;
        }
        facts.candidate_availability = Some(match reason {
            AuthorityFallbackReasonV2::CircuitOpen => {
                facts.circuit_before = CircuitStateV2::Open;
                crate::enforcement::CandidateAvailability::CircuitOpen
            }
            AuthorityFallbackReasonV2::AdmissionSaturated => {
                facts.circuit_before = CircuitStateV2::Closed;
                crate::enforcement::CandidateAvailability::AdmissionSaturated
            }
            AuthorityFallbackReasonV2::CandidateUnavailable => {
                facts.circuit_before = CircuitStateV2::Closed;
                crate::enforcement::CandidateAvailability::Unavailable
            }
            AuthorityFallbackReasonV2::ActuatorUnavailable => {
                facts.circuit_before = CircuitStateV2::Closed;
                crate::enforcement::CandidateAvailability::Available
            }
            _ => unreachable!("earlier fallback returned above"),
        });
        if reason == AuthorityFallbackReasonV2::ActuatorUnavailable {
            facts.actuator_available = Some(false);
        }
        facts
    }

    pub fn canonical_candidate(bucket: u32) -> Self {
        let mut facts = Self::canonical_fallback(AuthorityFallbackReasonV2::ActuatorUnavailable);
        facts.bucket = Some(bucket);
        facts.actuator_available = Some(true);
        facts
    }

    pub fn canonical_non_authority(kill_state: KillReadResult) -> Self {
        Self {
            kill_state,
            route_matched: true,
            identity_trusted: true,
            shape_supported: true,
            grant_present: false,
            grant_matched: false,
            grant_fresh: false,
            workload_matched: false,
            allowlist_matched: false,
            rollout_selected: false,
            bucket: None,
            pinned_model_matched: false,
            candidate_availability: None,
            actuator_available: None,
            circuit_before: CircuitStateV2::NotApplicable,
        }
    }

    pub fn validate_fallback(
        &self,
        reason: AuthorityFallbackReasonV2,
    ) -> Result<(), AuthorityRecordError> {
        if self.bucket.is_some_and(|bucket| bucket >= 1_000_000) {
            return Err(AuthorityRecordError::InvalidDecision);
        }
        let mut expected = Self::canonical_fallback(reason);
        expected.kill_state = self.kill_state;
        expected.bucket = self.bucket;
        let kill_valid = if reason == AuthorityFallbackReasonV2::KillNotArmed {
            self.kill_state != KillReadResult::Armed
        } else {
            self.kill_state == KillReadResult::Armed
        };
        let bucket_valid = match reason {
            AuthorityFallbackReasonV2::RolloutMiss
            | AuthorityFallbackReasonV2::PinnedModelMismatch
            | AuthorityFallbackReasonV2::CircuitOpen
            | AuthorityFallbackReasonV2::AdmissionSaturated
            | AuthorityFallbackReasonV2::CandidateUnavailable
            | AuthorityFallbackReasonV2::ActuatorUnavailable => self.bucket.is_some(),
            _ => self.bucket.is_none(),
        };
        if kill_valid && bucket_valid && self == &expected {
            Ok(())
        } else {
            Err(AuthorityRecordError::InvalidDecision)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDecisionV2 {
    pub decision_id: String,
    #[serde(default)]
    pub replaces_decision_id: Option<String>,
    #[serde(default)]
    pub configured_fallback_target: Option<PlanTarget>,
    pub ts_ms: u64,
    pub route_id: String,
    pub mode: RouteMode,
    pub protocol: AuthorityProtocol,
    pub task_class: TaskClass,
    #[serde(default)]
    pub workload_identity_digest: Option<String>,
    #[serde(default)]
    pub app: Option<String>,
    pub resolved_tags: Vec<String>,
    pub requested_supply_id: Option<String>,
    pub reason: SelectionReason,
    pub evidence_state: EvidenceState,
    pub selection_facts: AuthoritySelectionFactsV2,
    pub target: PlanTarget,
    pub intended_dispatch: u8,
    pub grant: Option<AuthorityGrantBindingV2>,
    pub selected_supply_id: Option<String>,
    pub baseline_supply_id: Option<String>,
    pub actuator_identity_digest: Option<String>,
    pub actuator_config_digest: Option<String>,
    pub enforcement_config_digest: String,
    pub route_config_digest: String,
    pub model_rewritten: bool,
}

impl AuthorityDecisionV2 {
    pub fn validate(&self) -> Result<(), AuthorityRecordError> {
        let common_valid = safe_authority_id(&self.decision_id)
            && self
                .replaces_decision_id
                .as_deref()
                .is_none_or(safe_authority_id)
            && self.replaces_decision_id.as_deref() != Some(self.decision_id.as_str())
            && self.configured_fallback_target != Some(PlanTarget::Candidate)
            && bounded_authority_identifier(&self.route_id)
            && self
                .workload_identity_digest
                .as_deref()
                .is_none_or(valid_authority_digest)
            && self.app.as_deref().is_none_or(bounded_authority_identifier)
            && self.resolved_tags.len() <= 64
            && self
                .resolved_tags
                .iter()
                .all(|tag| bounded_authority_identifier(tag))
            && self
                .requested_supply_id
                .as_deref()
                .is_none_or(bounded_authority_identifier)
            && valid_authority_digest(&self.enforcement_config_digest)
            && valid_authority_digest(&self.route_config_digest)
            && self
                .selected_supply_id
                .as_deref()
                .is_none_or(bounded_authority_identifier)
            && self
                .baseline_supply_id
                .as_deref()
                .is_none_or(bounded_authority_identifier);
        if !common_valid {
            return Err(AuthorityRecordError::InvalidDecision);
        }
        let candidate = self.target == PlanTarget::Candidate;
        if candidate {
            if self.replaces_decision_id.is_some()
                || self.protocol == AuthorityProtocol::Embeddings
                || self.workload_identity_digest.is_none()
                || self.app.is_none()
            {
                return Err(AuthorityRecordError::InvalidDecision);
            }
            let Some(grant) = self.grant.as_ref() else {
                return Err(AuthorityRecordError::InvalidDecision);
            };
            let Some(bucket) = self.selection_facts.bucket else {
                return Err(AuthorityRecordError::InvalidDecision);
            };
            if !self.mode.grants_authority()
                || self.reason != SelectionReason::CandidateSelected
                || self.evidence_state != EvidenceState::Presented
                || self.selection_facts != AuthoritySelectionFactsV2::canonical_candidate(bucket)
                || self.intended_dispatch != 1
                || self.selected_supply_id.is_none()
                || self.baseline_supply_id.is_none()
                || self
                    .actuator_identity_digest
                    .as_deref()
                    .is_none_or(|value| !valid_authority_digest(value))
                || self
                    .actuator_config_digest
                    .as_deref()
                    .is_none_or(|value| !valid_authority_digest(value))
                || !valid_authority_digest(&grant.grant_digest)
                || !valid_authority_digest(&grant.economics_source_digest)
                || !valid_authority_digest(&grant.quality_source_digest)
                || !valid_authority_digest(&grant.opportunity_digest)
                || grant.expires_at_ms < self.ts_ms
            {
                return Err(AuthorityRecordError::InvalidDecision);
            }
        } else if self.reason == SelectionReason::CandidateSelected
            || self.grant.is_some()
            || self.actuator_identity_digest.is_some()
            || self.actuator_config_digest.is_some()
            || self.model_rewritten
            || self.intended_dispatch != u8::from(self.target == PlanTarget::Original)
            || (self.target == PlanTarget::None && self.selected_supply_id.is_some())
            || (self.target == PlanTarget::Original
                && self.selected_supply_id != self.baseline_supply_id)
            || self.configured_fallback_target.is_some()
        {
            return Err(AuthorityRecordError::InvalidDecision);
        }
        if self.replaces_decision_id.is_some()
            && self.reason != SelectionReason::CandidateUnavailable
        {
            return Err(AuthorityRecordError::InvalidDecision);
        }
        if !candidate {
            match self.reason {
                SelectionReason::ObserveOnly | SelectionReason::RecommendationOnly => {
                    let expected_mode = if self.reason == SelectionReason::ObserveOnly {
                        RouteMode::Observe
                    } else {
                        RouteMode::Recommend
                    };
                    let evidence_valid = if self.mode == RouteMode::Observe {
                        self.evidence_state == EvidenceState::NotRequired
                    } else {
                        matches!(
                            self.evidence_state,
                            EvidenceState::Presented | EvidenceState::Unverified
                        )
                    };
                    if self.mode != expected_mode
                        || self.target != PlanTarget::Original
                        || !evidence_valid
                        || self.selection_facts
                            != AuthoritySelectionFactsV2::canonical_non_authority(
                                self.selection_facts.kill_state,
                            )
                    {
                        return Err(AuthorityRecordError::InvalidDecision);
                    }
                }
                reason => {
                    if !self.mode.grants_authority()
                        || self.evidence_state != EvidenceState::Unverified
                        || (self.target == PlanTarget::Original
                            && self.selected_supply_id.is_none())
                    {
                        return Err(AuthorityRecordError::InvalidDecision);
                    }
                    self.selection_facts
                        .validate_fallback(AuthorityFallbackReasonV2::try_from(reason)?)?;
                }
            }
        }
        Ok(())
    }

    pub fn grants_candidate_authority(&self) -> bool {
        self.target == PlanTarget::Candidate && self.validate().is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CircuitStateV2 {
    NotApplicable,
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompletionStateV2 {
    Succeeded,
    Failed,
    Cancelled,
    Local,
    PreDispatchRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateFailureClassV2 {
    Connect,
    ResponseHeaderTimeout,
    StreamIdleTimeout,
    TransportStream,
    ProtocolIncomplete,
    Authentication,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOutcomeV2 {
    pub decision_id: String,
    #[serde(default)]
    pub replaces_decision_id: Option<String>,
    pub ts_ms: u64,
    pub route_id: String,
    pub mode: RouteMode,
    pub protocol: AuthorityProtocol,
    pub task_class: TaskClass,
    #[serde(default)]
    pub workload_identity_digest: Option<String>,
    #[serde(default)]
    pub app: Option<String>,
    pub resolved_tags: Vec<String>,
    pub requested_supply_id: Option<String>,
    pub selection_facts: AuthoritySelectionFactsV2,
    pub grant_digest: Option<String>,
    pub grant_expires_at_ms: Option<u64>,
    pub model_rewritten: bool,
    pub selected_supply_id: Option<String>,
    pub baseline_supply_id: Option<String>,
    pub actuator_identity_digest: Option<String>,
    pub actuator_config_digest: Option<String>,
    pub enforcement_config_digest: String,
    pub route_config_digest: String,
    pub target: PlanTarget,
    pub fallback_reason: Option<AuthorityFallbackReasonV2>,
    pub circuit_before: CircuitStateV2,
    pub circuit_after: CircuitStateV2,
    pub actual_dispatch: u8,
    pub completion: CompletionStateV2,
    pub candidate_failure: Option<CandidateFailureClassV2>,
    pub status: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub usage_source: UsageSource,
    pub observed_actual_cost_micros: Option<u64>,
    pub approved_counterfactual_cost_micros: Option<u64>,
    #[serde(with = "optional_i128_json")]
    pub enforced_modeled_delta_micros: Option<i128>,
}

pub fn modeled_delta_applicable(outcome: &AuthorityOutcomeV2) -> bool {
    outcome.target == PlanTarget::Candidate
        && outcome.completion == CompletionStateV2::Succeeded
        && outcome
            .status
            .is_some_and(|status| (200..=299).contains(&status))
        && outcome.usage_source == UsageSource::Observed
        && outcome.input_tokens.is_some()
        && outcome.output_tokens.is_some()
}

mod optional_i128_json {
    use serde::{
        de::{Error, Visitor},
        Deserializer, Serializer,
    };

    pub fn serialize<S>(value: &Option<i128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(value),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<i128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionalVisitor;
        impl<'de> Visitor<'de> for OptionalVisitor {
            type Value = Option<i128>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a signed integer or null")
            }
            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                struct IntegerVisitor;
                impl<'de> Visitor<'de> for IntegerVisitor {
                    type Value = i128;
                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a signed integer")
                    }
                    fn visit_i64<E: Error>(self, value: i64) -> Result<Self::Value, E> {
                        Ok(i128::from(value))
                    }
                    fn visit_u64<E: Error>(self, value: u64) -> Result<Self::Value, E> {
                        Ok(i128::from(value))
                    }
                }
                deserializer.deserialize_any(IntegerVisitor).map(Some)
            }
        }
        deserializer.deserialize_option(OptionalVisitor)
    }
}

impl AuthorityOutcomeV2 {
    pub fn validate(&self) -> Result<(), AuthorityRecordError> {
        if !safe_authority_id(&self.decision_id)
            || self
                .replaces_decision_id
                .as_deref()
                .is_some_and(|value| !safe_authority_id(value))
            || self.replaces_decision_id.as_deref() == Some(self.decision_id.as_str())
            || !bounded_authority_identifier(&self.route_id)
            || self
                .workload_identity_digest
                .as_deref()
                .is_some_and(|value| !valid_authority_digest(value))
            || self
                .app
                .as_deref()
                .is_some_and(|value| !bounded_authority_identifier(value))
            || self.resolved_tags.len() > 64
            || !self
                .resolved_tags
                .iter()
                .all(|tag| bounded_authority_identifier(tag))
            || self
                .requested_supply_id
                .as_deref()
                .is_some_and(|value| !bounded_authority_identifier(value))
            || self
                .selected_supply_id
                .as_deref()
                .is_some_and(|value| !bounded_authority_identifier(value))
            || self
                .baseline_supply_id
                .as_deref()
                .is_some_and(|value| !bounded_authority_identifier(value))
            || !valid_authority_digest(&self.enforcement_config_digest)
            || !valid_authority_digest(&self.route_config_digest)
            || self
                .grant_digest
                .as_deref()
                .is_some_and(|value| !valid_authority_digest(value))
            || self.grant_digest.is_some() != self.grant_expires_at_ms.is_some()
            || self
                .actuator_identity_digest
                .as_deref()
                .is_some_and(|value| !valid_authority_digest(value))
            || self
                .actuator_config_digest
                .as_deref()
                .is_some_and(|value| !valid_authority_digest(value))
            || self.actual_dispatch > 1
            || (self.input_tokens.is_some() != self.output_tokens.is_some()
                && (self.completion != CompletionStateV2::Succeeded
                    || self.usage_source != UsageSource::Observed))
            || self
                .observed_actual_cost_micros
                .is_some_and(|value| value > i64::MAX as u64)
            || self
                .approved_counterfactual_cost_micros
                .is_some_and(|value| value > i64::MAX as u64)
        {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        let pre_dispatch_rejected = self.completion == CompletionStateV2::PreDispatchRejected
            && self.target == PlanTarget::Candidate
            && self.actual_dispatch == 0;
        if !pre_dispatch_rejected
            && self.actual_dispatch != u8::from(self.target != PlanTarget::None)
        {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.target == PlanTarget::Candidate {
            if self.replaces_decision_id.is_some()
                || self.protocol == AuthorityProtocol::Embeddings
                || self.workload_identity_digest.is_none()
                || self.app.is_none()
            {
                return Err(AuthorityRecordError::InvalidOutcome);
            }
            let Some(bucket) = self.selection_facts.bucket else {
                return Err(AuthorityRecordError::InvalidOutcome);
            };
            if !self.mode.grants_authority()
                || self.selection_facts != AuthoritySelectionFactsV2::canonical_candidate(bucket)
                || self.grant_digest.is_none()
                || self.selected_supply_id.is_none()
                || self.baseline_supply_id.is_none()
                || self.actuator_identity_digest.is_none()
                || self.actuator_config_digest.is_none()
                || self.fallback_reason.is_some()
            {
                return Err(AuthorityRecordError::InvalidOutcome);
            }
        } else if self.grant_digest.is_some()
            || self.actuator_identity_digest.is_some()
            || self.actuator_config_digest.is_some()
            || self.model_rewritten
        {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.replaces_decision_id.is_some()
            && self.fallback_reason != Some(AuthorityFallbackReasonV2::CandidateUnavailable)
        {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.target != PlanTarget::Candidate {
            if let Some(reason) = self.fallback_reason {
                if !self.mode.grants_authority() {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
                self.selection_facts
                    .validate_fallback(reason)
                    .map_err(|_| AuthorityRecordError::InvalidOutcome)?;
            } else if self.selection_facts
                != AuthoritySelectionFactsV2::canonical_non_authority(
                    self.selection_facts.kill_state,
                )
                || self.target != PlanTarget::Original
                || !matches!(self.mode, RouteMode::Observe | RouteMode::Recommend)
            {
                return Err(AuthorityRecordError::InvalidOutcome);
            }
        }
        let costs = (
            self.observed_actual_cost_micros,
            self.approved_counterfactual_cost_micros,
            self.enforced_modeled_delta_micros,
        );
        let has_complete_costs = match costs {
            (Some(actual), Some(counterfactual), Some(delta)) => {
                i128::from(counterfactual) - i128::from(actual) == delta
            }
            (None, None, None) => true,
            _ => false,
        };
        if !has_complete_costs {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.enforced_modeled_delta_micros.is_some() && !modeled_delta_applicable(self) {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        match self.completion {
            CompletionStateV2::Succeeded => {
                if self.candidate_failure.is_some() || self.status.is_none() {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
                if self.target == PlanTarget::Candidate
                    && self.status.is_some_and(candidate_failure_http_status)
                {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
                if self.target == PlanTarget::Candidate
                    && self.circuit_after != CircuitStateV2::Closed
                {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
            }
            CompletionStateV2::Failed => {
                if (self.target == PlanTarget::Candidate) != self.candidate_failure.is_some() {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
                if self.target == PlanTarget::Candidate
                    && !candidate_failure_status_is_coherent(
                        self.candidate_failure
                            .expect("candidate failure is present"),
                        self.status,
                    )
                {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
                if self.enforced_modeled_delta_micros.is_some() {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
            }
            CompletionStateV2::Cancelled => {
                if self.candidate_failure.is_some() || self.enforced_modeled_delta_micros.is_some()
                {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
                if self.circuit_after != self.circuit_before {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
            }
            CompletionStateV2::Local => {
                if self.target != PlanTarget::None
                    || self.actual_dispatch != 0
                    || self.candidate_failure.is_some()
                    || self.enforced_modeled_delta_micros.is_some()
                {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
            }
            CompletionStateV2::PreDispatchRejected => {
                if self.target != PlanTarget::Candidate
                    || self.actual_dispatch != 0
                    || self.candidate_failure.is_some()
                    || self.status.is_some()
                    || self.input_tokens.is_some()
                    || self.output_tokens.is_some()
                    || self.usage_source != UsageSource::Missing
                    || self.observed_actual_cost_micros.is_some()
                    || self.approved_counterfactual_cost_micros.is_some()
                    || self.enforced_modeled_delta_micros.is_some()
                    || self.circuit_after != self.circuit_before
                {
                    return Err(AuthorityRecordError::InvalidOutcome);
                }
            }
        }
        if self.target == PlanTarget::None && self.completion != CompletionStateV2::Local {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.target != PlanTarget::None && self.completion == CompletionStateV2::Local {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.target != PlanTarget::Candidate && self.candidate_failure.is_some() {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        if self.target != PlanTarget::Candidate && self.circuit_after != self.circuit_before {
            return Err(AuthorityRecordError::InvalidOutcome);
        }
        Ok(())
    }
}

fn candidate_failure_http_status(status: u16) -> bool {
    matches!(status, 401 | 403) || (500..=599).contains(&status)
}

fn candidate_failure_status_is_coherent(
    failure: CandidateFailureClassV2,
    status: Option<u16>,
) -> bool {
    match failure {
        CandidateFailureClassV2::Connect | CandidateFailureClassV2::ResponseHeaderTimeout => {
            status.is_none()
        }
        CandidateFailureClassV2::StreamIdleTimeout
        | CandidateFailureClassV2::TransportStream
        | CandidateFailureClassV2::ProtocolIncomplete => {
            status.is_none_or(|status| !candidate_failure_http_status(status))
        }
        CandidateFailureClassV2::Authentication => matches!(status, Some(401 | 403)),
        CandidateFailureClassV2::Server => {
            status.is_some_and(|status| (500..=599).contains(&status))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "kebab-case")]
pub enum AuthorityRecordV2 {
    Decision {
        schema_version: u32,
        sequence: u64,
        decision: AuthorityDecisionV2,
    },
    Outcome {
        schema_version: u32,
        sequence: u64,
        outcome: AuthorityOutcomeV2,
    },
}

impl AuthorityRecordV2 {
    pub fn decision(
        sequence: u64,
        decision: AuthorityDecisionV2,
    ) -> Result<Self, AuthorityRecordError> {
        if sequence == 0 {
            return Err(AuthorityRecordError::InvalidSequence);
        }
        decision.validate()?;
        Ok(Self::Decision {
            schema_version: 2,
            sequence,
            decision,
        })
    }

    pub fn outcome(
        sequence: u64,
        outcome: AuthorityOutcomeV2,
    ) -> Result<Self, AuthorityRecordError> {
        if sequence == 0 {
            return Err(AuthorityRecordError::InvalidSequence);
        }
        outcome.validate()?;
        Ok(Self::Outcome {
            schema_version: 2,
            sequence,
            outcome,
        })
    }

    pub fn sequence(&self) -> u64 {
        match self {
            Self::Decision { sequence, .. } | Self::Outcome { sequence, .. } => *sequence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorityRecordError {
    #[error("invalid authority decision")]
    InvalidDecision,
    #[error("invalid authority outcome")]
    InvalidOutcome,
    #[error("invalid authority record sequence")]
    InvalidSequence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCompleteAuthorityRunV2 {
    run_id: String,
    records_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRunDiagnosticsV2 {
    run_id: String,
    records_digest: String,
}

impl AuthorityRunDiagnosticsV2 {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn records_digest(&self) -> &str {
        &self.records_digest
    }
}

#[derive(Debug)]
pub struct ValidatedAuthorityRunReadV2 {
    manifest: AuthorityRunManifestV2,
    records: Vec<AuthorityRecordV2>,
    complete: ValidatedCompleteAuthorityRunV2,
}

/// Opaque evidence returned only after descriptor-anchored manifest/record reads, digest and
/// counter validation, and decision/outcome pair validation. Unlike the complete token, this may
/// contain a cancelled terminal and is therefore suitable only for diagnostic reporting.
///
/// Its private fields deliberately prevent callers from fabricating validated evidence:
/// ```compile_fail
/// use bowline_core::ledger::ValidatedAuthorityDiagnosticRunReadV2;
/// let forged = ValidatedAuthorityDiagnosticRunReadV2 {
///     records: Vec::new(),
///     diagnostics: panic!("opaque"),
///     complete: true,
/// };
/// ```
#[derive(Debug)]
pub struct ValidatedAuthorityDiagnosticRunReadV2 {
    records: Vec<AuthorityRecordV2>,
    diagnostics: AuthorityRunDiagnosticsV2,
    complete: bool,
}

impl ValidatedAuthorityDiagnosticRunReadV2 {
    pub(crate) fn records(&self) -> &[AuthorityRecordV2] {
        &self.records
    }

    pub(crate) fn diagnostics(&self) -> &AuthorityRunDiagnosticsV2 {
        &self.diagnostics
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

impl ValidatedAuthorityRunReadV2 {
    pub fn manifest(&self) -> &AuthorityRunManifestV2 {
        &self.manifest
    }

    pub fn records(&self) -> &[AuthorityRecordV2] {
        &self.records
    }

    pub fn complete(&self) -> &ValidatedCompleteAuthorityRunV2 {
        &self.complete
    }
}

#[derive(Debug, Error)]
pub enum AuthorityAuthoritativeReadError {
    #[error(transparent)]
    Run(#[from] RunError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Validation(#[from] AuthorityRunValidationError),
}

impl ValidatedCompleteAuthorityRunV2 {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn records_digest(&self) -> &str {
        &self.records_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorityRunValidationError {
    #[error("authority manifest is invalid or incomplete")]
    InvalidManifest,
    #[error("authority record sequence has a gap")]
    SequenceGap,
    #[error("authority decision is duplicated")]
    DuplicateDecision,
    #[error("authority terminal outcome is duplicated")]
    DuplicateTerminal,
    #[error("authority decision has no terminal outcome")]
    MissingTerminal,
    #[error("authority terminal outcome has no decision")]
    OrphanTerminal,
    #[error("authority decision and terminal outcome disagree")]
    PairMismatch,
}

pub fn validate_authority_pair_v2(
    decision: &AuthorityDecisionV2,
    outcome: &AuthorityOutcomeV2,
) -> Result<(), AuthorityRunValidationError> {
    if decision.validate().is_err() || outcome.validate().is_err() {
        return Err(AuthorityRunValidationError::PairMismatch);
    }
    let fallback_matches = match decision.reason {
        SelectionReason::CandidateSelected
        | SelectionReason::ObserveOnly
        | SelectionReason::RecommendationOnly => outcome.fallback_reason.is_none(),
        reason => AuthorityFallbackReasonV2::try_from(reason)
            .is_ok_and(|reason| outcome.fallback_reason == Some(reason)),
    };
    let pre_dispatch_rejected = outcome.completion == CompletionStateV2::PreDispatchRejected
        && decision.target == PlanTarget::Candidate
        && decision.intended_dispatch == 1
        && outcome.actual_dispatch == 0;
    if decision.target != outcome.target
        || (!pre_dispatch_rejected && decision.intended_dispatch != outcome.actual_dispatch)
        || outcome.ts_ms < decision.ts_ms
        || !fallback_matches
        || decision.replaces_decision_id != outcome.replaces_decision_id
        || decision.route_id != outcome.route_id
        || decision.mode != outcome.mode
        || decision.protocol != outcome.protocol
        || decision.task_class != outcome.task_class
        || decision.workload_identity_digest != outcome.workload_identity_digest
        || decision.app != outcome.app
        || decision.resolved_tags != outcome.resolved_tags
        || decision.requested_supply_id != outcome.requested_supply_id
        || decision.selection_facts != outcome.selection_facts
        || decision.model_rewritten != outcome.model_rewritten
        || decision.selected_supply_id != outcome.selected_supply_id
        || decision.baseline_supply_id != outcome.baseline_supply_id
        || decision.actuator_identity_digest != outcome.actuator_identity_digest
        || decision.actuator_config_digest != outcome.actuator_config_digest
        || decision.enforcement_config_digest != outcome.enforcement_config_digest
        || decision.route_config_digest != outcome.route_config_digest
        || decision
            .grant
            .as_ref()
            .map(|grant| grant.grant_digest.as_str())
            != outcome.grant_digest.as_deref()
        || decision.grant.as_ref().map(|grant| grant.expires_at_ms) != outcome.grant_expires_at_ms
        || decision.selection_facts.circuit_before != outcome.circuit_before
    {
        Err(AuthorityRunValidationError::PairMismatch)
    } else {
        Ok(())
    }
}

pub fn validate_authority_run_v2(
    manifest: &AuthorityRunManifestV2,
    records: &[AuthorityRecordV2],
) -> Result<AuthorityRunDiagnosticsV2, AuthorityRunValidationError> {
    validate_authority_run_structure_v2(manifest, records)
}

fn validate_authority_diagnostic_run_v2(
    manifest: &AuthorityRunManifestV2,
    records: &[AuthorityRecordV2],
) -> Result<(AuthorityRunDiagnosticsV2, bool), AuthorityRunValidationError> {
    let diagnostics = validate_authority_run_structure_v2_inner(manifest, records, true)?;
    let complete = records.iter().all(|record| {
        !matches!(
            record,
            AuthorityRecordV2::Outcome { outcome, .. }
                if outcome.completion == CompletionStateV2::Cancelled
        )
    });
    Ok((diagnostics, complete))
}

fn validate_authority_run_structure_v2(
    manifest: &AuthorityRunManifestV2,
    records: &[AuthorityRecordV2],
) -> Result<AuthorityRunDiagnosticsV2, AuthorityRunValidationError> {
    validate_authority_run_structure_v2_inner(manifest, records, false)
}

fn validate_authority_run_structure_v2_inner(
    manifest: &AuthorityRunManifestV2,
    records: &[AuthorityRecordV2],
    allow_cancelled: bool,
) -> Result<AuthorityRunDiagnosticsV2, AuthorityRunValidationError> {
    let expected_records =
        u64::try_from(records.len()).map_err(|_| AuthorityRunValidationError::InvalidManifest)?;
    if manifest.schema_version != 2
        || !manifest.clean_shutdown
        || !manifest.writer_healthy
        || manifest.writer_error.is_some()
        || manifest.dropped != 0
        || manifest.accepted != expected_records
        || manifest.recorded != expected_records
        || manifest.next_sequence != expected_records.saturating_add(1)
        || manifest.records_file != format!("authority-{}.bwl", manifest.run_id)
        || manifest.ended_at_ms.is_none()
        || manifest.last_flush_at_ms.is_none()
        || manifest.records_bytes.is_none()
        || manifest
            .records_digest
            .as_deref()
            .is_none_or(|value| !valid_authority_digest(value))
        || !valid_authority_digest(&manifest.enforcement_digest)
        || !valid_authority_digest(&manifest.actuator_set_digest)
        || !valid_authority_digest(&manifest.grant_set_digest)
    {
        return Err(AuthorityRunValidationError::InvalidManifest);
    }
    let mut decisions = std::collections::BTreeMap::new();
    let mut outcomes = std::collections::BTreeMap::new();
    let mut decision_positions = std::collections::BTreeMap::new();
    let mut outcome_positions = std::collections::BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if record.sequence() != expected {
            return Err(AuthorityRunValidationError::SequenceGap);
        }
        match record {
            AuthorityRecordV2::Decision {
                schema_version,
                decision,
                ..
            } => {
                if *schema_version != 2 || decision.validate().is_err() {
                    return Err(AuthorityRunValidationError::PairMismatch);
                }
                if decision.enforcement_config_digest != manifest.enforcement_digest {
                    return Err(AuthorityRunValidationError::PairMismatch);
                }
                if decisions
                    .insert(decision.decision_id.as_str(), decision)
                    .is_some()
                {
                    return Err(AuthorityRunValidationError::DuplicateDecision);
                }
                decision_positions.insert(decision.decision_id.as_str(), index);
            }
            AuthorityRecordV2::Outcome {
                schema_version,
                outcome,
                ..
            } => {
                if *schema_version != 2
                    || outcome.validate().is_err()
                    || (!allow_cancelled && outcome.completion == CompletionStateV2::Cancelled)
                {
                    return Err(AuthorityRunValidationError::PairMismatch);
                }
                if outcomes
                    .insert(outcome.decision_id.as_str(), outcome)
                    .is_some()
                {
                    return Err(AuthorityRunValidationError::DuplicateTerminal);
                }
                outcome_positions.insert(outcome.decision_id.as_str(), index);
            }
        }
    }
    if decisions.keys().any(|id| !outcomes.contains_key(id)) {
        return Err(AuthorityRunValidationError::MissingTerminal);
    }
    if outcomes.keys().any(|id| !decisions.contains_key(id)) {
        return Err(AuthorityRunValidationError::OrphanTerminal);
    }
    for (id, decision) in &decisions {
        let outcome = outcomes[id];
        if decision_positions[id] >= outcome_positions[id] {
            return Err(AuthorityRunValidationError::PairMismatch);
        }
        validate_authority_pair_v2(decision, outcome)?;
    }
    validate_replacement_links_v2(
        &decisions,
        &outcomes,
        &decision_positions,
        &outcome_positions,
    )?;
    Ok(AuthorityRunDiagnosticsV2 {
        run_id: manifest.run_id.clone(),
        records_digest: manifest
            .records_digest
            .clone()
            .ok_or(AuthorityRunValidationError::InvalidManifest)?,
    })
}

fn validate_replacement_links_v2(
    decisions: &std::collections::BTreeMap<&str, &AuthorityDecisionV2>,
    outcomes: &std::collections::BTreeMap<&str, &AuthorityOutcomeV2>,
    decision_positions: &std::collections::BTreeMap<&str, usize>,
    outcome_positions: &std::collections::BTreeMap<&str, usize>,
) -> Result<(), AuthorityRunValidationError> {
    let mut replacements_by_candidate = std::collections::BTreeMap::<&str, usize>::new();
    for replacement in decisions.values() {
        let Some(candidate_id) = replacement.replaces_decision_id.as_deref() else {
            continue;
        };
        let candidate = decisions
            .get(candidate_id)
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        let candidate_outcome = outcomes
            .get(candidate_id)
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        let candidate_decision_position = decision_positions
            .get(candidate_id)
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        let candidate_outcome_position = outcome_positions
            .get(candidate_id)
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        let replacement_decision_position = decision_positions
            .get(replacement.decision_id.as_str())
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        let replacement_outcome_position = outcome_positions
            .get(replacement.decision_id.as_str())
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        let exact_request_and_config = candidate.target == PlanTarget::Candidate
            && candidate.replaces_decision_id.is_none()
            && candidate.configured_fallback_target == Some(replacement.target)
            && candidate_outcome.completion == CompletionStateV2::PreDispatchRejected
            && replacement.reason == SelectionReason::CandidateUnavailable
            && replacement.target != PlanTarget::Candidate
            && replacement.ts_ms == candidate.ts_ms
            && replacement.route_id == candidate.route_id
            && replacement.mode == candidate.mode
            && replacement.protocol == candidate.protocol
            && replacement.task_class == candidate.task_class
            && replacement.workload_identity_digest == candidate.workload_identity_digest
            && replacement.app == candidate.app
            && replacement.resolved_tags == candidate.resolved_tags
            && replacement.requested_supply_id == candidate.requested_supply_id
            && replacement.baseline_supply_id == candidate.baseline_supply_id
            && replacement.enforcement_config_digest == candidate.enforcement_config_digest
            && replacement.route_config_digest == candidate.route_config_digest
            && replacement.selection_facts.bucket == candidate.selection_facts.bucket
            && replacement.selected_supply_id
                == (replacement.target == PlanTarget::Original)
                    .then(|| candidate.baseline_supply_id.clone())
                    .flatten()
            && replacement.intended_dispatch
                == u8::from(replacement.target == PlanTarget::Original)
            && candidate_decision_position < candidate_outcome_position
            && candidate_outcome_position < replacement_decision_position
            && replacement_decision_position < replacement_outcome_position;
        if !exact_request_and_config {
            return Err(AuthorityRunValidationError::PairMismatch);
        }
        let count = replacements_by_candidate.entry(candidate_id).or_default();
        *count = count
            .checked_add(1)
            .ok_or(AuthorityRunValidationError::PairMismatch)?;
        if *count != 1 {
            return Err(AuthorityRunValidationError::PairMismatch);
        }
    }
    for (id, outcome) in outcomes {
        if outcome.completion == CompletionStateV2::PreDispatchRejected
            && replacements_by_candidate.get(id).copied() != Some(1)
        {
            return Err(AuthorityRunValidationError::MissingTerminal);
        }
    }
    Ok(())
}

/// Dedicated schema-v2 authority ledger. It intentionally has a distinct magic and payload type,
/// so a schema-v1 reader can never treat authority records as observation records.
pub struct AuthorityLedgerV2 {
    path: PathBuf,
    writer: BufWriter<File>,
    current_bytes: u64,
    maximum_bytes: u64,
}

impl AuthorityLedgerV2 {
    pub fn create(
        directory: &Path,
        filename: &str,
        maximum_bytes: u64,
    ) -> Result<Self, LedgerError> {
        if !safe_authority_filename(filename)
            || maximum_bytes <= AUTHORITY_MAGIC.len() as u64
            || maximum_bytes > MAX_SEGMENT_BYTES
        {
            return Err(LedgerError::InvalidSegmentLimits);
        }
        create_ledger_dir_all(directory)?;
        let path = directory.join(filename);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(AUTHORITY_MAGIC)?;
        file.sync_data()?;
        let writer = BufWriter::new(file);
        Ok(Self {
            path,
            writer,
            current_bytes: AUTHORITY_MAGIC.len() as u64,
            maximum_bytes,
        })
    }

    pub fn append(&mut self, record: &AuthorityRecordV2) -> Result<(), LedgerError> {
        let payload = serde_json::to_vec(record)?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| LedgerError::PayloadTooLarge { len: payload.len() })?;
        let frame_len = FRAME_HEADER_LEN as u64 + payload.len() as u64;
        if self.current_bytes.saturating_add(frame_len) > self.maximum_bytes {
            return Err(LedgerError::FrameExceedsSegment {
                frame_bytes: frame_len,
                segment_bytes: self.maximum_bytes,
            });
        }
        self.writer.write_all(&payload_len.to_le_bytes())?;
        self.writer
            .write_all(&crc32fast::hash(&payload).to_le_bytes())?;
        self.writer.write_all(&payload)?;
        self.current_bytes += frame_len;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), LedgerError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    pub fn integrity(&mut self) -> Result<(u64, String), LedgerError> {
        self.flush()?;
        let bytes = fs::read(&self.path)?;
        Ok((
            bytes.len() as u64,
            format!("sha256:{:x}", Sha256::digest(&bytes)),
        ))
    }

    pub fn read_all(
        directory: &Path,
        filename: &str,
    ) -> Result<Vec<AuthorityRecordV2>, LedgerError> {
        if !safe_authority_filename(filename) {
            return Err(LedgerError::IntegrityMismatch);
        }
        let bytes = fs::read(directory.join(filename))?;
        Self::decode_records(&bytes)
    }

    pub fn read_authoritative_run(
        directory: &Path,
        manifest: &AuthorityRunManifestV2,
    ) -> Result<Vec<AuthorityRecordV2>, LedgerError> {
        if manifest.schema_version != 2
            || !manifest.clean_shutdown
            || !manifest.writer_healthy
            || manifest.dropped != 0
            || !safe_authority_filename(&manifest.records_file)
            || manifest.records_file != format!("authority-{}.bwl", manifest.run_id)
        {
            return Err(LedgerError::IntegrityMismatch);
        }
        let directory = open_anchored_directory(directory)?;
        validate_private_authority_object(
            &directory.metadata().map_err(LedgerError::from)?,
            PrivateAuthorityObject::Directory,
        )?;
        Self::read_authoritative_run_at(&directory, manifest)
    }

    fn read_authoritative_run_at(
        directory: &File,
        manifest: &AuthorityRunManifestV2,
    ) -> Result<Vec<AuthorityRecordV2>, LedgerError> {
        let expected_bytes = manifest
            .records_bytes
            .ok_or(LedgerError::IntegrityMismatch)?;
        let bytes = read_file_at_exact(
            directory.as_raw_fd(),
            &manifest.records_file,
            expected_bytes,
            MAX_SEGMENT_BYTES,
        )?;
        let observed_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if manifest.records_bytes != Some(bytes.len() as u64)
            || manifest.records_digest.as_deref() != Some(observed_digest.as_str())
        {
            return Err(LedgerError::IntegrityMismatch);
        }
        Self::decode_records(&bytes)
    }

    pub fn read_validated_authority_run(
        manifest_path: &Path,
    ) -> Result<ValidatedAuthorityRunReadV2, AuthorityAuthoritativeReadError> {
        Self::read_validated_authority_run_inner(manifest_path, || {})
    }

    pub fn read_validated_authority_diagnostic_run(
        manifest_path: &Path,
    ) -> Result<ValidatedAuthorityDiagnosticRunReadV2, AuthorityAuthoritativeReadError> {
        let parent = manifest_path.parent().ok_or(RunError::InvalidManifest)?;
        let filename = manifest_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RunError::InvalidManifest)?;
        let directory = open_anchored_directory(parent)?;
        validate_private_authority_object(
            &directory.metadata().map_err(LedgerError::from)?,
            PrivateAuthorityObject::Directory,
        )?;
        let manifest = load_authority_manifest_at(&directory, filename)?;
        let records = Self::read_authoritative_run_at(&directory, &manifest)?;
        let (diagnostics, complete) = validate_authority_diagnostic_run_v2(&manifest, &records)?;
        Ok(ValidatedAuthorityDiagnosticRunReadV2 {
            records,
            diagnostics,
            complete,
        })
    }

    fn read_validated_authority_run_inner<F: FnOnce()>(
        manifest_path: &Path,
        between_reads: F,
    ) -> Result<ValidatedAuthorityRunReadV2, AuthorityAuthoritativeReadError> {
        let parent = manifest_path.parent().ok_or(RunError::InvalidManifest)?;
        let filename = manifest_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RunError::InvalidManifest)?;
        let directory = open_anchored_directory(parent)?;
        validate_private_authority_object(
            &directory.metadata().map_err(LedgerError::from)?,
            PrivateAuthorityObject::Directory,
        )?;
        let manifest = load_authority_manifest_at(&directory, filename)?;
        between_reads();
        let records = Self::read_authoritative_run_at(&directory, &manifest)?;
        let diagnostics = validate_authority_run_structure_v2(&manifest, &records)?;
        let complete = ValidatedCompleteAuthorityRunV2 {
            run_id: diagnostics.run_id,
            records_digest: diagnostics.records_digest,
        };
        Ok(ValidatedAuthorityRunReadV2 {
            manifest,
            records,
            complete,
        })
    }

    fn decode_records(bytes: &[u8]) -> Result<Vec<AuthorityRecordV2>, LedgerError> {
        if bytes.len() > MAX_SEGMENT_BYTES as usize || !bytes.starts_with(AUTHORITY_MAGIC) {
            return Err(LedgerError::IntegrityMismatch);
        }
        let mut offset = AUTHORITY_MAGIC.len();
        let mut records = Vec::new();
        while offset < bytes.len() {
            if bytes.len() - offset < FRAME_HEADER_LEN {
                return Err(LedgerError::IntegrityMismatch);
            }
            let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            let expected_crc =
                u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            offset += FRAME_HEADER_LEN;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(LedgerError::IntegrityMismatch)?;
            let payload = &bytes[offset..end];
            if crc32fast::hash(payload) != expected_crc {
                return Err(LedgerError::IntegrityMismatch);
            }
            let record: AuthorityRecordV2 = serde_json::from_slice(payload)?;
            records.push(record);
            offset = end;
        }
        Ok(records)
    }
}

fn safe_authority_filename(value: &str) -> bool {
    value.starts_with("authority-")
        && value.ends_with(".bwl")
        && value.len() <= MAX_SEGMENT_FILENAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_authority_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.'))
}

fn bounded_authority_identifier(value: &str) -> bool {
    crate::identifier::is_bounded_identifier(value)
}

fn valid_authority_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: String,
    pub ts_ms: u64,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub sequence: Option<u64>,
    #[serde(default)]
    pub accounting_truncated: bool,
    #[serde(default)]
    pub protocol: ProtocolKind,
    #[serde(default)]
    pub observation_source: ObservationSource,
    #[serde(default)]
    pub coverage_status: CoverageStatus,
    #[serde(default)]
    pub coverage_reason: Option<String>,
    pub identity: WorkloadIdentity,
    pub decision: Decision,
    pub actual: ActualOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Absent,
    Clean {
        records: u64,
    },
    TornTail {
        records: u64,
        discarded_bytes: u64,
    },
    /// CRC mismatch: the bytes on disk were damaged (disk/write corruption).
    Corrupt {
        records: u64,
        at_offset: u64,
    },
    /// CRC is valid but the payload does not decode into `DecisionRecord`: the
    /// frame itself is intact, it just isn't a shape this build understands
    /// (schema drift), which is a different operator situation than disk
    /// corruption and must not be reported as one.
    Undecodable {
        records: u64,
        at_offset: u64,
    },
}

impl RecoveryOutcome {
    /// True when `Ledger::append` will refuse writes for this outcome (Corrupt or
    /// Undecodable). Callers deciding whether to enable shadow recording should use
    /// this instead of re-deriving the same match, so gateway/CLI call sites agree
    /// with the append path itself.
    pub fn blocks_append(&self) -> bool {
        matches!(
            self,
            RecoveryOutcome::Corrupt { .. } | RecoveryOutcome::Undecodable { .. }
        )
    }
}

pub struct Ledger {
    writer: BufWriter<File>,
    refusal: Option<AppendRefusal>,
}

/// Why further appends are refused. Kept distinct from `RecoveryOutcome` so the
/// append path can report the precise reason without re-deriving it from records/offset.
#[derive(Debug, Clone, Copy)]
enum AppendRefusal {
    Corrupt,
    Undecodable,
}

impl Ledger {
    /// Opens (or creates) `dir/decisions.bwl`. Runs recovery scan first.
    pub fn open(dir: &Path) -> Result<(Ledger, RecoveryOutcome), LedgerError> {
        let scan = scan_dir(dir, false)?;
        create_ledger_dir_all(dir)?;
        let path = ledger_path(dir);

        match scan.truncate_to {
            Some(truncate_to) => repair_torn_tail(&path, truncate_to)?,
            None if matches!(scan.outcome, RecoveryOutcome::Absent) => write_new_header(&path)?,
            None => {}
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)?;
        let refusal = match scan.outcome {
            RecoveryOutcome::Corrupt { .. } => Some(AppendRefusal::Corrupt),
            RecoveryOutcome::Undecodable { .. } => Some(AppendRefusal::Undecodable),
            _ => None,
        };
        let ledger = Ledger {
            writer: BufWriter::new(file),
            refusal,
        };

        Ok((ledger, scan.outcome))
    }

    pub fn append(&mut self, rec: &DecisionRecord) -> Result<(), LedgerError> {
        // Undecodable refuses appends for the same reason Corrupt does: reads stop
        // at the first undecodable frame (see scan_bytes), so anything appended past
        // it would be written but never read back. Refuse until an operator resolves
        // the schema drift, rather than silently accumulating invisible records.
        match self.refusal {
            Some(AppendRefusal::Corrupt) => return Err(LedgerError::CorruptRefusal),
            Some(AppendRefusal::Undecodable) => return Err(LedgerError::UndecodableRefusal),
            None => {}
        }

        self.writer.write_all(&encode_frame(rec)?)?;

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), LedgerError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    pub fn read_all(dir: &Path) -> Result<(Vec<DecisionRecord>, RecoveryOutcome), LedgerError> {
        let scan = scan_dir(dir, true)?;
        Ok((scan.records, scan.outcome))
    }
}

pub struct SegmentedLedger {
    directory: PathBuf,
    run_id: String,
    segment_bytes: u64,
    max_segments: u32,
    current_index: u32,
    current_len: u64,
    writer: BufWriter<File>,
    filenames: Vec<String>,
}

impl SegmentedLedger {
    pub fn open(
        directory: &Path,
        run_id: &str,
        segment_bytes: u64,
        max_segments: u32,
    ) -> Result<Self, LedgerError> {
        if segment_bytes <= MAGIC.len() as u64
            || segment_bytes > MAX_SEGMENT_BYTES
            || max_segments == 0
            || max_segments > MAX_SEGMENTS
        {
            return Err(LedgerError::InvalidSegmentLimits);
        }
        create_ledger_dir_all(directory)?;
        let segments = segment_paths(directory, run_id)?;
        let (current_index, path, filenames) = if segments.is_empty() {
            let index = 0;
            let filename = segment_filename(run_id, index);
            let path = directory.join(&filename);
            write_new_header(&path)?;
            (index, path, vec![filename])
        } else {
            for (_, path) in &segments {
                let scan = scan_bytes(&fs::read(path)?, false)?;
                match scan.outcome {
                    RecoveryOutcome::Corrupt { .. } => return Err(LedgerError::CorruptRefusal),
                    RecoveryOutcome::Undecodable { .. } => {
                        return Err(LedgerError::UndecodableRefusal)
                    }
                    RecoveryOutcome::TornTail { .. } => {
                        if let Some(offset) = scan.truncate_to {
                            repair_torn_tail(path, offset)?;
                        }
                    }
                    RecoveryOutcome::Absent | RecoveryOutcome::Clean { .. } => {}
                }
            }
            let (index, path) = segments.last().expect("non-empty segments").clone();
            let filenames = segments
                .iter()
                .map(|(_, path)| {
                    path.file_name()
                        .expect("segment path has filename")
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            (index, path, filenames)
        };
        let current_len = fs::metadata(&path)?.len();
        let writer = open_append_writer(&path)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            run_id: run_id.to_string(),
            segment_bytes,
            max_segments,
            current_index,
            current_len,
            writer,
            filenames,
        })
    }

    pub fn append(&mut self, record: &DecisionRecord) -> Result<(), LedgerError> {
        let frame = encode_frame(record)?;
        let frame_len = frame.len() as u64;
        if MAGIC.len() as u64 + frame_len > self.segment_bytes {
            return Err(LedgerError::FrameExceedsSegment {
                frame_bytes: frame_len,
                segment_bytes: self.segment_bytes,
            });
        }
        if self.current_len + frame_len > self.segment_bytes {
            self.rotate()?;
        }
        self.writer.write_all(&frame)?;
        self.current_len += frame_len;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), LedgerError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    pub fn segment_filenames(&self) -> &[String] {
        &self.filenames
    }

    pub fn read_run(
        directory: &Path,
        run_id: &str,
    ) -> Result<(Vec<DecisionRecord>, Vec<RecoveryOutcome>), LedgerError> {
        let segments = segment_paths(directory, run_id)?;
        let mut records = Vec::new();
        let mut outcomes = Vec::new();
        for (_, path) in segments {
            let scan = scan_bytes(&fs::read(path)?, true)?;
            records.extend(scan.records);
            outcomes.push(scan.outcome);
        }
        Ok((records, outcomes))
    }

    pub fn integrity_inventory(&mut self) -> Result<(Vec<RunSegment>, String), LedgerError> {
        self.flush()?;
        inventory_for_names(&self.directory, &self.run_id, &self.filenames)
    }

    pub fn read_authoritative_run(
        directory: &Path,
        manifest: &RunManifest,
    ) -> Result<Vec<DecisionRecord>, LedgerError> {
        Self::read_authoritative_run_inner(directory, manifest, || {})
    }

    #[cfg(test)]
    fn read_authoritative_run_with_hook<F: FnOnce()>(
        directory: &Path,
        manifest: &RunManifest,
        hook: F,
    ) -> Result<Vec<DecisionRecord>, LedgerError> {
        Self::read_authoritative_run_inner(directory, manifest, hook)
    }

    fn read_authoritative_run_inner<F: FnOnce()>(
        directory: &Path,
        manifest: &RunManifest,
        hook: F,
    ) -> Result<Vec<DecisionRecord>, LedgerError> {
        if manifest.segment_inventory.len() != manifest.segments.len()
            || manifest.segment_inventory.len() > manifest.max_segments as usize
            || manifest.segment_bytes > MAX_SEGMENT_BYTES
            || manifest.max_segments > MAX_SEGMENTS
            || manifest.records_digest.is_none()
            || manifest.segment_inventory.iter().any(|segment| {
                segment.bytes > manifest.segment_bytes || segment.bytes > MAX_SEGMENT_BYTES
            })
        {
            return Err(LedgerError::IntegrityMismatch);
        }
        let directory_file = open_anchored_directory(directory)?;
        validate_private_authority_object(
            &directory_file.metadata().map_err(LedgerError::from)?,
            PrivateAuthorityObject::Directory,
        )?;
        validate_segment_names_at(
            directory_file.as_raw_fd(),
            &manifest.run_id,
            &manifest.segments,
            manifest.max_segments,
        )?;
        let mut records = Vec::new();
        for (segment, expected) in manifest.segments.iter().zip(&manifest.segment_inventory) {
            let bytes = read_file_at_exact(
                directory_file.as_raw_fd(),
                segment,
                expected.bytes,
                manifest.segment_bytes.min(MAX_SEGMENT_BYTES),
            )?;
            let scan = scan_bytes(&bytes, true)?;
            let RecoveryOutcome::Clean { records: count } = scan.outcome else {
                return Err(LedgerError::IntegrityMismatch);
            };
            let actual = RunSegment {
                name: segment.clone(),
                bytes: bytes.len() as u64,
                records: count,
                first_sequence: scan.records.first().and_then(|record| record.sequence),
                last_sequence: scan.records.last().and_then(|record| record.sequence),
                digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
            };
            if &actual != expected {
                return Err(LedgerError::IntegrityMismatch);
            }
            records.extend(scan.records);
        }
        let digest = canonical_decision_records_digest(&records)?;
        if manifest.records_digest.as_deref() != Some(&digest) {
            return Err(LedgerError::IntegrityMismatch);
        }
        hook();
        if records.len() as u64 != manifest.recorded
            || manifest.next_sequence
                != manifest
                    .recorded
                    .checked_add(1)
                    .ok_or(LedgerError::IntegrityMismatch)?
            || records.iter().enumerate().any(|(index, record)| {
                record.run_id.as_deref() != Some(&manifest.run_id)
                    || record.sequence
                        != u64::try_from(index)
                            .ok()
                            .and_then(|value| value.checked_add(1))
            })
        {
            return Err(LedgerError::IntegrityMismatch);
        }
        Ok(records)
    }

    fn rotate(&mut self) -> Result<(), LedgerError> {
        if self.filenames.len() >= self.max_segments as usize {
            return Err(LedgerError::SegmentLimit {
                max_segments: self.max_segments,
            });
        }
        self.flush()?;
        self.current_index = self
            .current_index
            .checked_add(1)
            .ok_or(LedgerError::SegmentIndexOverflow)?;
        let filename = segment_filename(&self.run_id, self.current_index);
        let path = self.directory.join(&filename);
        write_new_header(&path)?;
        self.writer = open_append_writer(&path)?;
        self.current_len = MAGIC.len() as u64;
        self.filenames.push(filename);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("ledger JSON frame failed to decode: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ledger payload too large: {len} bytes")]
    PayloadTooLarge { len: usize },
    #[error("refusing to append to corrupt ledger")]
    CorruptRefusal,
    #[error("refusing to append past an undecodable ledger record (schema drift)")]
    UndecodableRefusal,
    #[error("ledger segment limits must be greater than zero")]
    InvalidSegmentLimits,
    #[error(
        "record frame ({frame_bytes} bytes) exceeds configured segment size ({segment_bytes} bytes)"
    )]
    FrameExceedsSegment {
        frame_bytes: u64,
        segment_bytes: u64,
    },
    #[error("run reached configured ledger segment limit {max_segments}")]
    SegmentLimit { max_segments: u32 },
    #[error("ledger segment index overflow")]
    SegmentIndexOverflow,
    #[error("decision-run integrity mismatch")]
    IntegrityMismatch,
}

struct Scan {
    records: Vec<DecisionRecord>,
    outcome: RecoveryOutcome,
    truncate_to: Option<u64>,
}

fn ledger_path(dir: &Path) -> PathBuf {
    dir.join(LEDGER_FILE)
}

fn encode_frame(record: &DecisionRecord) -> Result<Vec<u8>, LedgerError> {
    let payload = serde_json::to_vec(record)?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| LedgerError::PayloadTooLarge { len: payload.len() })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn segment_filename(run_id: &str, index: u32) -> String {
    format!("run-{run_id}-{index:06}.bwl")
}

fn segment_paths(directory: &Path, run_id: &str) -> Result<Vec<(u32, PathBuf)>, LedgerError> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let prefix = format!("run-{run_id}-");
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(index) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".bwl"))
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        paths.push((index, entry.path()));
    }
    paths.sort_by_key(|(index, _)| *index);
    Ok(paths)
}

fn inventory_for_names(
    directory: &Path,
    run_id: &str,
    names: &[String],
) -> Result<(Vec<RunSegment>, String), LedgerError> {
    let directory = open_anchored_directory(directory)?;
    inventory_for_names_at(directory.as_raw_fd(), run_id, names)
}

fn inventory_for_names_at(
    directory_fd: RawFd,
    run_id: &str,
    names: &[String],
) -> Result<(Vec<RunSegment>, String), LedgerError> {
    let mut inventory = Vec::with_capacity(names.len());
    let mut all_records = Vec::new();
    for (index, name) in names.iter().enumerate() {
        if name
            != &segment_filename(
                run_id,
                u32::try_from(index).map_err(|_| LedgerError::IntegrityMismatch)?,
            )
        {
            return Err(LedgerError::IntegrityMismatch);
        }
        let bytes = read_file_at(directory_fd, name, MAX_SEGMENT_BYTES)?;
        let scan = scan_bytes(&bytes, true)?;
        let RecoveryOutcome::Clean { records } = scan.outcome else {
            return Err(LedgerError::IntegrityMismatch);
        };
        let first_sequence = scan.records.first().and_then(|record| record.sequence);
        let last_sequence = scan.records.last().and_then(|record| record.sequence);
        inventory.push(RunSegment {
            name: name.clone(),
            bytes: bytes.len() as u64,
            records,
            first_sequence,
            last_sequence,
            digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
        });
        all_records.extend(scan.records);
    }
    let digest = canonical_decision_records_digest(&all_records)?;
    Ok((inventory, digest))
}

fn open_anchored_directory(path: &Path) -> Result<File, LedgerError> {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = CString::new("/").map_err(|_| LedgerError::IntegrityMismatch)?;
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for component in absolute.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(LedgerError::IntegrityMismatch);
            }
        };
        let name = CString::new(name.as_bytes()).map_err(|_| LedgerError::IntegrityMismatch)?;
        let next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(next) };
    }
    Ok(directory)
}

fn read_file_at(directory_fd: RawFd, name: &str, maximum: u64) -> Result<Vec<u8>, LedgerError> {
    if name.is_empty() || name.len() > MAX_SEGMENT_FILENAME_BYTES {
        return Err(LedgerError::IntegrityMismatch);
    }
    let name = CString::new(name).map_err(|_| LedgerError::IntegrityMismatch)?;
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    validate_private_authority_object(&metadata, PrivateAuthorityObject::RegularFile)?;
    if metadata.len() > maximum {
        return Err(LedgerError::IntegrityMismatch);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| LedgerError::IntegrityMismatch)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| LedgerError::IntegrityMismatch)?;
    file.take(maximum.checked_add(1).unwrap_or(maximum))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(LedgerError::IntegrityMismatch);
    }
    Ok(bytes)
}

fn read_file_at_exact(
    directory_fd: RawFd,
    name: &str,
    expected: u64,
    maximum: u64,
) -> Result<Vec<u8>, LedgerError> {
    if expected > maximum || name.is_empty() || name.len() > MAX_SEGMENT_FILENAME_BYTES {
        return Err(LedgerError::IntegrityMismatch);
    }
    let component = CString::new(name).map_err(|_| LedgerError::IntegrityMismatch)?;
    let fd = unsafe {
        libc::openat(
            directory_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    validate_private_authority_object(&metadata, PrivateAuthorityObject::RegularFile)?;
    if metadata.len() != expected || metadata.len() > maximum {
        return Err(LedgerError::IntegrityMismatch);
    }
    let length = usize::try_from(expected).map_err(|_| LedgerError::IntegrityMismatch)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| LedgerError::IntegrityMismatch)?;
    file.take(
        expected
            .checked_add(1)
            .ok_or(LedgerError::IntegrityMismatch)?,
    )
    .read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(LedgerError::IntegrityMismatch);
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum PrivateAuthorityObject {
    Directory,
    RegularFile,
}

fn validate_private_authority_object(
    metadata: &fs::Metadata,
    object: PrivateAuthorityObject,
) -> Result<(), LedgerError> {
    let expected_type = match object {
        PrivateAuthorityObject::Directory => metadata.file_type().is_dir(),
        PrivateAuthorityObject::RegularFile => metadata.file_type().is_file(),
    };
    let expected_mode = match object {
        PrivateAuthorityObject::Directory => 0o700,
        PrivateAuthorityObject::RegularFile => 0o600,
    };
    if private_authority_object_is_trusted(
        expected_type,
        metadata.permissions().mode() & 0o777,
        metadata.uid(),
        unsafe { libc::geteuid() },
        expected_mode,
    ) {
        Ok(())
    } else {
        Err(LedgerError::IntegrityMismatch)
    }
}

fn private_authority_object_is_trusted(
    expected_type: bool,
    mode: u32,
    owner: u32,
    effective_user: u32,
    expected_mode: u32,
) -> bool {
    expected_type && mode == expected_mode && owner == effective_user
}

fn validate_segment_names_at(
    directory_fd: RawFd,
    run_id: &str,
    expected: &[String],
    manifest_limit: u32,
) -> Result<(), LedgerError> {
    validate_segment_names_at_inner(
        directory_fd,
        run_id,
        expected,
        manifest_limit,
        MAX_LEDGER_DIRECTORY_ENTRIES_SCAN,
    )
}

fn validate_segment_names_at_inner(
    directory_fd: RawFd,
    run_id: &str,
    expected: &[String],
    manifest_limit: u32,
    maximum_entries_scan: usize,
) -> Result<(), LedgerError> {
    let duplicated = unsafe { libc::dup(directory_fd) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        unsafe {
            libc::close(duplicated);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = DirectoryStream(stream);
    let prefix = format!("run-{run_id}-");
    let mut seen = vec![false; expected.len()];
    let mut matched = 0usize;
    let mut scanned = 0usize;
    let limit = usize::try_from(manifest_limit.min(MAX_SEGMENTS))
        .map_err(|_| LedgerError::IntegrityMismatch)?;
    loop {
        reset_errno();
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = current_errno();
            if errno == 0 {
                break;
            }
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        let raw_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(raw_name.to_bytes(), b"." | b"..") {
            continue;
        }
        scanned = scanned
            .checked_add(1)
            .ok_or(LedgerError::IntegrityMismatch)?;
        if scanned > maximum_entries_scan {
            return Err(LedgerError::IntegrityMismatch);
        }
        let name = raw_name.to_string_lossy();
        if !name.starts_with(&prefix) || !name.ends_with(".bwl") {
            continue;
        }
        if raw_name.to_bytes().len() > MAX_SEGMENT_FILENAME_BYTES {
            return Err(LedgerError::IntegrityMismatch);
        }
        matched = matched
            .checked_add(1)
            .ok_or(LedgerError::IntegrityMismatch)?;
        if matched > limit || matched > expected.len() {
            return Err(LedgerError::IntegrityMismatch);
        }
        let Some(index) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".bwl"))
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return Err(LedgerError::IntegrityMismatch);
        };
        let index = usize::try_from(index).map_err(|_| LedgerError::IntegrityMismatch)?;
        if index >= expected.len() || expected[index] != name || seen[index] {
            return Err(LedgerError::IntegrityMismatch);
        }
        seen[index] = true;
    }
    if matched != expected.len() || seen.iter().any(|present| !present) {
        return Err(LedgerError::IntegrityMismatch);
    }
    Ok(())
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

fn reset_errno() {
    unsafe {
        *errno_location() = 0;
    }
}

fn current_errno() -> libc::c_int {
    unsafe { *errno_location() }
}

pub fn canonical_decision_records_digest(
    records: &[DecisionRecord],
) -> Result<String, LedgerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"bowline.decision-run.records.v1\0");
    for record in records {
        let bytes = serde_json::to_vec(record)?;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn open_append_writer(path: &Path) -> Result<BufWriter<File>, LedgerError> {
    let file = OpenOptions::new()
        .append(true)
        .read(true)
        .mode(0o600)
        .open(path)?;
    Ok(BufWriter::new(file))
}

fn create_ledger_dir_all(dir: &Path) -> Result<(), LedgerError> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    Ok(())
}

fn scan_dir(dir: &Path, collect_records: bool) -> Result<Scan, LedgerError> {
    if !dir.exists() {
        return Ok(absent_scan());
    }

    let path = ledger_path(dir);
    if !path.exists() {
        return Ok(absent_scan());
    }

    scan_bytes(&fs::read(path)?, collect_records)
}

fn scan_bytes(bytes: &[u8], collect_records: bool) -> Result<Scan, LedgerError> {
    if bytes.len() < MAGIC.len() {
        return Ok(Scan {
            records: Vec::new(),
            outcome: RecoveryOutcome::TornTail {
                records: 0,
                discarded_bytes: bytes.len() as u64,
            },
            truncate_to: Some(0),
        });
    }

    if &bytes[..MAGIC.len()] != MAGIC {
        return Ok(Scan {
            records: Vec::new(),
            outcome: RecoveryOutcome::Corrupt {
                records: 0,
                at_offset: 0,
            },
            truncate_to: None,
        });
    }

    let mut records = Vec::new();
    let mut offset = MAGIC.len();
    let mut record_count = 0_u64;

    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < FRAME_HEADER_LEN {
            return Ok(torn_scan(records, record_count, offset, bytes.len()));
        }

        let payload_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("slice length is checked"),
        ) as usize;
        let expected_crc = u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .expect("slice length is checked"),
        );
        let payload_start = offset + FRAME_HEADER_LEN;
        let Some(frame_end) = payload_start.checked_add(payload_len) else {
            return Ok(torn_scan(records, record_count, offset, bytes.len()));
        };
        if frame_end > bytes.len() {
            return Ok(torn_scan(records, record_count, offset, bytes.len()));
        }

        let payload = &bytes[payload_start..frame_end];
        if crc32fast::hash(payload) != expected_crc {
            return Ok(Scan {
                records,
                outcome: RecoveryOutcome::Corrupt {
                    records: record_count,
                    at_offset: offset as u64,
                },
                truncate_to: None,
            });
        }

        // Decode is attempted for every frame, even when collect_records is false
        // (the Ledger::open scan). This is the fix for the open/read_all asymmetry:
        // open used to only check CRC, so it could call a ledger "clean" that
        // read_all then hard-errored on. Now both paths run the same scan and reach
        // the same RecoveryOutcome, so open's classification is never contradicted.
        //
        // A frame that fails to decode here has a valid CRC (checked above) but its
        // payload isn't a `DecisionRecord` — schema drift, not disk corruption. We
        // stop at the first such frame and return the decodable prefix, exactly like
        // torn-tail/corrupt: it's the simplest safe choice, and it matches the
        // guarantee callers already rely on (a returned prefix is fully readable).
        // A decodable frame appearing after an undecodable one is deliberately not
        // recovered — resuming past unknown schema shapes risks silently reordering
        // or misinterpreting data padding that happens to satisfy CRC by chance.
        match serde_json::from_slice::<DecisionRecord>(payload) {
            Ok(record) => {
                if collect_records {
                    records.push(record);
                }
            }
            Err(_) => {
                return Ok(Scan {
                    records,
                    outcome: RecoveryOutcome::Undecodable {
                        records: record_count,
                        at_offset: offset as u64,
                    },
                    truncate_to: None,
                });
            }
        }
        record_count += 1;
        offset = frame_end;
    }

    Ok(Scan {
        records,
        outcome: RecoveryOutcome::Clean {
            records: record_count,
        },
        truncate_to: None,
    })
}

fn absent_scan() -> Scan {
    Scan {
        records: Vec::new(),
        outcome: RecoveryOutcome::Absent,
        truncate_to: None,
    }
}

fn torn_scan(
    records: Vec<DecisionRecord>,
    record_count: u64,
    last_good_offset: usize,
    file_len: usize,
) -> Scan {
    Scan {
        records,
        outcome: RecoveryOutcome::TornTail {
            records: record_count,
            discarded_bytes: (file_len - last_good_offset) as u64,
        },
        truncate_to: Some(last_good_offset as u64),
    }
}

fn write_new_header(path: &Path) -> Result<(), LedgerError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(MAGIC)?;
    file.sync_data()?;
    Ok(())
}

fn repair_torn_tail(path: &Path, truncate_to: u64) -> Result<(), LedgerError> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .mode(0o600)
        .open(path)?;
    file.set_len(truncate_to)?;
    file.seek(SeekFrom::Start(truncate_to))?;
    if truncate_to == 0 {
        file.write_all(MAGIC)?;
    }
    file.sync_data()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use proptest::prelude::*;
    use tempfile::tempdir;

    use super::*;
    use crate::decision::{Decision, Placement};
    use crate::policy::WorkloadIdentity;
    use crate::run::{AuthorityRunDigestsV2, AuthorityRunStoreV2, RunDigests, RunLimits, RunStore};
    use crate::supply::TaskClass;
    use crate::traffic::{CoverageStatus, ObservationSource, ProtocolKind};

    const MAGIC_LEN: usize = 5;
    const FRAME_HEADER_LEN: usize = 8;

    fn remediation_digest(value: u8) -> String {
        format!("sha256:{value:064x}")
    }

    fn remediation_candidate_decision(id: &str) -> AuthorityDecisionV2 {
        AuthorityDecisionV2 {
            decision_id: id.into(),
            replaces_decision_id: None,
            configured_fallback_target: Some(PlanTarget::Original),
            ts_ms: 10,
            route_id: "chat-canary".into(),
            mode: RouteMode::CanaryEnforce,
            protocol: AuthorityProtocol::ChatCompletions,
            task_class: TaskClass::HeavyLifting,
            workload_identity_digest: Some(remediation_digest(1)),
            app: Some("support".into()),
            resolved_tags: vec!["production".into()],
            requested_supply_id: Some("owned/a".into()),
            reason: SelectionReason::CandidateSelected,
            evidence_state: EvidenceState::Presented,
            selection_facts: AuthoritySelectionFactsV2::canonical_candidate(7),
            target: PlanTarget::Candidate,
            intended_dispatch: 1,
            grant: Some(AuthorityGrantBindingV2 {
                grant_digest: remediation_digest(2),
                expires_at_ms: 100,
                economics_source_digest: remediation_digest(3),
                quality_source_digest: remediation_digest(4),
                opportunity_digest: remediation_digest(5),
            }),
            selected_supply_id: Some("owned/a".into()),
            baseline_supply_id: Some("public/b".into()),
            actuator_identity_digest: Some(remediation_digest(6)),
            actuator_config_digest: Some(remediation_digest(7)),
            enforcement_config_digest: remediation_digest(8),
            route_config_digest: remediation_digest(9),
            model_rewritten: true,
        }
    }

    fn remediation_rejected_outcome(decision: &AuthorityDecisionV2) -> AuthorityOutcomeV2 {
        AuthorityOutcomeV2 {
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
            circuit_before: CircuitStateV2::Closed,
            circuit_after: CircuitStateV2::Closed,
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
        }
    }

    fn remediation_replacement_decision(candidate: &AuthorityDecisionV2) -> AuthorityDecisionV2 {
        let mut replacement = candidate.clone();
        replacement.decision_id = "replacement-1".into();
        replacement.replaces_decision_id = Some(candidate.decision_id.clone());
        replacement.configured_fallback_target = None;
        replacement.reason = SelectionReason::CandidateUnavailable;
        replacement.evidence_state = EvidenceState::Unverified;
        replacement.selection_facts = AuthoritySelectionFactsV2::canonical_fallback(
            AuthorityFallbackReasonV2::CandidateUnavailable,
        );
        replacement.selection_facts.bucket = candidate.selection_facts.bucket;
        replacement.target = PlanTarget::Original;
        replacement.grant = None;
        replacement.selected_supply_id = replacement.baseline_supply_id.clone();
        replacement.actuator_identity_digest = None;
        replacement.actuator_config_digest = None;
        replacement.model_rewritten = false;
        replacement
    }

    fn remediation_replacement_outcome(decision: &AuthorityDecisionV2) -> AuthorityOutcomeV2 {
        AuthorityOutcomeV2 {
            decision_id: decision.decision_id.clone(),
            replaces_decision_id: decision.replaces_decision_id.clone(),
            ts_ms: 30,
            route_id: decision.route_id.clone(),
            mode: decision.mode,
            protocol: decision.protocol,
            task_class: decision.task_class,
            workload_identity_digest: decision.workload_identity_digest.clone(),
            app: decision.app.clone(),
            resolved_tags: decision.resolved_tags.clone(),
            requested_supply_id: decision.requested_supply_id.clone(),
            selection_facts: decision.selection_facts.clone(),
            grant_digest: None,
            grant_expires_at_ms: None,
            model_rewritten: false,
            selected_supply_id: decision.selected_supply_id.clone(),
            baseline_supply_id: decision.baseline_supply_id.clone(),
            actuator_identity_digest: None,
            actuator_config_digest: None,
            enforcement_config_digest: decision.enforcement_config_digest.clone(),
            route_config_digest: decision.route_config_digest.clone(),
            target: decision.target,
            fallback_reason: Some(AuthorityFallbackReasonV2::CandidateUnavailable),
            circuit_before: decision.selection_facts.circuit_before,
            circuit_after: decision.selection_facts.circuit_before,
            actual_dispatch: 1,
            completion: CompletionStateV2::Succeeded,
            candidate_failure: None,
            status: Some(200),
            input_tokens: None,
            output_tokens: None,
            usage_source: UsageSource::Missing,
            observed_actual_cost_micros: None,
            approved_counterfactual_cost_micros: None,
            enforced_modeled_delta_micros: None,
        }
    }

    fn remediation_manifest(record_count: u64) -> AuthorityRunManifestV2 {
        AuthorityRunManifestV2 {
            schema_version: 2,
            run_id: "authority-run".into(),
            started_at_ms: 1,
            ended_at_ms: Some(40),
            clean_shutdown: true,
            writer_healthy: true,
            writer_error: None,
            enforcement_digest: remediation_digest(8),
            actuator_set_digest: remediation_digest(10),
            grant_set_digest: remediation_digest(11),
            accepted: record_count,
            recorded: record_count,
            dropped: 0,
            next_sequence: record_count + 1,
            records_file: "authority-authority-run.bwl".into(),
            records_bytes: Some(123),
            records_digest: Some(remediation_digest(12)),
            last_flush_at_ms: Some(35),
        }
    }

    fn remediation_linked_records() -> Vec<AuthorityRecordV2> {
        let candidate = remediation_candidate_decision("candidate-1");
        let rejected = remediation_rejected_outcome(&candidate);
        let replacement = remediation_replacement_decision(&candidate);
        let replacement_outcome = remediation_replacement_outcome(&replacement);
        vec![
            AuthorityRecordV2::decision(1, candidate).unwrap(),
            AuthorityRecordV2::outcome(2, rejected).unwrap(),
            AuthorityRecordV2::decision(3, replacement).unwrap(),
            AuthorityRecordV2::outcome(4, replacement_outcome).unwrap(),
        ]
    }

    fn remediation_resequence(records: Vec<AuthorityRecordV2>) -> Vec<AuthorityRecordV2> {
        records
            .into_iter()
            .enumerate()
            .map(|(index, record)| {
                let sequence = u64::try_from(index).unwrap() + 1;
                match record {
                    AuthorityRecordV2::Decision { decision, .. } => {
                        AuthorityRecordV2::decision(sequence, decision).unwrap()
                    }
                    AuthorityRecordV2::Outcome { outcome, .. } => {
                        AuthorityRecordV2::outcome(sequence, outcome).unwrap()
                    }
                }
            })
            .collect()
    }

    #[test]
    fn authority_evidence_accepts_configured_identifier_grammar_but_not_for_lifecycle_ids() {
        let mut decision = remediation_candidate_decision("candidate-1");
        decision.route_id = "routé:α/v1!".into();
        decision.app = Some("app:支援!".into());
        decision.resolved_tags = vec!["environment:test".into(), "région:eu-west/1".into()];
        decision.requested_supply_id = Some("requested/模型:v1?".into());
        decision.selected_supply_id = Some("owned/équipe:v1!".into());
        decision.baseline_supply_id = Some("public/基準:v1?".into());
        let outcome = remediation_rejected_outcome(&decision);
        validate_authority_pair_v2(&decision, &outcome)
            .expect("configured Unicode and punctuation identifiers remain durable");

        for lifecycle_id in ["décision-1", "decision:1", "decision 1"] {
            let mut invalid = decision.clone();
            invalid.decision_id = lifecycle_id.into();
            assert!(
                invalid.validate().is_err(),
                "accepted lifecycle id {lifecycle_id}"
            );
        }

        for invalid_value in [
            "".to_owned(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "control\nvalue".to_owned(),
            "x".repeat(crate::enforcement::MAX_IDENTIFIER_BYTES + 1),
        ] {
            let mut invalid = decision.clone();
            invalid.route_id = invalid_value;
            assert!(invalid.validate().is_err());
        }

        for field in ["route", "app", "tag", "requested", "selected", "baseline"] {
            let mut invalid = outcome.clone();
            match field {
                "route" => invalid.route_id = " invalid".into(),
                "app" => invalid.app = Some(" invalid".into()),
                "tag" => invalid.resolved_tags = vec![" invalid".into()],
                "requested" => invalid.requested_supply_id = Some(" invalid".into()),
                "selected" => invalid.selected_supply_id = Some(" invalid".into()),
                "baseline" => invalid.baseline_supply_id = Some(" invalid".into()),
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err(), "accepted invalid {field}");
        }
    }

    #[test]
    fn pre_dispatch_rejected_is_a_narrow_candidate_terminal() {
        let decision = remediation_candidate_decision("candidate-1");
        let outcome = remediation_rejected_outcome(&decision);
        outcome.validate().expect("exact rejection validates");
        validate_authority_pair_v2(&decision, &outcome).expect("exact rejection pairs");

        type OutcomeMutation = Box<dyn Fn(&mut AuthorityOutcomeV2)>;
        let mut mutations: Vec<OutcomeMutation> = vec![
            Box::new(|outcome| outcome.target = PlanTarget::Original),
            Box::new(|outcome| outcome.actual_dispatch = 1),
            Box::new(|outcome| outcome.status = Some(503)),
            Box::new(|outcome| outcome.candidate_failure = Some(CandidateFailureClassV2::Connect)),
            Box::new(|outcome| outcome.input_tokens = Some(1)),
            Box::new(|outcome| outcome.observed_actual_cost_micros = Some(1)),
            Box::new(|outcome| outcome.circuit_after = CircuitStateV2::Open),
        ];
        for mutate in mutations.drain(..) {
            let mut invalid = outcome.clone();
            mutate(&mut invalid);
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn replacement_link_requires_one_exact_unchained_route_fallback() {
        let records = remediation_linked_records();
        validate_authority_run_v2(&remediation_manifest(4), &records)
            .expect("complete linked transition validates");
        for partial_len in 1..=3 {
            assert!(
                validate_authority_run_v2(
                    &remediation_manifest(partial_len as u64),
                    &records[..partial_len],
                )
                .is_err(),
                "crash after {partial_len} writes remains incomplete after restart"
            );
        }

        for mutation in [
            "orphan",
            "duplicate",
            "chained",
            "route",
            "request",
            "task",
            "tags",
            "fallback",
            "config",
        ] {
            let mut changed = records.clone();
            if mutation == "duplicate" {
                let AuthorityRecordV2::Decision { decision, .. } = &changed[2] else {
                    unreachable!()
                };
                let mut duplicate = decision.clone();
                duplicate.decision_id = "replacement-2".into();
                let mut duplicate_outcome = remediation_replacement_outcome(&duplicate);
                duplicate_outcome.decision_id = "replacement-2".into();
                changed.push(AuthorityRecordV2::decision(5, duplicate).unwrap());
                changed.push(AuthorityRecordV2::outcome(6, duplicate_outcome).unwrap());
                let manifest = remediation_manifest(changed.len() as u64);
                assert!(validate_authority_run_v2(&manifest, &changed).is_err());
                continue;
            }
            let AuthorityRecordV2::Decision { decision, .. } = &mut changed[2] else {
                unreachable!()
            };
            match mutation {
                "orphan" => decision.replaces_decision_id = Some("missing".into()),
                "chained" => decision.replaces_decision_id = Some("replacement-1".into()),
                "route" => decision.route_id = "other-route".into(),
                "request" => decision.requested_supply_id = Some("other".into()),
                "task" => decision.task_class = TaskClass::Judgment,
                "tags" => decision.resolved_tags.push("other".into()),
                "fallback" => {
                    decision.target = PlanTarget::None;
                    decision.intended_dispatch = 0;
                    decision.selected_supply_id = None;
                }
                "config" => decision.route_config_digest = remediation_digest(99),
                _ => unreachable!(),
            }
            let manifest = remediation_manifest(changed.len() as u64);
            assert!(
                validate_authority_run_v2(&manifest, &changed).is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn replacement_link_rejects_coherent_target_and_bucket_tampering() {
        for configured_target in [PlanTarget::Original, PlanTarget::None] {
            let mut baseline = remediation_linked_records();
            let (candidate_records, replacement_records) = baseline.split_at_mut(3);
            let AuthorityRecordV2::Decision {
                decision: candidate,
                ..
            } = &mut candidate_records[0]
            else {
                unreachable!()
            };
            candidate.configured_fallback_target = Some(configured_target);
            let AuthorityRecordV2::Decision {
                decision: replacement,
                ..
            } = &mut candidate_records[2]
            else {
                unreachable!()
            };
            let AuthorityRecordV2::Outcome {
                outcome: replacement_outcome,
                ..
            } = &mut replacement_records[0]
            else {
                unreachable!()
            };
            if configured_target == PlanTarget::None {
                replacement.target = PlanTarget::None;
                replacement.intended_dispatch = 0;
                replacement.selected_supply_id = None;
                replacement_outcome.target = PlanTarget::None;
                replacement_outcome.actual_dispatch = 0;
                replacement_outcome.selected_supply_id = None;
                replacement_outcome.completion = CompletionStateV2::Local;
                replacement_outcome.status = None;
            }
            validate_authority_run_v2(&remediation_manifest(4), &baseline)
                .expect("baseline matches independently persisted configured fallback");

            for mutation in ["target", "bucket"] {
                let mut records = baseline.clone();
                let (candidate_records, replacement_records) = records.split_at_mut(3);
                let AuthorityRecordV2::Decision {
                    decision: replacement,
                    ..
                } = &mut candidate_records[2]
                else {
                    unreachable!()
                };
                let AuthorityRecordV2::Outcome {
                    outcome: replacement_outcome,
                    ..
                } = &mut replacement_records[0]
                else {
                    unreachable!()
                };
                match mutation {
                    "target" if configured_target == PlanTarget::Original => {
                        replacement.target = PlanTarget::None;
                        replacement.intended_dispatch = 0;
                        replacement.selected_supply_id = None;
                        replacement_outcome.target = PlanTarget::None;
                        replacement_outcome.actual_dispatch = 0;
                        replacement_outcome.selected_supply_id = None;
                        replacement_outcome.completion = CompletionStateV2::Local;
                        replacement_outcome.status = None;
                    }
                    "target" => {
                        replacement.target = PlanTarget::Original;
                        replacement.intended_dispatch = 1;
                        replacement.selected_supply_id = replacement.baseline_supply_id.clone();
                        replacement_outcome.target = PlanTarget::Original;
                        replacement_outcome.actual_dispatch = 1;
                        replacement_outcome.selected_supply_id =
                            replacement_outcome.baseline_supply_id.clone();
                        replacement_outcome.completion = CompletionStateV2::Succeeded;
                        replacement_outcome.status = Some(200);
                    }
                    "bucket" => {
                        replacement.selection_facts.bucket = Some(8);
                        replacement_outcome.selection_facts.bucket = Some(8);
                    }
                    _ => unreachable!(),
                }
                replacement
                    .validate()
                    .expect("coherent replacement validates");
                replacement_outcome
                    .validate()
                    .expect("coherent replacement terminal validates");
                validate_authority_pair_v2(replacement, replacement_outcome)
                    .expect("coherent replacement pair validates independently");
                assert!(
                    validate_authority_run_v2(&remediation_manifest(4), &records).is_err(),
                    "run validation must reject coherent {mutation} tampering from {configured_target:?}"
                );
            }
        }
    }

    #[test]
    fn replacement_link_requires_exact_durable_record_order() {
        let canonical = remediation_linked_records();
        for first in 0..4 {
            for second in 0..4 {
                for third in 0..4 {
                    for fourth in 0..4 {
                        let order = [first, second, third, fourth];
                        if order
                            .iter()
                            .copied()
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                            != 4
                        {
                            continue;
                        }
                        let records = remediation_resequence(
                            order
                                .iter()
                                .map(|index| canonical[*index].clone())
                                .collect(),
                        );
                        let result = validate_authority_run_v2(&remediation_manifest(4), &records);
                        if order == [0, 1, 2, 3] {
                            result.expect("canonical durable transition order validates");
                        } else {
                            assert!(
                                result.is_err(),
                                "out-of-order transition {order:?} must be rejected"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn replacement_link_fields_default_for_previous_schema_v2_records() {
        let decision = remediation_candidate_decision("candidate-1");
        let outcome = remediation_rejected_outcome(&decision);
        let mut decision_json = serde_json::to_value(decision).unwrap();
        decision_json
            .as_object_mut()
            .unwrap()
            .remove("replaces_decision_id");
        decision_json
            .as_object_mut()
            .unwrap()
            .remove("configured_fallback_target");
        let mut outcome_json = serde_json::to_value(outcome).unwrap();
        outcome_json
            .as_object_mut()
            .unwrap()
            .remove("replaces_decision_id");
        let decoded_decision: AuthorityDecisionV2 = serde_json::from_value(decision_json).unwrap();
        let decoded_outcome: AuthorityOutcomeV2 = serde_json::from_value(outcome_json).unwrap();
        assert_eq!(decoded_decision.replaces_decision_id, None);
        assert_eq!(decoded_decision.configured_fallback_target, None);
        assert_eq!(decoded_outcome.replaces_decision_id, None);

        let mut old_linked_records = remediation_linked_records();
        let AuthorityRecordV2::Decision { decision, .. } = &mut old_linked_records[0] else {
            unreachable!()
        };
        decision.configured_fallback_target = None;
        assert!(
            validate_authority_run_v2(&remediation_manifest(4), &old_linked_records).is_err(),
            "defaulted old candidate records cannot grant false linked-run completeness"
        );
    }

    #[derive(Debug, Clone, Copy)]
    struct FrameSpan {
        start: usize,
        payload_start: usize,
        end: usize,
    }

    #[test]
    fn private_authority_object_trust_rejects_wrong_owner_type_and_mode() {
        assert!(private_authority_object_is_trusted(
            true, 0o600, 501, 501, 0o600
        ));
        assert!(!private_authority_object_is_trusted(
            true, 0o600, 502, 501, 0o600
        ));
        assert!(!private_authority_object_is_trusted(
            true, 0o644, 501, 501, 0o600
        ));
        assert!(!private_authority_object_is_trusted(
            false, 0o600, 501, 501, 0o600
        ));
        assert!(private_authority_object_is_trusted(
            true, 0o700, 501, 501, 0o700
        ));
        assert!(!private_authority_object_is_trusted(
            true, 0o755, 501, 501, 0o700
        ));
    }

    #[test]
    fn validated_authority_restart_keeps_one_directory_descriptor_across_swap() {
        let temp = tempdir().unwrap();
        let directory = temp.path().join("authority");
        let digest = |value: u8| format!("sha256:{value:064x}");
        let run = AuthorityRunStoreV2::create(
            &directory,
            AuthorityRunDigestsV2 {
                enforcement: digest(1),
                actuator_set: digest(2),
                grant_set: digest(3),
            },
        )
        .unwrap();
        let snapshot = run.snapshot();
        let mut ledger =
            AuthorityLedgerV2::create(&directory, &snapshot.records_file, 1024 * 1024).unwrap();
        let (bytes, records_digest) = ledger.integrity().unwrap();
        run.finish(true, Some(bytes), Some(records_digest)).unwrap();
        let manifest_path = run.manifest_path().to_path_buf();
        drop(ledger);
        drop(run);

        let anchored = temp.path().join("anchored-original");
        let replacement = directory.clone();
        let verified =
            AuthorityLedgerV2::read_validated_authority_run_inner(&manifest_path, || {
                std::fs::rename(&directory, &anchored).unwrap();
                std::fs::create_dir(&replacement).unwrap();
                std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            })
            .unwrap();
        assert_eq!(verified.records().len(), 0);
        assert_eq!(verified.complete().run_id(), snapshot.run_id);
    }

    fn sample_record(n: u64) -> DecisionRecord {
        DecisionRecord {
            id: format!("00000000-0000-4000-8000-{n:012}"),
            ts_ms: 1_800_000_000_000 + n,
            run_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
            sequence: Some(n),
            accounting_truncated: false,
            protocol: ProtocolKind::ChatCompletions,
            observation_source: ObservationSource::Inline,
            coverage_status: CoverageStatus::Supported,
            coverage_reason: None,
            identity: WorkloadIdentity {
                api_key_digest: Some(format!("sha256:{n:064x}")),
                route: "/v1/chat/completions".to_string(),
                app: Some(format!("app-{n}")),
                tags: vec!["customer-data".to_string(), format!("tenant-{n}")],
            },
            decision: Decision {
                policy_digest: format!("sha256:{:064x}", n + 10),
                task_class: TaskClass::HeavyLifting,
                feasible_ids: vec![
                    "local/qwen3-32b".to_string(),
                    "openai/gpt-5-mini".to_string(),
                ],
                floor: 0.55,
                shadow: Some(Placement {
                    supply_id: "local/qwen3-32b".to_string(),
                    est_cost_usd: Some(n as f64 / 100.0),
                }),
            },
            actual: ActualOutcome {
                upstream: "openai".to_string(),
                supply_id: Some("openai/gpt-5-mini".to_string()),
                model: Some("gpt-5-mini".to_string()),
                status: 200,
                streamed: n.is_multiple_of(2),
                latency_ms: 100 + n,
                input_tokens: Some(1_000 + n),
                output_tokens: Some(200 + n),
                usage_source: UsageSource::Observed,
                est_cost_usd: Some(n as f64 / 10.0),
                attribution_status: AttributionStatus::StaticConfigured,
                attribution_source: AttributionSource::LegacyConfigured,
                attribution_reference: None,
                attribution_reason: None,
            },
        }
    }

    fn bound_run(directory: &Path) -> RunManifest {
        let store = RunStore::create(
            directory,
            RunDigests {
                policy: "sha256:policy".into(),
                registry: "sha256:registry".into(),
                attribution: None,
                owned_cost: None,
                passive_profile: None,
                passive_input: None,
            },
            RunLimits {
                segment_bytes: 4096,
                max_segments: 4,
            },
        )
        .unwrap();
        let run_id = store.run_id();
        let mut ledger = SegmentedLedger::open(directory, &run_id, 4096, 4).unwrap();
        let sequence = store.accept().unwrap();
        let mut record = sample_record(sequence);
        record.run_id = Some(run_id.clone());
        ledger.append(&record).unwrap();
        store.recorded(sequence).unwrap();
        for name in ledger.segment_filenames() {
            store.add_segment(name.clone()).unwrap();
        }
        let (inventory, digest) = ledger.integrity_inventory().unwrap();
        store.bind_integrity(inventory, digest).unwrap();
        store.finish(true).unwrap();
        store.snapshot()
    }

    #[test]
    fn authoritative_read_uses_one_validated_snapshot_and_enforces_size_boundaries() {
        let temp = tempdir().unwrap();
        let directory = fs::canonicalize(temp.path()).unwrap().join("run");
        let manifest = bound_run(&directory);
        let segment = directory.join(&manifest.segments[0]);
        let original = fs::read(&segment).unwrap();
        let held = directory.join("held-segment");
        let records =
            SegmentedLedger::read_authoritative_run_with_hook(&directory, &manifest, || {
                fs::rename(&segment, &held).unwrap();
                fs::write(&segment, b"attacker").unwrap();
            })
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(fs::read(&segment).unwrap(), b"attacker");
        fs::rename(&held, &segment).unwrap();

        let exact = manifest
            .segment_inventory
            .iter()
            .map(|value| value.bytes)
            .max()
            .unwrap();
        let mut exact_manifest = manifest.clone();
        exact_manifest.segment_bytes = exact;
        assert!(SegmentedLedger::read_authoritative_run(&directory, &exact_manifest).is_ok());
        exact_manifest.segment_bytes = exact - 1;
        assert!(SegmentedLedger::read_authoritative_run(&directory, &exact_manifest).is_err());

        let mut compiled_over = manifest.clone();
        compiled_over.segment_bytes = MAX_SEGMENT_BYTES + 1;
        assert!(SegmentedLedger::read_authoritative_run(&directory, &compiled_over).is_err());
        let mut count_over = manifest.clone();
        count_over.max_segments = MAX_SEGMENTS + 1;
        assert!(SegmentedLedger::read_authoritative_run(&directory, &count_over).is_err());
        let mut forged_exact = manifest.clone();
        forged_exact.segment_bytes = MAX_SEGMENT_BYTES;
        forged_exact.segment_inventory[0].bytes = MAX_SEGMENT_BYTES;
        assert!(SegmentedLedger::read_authoritative_run(&directory, &forged_exact).is_err());

        for index in 0..256 {
            fs::write(directory.join(format!("irrelevant-{index}")), b"ignored").unwrap();
        }
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_ok());
        let entries = fs::read_dir(&directory).unwrap().count();
        let anchored = open_anchored_directory(&directory).unwrap();
        assert!(validate_segment_names_at_inner(
            anchored.as_raw_fd(),
            &manifest.run_id,
            &manifest.segments,
            manifest.max_segments,
            entries,
        )
        .is_ok());
        let over_scan_limit = directory.join("irrelevant-over-scan-limit");
        fs::write(&over_scan_limit, b"ignored").unwrap();
        let anchored = open_anchored_directory(&directory).unwrap();
        assert!(validate_segment_names_at_inner(
            anchored.as_raw_fd(),
            &manifest.run_id,
            &manifest.segments,
            manifest.max_segments,
            entries,
        )
        .is_err());
        fs::remove_file(over_scan_limit).unwrap();

        let extra = directory.join(segment_filename(&manifest.run_id, 1));
        fs::write(&extra, &original).unwrap();
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_err());
        fs::remove_file(extra).unwrap();

        let sparse = directory.join(&manifest.segments[0]);
        let file = OpenOptions::new().write(true).open(&sparse).unwrap();
        file.set_len(MAX_SEGMENT_BYTES + 1).unwrap();
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_err());
        fs::write(sparse, original).unwrap();
    }

    #[test]
    fn integrity_inventory_refuses_a_loosened_segment_before_sealing_the_digest() {
        let temp = tempdir().unwrap();
        let directory = fs::canonicalize(temp.path()).unwrap().join("run");
        let run_id = "00000000-0000-4000-8000-000000000001".to_string();
        let mut ledger = SegmentedLedger::open(&directory, &run_id, 4096, 4).unwrap();
        let mut record = sample_record(1);
        record.run_id = Some(run_id.clone());
        ledger.append(&record).unwrap();

        let segment = directory.join(&ledger.filenames[0]);
        std::fs::set_permissions(&segment, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ledger.integrity_inventory(),
            Err(LedgerError::IntegrityMismatch)
        ));

        std::fs::set_permissions(&segment, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ledger.integrity_inventory().is_ok());
    }

    #[test]
    fn read_authoritative_run_refuses_a_world_readable_run_directory() {
        let temp = tempdir().unwrap();
        let directory = fs::canonicalize(temp.path()).unwrap().join("run");
        let manifest = bound_run(&directory);

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            SegmentedLedger::read_authoritative_run(&directory, &manifest),
            Err(LedgerError::IntegrityMismatch)
        ));

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(SegmentedLedger::read_authoritative_run(&directory, &manifest).is_ok());
    }

    #[test]
    fn legacy_record_defaults_to_inline_supported_chat() {
        let json = serde_json::to_value(sample_record(1)).expect("record serializes");
        let mut object = json.as_object().expect("record object").clone();
        object.remove("protocol");
        object.remove("observation_source");
        object.remove("coverage_status");
        object.remove("coverage_reason");

        let decoded: DecisionRecord = serde_json::from_value(serde_json::Value::Object(object))
            .expect("legacy record decodes");

        assert_eq!(decoded.protocol, ProtocolKind::ChatCompletions);
        assert_eq!(decoded.observation_source, ObservationSource::Inline);
        assert_eq!(decoded.coverage_status, CoverageStatus::Supported);
        assert_eq!(decoded.coverage_reason, None);
    }

    fn assert_record_values_eq(left: &[DecisionRecord], right: &[DecisionRecord]) {
        let left: Vec<Vec<u8>> = left
            .iter()
            .map(|record| serde_json::to_vec(record).expect("record serializes"))
            .collect();
        let right: Vec<Vec<u8>> = right
            .iter()
            .map(|record| serde_json::to_vec(record).expect("record serializes"))
            .collect();

        assert_eq!(left, right);
    }

    fn ledger_path(dir: &Path) -> PathBuf {
        dir.join("decisions.bwl")
    }

    fn write_records(dir: &Path, records: &[DecisionRecord]) {
        let (mut ledger, _) = Ledger::open(dir).expect("ledger opens");
        for record in records {
            ledger.append(record).expect("append succeeds");
        }
        ledger.flush().expect("flush succeeds");
    }

    /// Appends a raw CRC-valid frame directly to the ledger file, bypassing
    /// `Ledger::append`'s JSON encoding. Used to construct valid-CRC/undecodable
    /// frames (e.g. schema drift) that could never be produced through the normal
    /// write path.
    fn append_raw_frame(path: &Path, payload: &[u8]) {
        let crc = crc32fast::hash(payload);
        let len = u32::try_from(payload.len()).expect("payload len fits u32");
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("ledger opens for raw frame append");
        file.write_all(&len.to_le_bytes())
            .expect("frame len writes");
        file.write_all(&crc.to_le_bytes())
            .expect("frame crc writes");
        file.write_all(payload).expect("frame payload writes");
        file.flush().expect("frame flush succeeds");
    }

    fn frame_spans(bytes: &[u8]) -> Vec<FrameSpan> {
        assert_eq!(&bytes[..MAGIC_LEN], b"BWL1\n");
        let mut spans = Vec::new();
        let mut offset = MAGIC_LEN;

        while offset < bytes.len() {
            let len = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("length bytes exist"),
            ) as usize;
            let payload_start = offset + FRAME_HEADER_LEN;
            let end = payload_start + len;
            spans.push(FrameSpan {
                start: offset,
                payload_start,
                end,
            });
            offset = end;
        }

        spans
    }

    fn record_strategy() -> impl Strategy<Value = DecisionRecord> {
        (
            safe_string_strategy(),
            0_u64..=u64::MAX / 2,
            identity_strategy(),
            decision_strategy(),
            actual_strategy(),
        )
            .prop_map(
                |(id_suffix, ts_ms, identity, decision, actual)| DecisionRecord {
                    id: format!("00000000-0000-4000-8000-{id_suffix:0>12}"),
                    ts_ms,
                    run_id: None,
                    sequence: None,
                    accounting_truncated: false,
                    protocol: ProtocolKind::ChatCompletions,
                    observation_source: ObservationSource::Inline,
                    coverage_status: CoverageStatus::Supported,
                    coverage_reason: None,
                    identity,
                    decision,
                    actual,
                },
            )
    }

    fn safe_string_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z0-9_./:-]{0,32}").expect("regex compiles")
    }

    fn identity_strategy() -> impl Strategy<Value = WorkloadIdentity> {
        (
            any::<u64>(),
            prop::option::of(safe_string_strategy()),
            prop::collection::vec(safe_string_strategy(), 0..4),
        )
            .prop_map(|(digest_seed, app, tags)| WorkloadIdentity {
                api_key_digest: Some(format!("sha256:{digest_seed:064x}")),
                route: "/v1/chat/completions".to_string(),
                app,
                tags,
            })
    }

    fn decision_strategy() -> impl Strategy<Value = Decision> {
        (
            any::<u64>(),
            task_class_strategy(),
            prop::collection::vec(safe_string_strategy(), 0..4),
            floor_strategy(),
            prop::option::of((safe_string_strategy(), prop::option::of(cost_strategy()))),
        )
            .prop_map(
                |(digest_seed, task_class, feasible_ids, floor, shadow)| Decision {
                    policy_digest: format!("sha256:{digest_seed:064x}"),
                    task_class,
                    feasible_ids,
                    floor,
                    shadow: shadow.map(|(supply_id, est_cost_usd)| Placement {
                        supply_id,
                        est_cost_usd,
                    }),
                },
            )
    }

    fn actual_strategy() -> impl Strategy<Value = ActualOutcome> {
        (
            safe_string_strategy(),
            prop::option::of(safe_string_strategy()),
            100_u16..=599,
            any::<bool>(),
            0_u64..=600_000,
            prop::option::of(0_u64..=10_000_000),
            prop::option::of(0_u64..=10_000_000),
            usage_source_strategy(),
            prop::option::of(cost_strategy()),
        )
            .prop_map(
                |(
                    upstream,
                    model,
                    status,
                    streamed,
                    latency_ms,
                    input_tokens,
                    output_tokens,
                    usage_source,
                    est_cost_usd,
                )| ActualOutcome {
                    upstream,
                    supply_id: None,
                    model,
                    status,
                    streamed,
                    latency_ms,
                    input_tokens,
                    output_tokens,
                    usage_source,
                    est_cost_usd,
                    attribution_status: AttributionStatus::StaticConfigured,
                    attribution_source: AttributionSource::LegacyConfigured,
                    attribution_reference: None,
                    attribution_reason: None,
                },
            )
    }

    fn task_class_strategy() -> impl Strategy<Value = TaskClass> {
        prop_oneof![
            Just(TaskClass::Mechanical),
            Just(TaskClass::HeavyLifting),
            Just(TaskClass::TasteSensitive),
            Just(TaskClass::Judgment),
            Just(TaskClass::Unclassified),
        ]
    }

    fn usage_source_strategy() -> impl Strategy<Value = UsageSource> {
        prop_oneof![
            Just(UsageSource::Observed),
            Just(UsageSource::Estimated),
            Just(UsageSource::Missing),
        ]
    }

    fn floor_strategy() -> impl Strategy<Value = f32> {
        (0_u8..=100).prop_map(|n| f32::from(n) / 100.0)
    }

    fn cost_strategy() -> impl Strategy<Value = f64> {
        (0_u64..=1_000_000).prop_map(|cents| cents as f64 / 100.0)
    }

    fn complete_frames_before_cut(spans: &[FrameSpan], cut: usize) -> usize {
        spans.iter().take_while(|span| span.end <= cut).count()
    }

    fn complete_boundary_for_count(spans: &[FrameSpan], count: usize) -> usize {
        if count == 0 {
            MAGIC_LEN
        } else {
            spans[count - 1].end
        }
    }

    fn is_complete_boundary(spans: &[FrameSpan], cut: usize) -> bool {
        cut == MAGIC_LEN || spans.iter().any(|span| span.end == cut)
    }

    #[test]
    fn absent_dir_is_absent_not_error() {
        let root = tempdir().expect("tempdir exists");
        let missing = root.path().join("missing");

        let (records, outcome) = Ledger::read_all(&missing).expect("absent dir is readable");

        assert!(records.is_empty());
        assert_eq!(outcome, RecoveryOutcome::Absent);
    }

    #[test]
    fn roundtrip_write_read() {
        let dir = tempdir().expect("tempdir exists");
        let expected = vec![sample_record(1), sample_record(2), sample_record(3)];

        write_records(dir.path(), &expected);
        let (actual, outcome) = Ledger::read_all(dir.path()).expect("ledger reads");

        assert_eq!(outcome, RecoveryOutcome::Clean { records: 3 });
        assert_record_values_eq(&actual, &expected);
    }

    #[test]
    fn legacy_record_defaults_production_pov_metadata() {
        let mut legacy = serde_json::to_value(sample_record(7)).expect("record serializes");
        let object = legacy.as_object_mut().expect("record is an object");
        object.remove("run_id");
        object.remove("sequence");
        object.remove("accounting_truncated");
        object
            .get_mut("actual")
            .and_then(serde_json::Value::as_object_mut)
            .expect("actual is an object")
            .remove("supply_id");
        let record: DecisionRecord =
            serde_json::from_value(legacy).expect("legacy record remains readable");

        assert_eq!(record.run_id, None);
        assert_eq!(record.sequence, None);
        assert!(!record.accounting_truncated);
        assert_eq!(record.actual.supply_id, None);
    }

    #[test]
    fn legacy_record_defaults_to_static_attribution() {
        let mut legacy = serde_json::to_value(sample_record(8)).expect("record serializes");
        let actual = legacy
            .get_mut("actual")
            .and_then(serde_json::Value::as_object_mut)
            .expect("actual is an object");
        actual.remove("attribution_status");
        actual.remove("attribution_source");
        actual.remove("attribution_reference");
        actual.remove("attribution_reason");

        let record: DecisionRecord = serde_json::from_value(legacy).expect("legacy record parses");

        assert_eq!(
            record.actual.attribution_status,
            crate::attribution::AttributionStatus::StaticConfigured
        );
        assert_eq!(
            record.actual.attribution_source,
            crate::attribution::AttributionSource::LegacyConfigured
        );
        assert_eq!(record.actual.attribution_reference, None);
        assert_eq!(record.actual.attribution_reason, None);
    }

    #[test]
    fn segmented_ledger_rotates_between_complete_frames_and_reads_in_order() {
        let temp = tempdir().expect("temporary ledger directory");
        let run_id = "00000000-0000-4000-8000-000000000042";
        let mut ledger =
            SegmentedLedger::open(temp.path(), run_id, 1_200, 8).expect("segmented ledger opens");

        for sequence in 1..=6 {
            ledger
                .append(&sample_record(sequence))
                .expect("record appends or rotates");
        }
        ledger.flush().expect("segments flush");

        assert!(ledger.segment_filenames().len() > 1);
        let (records, recovery) =
            SegmentedLedger::read_run(temp.path(), run_id).expect("run reads");
        assert_eq!(
            records
                .iter()
                .map(|record| record.sequence.expect("production sequence"))
                .collect::<Vec<_>>(),
            (1..=6).collect::<Vec<_>>()
        );
        assert!(recovery
            .iter()
            .all(|outcome| matches!(outcome, RecoveryOutcome::Clean { .. })));
    }

    #[test]
    fn segment_limit_refuses_append_without_deleting_evidence() {
        let temp = tempdir().expect("temporary ledger directory");
        let run_id = "00000000-0000-4000-8000-000000000043";
        let mut ledger =
            SegmentedLedger::open(temp.path(), run_id, 1_200, 1).expect("segmented ledger opens");

        ledger.append(&sample_record(1)).expect("first record fits");
        let error = ledger
            .append(&sample_record(2))
            .expect_err("second segment must be refused");

        assert!(matches!(
            error,
            LedgerError::SegmentLimit { max_segments: 1 }
        ));
        ledger.flush().expect("existing evidence flushes");
        let (records, _) = SegmentedLedger::read_run(temp.path(), run_id).expect("run reads");
        assert_eq!(records.len(), 1);
        assert_eq!(ledger.segment_filenames().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_ledger_dir_and_file() {
        let root = tempdir().expect("tempdir exists");
        let dir = root.path().join("ledger");

        let (_ledger, outcome) = Ledger::open(&dir).expect("ledger opens");

        assert_eq!(outcome, RecoveryOutcome::Absent);
        assert_eq!(
            fs::metadata(&dir).expect("dir metadata reads").mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(ledger_path(&dir))
                .expect("file metadata reads")
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn torn_tail_recovers_prefix() {
        let dir = tempdir().expect("tempdir exists");
        let records = vec![sample_record(1), sample_record(2), sample_record(3)];
        write_records(dir.path(), &records);
        let path = ledger_path(dir.path());
        let bytes = fs::read(&path).expect("ledger bytes read");
        let spans = frame_spans(&bytes);
        let cut = spans[2].payload_start + 2;
        let prefix_len = spans[1].end as u64;

        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("ledger opens for truncation")
            .set_len(cut as u64)
            .expect("truncate succeeds");

        let (recovered, read_outcome) = Ledger::read_all(dir.path()).expect("torn ledger reads");
        assert_eq!(
            read_outcome,
            RecoveryOutcome::TornTail {
                records: 2,
                discarded_bytes: (cut as u64) - prefix_len
            }
        );
        assert_record_values_eq(&recovered, &records[..2]);

        let (mut ledger, open_outcome) = Ledger::open(dir.path()).expect("torn ledger opens");
        assert_eq!(
            open_outcome,
            RecoveryOutcome::TornTail {
                records: 2,
                discarded_bytes: (cut as u64) - prefix_len
            }
        );
        assert_eq!(
            fs::metadata(&path).expect("metadata reads").len(),
            prefix_len
        );
        ledger
            .append(&sample_record(4))
            .expect("append after repair");
        ledger.flush().expect("flush succeeds");

        let (after, after_outcome) = Ledger::read_all(dir.path()).expect("repaired ledger reads");
        assert_eq!(after_outcome, RecoveryOutcome::Clean { records: 3 });
        assert_record_values_eq(
            &after,
            &[records[0].clone(), records[1].clone(), sample_record(4)],
        );
    }

    #[test]
    fn bitflip_is_corrupt_not_torn() {
        let dir = tempdir().expect("tempdir exists");
        let records = vec![sample_record(1), sample_record(2), sample_record(3)];
        write_records(dir.path(), &records);
        let path = ledger_path(dir.path());
        let bytes = fs::read(&path).expect("ledger bytes read");
        let spans = frame_spans(&bytes);
        let flip_at = spans[1].payload_start + 1;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("ledger opens for bitflip");
        file.seek(SeekFrom::Start(flip_at as u64))
            .expect("seek succeeds");
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("byte reads");
        file.seek(SeekFrom::Start(flip_at as u64))
            .expect("seek succeeds");
        file.write_all(&[byte[0] ^ 0x01]).expect("byte writes");
        drop(file);

        let (recovered, read_outcome) = Ledger::read_all(dir.path()).expect("corrupt ledger scans");
        assert_eq!(
            read_outcome,
            RecoveryOutcome::Corrupt {
                records: 1,
                at_offset: spans[1].start as u64
            }
        );
        assert_record_values_eq(&recovered, &records[..1]);

        let (mut ledger, open_outcome) = Ledger::open(dir.path()).expect("corrupt ledger opens");
        assert_eq!(read_outcome, open_outcome);
        let err = ledger
            .append(&sample_record(4))
            .expect_err("append refuses corrupt ledger");
        assert!(matches!(err, LedgerError::CorruptRefusal));
    }

    #[test]
    fn undecodable_tail_frame_returns_prefix_and_signal() {
        let dir = tempdir().expect("tempdir exists");
        let records = vec![sample_record(1), sample_record(2)];
        write_records(dir.path(), &records);
        let path = ledger_path(dir.path());
        let garbage_offset = fs::read(&path).expect("ledger bytes read").len() as u64;

        append_raw_frame(&path, b"not-json-and-not-a-decision-record");

        let (recovered, outcome) =
            Ledger::read_all(dir.path()).expect("valid-CRC/undecodable frame must not hard-error");
        assert_eq!(
            outcome,
            RecoveryOutcome::Undecodable {
                records: 2,
                at_offset: garbage_offset,
            }
        );
        assert_record_values_eq(&recovered, &records);
    }

    #[test]
    fn undecodable_mid_file_frame_stops_before_later_valid_frames() {
        // Locks the boundary-semantics choice: stop-at-first-undecodable. A
        // decodable frame written after the undecodable one is deliberately not
        // recovered (see the comment in scan_bytes for rationale).
        let dir = tempdir().expect("tempdir exists");
        write_records(dir.path(), &[sample_record(1)]);
        let path = ledger_path(dir.path());
        let garbage_offset = fs::read(&path).expect("ledger bytes read").len() as u64;

        append_raw_frame(&path, b"schema-drifted-payload");
        let trailing_payload = serde_json::to_vec(&sample_record(2)).expect("record serializes");
        append_raw_frame(&path, &trailing_payload);

        let (recovered, outcome) =
            Ledger::read_all(dir.path()).expect("valid-CRC/undecodable frame must not hard-error");
        assert_eq!(
            outcome,
            RecoveryOutcome::Undecodable {
                records: 1,
                at_offset: garbage_offset,
            }
        );
        assert_record_values_eq(&recovered, &[sample_record(1)]);
    }

    #[test]
    fn undecodable_ledger_open_and_read_all_agree_and_refuse_append() {
        let dir = tempdir().expect("tempdir exists");
        write_records(dir.path(), &[sample_record(1)]);
        let path = ledger_path(dir.path());
        let garbage_offset = fs::read(&path).expect("ledger bytes read").len() as u64;
        append_raw_frame(&path, b"not-json");

        let (recovered, read_outcome) =
            Ledger::read_all(dir.path()).expect("valid-CRC/undecodable frame must not hard-error");
        let (mut ledger, open_outcome) =
            Ledger::open(dir.path()).expect("undecodable ledger still opens");

        // open must never classify a ledger as something read_all then contradicts.
        assert_eq!(read_outcome, open_outcome);
        assert_eq!(
            open_outcome,
            RecoveryOutcome::Undecodable {
                records: 1,
                at_offset: garbage_offset,
            }
        );
        assert_record_values_eq(&recovered, &[sample_record(1)]);

        let err = ledger
            .append(&sample_record(2))
            .expect_err("append refuses a ledger with an undecodable frame");
        assert!(matches!(err, LedgerError::UndecodableRefusal));
    }

    #[test]
    fn empty_file_is_torn_zero() {
        let dir = tempdir().expect("tempdir exists");
        fs::File::create(ledger_path(dir.path())).expect("empty ledger file created");

        let (records, outcome) = Ledger::read_all(dir.path()).expect("empty ledger scans");

        assert!(records.is_empty());
        assert_eq!(
            outcome,
            RecoveryOutcome::TornTail {
                records: 0,
                discarded_bytes: 0
            }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn recovery_scan_returns_only_complete_prefixes(
            records in prop::collection::vec(record_strategy(), 0..=8),
            truncate in any::<bool>(),
            selector in any::<usize>(),
        ) {
            let dir = tempdir().expect("tempdir exists");
            write_records(dir.path(), &records);
            let path = ledger_path(dir.path());
            let bytes = fs::read(&path).expect("ledger bytes read");
            let spans = frame_spans(&bytes);

            if truncate {
                let cut = selector % (bytes.len() + 1);
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("ledger opens for truncation")
                    .set_len(cut as u64)
                    .expect("truncate succeeds");

                let (recovered, outcome) = Ledger::read_all(dir.path()).expect("truncated ledger scans");
                let complete = if cut < MAGIC_LEN {
                    0
                } else {
                    complete_frames_before_cut(&spans, cut)
                };

                assert_record_values_eq(&recovered, &records[..complete]);
                if cut < MAGIC_LEN {
                    prop_assert_eq!(
                        outcome,
                        RecoveryOutcome::TornTail {
                            records: 0,
                            discarded_bytes: cut as u64
                        }
                    );
                } else if is_complete_boundary(&spans, cut) {
                    prop_assert_eq!(
                        outcome,
                        RecoveryOutcome::Clean {
                            records: complete as u64
                        }
                    );
                } else {
                    let boundary = complete_boundary_for_count(&spans, complete);
                    prop_assert_eq!(
                        outcome,
                        RecoveryOutcome::TornTail {
                            records: complete as u64,
                            discarded_bytes: (cut - boundary) as u64
                        }
                    );
                }
            } else if !spans.is_empty() {
                let frame_index = selector % spans.len();
                let span = spans[frame_index];
                let payload_len = span.end - span.payload_start;
                let flip_at = span.payload_start + ((selector / spans.len().max(1)) % payload_len);

                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .expect("ledger opens for bitflip");
                file.seek(SeekFrom::Start(flip_at as u64))
                    .expect("seek succeeds");
                let mut byte = [0_u8; 1];
                file.read_exact(&mut byte).expect("byte reads");
                file.seek(SeekFrom::Start(flip_at as u64))
                    .expect("seek succeeds");
                file.write_all(&[byte[0] ^ 0x01]).expect("byte writes");
                drop(file);

                let (recovered, outcome) = Ledger::read_all(dir.path()).expect("bitflipped ledger scans");
                assert_record_values_eq(&recovered, &records[..frame_index]);
                prop_assert_eq!(
                    outcome,
                    RecoveryOutcome::Corrupt {
                        records: frame_index as u64,
                        at_offset: span.start as u64
                    }
                );
                prop_assert!(recovered.len() < records.len());
            } else {
                let (recovered, outcome) = Ledger::read_all(dir.path()).expect("empty ledger scans");
                prop_assert!(recovered.is_empty());
                prop_assert_eq!(outcome, RecoveryOutcome::Clean { records: 0 });
            }
        }
    }
}
