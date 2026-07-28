use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    config::OwnedCostCatalog, policy::PolicyBundle, quality::PromotionVerdict,
    quality_report::quality_workload_identity_digest, supply::TaskClass,
};

pub const MAX_ACTUATORS: usize = 64;
pub const MAX_ROUTES: usize = 256;
pub const MAX_IDENTIFIER_BYTES: usize = crate::identifier::MAX_IDENTIFIER_BYTES;
pub const MAX_TAGS: usize = 64;
pub const MAX_TAG_BYTES: usize = crate::quality::MAX_IDENTIFIER_BYTES;
pub const MAX_TAG_AGGREGATE_BYTES: usize = MAX_TAGS * MAX_TAG_BYTES;
pub const MAX_PATH_BYTES: usize = 1_024;
pub const MAX_URL_BYTES: usize = 2_048;
pub const MAX_TIMEOUT_MS: u64 = 300_000;
pub const MAX_CONCURRENCY: u32 = 64;
pub const MAX_PROBE_BYTES: usize = 1_048_576;
pub const MAX_BREAKER_FAILURES: u32 = 1_024;
pub const MAX_ECONOMICS_AGE_MS: u64 = 31_536_000_000;
pub const MAX_EXPIRY_MS: u64 = crate::billing::MAX_BILLING_TIMESTAMP_MS;
pub const MAX_ROLLOUT_PPM: u32 = 1_000_000;

/// Renders a validated route identifier safely for operator-visible text.
///
/// This is a display-only transformation. Callers must retain the original value for route
/// selection, evidence binding, and digest computation.
pub fn operator_safe_route_id(route_id: &str) -> String {
    let mut rendered = String::with_capacity(route_id.len());
    for character in route_id.chars() {
        if character.is_ascii_graphic() && character != '\\' || character == ' ' {
            rendered.push(character);
        } else {
            rendered.extend(character.escape_default());
        }
    }
    rendered
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementConfigV1 {
    pub version: u32,
    pub global_candidate_in_flight: u32,
    pub kill_switch: KillSwitchConfig,
    pub actuators: Vec<ActuatorConfig>,
    pub routes: Vec<EnforcementRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchConfig {
    pub trust_root: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActuatorConfig {
    pub supply_id: String,
    pub base_url: String,
    pub authorization_env: String,
    #[serde(default)]
    pub health_path: Option<String>,
    /// Explicit operator opt-in required for a non-loopback HTTPS `base_url`. Loopback endpoints
    /// never need this; defaults to `false` so a config that omits it is fail-closed.
    #[serde(default)]
    pub remote_acknowledged: bool,
    pub connect_timeout_ms: u64,
    pub response_header_timeout_ms: u64,
    pub stream_idle_timeout_ms: u64,
    pub concurrency: u32,
    pub probe_timeout_ms: u64,
    pub probe_max_bytes: usize,
    pub breaker_consecutive_failures: u32,
    pub breaker_cooldown_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementRoute {
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub protocol: AuthorityProtocol,
    #[serde(default)]
    pub workload: Option<WorkloadSelector>,
    pub mode: RouteMode,
    pub rollout_ppm: u32,
    #[serde(default)]
    pub promoted_supply_id: Option<String>,
    #[serde(default)]
    pub actual_supply_id: Option<String>,
    #[serde(default)]
    pub task_class: Option<TaskClass>,
    #[serde(default)]
    pub model_authority: Option<ModelAuthority>,
    #[serde(default)]
    pub fallback: Option<FallbackMode>,
    #[serde(default)]
    pub promotion: Option<PromotionRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSelector {
    pub app: String,
    #[serde(default)]
    pub resolved_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionRequirement {
    pub economics_bundle_path: String,
    pub economics_report_digest: String,
    pub opportunity_digest: String,
    pub quality_run_path: String,
    pub authorization_path: String,
    pub quality_run_id: String,
    pub quality_report_digest: String,
    pub policy_digest: String,
    pub registry_digest: String,
    pub owned_cost_digest: String,
    pub max_economics_age_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionOpportunityEvidence {
    pub digest: String,
    pub workload_identity_digest: String,
    pub task_class: TaskClass,
    pub protocol: AuthorityProtocol,
    pub actual_supply_id: String,
    pub candidate_supply_id: String,
    pub eligible: bool,
    pub policy_feasible: bool,
    pub capacity_available: bool,
    pub actual_cost_micros: Option<u64>,
    pub candidate_cost_micros: Option<u64>,
    pub actual_rate_micros: Option<crate::economics::CostRateMicros>,
    pub candidate_rate_micros: Option<crate::economics::CostRateMicros>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicsPromotionSource {
    pub schema_version: u32,
    pub as_of_ms: u64,
    pub window_end_ms: u64,
    pub complete: bool,
    pub report_digest: String,
    pub bundle_digest: String,
    pub artifact_digests: BTreeMap<String, String>,
    pub selected_traffic_digest: String,
    pub selected_billing_digest: Option<String>,
    pub selected_quality_digests: Vec<String>,
    pub opportunity: PromotionOpportunityEvidence,
    pub policy_digest: String,
    pub registry_digest: String,
    pub owned_cost_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityPromotionSource {
    pub schema_version: u32,
    pub run_id: String,
    pub completed_at_ms: u64,
    pub valid_until_ms: u64,
    pub workload_identity_digest: String,
    pub task_class: TaskClass,
    pub protocol: AuthorityProtocol,
    pub candidate_supply_id: String,
    pub effective_verdict: PromotionVerdict,
    pub manifest_digest: String,
    pub outcomes_digest: String,
    pub report_digest: String,
    pub manifest_valid: bool,
    pub outcomes_valid: bool,
    pub report_valid: bool,
    pub policy_digest: String,
    pub registry_digest: String,
    pub owned_cost_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRuntimeProvenance {
    policy_digest: String,
    registry_digest: String,
    owned_cost_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionAuthorizationV1 {
    pub schema_version: u32,
    pub route_id: String,
    pub created_at_ms: u64,
    pub economics_bundle_digest: String,
    pub economics_report_digest: String,
    pub opportunity_digest: String,
    pub quality_source_digest: String,
    pub quality_run_id: String,
    pub quality_report_digest: String,
    pub policy_digest: String,
    pub registry_digest: String,
    pub owned_cost_digest: String,
    pub enforcement_digest: String,
    pub actuator_digest: String,
    pub route_digest: String,
    pub workload_identity_digest: String,
    pub task_class: TaskClass,
    pub protocol: AuthorityProtocol,
    pub actual_supply_id: String,
    pub candidate_supply_id: String,
    pub authorization_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedPromotionDocuments {
    route_id: String,
    workload_identity_digest: String,
    task_class: TaskClass,
    protocol: AuthorityProtocol,
    actual_supply_id: String,
    candidate_supply_id: String,
    economics_source_digest: String,
    quality_source_digest: String,
    config_digest: String,
    actuator_digest: String,
    route_digest: String,
    authorization_digest: String,
    not_before_ms: u64,
    expires_at_ms: u64,
    actual_rate_micros: crate::economics::CostRateMicros,
    candidate_rate_micros: crate::economics::CostRateMicros,
    opportunity_digest: String,
    validation_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityProtocol {
    ChatCompletions,
    Responses,
    Embeddings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteMode {
    Observe,
    Recommend,
    CanaryEnforce,
    Enforce,
}

impl RouteMode {
    pub fn grants_authority(self) -> bool {
        matches!(self, Self::CanaryEnforce | Self::Enforce)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelAuthority {
    Preserve,
    RewriteToCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackMode {
    Bypass,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KillReadResult {
    Armed,
    Bypass,
    Missing,
    Unsafe,
    Unreadable,
    Malformed,
    QueueUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateAvailability {
    Available,
    CircuitOpen,
    AdmissionSaturated,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanTarget {
    Original,
    Candidate,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceState {
    NotRequired,
    Presented,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionReason {
    ObserveOnly,
    RecommendationOnly,
    KillNotArmed,
    RouteMismatch,
    UntrustedIdentity,
    UnsupportedShape,
    GrantMissing,
    SignatureMissing,
    SignatureInvalid,
    GrantMismatch,
    GrantStale,
    ApprovalMissing,
    ApprovalSignatureInvalid,
    ApprovalUnbound,
    ApprovalExpired,
    WorkloadMismatch,
    AllowlistMiss,
    RolloutMiss,
    PinnedModelMismatch,
    CircuitOpen,
    AdmissionSaturated,
    CandidateUnavailable,
    ActuatorUnavailable,
    CandidateSelected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionInput {
    pub route: EnforcementRoute,
    pub method: String,
    pub path: String,
    pub protocol: AuthorityProtocol,
    pub identity_trusted: bool,
    pub authority_metadata_valid: bool,
    pub shape_supported: bool,
    pub task_class: TaskClass,
    pub app: Option<String>,
    pub resolved_tags: Vec<String>,
    pub workload_identity_digest: Option<String>,
    pub request_body_digest: [u8; 32],
    pub requested_supply_id: Option<String>,
    pub kill: KillReadResult,
    pub now_ms: u64,
    pub candidate_availability: CandidateAvailability,
    pub actuator_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRequestFacts {
    pub method: String,
    pub path: String,
    pub protocol: AuthorityProtocol,
    pub identity_trusted: bool,
    pub authority_metadata_valid: bool,
    pub shape_supported: bool,
    pub task_class: TaskClass,
    pub app: Option<String>,
    pub resolved_tags: Vec<String>,
    pub workload_identity_digest: Option<String>,
    pub request_body_digest: [u8; 32],
    pub requested_supply_id: Option<String>,
    pub kill: KillReadResult,
    pub now_ms: u64,
    pub candidate_availability: CandidateAvailability,
    pub actuator_available: bool,
}

impl SelectionInput {
    pub fn from_validated_route(route: &EnforcementRoute, facts: &SelectionRequestFacts) -> Self {
        Self {
            route: route.clone(),
            method: facts.method.clone(),
            path: facts.path.clone(),
            protocol: facts.protocol,
            identity_trusted: facts.identity_trusted,
            authority_metadata_valid: facts.authority_metadata_valid,
            shape_supported: facts.shape_supported,
            task_class: facts.task_class,
            app: facts.app.clone(),
            resolved_tags: facts.resolved_tags.clone(),
            workload_identity_digest: facts.workload_identity_digest.clone(),
            request_body_digest: facts.request_body_digest,
            requested_supply_id: facts.requested_supply_id.clone(),
            kill: facts.kill,
            now_ms: facts.now_ms,
            candidate_availability: facts.candidate_availability,
            actuator_available: facts.actuator_available,
        }
    }
}

/// A content-free snapshot used only by pure selection. It is not allocation authority.
/// Gateway dispatch must retain and consume the opaque descriptor-loaded grant instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionGrantSnapshot {
    pub route_id: String,
    pub workload_identity_digest: String,
    pub task_class: TaskClass,
    pub protocol: AuthorityProtocol,
    pub actual_supply_id: String,
    pub candidate_supply_id: String,
    pub config_digest: String,
    pub actuator_digest: String,
    pub route_digest: String,
    pub grant_digest: String,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
}

/// A pure, content-free decision proposal. This value never authorizes dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementPlan {
    pub target: PlanTarget,
    pub mode: RouteMode,
    pub reason: SelectionReason,
    pub evidence_state: EvidenceState,
    pub bucket: Option<u32>,
    pub selected_supply_id: Option<String>,
    pub baseline_supply_id: Option<String>,
    pub actuator_digest: Option<String>,
    pub config_digest: Option<String>,
    pub route_digest: Option<String>,
    pub model_rewritten: bool,
    pub grant_digest: Option<String>,
    pub dispatch_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewriteLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RewriteError {
    #[error("request body exceeds byte limit")]
    ByteLimit,
    #[error("request body exceeds JSON depth limit")]
    DepthLimit,
    #[error("request body exceeds JSON node limit")]
    NodeLimit,
    #[error("request body is malformed JSON")]
    MalformedJson,
    #[error("request body has duplicate top-level model keys")]
    DuplicateModel,
    #[error("request body is missing a top-level model key")]
    MissingModel,
    #[error("top-level model value is not a JSON string")]
    ModelNotString,
}

#[derive(Debug, Clone)]
pub struct ValidatedEnforcement {
    config: EnforcementConfigV1,
    actuators: BTreeMap<String, usize>,
    routes: BTreeMap<String, usize>,
    normalized_digest: String,
    digest_document: EnforcementDigestDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementDigestDocument {
    version: u32,
    global_candidate_in_flight: u32,
    kill_path_digest: String,
    actuators: Vec<ActuatorDigest>,
    routes: Vec<RouteDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActuatorDigest {
    supply_id: String,
    endpoint_identity_digest: String,
    authorization_reference_digest: String,
    health_path_digest: Option<String>,
    connect_timeout_ms: u64,
    response_header_timeout_ms: u64,
    stream_idle_timeout_ms: u64,
    concurrency: u32,
    probe_timeout_ms: u64,
    probe_max_bytes: usize,
    breaker_consecutive_failures: u32,
    breaker_cooldown_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RouteDigest {
    route_id: String,
    method: String,
    route_identity_digest: String,
    protocol: AuthorityProtocol,
    workload_digest: Option<String>,
    selector_identity_digest: Option<String>,
    mode: RouteMode,
    rollout_ppm: u32,
    promoted_supply_id: Option<String>,
    actual_supply_id: Option<String>,
    task_class: Option<TaskClass>,
    model_authority: Option<ModelAuthority>,
    fallback: Option<FallbackMode>,
    promotion_binding_digest: Option<String>,
}

#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("failed to parse enforcement configuration: {0}")]
    Parse(String),
    #[error("invalid enforcement field {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}

impl EnforcementError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }
}

impl EnforcementConfigV1 {
    pub fn from_yaml(source: &str) -> Result<Self, EnforcementError> {
        serde_yaml::from_str(source).map_err(|error| EnforcementError::Parse(error.to_string()))
    }

    pub fn validate(&self) -> Result<ValidatedEnforcement, EnforcementError> {
        if self.version != 1 {
            return Err(EnforcementError::invalid("version", "must equal 1"));
        }
        bounded_positive(
            "global_candidate_in_flight",
            self.global_candidate_in_flight,
            MAX_CONCURRENCY,
        )?;
        validate_kill_switch(&self.kill_switch)?;
        if self.actuators.len() > MAX_ACTUATORS {
            return Err(EnforcementError::invalid("actuators", "too many entries"));
        }
        if self.routes.len() > MAX_ROUTES {
            return Err(EnforcementError::invalid("routes", "too many entries"));
        }

        let mut actuator_index = BTreeMap::new();
        for (index, actuator) in self.actuators.iter().enumerate() {
            validate_actuator(actuator)?;
            if actuator_index
                .insert(actuator.supply_id.clone(), index)
                .is_some()
            {
                return Err(EnforcementError::invalid(
                    "actuators",
                    "duplicate supply id",
                ));
            }
        }

        let mut route_index = BTreeMap::new();
        let mut match_keys = BTreeSet::new();
        for (index, route) in self.routes.iter().enumerate() {
            validate_route(route, &actuator_index, &self.actuators)?;
            if route_index.insert(route.route_id.clone(), index).is_some() {
                return Err(EnforcementError::invalid("routes", "duplicate route id"));
            }
            let key = (route.method.as_str(), route.path.as_str(), route.protocol);
            if !match_keys.insert(key) {
                return Err(EnforcementError::invalid(
                    "routes",
                    "overlapping exact route match",
                ));
            }
        }

        let digest_document = build_digest_document(self)?;
        let normalized_digest = domain_digest(
            b"bowline.enforcement.config.v1",
            &serde_json::to_vec(&digest_document)
                .map_err(|error| EnforcementError::Parse(error.to_string()))?,
        );
        Ok(ValidatedEnforcement {
            config: self.clone(),
            actuators: actuator_index,
            routes: route_index,
            normalized_digest,
            digest_document,
        })
    }
}

impl ValidatedEnforcement {
    pub fn routes(&self) -> impl Iterator<Item = &EnforcementRoute> {
        self.config.routes.iter()
    }

    pub fn route(&self, route_id: &str) -> Option<&EnforcementRoute> {
        self.routes
            .get(route_id)
            .map(|index| &self.config.routes[*index])
    }

    pub fn actuator(&self, supply_id: &str) -> Option<&ActuatorConfig> {
        self.actuators
            .get(supply_id)
            .map(|index| &self.config.actuators[*index])
    }

    pub fn normalized_digest(&self) -> &str {
        &self.normalized_digest
    }

    pub fn digest_document(&self) -> &EnforcementDigestDocument {
        &self.digest_document
    }

    pub fn authority_routes(&self) -> impl Iterator<Item = &EnforcementRoute> {
        self.config
            .routes
            .iter()
            .filter(|route| route.mode.grants_authority())
    }

    pub fn actuator_digest(&self, supply_id: &str) -> Option<String> {
        self.digest_document
            .actuators
            .iter()
            .find(|actuator| actuator.supply_id == supply_id)
            .and_then(|actuator| serde_json::to_vec(actuator).ok())
            .map(|bytes| domain_digest(b"bowline.enforcement.actuator.v1", &bytes))
    }

    pub fn actuator_endpoint_identity_digest(&self, supply_id: &str) -> Option<String> {
        self.digest_document
            .actuators
            .iter()
            .find(|actuator| actuator.supply_id == supply_id)
            .map(|actuator| actuator.endpoint_identity_digest.clone())
    }

    pub fn route_digest(&self, route_id: &str) -> Option<String> {
        self.digest_document
            .routes
            .iter()
            .find(|route| route.route_id == route_id)
            .and_then(|route| serde_json::to_vec(route).ok())
            .map(|bytes| domain_digest(b"bowline.enforcement.route.v1", &bytes))
    }
}

impl ActiveRuntimeProvenance {
    pub fn from_loaded(
        policy: &PolicyBundle,
        registry_source: &str,
        owned_costs: &OwnedCostCatalog,
    ) -> Self {
        Self {
            policy_digest: policy.digest().to_owned(),
            registry_digest: format!("sha256:{:x}", Sha256::digest(registry_source.as_bytes())),
            owned_cost_digest: owned_costs.normalized_digest().to_owned(),
        }
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn registry_digest(&self) -> &str {
        &self.registry_digest
    }

    pub fn owned_cost_digest(&self) -> &str {
        &self.owned_cost_digest
    }
}

impl ValidatedPromotionDocuments {
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    pub fn workload_identity_digest(&self) -> &str {
        &self.workload_identity_digest
    }

    pub fn task_class(&self) -> TaskClass {
        self.task_class
    }

    pub fn protocol(&self) -> AuthorityProtocol {
        self.protocol
    }

    pub fn actual_supply_id(&self) -> &str {
        &self.actual_supply_id
    }

    pub fn candidate_supply_id(&self) -> &str {
        &self.candidate_supply_id
    }

    pub fn economics_source_digest(&self) -> &str {
        &self.economics_source_digest
    }

    pub fn quality_source_digest(&self) -> &str {
        &self.quality_source_digest
    }

    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    pub fn actuator_digest(&self) -> &str {
        &self.actuator_digest
    }

    pub fn route_digest(&self) -> &str {
        &self.route_digest
    }

    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }

    pub fn validation_digest(&self) -> &str {
        &self.validation_digest
    }

    pub fn is_fresh_at(&self, now_ms: u64) -> bool {
        self.not_before_ms <= now_ms && now_ms <= self.expires_at_ms
    }

    pub fn actual_rate_micros(&self) -> crate::economics::CostRateMicros {
        self.actual_rate_micros
    }

    pub fn candidate_rate_micros(&self) -> crate::economics::CostRateMicros {
        self.candidate_rate_micros
    }

    pub fn opportunity_digest(&self) -> &str {
        &self.opportunity_digest
    }
}

pub fn validate_promotion_documents(
    validated: &ValidatedEnforcement,
    route_id: &str,
    economics: &EconomicsPromotionSource,
    quality: &QualityPromotionSource,
    authorization: &PromotionAuthorizationV1,
    active: &ActiveRuntimeProvenance,
    now_ms: u64,
) -> Result<ValidatedPromotionDocuments, EnforcementError> {
    let expected = promotion_authorization_claims(
        validated,
        route_id,
        economics,
        quality,
        active,
        authorization.created_at_ms,
    )?;
    if authorization != &expected {
        return Err(EnforcementError::invalid(
            "promotion.authorization",
            "sealed authorization does not match active evidence and configuration",
        ));
    }
    if authorization.created_at_ms > now_ms {
        return Err(EnforcementError::invalid(
            "promotion.authorization.created_at_ms",
            "cannot be in the future",
        ));
    }

    let context =
        promotion_validation_context(validated, route_id, economics, quality, active, now_ms)?;
    let mut grant = ValidatedPromotionDocuments {
        route_id: context.route_id,
        workload_identity_digest: context.workload_identity_digest,
        task_class: context.task_class,
        protocol: context.protocol,
        actual_supply_id: context.actual_supply_id,
        candidate_supply_id: context.candidate_supply_id,
        economics_source_digest: economics.bundle_digest.clone(),
        quality_source_digest: context.quality_source_digest,
        config_digest: context.enforcement_digest,
        actuator_digest: context.actuator_digest,
        route_digest: context.route_digest,
        authorization_digest: authorization.authorization_digest.clone(),
        not_before_ms: context.not_before_ms.max(authorization.created_at_ms),
        expires_at_ms: context.expires_at_ms,
        actual_rate_micros: economics
            .opportunity
            .actual_rate_micros
            .ok_or_else(|| EnforcementError::invalid("promotion", "actual rate missing"))?,
        candidate_rate_micros: economics
            .opportunity
            .candidate_rate_micros
            .ok_or_else(|| EnforcementError::invalid("promotion", "candidate rate missing"))?,
        opportunity_digest: economics.opportunity.digest.clone(),
        validation_digest: String::new(),
    };
    grant.validation_digest = domain_digest(
        b"bowline.enforcement.validated-promotion-documents.v1",
        &serde_json::to_vec(&grant).map_err(|error| EnforcementError::Parse(error.to_string()))?,
    );
    Ok(grant)
}

pub fn validate_recommendation_documents(
    validated: &ValidatedEnforcement,
    route_id: &str,
    economics: &EconomicsPromotionSource,
    quality: &QualityPromotionSource,
    authorization: &PromotionAuthorizationV1,
    active: &ActiveRuntimeProvenance,
    now_ms: u64,
) -> Result<ValidatedPromotionDocuments, EnforcementError> {
    let route = validated
        .route(route_id)
        .filter(|route| route.mode == RouteMode::Recommend && route.promotion.is_some())
        .ok_or_else(|| {
            EnforcementError::invalid(
                "promotion",
                "no exact recommendation evidence route matches",
            )
        })?;
    debug_assert_eq!(route.route_id, route_id);
    validate_promotion_documents(
        validated,
        route_id,
        economics,
        quality,
        authorization,
        active,
        now_ms,
    )
}

pub fn seal_promotion_authorization(
    validated: &ValidatedEnforcement,
    route_id: &str,
    economics: &EconomicsPromotionSource,
    quality: &QualityPromotionSource,
    active: &ActiveRuntimeProvenance,
    created_at_ms: u64,
) -> Result<PromotionAuthorizationV1, EnforcementError> {
    promotion_authorization_claims(
        validated,
        route_id,
        economics,
        quality,
        active,
        created_at_ms,
    )
}

#[derive(Debug)]
struct PromotionValidationContext {
    route_id: String,
    workload_identity_digest: String,
    task_class: TaskClass,
    protocol: AuthorityProtocol,
    actual_supply_id: String,
    candidate_supply_id: String,
    quality_source_digest: String,
    enforcement_digest: String,
    actuator_digest: String,
    route_digest: String,
    not_before_ms: u64,
    expires_at_ms: u64,
}

fn promotion_authorization_claims(
    validated: &ValidatedEnforcement,
    route_id: &str,
    economics: &EconomicsPromotionSource,
    quality: &QualityPromotionSource,
    active: &ActiveRuntimeProvenance,
    created_at_ms: u64,
) -> Result<PromotionAuthorizationV1, EnforcementError> {
    if created_at_ms == 0 {
        return Err(EnforcementError::invalid(
            "promotion.authorization.created_at_ms",
            "must be positive",
        ));
    }
    let context = promotion_validation_context(
        validated,
        route_id,
        economics,
        quality,
        active,
        created_at_ms,
    )?;
    let mut authorization = PromotionAuthorizationV1 {
        schema_version: 1,
        route_id: context.route_id,
        created_at_ms,
        economics_bundle_digest: economics.bundle_digest.clone(),
        economics_report_digest: economics.report_digest.clone(),
        opportunity_digest: economics.opportunity.digest.clone(),
        quality_source_digest: context.quality_source_digest,
        quality_run_id: quality.run_id.clone(),
        quality_report_digest: quality.report_digest.clone(),
        policy_digest: active.policy_digest.clone(),
        registry_digest: active.registry_digest.clone(),
        owned_cost_digest: active.owned_cost_digest.clone(),
        enforcement_digest: context.enforcement_digest,
        actuator_digest: context.actuator_digest,
        route_digest: context.route_digest,
        workload_identity_digest: context.workload_identity_digest,
        task_class: context.task_class,
        protocol: context.protocol,
        actual_supply_id: context.actual_supply_id,
        candidate_supply_id: context.candidate_supply_id,
        authorization_digest: String::new(),
    };
    authorization.authorization_digest = domain_digest(
        b"bowline.enforcement.promotion-authorization.v1",
        &serde_json::to_vec(&authorization)
            .map_err(|error| EnforcementError::Parse(error.to_string()))?,
    );
    Ok(authorization)
}

fn promotion_validation_context(
    validated: &ValidatedEnforcement,
    route_id: &str,
    economics: &EconomicsPromotionSource,
    quality: &QualityPromotionSource,
    active: &ActiveRuntimeProvenance,
    now_ms: u64,
) -> Result<PromotionValidationContext, EnforcementError> {
    validate_economics_source(economics, now_ms)?;
    validate_quality_source(quality, now_ms)?;
    let route = validated
        .route(route_id)
        .filter(|route| route.mode != RouteMode::Observe && route.promotion.is_some())
        .ok_or_else(|| {
            EnforcementError::invalid("promotion", "no exact promotion evidence route matches")
        })?;
    let requirement = route.promotion.as_ref().expect("promotion route filtered");
    let workload = route_workload_digest(
        route.protocol,
        route.workload.as_ref().ok_or_else(|| {
            EnforcementError::invalid("promotion", "promotion route lacks workload")
        })?,
    )?;
    let task = route.task_class.ok_or_else(|| {
        EnforcementError::invalid("promotion", "promotion route lacks task class")
    })?;
    let actual = route
        .actual_supply_id
        .as_deref()
        .ok_or_else(|| EnforcementError::invalid("promotion", "promotion route lacks actual"))?;
    let candidate = route
        .promoted_supply_id
        .as_deref()
        .ok_or_else(|| EnforcementError::invalid("promotion", "promotion route lacks candidate"))?;
    let actuator_digest = validated.actuator_digest(candidate).ok_or_else(|| {
        EnforcementError::invalid("promotion.actuator_digest", "missing actuator")
    })?;
    let route_digest = validated
        .route_digest(&route.route_id)
        .ok_or_else(|| EnforcementError::invalid("promotion.route_digest", "missing route"))?;

    let exact_sources = requirement.economics_report_digest == economics.report_digest
        && requirement.opportunity_digest == economics.opportunity.digest
        && requirement.quality_run_id == quality.run_id
        && requirement.quality_report_digest == quality.report_digest
        && economics.opportunity.workload_identity_digest == workload
        && quality.workload_identity_digest == workload
        && economics.opportunity.task_class == task
        && quality.task_class == task
        && economics.opportunity.protocol == route.protocol
        && quality.protocol == route.protocol
        && economics.opportunity.actual_supply_id == actual
        && economics.opportunity.candidate_supply_id == candidate
        && quality.candidate_supply_id == candidate;
    let exact_provenance = economics.policy_digest == requirement.policy_digest
        && economics
            .selected_quality_digests
            .binary_search(&quality.report_digest)
            .is_ok()
        && quality.policy_digest == requirement.policy_digest
        && economics.registry_digest == requirement.registry_digest
        && quality.registry_digest == requirement.registry_digest
        && economics.owned_cost_digest == requirement.owned_cost_digest
        && quality.owned_cost_digest == requirement.owned_cost_digest
        && active.policy_digest == requirement.policy_digest
        && active.registry_digest == requirement.registry_digest
        && active.owned_cost_digest == requirement.owned_cost_digest;
    if !exact_sources || !exact_provenance || route.protocol == AuthorityProtocol::Embeddings {
        return Err(EnforcementError::invalid(
            "promotion",
            "source identity or active provenance mismatch",
        ));
    }

    let economics_expiry = economics
        .as_of_ms
        .checked_add(requirement.max_economics_age_ms)
        .ok_or_else(|| {
            EnforcementError::invalid("promotion.max_economics_age_ms", "expiry overflow")
        })?;
    let expires_at_ms = economics_expiry
        .min(quality.valid_until_ms)
        .min(requirement.expires_at_ms);
    let not_before_ms = economics.as_of_ms.max(quality.completed_at_ms);
    if now_ms > expires_at_ms {
        return Err(EnforcementError::invalid(
            "promotion",
            "promotion evidence is stale",
        ));
    }

    let quality_source_digest = domain_digest(
        b"bowline.enforcement.quality-source.v1",
        &serde_json::to_vec(quality).map_err(|error| EnforcementError::Parse(error.to_string()))?,
    );
    Ok(PromotionValidationContext {
        route_id: route.route_id.clone(),
        workload_identity_digest: workload,
        task_class: task,
        protocol: route.protocol,
        actual_supply_id: actual.to_owned(),
        candidate_supply_id: candidate.to_owned(),
        quality_source_digest,
        enforcement_digest: validated.normalized_digest.clone(),
        actuator_digest,
        route_digest,
        not_before_ms,
        expires_at_ms,
    })
}

fn validate_economics_source(
    source: &EconomicsPromotionSource,
    now_ms: u64,
) -> Result<(), EnforcementError> {
    const ARTIFACTS: [&str; 6] = [
        "dimensions.csv",
        "opportunities.csv",
        "reconciliation.csv",
        "report.html",
        "report.json",
        "report.md",
    ];
    let valid_artifacts = source.artifact_digests.len() == ARTIFACTS.len()
        && ARTIFACTS.iter().all(|name| {
            source
                .artifact_digests
                .get(*name)
                .is_some_and(|digest| valid_digest(digest))
        })
        && source.artifact_digests.get("report.json") == Some(&source.report_digest);
    let selected_valid = valid_digest(&source.selected_traffic_digest)
        && source
            .selected_billing_digest
            .as_deref()
            .is_some_and(valid_digest)
        && !source.selected_quality_digests.is_empty()
        && source.selected_quality_digests.len() <= MAX_ROUTES
        && source
            .selected_quality_digests
            .iter()
            .all(|digest| valid_digest(digest))
        && source
            .selected_quality_digests
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
    let opportunity = &source.opportunity;
    if source.schema_version != 1
        || !source.complete
        || source.window_end_ms > source.as_of_ms
        || source.as_of_ms > now_ms
        || !valid_digest(&source.report_digest)
        || !valid_digest(&source.bundle_digest)
        || !valid_artifacts
        || !selected_valid
        || !valid_digest(&opportunity.digest)
        || !valid_digest(&opportunity.workload_identity_digest)
        || opportunity.protocol == AuthorityProtocol::Embeddings
        || !opportunity.eligible
        || !opportunity.policy_feasible
        || !opportunity.capacity_available
        || opportunity.actual_cost_micros.is_none()
        || opportunity.candidate_cost_micros.is_none()
        || opportunity.actual_rate_micros.is_none()
        || opportunity.candidate_rate_micros.is_none()
        || opportunity.actual_supply_id == opportunity.candidate_supply_id
        || [
            &source.policy_digest,
            &source.registry_digest,
            &source.owned_cost_digest,
        ]
        .into_iter()
        .any(|digest| !valid_digest(digest))
    {
        return Err(EnforcementError::invalid(
            "promotion.economics",
            "invalid, incomplete, future, or noneligible economics evidence",
        ));
    }
    Ok(())
}

fn validate_quality_source(
    source: &QualityPromotionSource,
    now_ms: u64,
) -> Result<(), EnforcementError> {
    if source.schema_version != 2
        || source.completed_at_ms > now_ms
        || source.completed_at_ms > source.valid_until_ms
        || now_ms > source.valid_until_ms
        || source.protocol == AuthorityProtocol::Embeddings
        || source.effective_verdict != PromotionVerdict::Eligible
        || !source.manifest_valid
        || !source.outcomes_valid
        || !source.report_valid
        || !valid_id(&source.run_id)
        || !valid_id(&source.candidate_supply_id)
        || [
            &source.workload_identity_digest,
            &source.manifest_digest,
            &source.outcomes_digest,
            &source.report_digest,
            &source.policy_digest,
            &source.registry_digest,
            &source.owned_cost_digest,
        ]
        .into_iter()
        .any(|digest| !valid_digest(digest))
    {
        return Err(EnforcementError::invalid(
            "promotion.quality",
            "invalid, stale, incomplete, or noneligible quality-v2 evidence",
        ));
    }
    Ok(())
}

fn validate_kill_switch(kill: &KillSwitchConfig) -> Result<(), EnforcementError> {
    if kill.trust_root.len() > MAX_PATH_BYTES
        || kill.trust_root.chars().any(char::is_control)
        || !Path::new(&kill.trust_root).is_absolute()
    {
        return Err(EnforcementError::invalid(
            "kill_switch.trust_root",
            "must be a bounded absolute path",
        ));
    }
    validate_relative_path("kill_switch.relative_path", &kill.relative_path)
}

fn validate_actuator(actuator: &ActuatorConfig) -> Result<(), EnforcementError> {
    validate_id("actuators.supply_id", &actuator.supply_id)?;
    if actuator.base_url.len() > MAX_URL_BYTES {
        return Err(EnforcementError::invalid("actuators.base_url", "too long"));
    }
    if crate::config::validate_credential_free_endpoint(
        &actuator.base_url,
        actuator.remote_acknowledged,
        false,
    )
    .is_err()
    {
        return Err(EnforcementError::invalid(
            "actuators.base_url",
            "must be credential-free HTTPS or loopback HTTP without query or fragment; a \
             non-loopback HTTPS actuator requires remote_acknowledged: true",
        ));
    }
    validate_secret_env(&actuator.authorization_env)?;
    if let Some(path) = &actuator.health_path {
        validate_http_path("actuators.health_path", path)?;
    }
    for (field, value) in [
        ("actuators.connect_timeout_ms", actuator.connect_timeout_ms),
        (
            "actuators.response_header_timeout_ms",
            actuator.response_header_timeout_ms,
        ),
        (
            "actuators.stream_idle_timeout_ms",
            actuator.stream_idle_timeout_ms,
        ),
        ("actuators.probe_timeout_ms", actuator.probe_timeout_ms),
        (
            "actuators.breaker_cooldown_ms",
            actuator.breaker_cooldown_ms,
        ),
    ] {
        bounded_positive(field, value, MAX_TIMEOUT_MS)?;
    }
    bounded_positive(
        "actuators.concurrency",
        actuator.concurrency,
        MAX_CONCURRENCY,
    )?;
    bounded_positive(
        "actuators.breaker_consecutive_failures",
        actuator.breaker_consecutive_failures,
        MAX_BREAKER_FAILURES,
    )?;
    if actuator.probe_max_bytes == 0 || actuator.probe_max_bytes > MAX_PROBE_BYTES {
        return Err(EnforcementError::invalid(
            "actuators.probe_max_bytes",
            "outside compiled bound",
        ));
    }
    Ok(())
}

fn validate_route(
    route: &EnforcementRoute,
    actuator_index: &BTreeMap<String, usize>,
    actuators: &[ActuatorConfig],
) -> Result<(), EnforcementError> {
    validate_id("routes.route_id", &route.route_id)?;
    if route.method != "POST" {
        return Err(EnforcementError::invalid(
            "routes.method",
            "must equal POST",
        ));
    }
    validate_http_path("routes.path", &route.path)?;
    if route.protocol == AuthorityProtocol::Embeddings && route.mode.grants_authority() {
        return Err(EnforcementError::invalid(
            "routes.protocol",
            "Embeddings cannot receive allocation authority",
        ));
    }
    if route.protocol == AuthorityProtocol::Embeddings
        && (route.promoted_supply_id.is_some()
            || route.model_authority.is_some()
            || route.fallback.is_some()
            || route.promotion.is_some())
    {
        return Err(EnforcementError::invalid(
            "routes.protocol",
            "Embeddings cannot carry candidate authority fields",
        ));
    }
    if route.rollout_ppm > MAX_ROLLOUT_PPM
        || route.mode != RouteMode::CanaryEnforce && route.rollout_ppm != 0
    {
        return Err(EnforcementError::invalid(
            "routes.rollout_ppm",
            "invalid for mode",
        ));
    }
    if route.mode == RouteMode::Enforce && route.rollout_ppm != 0 {
        return Err(EnforcementError::invalid(
            "routes.rollout_ppm",
            "enforce implies full rollout",
        ));
    }
    if let Some(workload) = &route.workload {
        validate_workload(workload, route.protocol)?;
    }
    if let Some(value) = &route.promoted_supply_id {
        validate_id("routes.promoted_supply_id", value)?;
    }
    if let Some(value) = &route.actual_supply_id {
        validate_id("routes.actual_supply_id", value)?;
    }
    if route.mode.grants_authority() {
        let workload = route.workload.as_ref().ok_or_else(|| {
            EnforcementError::invalid("routes.workload", "required for authority")
        })?;
        validate_workload(workload, route.protocol)?;
        let supply = route.promoted_supply_id.as_deref().ok_or_else(|| {
            EnforcementError::invalid("routes.promoted_supply_id", "required for authority")
        })?;
        validate_id("routes.promoted_supply_id", supply)?;
        let actuator = actuator_index
            .get(supply)
            .map(|index| &actuators[*index])
            .ok_or_else(|| {
                EnforcementError::invalid("routes.promoted_supply_id", "unknown actuator")
            })?;
        if actuator.health_path.is_none() {
            return Err(EnforcementError::invalid(
                "actuators.health_path",
                "required when referenced by an authority route",
            ));
        }
        let actual = route.actual_supply_id.as_deref().ok_or_else(|| {
            EnforcementError::invalid("routes.actual_supply_id", "required for authority")
        })?;
        validate_id("routes.actual_supply_id", actual)?;
        if actual == supply {
            return Err(EnforcementError::invalid(
                "routes.promoted_supply_id",
                "must differ from actual supply",
            ));
        }
        if route.task_class.is_none()
            || route.model_authority.is_none()
            || route.fallback.is_none()
            || route.promotion.is_none()
        {
            return Err(EnforcementError::invalid(
                "routes",
                "authority route lacks task/model/fallback/promotion fields",
            ));
        }
        validate_promotion(route.promotion.as_ref().expect("checked"))?;
    } else if route.mode == RouteMode::Recommend && route.promotion.is_some() {
        let workload = route.workload.as_ref().ok_or_else(|| {
            EnforcementError::invalid("routes.workload", "required for recommendation evidence")
        })?;
        validate_workload(workload, route.protocol)?;
        let supply = route.promoted_supply_id.as_deref().ok_or_else(|| {
            EnforcementError::invalid(
                "routes.promoted_supply_id",
                "required for recommendation evidence",
            )
        })?;
        validate_id("routes.promoted_supply_id", supply)?;
        if !actuator_index.contains_key(supply) {
            return Err(EnforcementError::invalid(
                "routes.promoted_supply_id",
                "unknown actuator",
            ));
        }
        let actual = route.actual_supply_id.as_deref().ok_or_else(|| {
            EnforcementError::invalid(
                "routes.actual_supply_id",
                "required for recommendation evidence",
            )
        })?;
        validate_id("routes.actual_supply_id", actual)?;
        if actual == supply {
            return Err(EnforcementError::invalid(
                "routes.promoted_supply_id",
                "must differ from actual supply",
            ));
        }
        if route.task_class.is_none() || route.fallback.is_none() {
            return Err(EnforcementError::invalid(
                "routes",
                "recommendation evidence route lacks task/fallback fields",
            ));
        }
        if route.model_authority.is_some() {
            return Err(EnforcementError::invalid(
                "routes.model_authority",
                "recommendation evidence cannot grant model authority",
            ));
        }
        validate_promotion(route.promotion.as_ref().expect("checked"))?;
    } else if route.promotion.is_some() {
        return Err(EnforcementError::invalid(
            "routes.promotion",
            "observe routes cannot carry promotion evidence",
        ));
    }
    Ok(())
}

fn validate_workload(
    workload: &WorkloadSelector,
    protocol: AuthorityProtocol,
) -> Result<(), EnforcementError> {
    validate_id("routes.workload.app", &workload.app)?;
    let aggregate_bytes = workload
        .resolved_tags
        .iter()
        .try_fold(0usize, |total, tag| total.checked_add(tag.len()));
    if workload.resolved_tags.len() > MAX_TAGS
        || aggregate_bytes.is_none_or(|bytes| bytes > MAX_TAG_AGGREGATE_BYTES)
        || workload.resolved_tags.iter().any(|tag| {
            tag.is_empty() || tag.len() > MAX_TAG_BYTES || tag.chars().any(char::is_control)
        })
        || workload
            .resolved_tags
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(EnforcementError::invalid(
            "routes.workload.resolved_tags",
            "must be unique, canonical sorted, and bounded",
        ));
    }
    let quality_protocol = match protocol {
        AuthorityProtocol::ChatCompletions => crate::quality::QualityProtocol::Chat,
        AuthorityProtocol::Responses => crate::quality::QualityProtocol::Responses,
        AuthorityProtocol::Embeddings => return Ok(()),
    };
    quality_workload_identity_digest(quality_protocol, &workload.app, &workload.resolved_tags)
        .map_err(|_| EnforcementError::invalid("routes.workload", "invalid workload identity"))?;
    Ok(())
}

fn validate_promotion(promotion: &PromotionRequirement) -> Result<(), EnforcementError> {
    validate_relative_path(
        "promotion.economics_bundle_path",
        &promotion.economics_bundle_path,
    )?;
    validate_relative_path("promotion.quality_run_path", &promotion.quality_run_path)?;
    validate_relative_path(
        "promotion.authorization_path",
        &promotion.authorization_path,
    )?;
    validate_id("promotion.quality_run_id", &promotion.quality_run_id)?;
    for (field, digest) in [
        (
            "promotion.economics_report_digest",
            &promotion.economics_report_digest,
        ),
        (
            "promotion.opportunity_digest",
            &promotion.opportunity_digest,
        ),
        (
            "promotion.quality_report_digest",
            &promotion.quality_report_digest,
        ),
        ("promotion.policy_digest", &promotion.policy_digest),
        ("promotion.registry_digest", &promotion.registry_digest),
        ("promotion.owned_cost_digest", &promotion.owned_cost_digest),
    ] {
        validate_digest(field, digest)?;
    }
    bounded_positive(
        "promotion.max_economics_age_ms",
        promotion.max_economics_age_ms,
        MAX_ECONOMICS_AGE_MS,
    )?;
    if promotion.expires_at_ms == 0 {
        return Err(EnforcementError::invalid(
            "promotion.expires_at_ms",
            "must be positive",
        ));
    }
    if promotion.expires_at_ms > MAX_EXPIRY_MS {
        return Err(EnforcementError::invalid(
            "promotion.expires_at_ms",
            "exceeds maximum timestamp",
        ));
    }
    Ok(())
}

fn build_digest_document(
    config: &EnforcementConfigV1,
) -> Result<EnforcementDigestDocument, EnforcementError> {
    let mut actuators = config
        .actuators
        .iter()
        .map(|actuator| ActuatorDigest {
            supply_id: actuator.supply_id.clone(),
            endpoint_identity_digest: domain_digest(
                b"bowline.enforcement.endpoint.v1",
                sanitized_endpoint_identity(&actuator.base_url).as_bytes(),
            ),
            authorization_reference_digest: domain_digest(
                b"bowline.enforcement.authorization-reference.v1",
                actuator.authorization_env.as_bytes(),
            ),
            health_path_digest: actuator
                .health_path
                .as_ref()
                .map(|path| domain_digest(b"bowline.enforcement.health-path.v1", path.as_bytes())),
            connect_timeout_ms: actuator.connect_timeout_ms,
            response_header_timeout_ms: actuator.response_header_timeout_ms,
            stream_idle_timeout_ms: actuator.stream_idle_timeout_ms,
            concurrency: actuator.concurrency,
            probe_timeout_ms: actuator.probe_timeout_ms,
            probe_max_bytes: actuator.probe_max_bytes,
            breaker_consecutive_failures: actuator.breaker_consecutive_failures,
            breaker_cooldown_ms: actuator.breaker_cooldown_ms,
        })
        .collect::<Vec<_>>();
    actuators.sort_by(|left, right| left.supply_id.cmp(&right.supply_id));
    let mut routes = config
        .routes
        .iter()
        .map(|route| {
            let workload_digest = route
                .workload
                .as_ref()
                .filter(|_| route.protocol != AuthorityProtocol::Embeddings)
                .map(|workload| route_workload_digest(route.protocol, workload))
                .transpose()?;
            let selector_identity_digest = route.workload.as_ref().map(|workload| {
                domain_digest(
                    b"bowline.enforcement.workload-selector.v1",
                    &serde_json::to_vec(workload).expect("workload selector serializes"),
                )
            });
            Ok(RouteDigest {
                route_id: route.route_id.clone(),
                method: route.method.clone(),
                route_identity_digest: domain_digest(
                    b"bowline.enforcement.route-identity.v1",
                    format!("{}\0{}", route.method, route.path).as_bytes(),
                ),
                protocol: route.protocol,
                workload_digest,
                selector_identity_digest,
                mode: route.mode,
                rollout_ppm: route.rollout_ppm,
                promoted_supply_id: route.promoted_supply_id.clone(),
                actual_supply_id: route.actual_supply_id.clone(),
                task_class: route.task_class,
                model_authority: route.model_authority,
                fallback: route.fallback,
                promotion_binding_digest: route.promotion.as_ref().map(|promotion| {
                    domain_digest(
                        b"bowline.enforcement.promotion-binding.v1",
                        serde_json::to_vec(&(
                            domain_digest(
                                b"bowline.enforcement.economics-bundle-path.v1",
                                promotion.economics_bundle_path.as_bytes(),
                            ),
                            &promotion.economics_report_digest,
                            &promotion.opportunity_digest,
                            domain_digest(
                                b"bowline.enforcement.quality-run-path.v1",
                                promotion.quality_run_path.as_bytes(),
                            ),
                            &promotion.quality_run_id,
                            &promotion.quality_report_digest,
                            &promotion.authorization_path,
                            &promotion.policy_digest,
                            &promotion.registry_digest,
                            &promotion.owned_cost_digest,
                            promotion.max_economics_age_ms,
                            promotion.expires_at_ms,
                        ))
                        .expect("promotion binding serializes")
                        .as_slice(),
                    )
                }),
            })
        })
        .collect::<Result<Vec<_>, EnforcementError>>()?;
    routes.sort_by(|left, right| left.route_id.cmp(&right.route_id));
    Ok(EnforcementDigestDocument {
        version: 1,
        global_candidate_in_flight: config.global_candidate_in_flight,
        kill_path_digest: domain_digest(
            b"bowline.enforcement.kill-path.v1",
            format!(
                "{}\0{}",
                config.kill_switch.trust_root, config.kill_switch.relative_path
            )
            .as_bytes(),
        ),
        actuators,
        routes,
    })
}

pub fn route_workload_digest(
    protocol: AuthorityProtocol,
    workload: &WorkloadSelector,
) -> Result<String, EnforcementError> {
    let quality = match protocol {
        AuthorityProtocol::ChatCompletions => crate::quality::QualityProtocol::Chat,
        AuthorityProtocol::Responses => crate::quality::QualityProtocol::Responses,
        AuthorityProtocol::Embeddings => {
            return Err(EnforcementError::invalid("routes.protocol", "unsupported"));
        }
    };
    quality_workload_identity_digest(quality, &workload.app, &workload.resolved_tags)
        .map_err(|_| EnforcementError::invalid("routes.workload", "invalid workload identity"))
}

pub fn enforcement_bucket(
    route_id: &str,
    workload_identity_digest: &str,
    request_body_digest: &[u8; 32],
) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(b"bowline.enforcement.bucket.v1");
    for value in [
        route_id.as_bytes(),
        workload_identity_digest.as_bytes(),
        request_body_digest.as_slice(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    let digest = hasher.finalize();
    let first = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"));
    (first % u64::from(MAX_ROLLOUT_PPM)) as u32
}

/// Whether a candidate grant is present, or the specific reason none is usable. `Absent` reasons
/// occupy the exact pipeline position the legacy `GrantMissing` check always held: they are only
/// ever considered after kill/route/identity/shape have already passed.
enum GrantAvailability<'a> {
    Present(&'a PromotionGrantSnapshot),
    Absent(SelectionReason),
}

impl<'a> GrantAvailability<'a> {
    fn as_option(&self) -> Option<&'a PromotionGrantSnapshot> {
        match *self {
            GrantAvailability::Present(grant) => Some(grant),
            GrantAvailability::Absent(_) => None,
        }
    }
}

pub fn select_enforcement_plan_without_grant(input: &SelectionInput) -> EnforcementPlan {
    select_enforcement_plan_inner(
        input,
        GrantAvailability::Absent(SelectionReason::GrantMissing),
    )
}

pub fn select_enforcement_plan(
    input: &SelectionInput,
    grant: &PromotionGrantSnapshot,
) -> EnforcementPlan {
    select_enforcement_plan_inner(input, GrantAvailability::Present(grant))
}

/// Selects a fallback plan for a route whose promotion grant was rejected wholesale — a missing
/// or invalid `authority_signing` signature, or a missing, invalid, unbound, or expired
/// `promotion_approval` artifact. This reuses the exact existing zero-authority fallback
/// pipeline: kill/route/identity/shape checks still take precedence, exactly as they do for
/// `GrantMissing` today. `reason` must be one of `SelectionReason::SignatureMissing`,
/// `SignatureInvalid`, `ApprovalMissing`, `ApprovalSignatureInvalid`, `ApprovalUnbound`, or
/// `ApprovalExpired`.
pub fn select_enforcement_plan_with_grant_rejection(
    input: &SelectionInput,
    reason: SelectionReason,
) -> EnforcementPlan {
    debug_assert!(matches!(
        reason,
        SelectionReason::SignatureMissing
            | SelectionReason::SignatureInvalid
            | SelectionReason::ApprovalMissing
            | SelectionReason::ApprovalSignatureInvalid
            | SelectionReason::ApprovalUnbound
            | SelectionReason::ApprovalExpired
    ));
    select_enforcement_plan_inner(input, GrantAvailability::Absent(reason))
}

fn select_enforcement_plan_inner(
    input: &SelectionInput,
    grant: GrantAvailability<'_>,
) -> EnforcementPlan {
    let mode = input.route.mode;
    // Observe and recommend never hold candidate authority. Kill/circuit/admission state therefore
    // cannot turn these byte-faithful modes into fail-closed behavior that their schema cannot
    // durably represent. Invalid recommendation identity/metadata/shape is explicit unverified
    // evidence; kill state cannot change the truth of separately verified recommendation evidence.
    if mode == RouteMode::Observe {
        return original_plan(
            input,
            SelectionReason::ObserveOnly,
            EvidenceState::NotRequired,
        );
    }
    if mode == RouteMode::Recommend {
        let exact_context = input.method == input.route.method
            && input.path == input.route.path
            && input.protocol == input.route.protocol
            && input.identity_trusted
            && input.authority_metadata_valid
            && input.shape_supported;
        let evidence_state = exact_context
            .then(|| grant.as_option())
            .flatten()
            .filter(|grant| {
                grant_matches_route(input, grant)
                    && grant_is_fresh(input, grant)
                    && input.workload_identity_digest.as_deref()
                        == Some(grant.workload_identity_digest.as_str())
            })
            .map_or(EvidenceState::Unverified, |_| EvidenceState::Presented);
        return original_plan(input, SelectionReason::RecommendationOnly, evidence_state);
    }
    if input.kill != KillReadResult::Armed {
        return fallback_plan(input, SelectionReason::KillNotArmed, None);
    }
    if input.method != input.route.method
        || input.path != input.route.path
        || input.protocol != input.route.protocol
        || input.protocol == AuthorityProtocol::Embeddings
    {
        return fallback_plan(input, SelectionReason::RouteMismatch, None);
    }
    if !input.identity_trusted || !input.authority_metadata_valid {
        return fallback_plan(input, SelectionReason::UntrustedIdentity, None);
    }
    if !input.shape_supported {
        return fallback_plan(input, SelectionReason::UnsupportedShape, None);
    }

    let grant = match grant {
        GrantAvailability::Present(grant) => grant,
        GrantAvailability::Absent(reason) => return fallback_plan(input, reason, None),
    };
    if !grant_matches_route(input, grant) {
        return fallback_plan(input, SelectionReason::GrantMismatch, None);
    }
    if !grant_is_fresh(input, grant) {
        return fallback_plan(input, SelectionReason::GrantStale, None);
    }
    if input.workload_identity_digest.as_deref() != Some(grant.workload_identity_digest.as_str()) {
        return fallback_plan(input, SelectionReason::WorkloadMismatch, None);
    }
    let allowlisted = input.route.workload.as_ref().is_some_and(|selector| {
        input.app.as_deref() == Some(selector.app.as_str())
            && canonical_tag_sets_equal(&selector.resolved_tags, &input.resolved_tags)
    });
    if !allowlisted {
        return fallback_plan(input, SelectionReason::AllowlistMiss, None);
    }

    let Some(workload_identity_digest) = input.workload_identity_digest.as_deref() else {
        return fallback_plan(input, SelectionReason::WorkloadMismatch, None);
    };
    let bucket = enforcement_bucket(
        &input.route.route_id,
        workload_identity_digest,
        &input.request_body_digest,
    );
    let rollout_ppm = if mode == RouteMode::Enforce {
        MAX_ROLLOUT_PPM
    } else {
        input.route.rollout_ppm
    };
    if bucket >= rollout_ppm {
        return fallback_plan(input, SelectionReason::RolloutMiss, Some(bucket));
    }

    let promoted = input.route.promoted_supply_id.as_deref();
    let rewrite = match input.route.model_authority {
        Some(ModelAuthority::Preserve) => {
            if input.requested_supply_id.as_deref() != promoted {
                return fallback_plan(input, SelectionReason::PinnedModelMismatch, Some(bucket));
            }
            false
        }
        Some(ModelAuthority::RewriteToCanonical) => {
            input.requested_supply_id.as_deref() != promoted
        }
        None => {
            return fallback_plan(input, SelectionReason::PinnedModelMismatch, Some(bucket));
        }
    };

    let unavailable_reason = match input.candidate_availability {
        CandidateAvailability::Available => None,
        CandidateAvailability::CircuitOpen => Some(SelectionReason::CircuitOpen),
        CandidateAvailability::AdmissionSaturated => Some(SelectionReason::AdmissionSaturated),
        CandidateAvailability::Unavailable => Some(SelectionReason::CandidateUnavailable),
    };
    if let Some(reason) = unavailable_reason {
        return fallback_plan(input, reason, Some(bucket));
    }
    if !input.actuator_available {
        return fallback_plan(input, SelectionReason::ActuatorUnavailable, Some(bucket));
    }

    EnforcementPlan {
        target: PlanTarget::Candidate,
        mode,
        reason: SelectionReason::CandidateSelected,
        evidence_state: EvidenceState::Presented,
        bucket: Some(bucket),
        selected_supply_id: Some(grant.candidate_supply_id.clone()),
        baseline_supply_id: Some(grant.actual_supply_id.clone()),
        actuator_digest: Some(grant.actuator_digest.clone()),
        config_digest: Some(grant.config_digest.clone()),
        route_digest: Some(grant.route_digest.clone()),
        model_rewritten: rewrite,
        grant_digest: Some(grant.grant_digest.clone()),
        dispatch_count: 0,
    }
}

fn grant_matches_route(input: &SelectionInput, grant: &PromotionGrantSnapshot) -> bool {
    grant.route_id == input.route.route_id
        && grant.protocol == input.route.protocol
        && Some(grant.task_class) == input.route.task_class
        && grant.task_class == input.task_class
        && Some(grant.actual_supply_id.as_str()) == input.route.actual_supply_id.as_deref()
        && Some(grant.candidate_supply_id.as_str()) == input.route.promoted_supply_id.as_deref()
}

fn canonical_tag_sets_equal(left: &[String], right: &[String]) -> bool {
    fn canonical(tags: &[String]) -> Option<Vec<&str>> {
        let mut values = tags.iter().map(String::as_str).collect::<Vec<_>>();
        values.sort_unstable();
        let original_len = values.len();
        values.dedup();
        (values.len() == original_len).then_some(values)
    }
    canonical(left)
        .zip(canonical(right))
        .is_some_and(|(left, right)| left == right)
}

fn grant_is_fresh(input: &SelectionInput, grant: &PromotionGrantSnapshot) -> bool {
    grant.not_before_ms <= input.now_ms && input.now_ms <= grant.expires_at_ms
}

fn fallback_plan(
    input: &SelectionInput,
    reason: SelectionReason,
    bucket: Option<u32>,
) -> EnforcementPlan {
    // An unset fallback must fail closed: production callers always go through
    // ValidatedEnforcement, which guarantees `fallback` is set for authority-granting routes
    // (see `validate`); a caller-constructed SelectionInput that skips validation and leaves
    // `fallback` unset on an Enforce/CanaryEnforce route must not silently bypass to baseline.
    let target = match input.route.fallback.unwrap_or(FallbackMode::FailClosed) {
        FallbackMode::Bypass => PlanTarget::Original,
        FallbackMode::FailClosed => PlanTarget::None,
    };
    let selected_supply_id = (target == PlanTarget::Original)
        .then(|| input.route.actual_supply_id.clone())
        .flatten();
    EnforcementPlan {
        target,
        mode: input.route.mode,
        reason,
        evidence_state: EvidenceState::Unverified,
        bucket,
        selected_supply_id,
        baseline_supply_id: input.route.actual_supply_id.clone(),
        actuator_digest: None,
        config_digest: None,
        route_digest: None,
        model_rewritten: false,
        grant_digest: None,
        dispatch_count: 0,
    }
}

fn original_plan(
    input: &SelectionInput,
    reason: SelectionReason,
    evidence_state: EvidenceState,
) -> EnforcementPlan {
    EnforcementPlan {
        target: PlanTarget::Original,
        mode: input.route.mode,
        reason,
        evidence_state,
        bucket: None,
        selected_supply_id: input.route.actual_supply_id.clone(),
        baseline_supply_id: input.route.actual_supply_id.clone(),
        actuator_digest: None,
        config_digest: None,
        route_digest: None,
        model_rewritten: false,
        grant_digest: None,
        dispatch_count: 0,
    }
}

pub fn rewrite_top_level_model<'a>(
    body: &'a [u8],
    canonical: &str,
    limits: RewriteLimits,
) -> Result<Cow<'a, [u8]>, RewriteError> {
    if body.len() > limits.max_bytes {
        return Err(RewriteError::ByteLimit);
    }
    let mut parser = JsonSpanParser {
        input: body,
        offset: 0,
        limits,
        nodes: 0,
        top_level_model_count: 0,
        top_level_model_span: None,
        top_level_model_non_string: false,
    };
    parser.skip_whitespace();
    parser.parse_value(1, true)?;
    parser.skip_whitespace();
    if parser.offset != body.len() {
        return Err(RewriteError::MalformedJson);
    }
    if parser.top_level_model_count > 1 {
        return Err(RewriteError::DuplicateModel);
    }
    if parser.top_level_model_non_string {
        return Err(RewriteError::ModelNotString);
    }
    let (start, end) = parser
        .top_level_model_span
        .ok_or(RewriteError::MissingModel)?;
    let encoded = serde_json::to_vec(canonical).expect("string serialization cannot fail");
    if body[start..end] == encoded {
        return Ok(Cow::Borrowed(body));
    }
    let output_len = body
        .len()
        .checked_sub(end - start)
        .and_then(|length| length.checked_add(encoded.len()))
        .ok_or(RewriteError::ByteLimit)?;
    if output_len > limits.max_bytes {
        return Err(RewriteError::ByteLimit);
    }
    let mut rewritten = Vec::with_capacity(output_len);
    rewritten.extend_from_slice(&body[..start]);
    rewritten.extend_from_slice(&encoded);
    rewritten.extend_from_slice(&body[end..]);
    Ok(Cow::Owned(rewritten))
}

struct JsonSpanParser<'a> {
    input: &'a [u8],
    offset: usize,
    limits: RewriteLimits,
    nodes: usize,
    top_level_model_count: usize,
    top_level_model_span: Option<(usize, usize)>,
    top_level_model_non_string: bool,
}

impl JsonSpanParser<'_> {
    fn parse_value(&mut self, depth: usize, top_level: bool) -> Result<(), RewriteError> {
        if depth > self.limits.max_depth {
            return Err(RewriteError::DepthLimit);
        }
        self.nodes = self.nodes.checked_add(1).ok_or(RewriteError::NodeLimit)?;
        if self.nodes > self.limits.max_nodes {
            return Err(RewriteError::NodeLimit);
        }
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(depth, top_level),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(RewriteError::MalformedJson),
        }
    }

    fn parse_object(&mut self, depth: usize, top_level: bool) -> Result<(), RewriteError> {
        self.offset += 1;
        self.skip_whitespace();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(RewriteError::MalformedJson);
            }
            let key_span = self.parse_string()?;
            let key: String = serde_json::from_slice(&self.input[key_span.0..key_span.1])
                .map_err(|_| RewriteError::MalformedJson)?;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(RewriteError::MalformedJson);
            }
            self.skip_whitespace();
            let is_model = top_level && key == "model";
            if is_model {
                self.top_level_model_count += 1;
                if self.peek() == Some(b'"') {
                    let span = self.parse_string()?;
                    self.top_level_model_span.get_or_insert(span);
                    self.nodes = self.nodes.checked_add(1).ok_or(RewriteError::NodeLimit)?;
                    if depth + 1 > self.limits.max_depth {
                        return Err(RewriteError::DepthLimit);
                    }
                    if self.nodes > self.limits.max_nodes {
                        return Err(RewriteError::NodeLimit);
                    }
                } else {
                    self.top_level_model_non_string = true;
                    self.parse_value(depth + 1, false)?;
                }
            } else {
                self.parse_value(depth + 1, false)?;
            }
            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(RewriteError::MalformedJson);
            }
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), RewriteError> {
        self.offset += 1;
        self.skip_whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.parse_value(depth + 1, false)?;
            self.skip_whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(RewriteError::MalformedJson);
            }
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self) -> Result<(usize, usize), RewriteError> {
        let start = self.offset;
        if !self.consume(b'"') {
            return Err(RewriteError::MalformedJson);
        }
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    self.offset += 1;
                    let span = (start, self.offset);
                    serde_json::from_slice::<String>(&self.input[span.0..span.1])
                        .map_err(|_| RewriteError::MalformedJson)?;
                    return Ok(span);
                }
                b'\\' => {
                    self.offset += 1;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.offset += 1;
                        }
                        Some(b'u') => {
                            self.offset += 1;
                            for _ in 0..4 {
                                if !self.peek().is_some_and(|value| value.is_ascii_hexdigit()) {
                                    return Err(RewriteError::MalformedJson);
                                }
                                self.offset += 1;
                            }
                        }
                        _ => return Err(RewriteError::MalformedJson),
                    }
                }
                0x00..=0x1f => return Err(RewriteError::MalformedJson),
                _ => self.offset += 1,
            }
        }
        Err(RewriteError::MalformedJson)
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), RewriteError> {
        if self.input.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(RewriteError::MalformedJson)
        }
    }

    fn parse_number(&mut self) -> Result<(), RewriteError> {
        self.consume(b'-');
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(RewriteError::MalformedJson);
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return Err(RewriteError::MalformedJson),
        }
        if self.consume(b'.') {
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(RewriteError::MalformedJson);
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
        }
        if self.peek().is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            self.offset += 1;
            if self.peek().is_some_and(|byte| matches!(byte, b'+' | b'-')) {
                self.offset += 1;
            }
            if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(RewriteError::MalformedJson);
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
}

fn sanitized_endpoint_identity(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "<invalid>".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string().trim_end_matches('/').to_owned()
}

fn validate_secret_env(value: &str) -> Result<(), EnforcementError> {
    let syntax = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase());
    let meaning = ["TOKEN", "KEY", "SECRET", "AUTH"]
        .iter()
        .any(|marker| value.contains(marker));
    if syntax && meaning {
        Ok(())
    } else {
        Err(EnforcementError::invalid(
            "actuators.authorization_env",
            "must be a bounded uppercase credential environment reference",
        ))
    }
}

fn validate_id(field: &'static str, value: &str) -> Result<(), EnforcementError> {
    if !crate::identifier::is_bounded_identifier(value) {
        Err(EnforcementError::invalid(
            field,
            "must be a bounded identifier",
        ))
    } else {
        Ok(())
    }
}

fn validate_http_path(field: &'static str, value: &str) -> Result<(), EnforcementError> {
    if value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
    {
        Err(EnforcementError::invalid(
            field,
            "must be a bounded absolute HTTP path",
        ))
    } else {
        Ok(())
    }
}

fn validate_relative_path(field: &'static str, value: &str) -> Result<(), EnforcementError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.chars().any(char::is_control)
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(EnforcementError::invalid(
            field,
            "must be a bounded relative path",
        ))
    } else {
        Ok(())
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), EnforcementError> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(EnforcementError::invalid(field, "must be a SHA-256 digest"))
    }
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_id(value: &str) -> bool {
    crate::identifier::is_bounded_identifier(value)
}

fn bounded_positive<T>(field: &'static str, value: T, max: T) -> Result<(), EnforcementError>
where
    T: Copy + Default + PartialEq + PartialOrd,
{
    if value == T::default() || value > max {
        Err(EnforcementError::invalid(field, "outside compiled bound"))
    } else {
        Ok(())
    }
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

pub fn economics_opportunity_digest(
    opportunity: &crate::economics::OpportunityRow,
) -> Result<String, EnforcementError> {
    Ok(domain_digest(
        b"bowline.enforcement.economics-opportunity.v1",
        &serde_json::to_vec(opportunity)
            .map_err(|error| EnforcementError::Parse(error.to_string()))?,
    ))
}
