use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, SyncSender, TrySendError},
        Arc, Mutex,
    },
};

use bowline_core::{
    economics::{
        canonical_quality_projection_digest, ActionableEconomicsReport, AnalysisMode,
        QualityJoinEvidence, SelectedEvidence, SourceBindingCheck,
    },
    enforcement::{
        economics_opportunity_digest, select_enforcement_plan,
        select_enforcement_plan_without_grant, validate_promotion_documents,
        validate_recommendation_documents, ActiveRuntimeProvenance, AuthorityProtocol,
        EconomicsPromotionSource, EnforcementPlan, EnforcementRoute, EvidenceState, KillReadResult,
        PlanTarget, PromotionAuthorizationV1, PromotionGrantSnapshot, PromotionOpportunityEvidence,
        QualityPromotionSource, RouteMode, SelectionInput, SelectionReason, SelectionRequestFacts,
        ValidatedEnforcement,
    },
    quality_report::{
        parse_quality_report_document, quality_report_v2_digest, validate_quality_report_evidence,
        validate_quality_report_v2_evidence, QualityReportDocument,
    },
    quality_run::{QualityLedgerRead, QualityOutcome, QualityRecovery, QualityRunManifest},
    traffic::ProtocolKind,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnforcementLoadError {
    #[error("unsafe enforcement evidence path")]
    UnsafePath,
    #[error("enforcement evidence is not a private regular file")]
    UnsafeFile,
    #[error("enforcement evidence exceeds its byte limit")]
    TooLarge,
    #[error("invalid or incomplete enforcement evidence: {0}")]
    Invalid(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

const ECONOMICS_PAYLOADS: [&str; 6] = [
    "dimensions.csv",
    "opportunities.csv",
    "reconciliation.csv",
    "report.html",
    "report.json",
    "report.md",
];
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_QUALITY_LEDGER_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROMOTION_AUTHORIZATION_BYTES: usize = 64 * 1024;
const MAX_QUALITY_RECORDS: u64 = bowline_core::quality::MAX_CASES as u64;

/// Allocation authority is obtainable only by descriptor-safe source loading in this module.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedPromotionGrant {
    validation: bowline_core::enforcement::ValidatedPromotionDocuments,
    grant_digest: String,
    #[cfg(test)]
    #[serde(skip)]
    task_class_override: Option<bowline_core::supply::TaskClass>,
}

/// Fresh, exact recommendation evidence. This type is deliberately distinct from allocation
/// authority and has no conversion into `VerifiedPromotionGrant`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedRecommendationEvidence {
    validation: bowline_core::enforcement::ValidatedPromotionDocuments,
    evidence_digest: String,
}

impl VerifiedRecommendationEvidence {
    fn selection_snapshot(&self) -> PromotionGrantSnapshot {
        PromotionGrantSnapshot {
            route_id: self.validation.route_id().to_owned(),
            workload_identity_digest: self.validation.workload_identity_digest().to_owned(),
            task_class: self.validation.task_class(),
            protocol: self.validation.protocol(),
            actual_supply_id: self.validation.actual_supply_id().to_owned(),
            candidate_supply_id: self.validation.candidate_supply_id().to_owned(),
            config_digest: self.validation.config_digest().to_owned(),
            actuator_digest: self.validation.actuator_digest().to_owned(),
            route_digest: self.validation.route_digest().to_owned(),
            grant_digest: self.evidence_digest.clone(),
            not_before_ms: self.validation.not_before_ms(),
            expires_at_ms: self.validation.expires_at_ms(),
        }
    }
}

impl VerifiedPromotionGrant {
    pub fn route_id(&self) -> &str {
        self.validation.route_id()
    }
    pub fn workload_identity_digest(&self) -> &str {
        self.validation.workload_identity_digest()
    }
    pub fn task_class(&self) -> bowline_core::supply::TaskClass {
        #[cfg(test)]
        if let Some(task_class) = self.task_class_override {
            return task_class;
        }
        self.validation.task_class()
    }
    pub fn protocol(&self) -> AuthorityProtocol {
        self.validation.protocol()
    }
    pub fn actual_supply_id(&self) -> &str {
        self.validation.actual_supply_id()
    }
    pub fn candidate_supply_id(&self) -> &str {
        self.validation.candidate_supply_id()
    }
    pub fn economics_source_digest(&self) -> &str {
        self.validation.economics_source_digest()
    }
    pub fn quality_source_digest(&self) -> &str {
        self.validation.quality_source_digest()
    }
    pub fn config_digest(&self) -> &str {
        self.validation.config_digest()
    }
    pub fn actuator_digest(&self) -> &str {
        self.validation.actuator_digest()
    }
    pub fn route_digest(&self) -> &str {
        self.validation.route_digest()
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.validation.expires_at_ms()
    }
    pub fn not_before_ms(&self) -> u64 {
        self.validation.not_before_ms()
    }
    pub fn validation_digest(&self) -> &str {
        self.validation.validation_digest()
    }
    pub fn is_fresh_at(&self, now_ms: u64) -> bool {
        self.validation.is_fresh_at(now_ms)
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub(crate) fn actual_rate_micros(&self) -> bowline_core::economics::CostRateMicros {
        self.validation.actual_rate_micros()
    }
    pub(crate) fn candidate_rate_micros(&self) -> bowline_core::economics::CostRateMicros {
        self.validation.candidate_rate_micros()
    }
    pub(crate) fn opportunity_digest(&self) -> &str {
        self.validation.opportunity_digest()
    }

    fn selection_snapshot(&self) -> PromotionGrantSnapshot {
        PromotionGrantSnapshot {
            route_id: self.route_id().to_owned(),
            workload_identity_digest: self.workload_identity_digest().to_owned(),
            task_class: self.task_class(),
            protocol: self.protocol(),
            actual_supply_id: self.actual_supply_id().to_owned(),
            candidate_supply_id: self.candidate_supply_id().to_owned(),
            config_digest: self.config_digest().to_owned(),
            actuator_digest: self.actuator_digest().to_owned(),
            route_digest: self.route_digest().to_owned(),
            grant_digest: self.grant_digest().to_owned(),
            not_before_ms: self.not_before_ms(),
            expires_at_ms: self.expires_at_ms(),
        }
    }
}

#[cfg(test)]
pub(crate) fn test_verified_promotion_grant(
    validation: bowline_core::enforcement::ValidatedPromotionDocuments,
) -> VerifiedPromotionGrant {
    let grant_digest = domain_digest(
        b"bowline.enforcement.verified-promotion-grant.v1",
        validation.validation_digest().as_bytes(),
    );
    VerifiedPromotionGrant {
        validation,
        grant_digest,
        task_class_override: None,
    }
}

#[cfg(test)]
pub(crate) fn test_verified_promotion_grant_for_task(
    validation: bowline_core::enforcement::ValidatedPromotionDocuments,
    task_class: bowline_core::supply::TaskClass,
) -> VerifiedPromotionGrant {
    let mut grant = test_verified_promotion_grant(validation);
    grant.task_class_override = Some(task_class);
    grant
}

#[cfg(test)]
pub(crate) fn test_verified_recommendation_evidence(
    validation: bowline_core::enforcement::ValidatedPromotionDocuments,
) -> VerifiedRecommendationEvidence {
    let evidence_digest = domain_digest(
        b"bowline.enforcement.verified-recommendation-evidence.v1",
        validation.validation_digest().as_bytes(),
    );
    VerifiedRecommendationEvidence {
        validation,
        evidence_digest,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayEvidenceState {
    NotRequired,
    Verified,
    Unverified,
}

/// A gateway decision proposal whose verified state can only be created from the opaque grant and
/// its exact validated enforcement context. It remains non-dispatchable without verified sealed
/// promotion authority.
#[derive(Debug)]
pub struct GatewayEnforcementPlan {
    plan: EnforcementPlan,
    evidence_state: GatewayEvidenceState,
    selection_binding: ExactSelectionBinding,
}

#[derive(Debug)]
pub(crate) struct ExactSelectionBinding {
    pub(crate) route_id: String,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) protocol: AuthorityProtocol,
    pub(crate) task_class: bowline_core::supply::TaskClass,
    pub(crate) app: Option<String>,
    pub(crate) resolved_tags: Vec<String>,
    pub(crate) workload_identity_digest: Option<String>,
    pub(crate) request_body_digest: [u8; 32],
    pub(crate) requested_supply_id: Option<String>,
    pub(crate) selected_bucket: Option<u32>,
}

impl GatewayEnforcementPlan {
    pub fn plan(&self) -> &EnforcementPlan {
        &self.plan
    }

    pub fn target(&self) -> PlanTarget {
        self.plan.target
    }

    pub fn reason(&self) -> SelectionReason {
        self.plan.reason
    }

    pub fn evidence_state(&self) -> GatewayEvidenceState {
        self.evidence_state
    }

    pub(crate) fn into_parts(
        self,
    ) -> (EnforcementPlan, GatewayEvidenceState, ExactSelectionBinding) {
        (self.plan, self.evidence_state, self.selection_binding)
    }
}

pub fn select_enforcement_target(
    validated: &ValidatedEnforcement,
    route_id: &str,
    facts: &SelectionRequestFacts,
    grant: &VerifiedPromotionGrant,
) -> Result<GatewayEnforcementPlan, EnforcementLoadError> {
    let route = validated
        .route(route_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("unknown enforcement route".into()))?;
    if !route.mode.grants_authority() {
        return Err(EnforcementLoadError::Invalid(
            "promotion grant cannot be used by a non-authority route".into(),
        ));
    }
    let input = SelectionInput::from_validated_route(route, facts);
    let mut snapshot = grant.selection_snapshot();
    let candidate = route.promoted_supply_id.as_deref();
    let exact_context = grant.route_id() == route_id
        && grant.config_digest() == validated.normalized_digest()
        && validated.route_digest(route_id).as_deref() == Some(grant.route_digest())
        && candidate.and_then(|supply| {
            validated
                .actuator_digest(supply)
                .as_deref()
                .map(str::to_owned)
        }) == Some(grant.actuator_digest().to_owned());
    if !exact_context {
        snapshot.route_id = "<validated-context-mismatch>".into();
    }
    let mut plan = select_enforcement_plan(&input, &snapshot);
    bind_validated_plan(validated, route_id, &mut plan)?;
    let evidence_state = match (exact_context, plan.evidence_state) {
        (true, EvidenceState::Presented) => GatewayEvidenceState::Verified,
        (_, EvidenceState::NotRequired) => GatewayEvidenceState::NotRequired,
        _ => GatewayEvidenceState::Unverified,
    };
    Ok(GatewayEnforcementPlan {
        selection_binding: exact_selection_binding(route_id, facts, plan.bucket),
        plan,
        evidence_state,
    })
}

pub fn select_recommendation_target(
    validated: &ValidatedEnforcement,
    route_id: &str,
    facts: &SelectionRequestFacts,
    evidence: &VerifiedRecommendationEvidence,
) -> Result<GatewayEnforcementPlan, EnforcementLoadError> {
    let route = validated
        .route(route_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("unknown enforcement route".into()))?;
    if route.mode != RouteMode::Recommend {
        return Err(EnforcementLoadError::Invalid(
            "recommendation evidence requires a recommend route".into(),
        ));
    }
    let input = SelectionInput::from_validated_route(route, facts);
    let mut snapshot = evidence.selection_snapshot();
    let candidate = route.promoted_supply_id.as_deref();
    let exact_context = snapshot.route_id == route_id
        && snapshot.config_digest == validated.normalized_digest()
        && validated.route_digest(route_id).as_deref() == Some(snapshot.route_digest.as_str())
        && candidate.and_then(|supply| validated.actuator_digest(supply))
            == Some(snapshot.actuator_digest.clone());
    if !exact_context {
        snapshot.route_id = "<validated-context-mismatch>".into();
    }
    let mut plan = select_enforcement_plan(&input, &snapshot);
    bind_validated_plan(validated, route_id, &mut plan)?;
    let evidence_state = if exact_context && plan.evidence_state == EvidenceState::Presented {
        GatewayEvidenceState::Verified
    } else {
        GatewayEvidenceState::Unverified
    };
    Ok(GatewayEnforcementPlan {
        selection_binding: exact_selection_binding(route_id, facts, plan.bucket),
        plan,
        evidence_state,
    })
}

fn exact_selection_binding(
    route_id: &str,
    facts: &SelectionRequestFacts,
    selected_bucket: Option<u32>,
) -> ExactSelectionBinding {
    ExactSelectionBinding {
        route_id: route_id.to_owned(),
        method: facts.method.clone(),
        path: facts.path.clone(),
        protocol: facts.protocol,
        task_class: facts.task_class,
        app: facts.app.clone(),
        resolved_tags: facts.resolved_tags.clone(),
        workload_identity_digest: facts.workload_identity_digest.clone(),
        request_body_digest: facts.request_body_digest,
        requested_supply_id: facts.requested_supply_id.clone(),
        selected_bucket,
    }
}

pub fn select_enforcement_target_without_grant(
    validated: &ValidatedEnforcement,
    route_id: &str,
    facts: &SelectionRequestFacts,
) -> Result<GatewayEnforcementPlan, EnforcementLoadError> {
    let route = validated
        .route(route_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("unknown enforcement route".into()))?;
    let mut plan =
        select_enforcement_plan_without_grant(&SelectionInput::from_validated_route(route, facts));
    bind_validated_plan(validated, route_id, &mut plan)?;
    let evidence_state = if plan.evidence_state == EvidenceState::NotRequired {
        GatewayEvidenceState::NotRequired
    } else {
        GatewayEvidenceState::Unverified
    };
    Ok(GatewayEnforcementPlan {
        selection_binding: exact_selection_binding(route_id, facts, plan.bucket),
        plan,
        evidence_state,
    })
}

fn bind_validated_plan(
    validated: &ValidatedEnforcement,
    route_id: &str,
    plan: &mut EnforcementPlan,
) -> Result<(), EnforcementLoadError> {
    plan.config_digest = Some(validated.normalized_digest().to_owned());
    plan.route_digest = Some(
        validated
            .route_digest(route_id)
            .ok_or_else(|| EnforcementLoadError::Invalid("route digest unavailable".into()))?,
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBinding {
    name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    schema_version: u32,
    package_version: String,
    source_revision: String,
    analysis_digest: String,
    config_digest: String,
    source_bindings_digest: String,
    selected_evidence: SelectedEvidence,
    artifacts: Vec<ArtifactBinding>,
}

fn load_unsealed_promotion_sources(
    validated: &ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
) -> Result<(EconomicsPromotionSource, QualityPromotionSource), EnforcementLoadError> {
    let route = validated
        .route(route_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("unknown enforcement route".into()))?;
    let requirement = route
        .promotion
        .as_ref()
        .ok_or_else(|| EnforcementLoadError::Invalid("route has no promotion evidence".into()))?;
    let quality = load_quality_source(
        evidence_root,
        &requirement.quality_run_path,
        route.protocol,
        route
            .promoted_supply_id
            .as_deref()
            .ok_or_else(|| EnforcementLoadError::Invalid("route has no promoted supply".into()))?,
    )?;
    let economics = load_economics_source(
        route,
        evidence_root,
        &requirement.economics_bundle_path,
        &quality,
    )?;
    Ok((economics, quality))
}

fn load_promotion_authorization(
    validated: &ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
) -> Result<PromotionAuthorizationV1, EnforcementLoadError> {
    let authorization_path = &validated
        .route(route_id)
        .and_then(|route| route.promotion.as_ref())
        .ok_or_else(|| EnforcementLoadError::Invalid("route has no promotion evidence".into()))?
        .authorization_path;
    let bytes = read_private_bundle_file(
        evidence_root,
        authorization_path,
        MAX_PROMOTION_AUTHORIZATION_BYTES,
    )?;
    serde_json::from_slice(&bytes).map_err(EnforcementLoadError::Json)
}

pub fn seal_promotion_authorization_for_route(
    validated: &ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
    active: &ActiveRuntimeProvenance,
    now_ms: u64,
) -> Result<PromotionAuthorizationV1, EnforcementLoadError> {
    let route = validated
        .route(route_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("unknown enforcement route".into()))?;
    if !matches!(
        route.protocol,
        AuthorityProtocol::ChatCompletions | AuthorityProtocol::Responses
    ) || route.mode == RouteMode::Observe
        || route.promotion.is_none()
    {
        return Err(EnforcementLoadError::Invalid(
            "route cannot carry promotion authorization".into(),
        ));
    }
    let (economics, quality) = load_unsealed_promotion_sources(validated, route_id, evidence_root)?;
    let authorization = bowline_core::enforcement::seal_promotion_authorization(
        validated, route_id, &economics, &quality, active, now_ms,
    )
    .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let mut bytes = serde_json::to_vec(&authorization)?;
    bytes.push(b'\n');
    publish_private_file_exclusive(
        evidence_root,
        &route
            .promotion
            .as_ref()
            .expect("promotion checked above")
            .authorization_path,
        &bytes,
    )?;
    Ok(authorization)
}

pub fn load_verified_promotion_grant(
    validated: &ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
    active: &ActiveRuntimeProvenance,
    now_ms: u64,
) -> Result<VerifiedPromotionGrant, EnforcementLoadError> {
    let (economics, quality) = load_unsealed_promotion_sources(validated, route_id, evidence_root)?;
    let authorization = load_promotion_authorization(validated, route_id, evidence_root)?;
    if !economics
        .selected_quality_digests
        .iter()
        .any(|digest| digest == &quality.report_digest)
    {
        return Err(EnforcementLoadError::Invalid(
            "loaded quality report is not in selected economics evidence".into(),
        ));
    }
    let validation = validate_promotion_documents(
        validated,
        route_id,
        &economics,
        &quality,
        &authorization,
        active,
        now_ms,
    )
    .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let grant_digest = domain_digest(
        b"bowline.enforcement.verified-promotion-grant.v1",
        validation.validation_digest().as_bytes(),
    );
    Ok(VerifiedPromotionGrant {
        validation,
        grant_digest,
        #[cfg(test)]
        task_class_override: None,
    })
}

pub fn load_verified_recommendation_evidence(
    validated: &ValidatedEnforcement,
    route_id: &str,
    evidence_root: &Path,
    active: &ActiveRuntimeProvenance,
    now_ms: u64,
) -> Result<VerifiedRecommendationEvidence, EnforcementLoadError> {
    let route = validated
        .route(route_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("unknown enforcement route".into()))?;
    if route.mode != RouteMode::Recommend {
        return Err(EnforcementLoadError::Invalid(
            "recommendation evidence requires a recommend route".into(),
        ));
    }
    let (economics, quality) = load_unsealed_promotion_sources(validated, route_id, evidence_root)?;
    let authorization = load_promotion_authorization(validated, route_id, evidence_root)?;
    if !economics
        .selected_quality_digests
        .iter()
        .any(|digest| digest == &quality.report_digest)
    {
        return Err(EnforcementLoadError::Invalid(
            "loaded quality report is not in selected economics evidence".into(),
        ));
    }
    let validation = validate_recommendation_documents(
        validated,
        route_id,
        &economics,
        &quality,
        &authorization,
        active,
        now_ms,
    )
    .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let evidence_digest = domain_digest(
        b"bowline.enforcement.verified-recommendation-evidence.v1",
        validation.validation_digest().as_bytes(),
    );
    Ok(VerifiedRecommendationEvidence {
        validation,
        evidence_digest,
    })
}

fn load_economics_source(
    route: &EnforcementRoute,
    root: &Path,
    directory: &str,
    quality: &QualityPromotionSource,
) -> Result<EconomicsPromotionSource, EnforcementLoadError> {
    let manifest_path = joined(directory, "manifest.json")?;
    let manifest_bytes = read_private_bundle_file(root, &manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema_version != 1
        || manifest.package_version.is_empty()
        || manifest.source_revision.is_empty()
        || !valid_digest(&manifest.analysis_digest)
        || !valid_digest(&manifest.config_digest)
        || manifest.artifacts.len() != ECONOMICS_PAYLOADS.len()
    {
        return Err(EnforcementLoadError::Invalid(
            "invalid economics manifest".into(),
        ));
    }
    manifest
        .selected_evidence
        .validate()
        .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;

    let bindings = manifest
        .artifacts
        .iter()
        .map(|binding| (binding.name.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    if bindings.len() != ECONOMICS_PAYLOADS.len()
        || ECONOMICS_PAYLOADS
            .iter()
            .any(|name| !bindings.contains_key(name))
    {
        return Err(EnforcementLoadError::Invalid(
            "economics payload set mismatch".into(),
        ));
    }
    let mut artifact_digests = BTreeMap::new();
    let mut report_bytes = None;
    for name in ECONOMICS_PAYLOADS {
        let bytes = read_private_bundle_file(root, &joined(directory, name)?, MAX_ARTIFACT_BYTES)?;
        let binding = bindings[name];
        let digest = plain_digest(&bytes);
        if binding.size_bytes != bytes.len() as u64 || binding.sha256 != digest {
            return Err(EnforcementLoadError::Invalid(format!(
                "economics payload hash mismatch: {name}"
            )));
        }
        if name == "report.json" {
            report_bytes = Some(bytes);
        }
        artifact_digests.insert(name.to_owned(), digest);
    }
    let report: ActionableEconomicsReport = serde_json::from_slice(
        report_bytes
            .as_deref()
            .ok_or_else(|| EnforcementLoadError::Invalid("missing economics report".into()))?,
    )?;
    report
        .build_provenance
        .validate()
        .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    if report.selected_evidence != manifest.selected_evidence
        || report.build_provenance.package_version != manifest.package_version
        || report.build_provenance.source_revision != manifest.source_revision
        || plain_digest(
            &serde_json::to_vec(&report.source_bindings).map_err(EnforcementLoadError::Json)?,
        ) != manifest.source_bindings_digest
    {
        return Err(EnforcementLoadError::Invalid(
            "economics manifest/report binding mismatch".into(),
        ));
    }
    validate_source_binding_matrix(&report, &manifest.analysis_digest, &manifest.config_digest)?;
    let actual = route.actual_supply_id.as_deref().unwrap_or_default();
    let candidate = route.promoted_supply_id.as_deref().unwrap_or_default();
    let task = route
        .task_class
        .ok_or_else(|| EnforcementLoadError::Invalid("route lacks task".into()))?;
    let configured_workload = bowline_core::enforcement::route_workload_digest(
        route.protocol,
        route
            .workload
            .as_ref()
            .ok_or_else(|| EnforcementLoadError::Invalid("route lacks workload".into()))?,
    )
    .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let matches = report
        .opportunities
        .iter()
        .filter(|row| {
            row.key.actual_supply_id == actual
                && row.key.candidate_supply_id == candidate
                && row.key.task_class == task
                && protocol_from_traffic(row.key.protocol) == Some(route.protocol)
                && row.workload_identity_digest == configured_workload
                && economics_opportunity_digest(row).ok().as_deref()
                    == route
                        .promotion
                        .as_ref()
                        .map(|promotion| promotion.opportunity_digest.as_str())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(EnforcementLoadError::Invalid(
            "exact opportunity join is not unique".into(),
        ));
    }
    let opportunity = matches[0];
    let quality_protocol = protocol_to_traffic(route.protocol)
        .ok_or_else(|| EnforcementLoadError::Invalid("unsupported quality protocol".into()))?;
    let projection_digest = canonical_quality_projection_digest(&[QualityJoinEvidence {
        run_id: quality.run_id.clone(),
        schema_version: quality.schema_version,
        completed_at_ms: quality.completed_at_ms,
        valid_until_ms: quality.valid_until_ms,
        workload_identity_digest: Some(quality.workload_identity_digest.clone()),
        task_class: quality.task_class,
        protocol: quality_protocol,
        candidate_supply_id: quality.candidate_supply_id.clone(),
        effective_verdict: quality.effective_verdict,
        manifest_valid: quality.manifest_valid,
        outcomes_digest_valid: quality.outcomes_valid,
        report_digest_valid: quality.report_valid,
    }])
    .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let expected_age_ms = report
        .as_of_ms
        .checked_sub(quality.completed_at_ms)
        .ok_or_else(|| EnforcementLoadError::Invalid("quality evidence is future-dated".into()))?;
    let quality_summary = opportunity.quality.as_ref();
    let quality_bindings = report
        .selected_evidence
        .quality
        .iter()
        .filter(|binding| {
            binding.run_id == quality.run_id
                && binding.schema_version == quality.schema_version
                && binding.manifest_digest == quality.manifest_digest
                && binding.recomputed_manifest_digest == quality.manifest_digest
                && binding.outcomes_digest == quality.outcomes_digest
                && binding.recomputed_outcomes_digest == quality.outcomes_digest
                && binding.report_digest == quality.report_digest
                && binding.recomputed_report_digest == quality.report_digest
                && binding.registry_digest == quality.registry_digest
                && binding.owned_cost_digest == quality.owned_cost_digest
                && binding.policy_digest == quality.policy_digest
                && binding.join_projection_digest == projection_digest
                && quality_summary.is_some_and(|summary| {
                    summary.run_id == quality.run_id
                        && summary.verdict == quality.effective_verdict
                        && summary.completed_at_ms == quality.completed_at_ms
                        && summary.age_ms == expected_age_ms
                })
        })
        .collect::<Vec<_>>();
    if quality_bindings.len() != 1 {
        return Err(EnforcementLoadError::Invalid(
            "exact economics-to-quality binding is not unique".into(),
        ));
    }
    let quality_binding = quality_bindings[0];
    let selected_quality_digests = report
        .selected_evidence
        .quality
        .iter()
        .map(|binding| binding.report_digest.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let selected_traffic_digest = structured_digest(&report.selected_evidence.traffic)?;
    let selected_billing_digest = report
        .selected_evidence
        .billing
        .as_ref()
        .map(structured_digest)
        .transpose()?;
    Ok(EconomicsPromotionSource {
        schema_version: report.schema_version,
        as_of_ms: report.as_of_ms,
        window_end_ms: report.window_end_ms,
        complete: report.complete,
        report_digest: artifact_digests["report.json"].clone(),
        bundle_digest: domain_digest(b"bowline.economics.bundle.v1", &manifest_bytes),
        artifact_digests,
        selected_traffic_digest,
        selected_billing_digest,
        selected_quality_digests,
        opportunity: PromotionOpportunityEvidence {
            digest: economics_opportunity_digest(opportunity)
                .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?,
            workload_identity_digest: opportunity.workload_identity_digest.clone(),
            task_class: opportunity.key.task_class,
            protocol: route.protocol,
            actual_supply_id: opportunity.key.actual_supply_id.clone(),
            candidate_supply_id: opportunity.key.candidate_supply_id.clone(),
            eligible: opportunity.eligible,
            policy_feasible: !opportunity.blockers.iter().any(|blocker| {
                matches!(
                    blocker,
                    bowline_core::economics::Blocker::PolicyViolation
                        | bowline_core::economics::Blocker::PolicyUnknown
                )
            }),
            capacity_available: !opportunity
                .blockers
                .contains(&bowline_core::economics::Blocker::CandidateNotFeasible),
            actual_cost_micros: opportunity.actual_cost_micros,
            candidate_cost_micros: opportunity.candidate_cost_micros,
            actual_rate_micros: opportunity.actual_rate_micros,
            candidate_rate_micros: opportunity.candidate_rate_micros,
        },
        policy_digest: quality_binding.policy_digest.clone(),
        registry_digest: quality_binding.registry_digest.clone(),
        owned_cost_digest: quality_binding.owned_cost_digest.clone(),
    })
}

fn load_quality_source(
    root: &Path,
    directory: &str,
    protocol: AuthorityProtocol,
    candidate_supply_id: &str,
) -> Result<QualityPromotionSource, EnforcementLoadError> {
    let manifest_bytes = read_private_bundle_file(
        root,
        &joined(directory, "manifest.json")?,
        MAX_MANIFEST_BYTES,
    )?;
    let manifest: QualityRunManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest
        .validate()
        .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let report_bytes = read_private_bundle_file(
        root,
        &joined(directory, "quality-report.json")?,
        MAX_MANIFEST_BYTES,
    )?;
    let report_document = parse_quality_report_document(&report_bytes)
        .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
    let ledger_bytes = read_private_bundle_file(
        root,
        &joined(directory, "outcomes.bwq")?,
        MAX_QUALITY_LEDGER_BYTES,
    )?;
    let ledger = decode_quality_ledger(&ledger_bytes, manifest.accepted)?;
    let report = match report_document {
        QualityReportDocument::V2(report) => {
            validate_quality_report_v2_evidence(&report, &manifest, &ledger)
                .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
            report
        }
        QualityReportDocument::V1(report) => {
            validate_quality_report_evidence(&report, &manifest, &ledger)
                .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
            return Err(EnforcementLoadError::Invalid(
                "quality schema v1 is non-joinable".into(),
            ));
        }
    };
    let candidate = report
        .candidates
        .iter()
        .find(|entry| entry.evidence.candidate_supply_id == candidate_supply_id)
        .ok_or_else(|| EnforcementLoadError::Invalid("quality candidate is absent".into()))?;
    let expected_quality_protocol = match protocol {
        AuthorityProtocol::ChatCompletions => bowline_core::quality::QualityProtocol::Chat,
        AuthorityProtocol::Responses => bowline_core::quality::QualityProtocol::Responses,
        AuthorityProtocol::Embeddings => {
            return Err(EnforcementLoadError::Invalid(
                "Embeddings cannot load Chat evidence".into(),
            ));
        }
    };
    if candidate.evidence.protocol != expected_quality_protocol {
        return Err(EnforcementLoadError::Invalid(
            "quality protocol mismatch".into(),
        ));
    }
    Ok(QualityPromotionSource {
        schema_version: report.schema_version,
        run_id: report.run_id.clone(),
        completed_at_ms: report.completed_at_ms,
        valid_until_ms: report.valid_until_ms,
        workload_identity_digest: candidate.workload_identity_digest.clone(),
        task_class: candidate.evidence.task_class,
        protocol,
        candidate_supply_id: candidate.evidence.candidate_supply_id.clone(),
        effective_verdict: candidate.evidence.assessment.effective_verdict,
        manifest_digest: canonical_digest(
            b"bowline.economics.quality-manifest.v1",
            &serde_json::to_vec(&manifest).map_err(EnforcementLoadError::Json)?,
        ),
        outcomes_digest: report.outcomes_digest.clone(),
        report_digest: quality_report_v2_digest(&report)
            .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?,
        manifest_valid: true,
        outcomes_valid: true,
        report_valid: true,
        policy_digest: manifest.provenance.policy_digest.clone(),
        registry_digest: manifest.provenance.registry_digest.clone(),
        owned_cost_digest: manifest
            .provenance
            .owned_cost_digest
            .clone()
            .ok_or_else(|| {
                EnforcementLoadError::Invalid("quality owned-cost binding absent".into())
            })?,
    })
}

fn validate_source_binding_matrix(
    report: &ActionableEconomicsReport,
    analysis_digest: &str,
    config_digest: &str,
) -> Result<(), EnforcementLoadError> {
    let registries = report
        .selected_evidence
        .quality
        .iter()
        .map(|quality| quality.registry_digest.as_str())
        .collect::<BTreeSet<_>>();
    let owned_costs = report
        .selected_evidence
        .quality
        .iter()
        .map(|quality| quality.owned_cost_digest.as_str())
        .collect::<BTreeSet<_>>();
    let policies = report
        .selected_evidence
        .quality
        .iter()
        .map(|quality| quality.policy_digest.as_str())
        .collect::<BTreeSet<_>>();
    if registries.len() != 1 || owned_costs.len() != 1 || policies.len() != 1 {
        return Err(EnforcementLoadError::Invalid(
            "source binding matrix has no single quality provenance".into(),
        ));
    }
    let registry = (*registries.first().expect("checked")).to_owned();
    let owned_cost = (*owned_costs.first().expect("checked")).to_owned();
    let policy = (*policies.first().expect("checked")).to_owned();
    let mut expected = BTreeMap::<(String, String), Option<String>>::new();
    let mut require = |source: &str, field: &str, digest: Option<String>| {
        expected.insert((source.to_owned(), field.to_owned()), digest);
    };
    require(
        "analysis",
        "analysis-manifest",
        Some(analysis_digest.to_owned()),
    );
    require(
        "traffic",
        "selected-records",
        Some(report.selected_evidence.traffic.records_digest.clone()),
    );
    require(
        "traffic",
        "manifest",
        Some(report.selected_evidence.traffic.manifest_digest.clone()),
    );
    require(
        "traffic",
        "recovery",
        Some(report.selected_evidence.traffic.recovery_digest.clone()),
    );
    require("traffic", "manifest-recovery", None);
    require("config", "configuration", Some(config_digest.to_owned()));
    require("traffic", "registry", Some(registry.clone()));
    if report.mode == AnalysisMode::BillingReconciled {
        let billing = report.selected_evidence.billing.as_ref().ok_or_else(|| {
            EnforcementLoadError::Invalid("source binding matrix lacks billing evidence".into())
        })?;
        require(
            "billing",
            "normalized-rows",
            Some(billing.rows_digest.clone()),
        );
        require("billing", "manifest", Some(billing.manifest_digest.clone()));
        require("billing", "recovery", Some(billing.recovery_digest.clone()));
        require("billing", "manifest-recovery", None);
        require("billing", "registry", Some(registry));
    }
    require("traffic", "owned-cost", Some(owned_cost));
    require("traffic", "policy", Some(policy));
    for quality in &report.selected_evidence.quality {
        for (field, digest) in [
            ("manifest", quality.manifest_digest.clone()),
            ("registry", quality.registry_digest.clone()),
            ("report-registry", quality.registry_digest.clone()),
            ("owned-cost", quality.owned_cost_digest.clone()),
            ("report-owned-cost", quality.owned_cost_digest.clone()),
            ("policy", quality.policy_digest.clone()),
            ("report-policy", quality.policy_digest.clone()),
            ("outcomes", quality.outcomes_digest.clone()),
            ("report-outcomes", quality.outcomes_digest.clone()),
            ("report-source", quality.report_digest.clone()),
            ("report-document", quality.report_digest.clone()),
            ("join-projection", quality.join_projection_digest.clone()),
        ] {
            require(&quality.run_id, field, Some(digest));
        }
    }

    let mut actual = BTreeMap::new();
    for check in &report.source_bindings {
        validate_source_binding_check(check)?;
        if actual
            .insert((check.source.clone(), check.field.clone()), check)
            .is_some()
        {
            return Err(EnforcementLoadError::Invalid(
                "source binding matrix contains a duplicate".into(),
            ));
        }
    }
    if actual.len() != expected.len()
        || actual.keys().any(|key| !expected.contains_key(key))
        || expected.iter().any(|(key, exact)| {
            actual.get(key).is_none_or(|check| {
                exact
                    .as_ref()
                    .is_some_and(|digest| check.expected.as_ref() != Some(digest))
            })
        })
    {
        return Err(EnforcementLoadError::Invalid(
            "source binding matrix is missing, extra, or mismatched".into(),
        ));
    }
    Ok(())
}

fn validate_source_binding_check(check: &SourceBindingCheck) -> Result<(), EnforcementLoadError> {
    let recomputed = check.expected.is_some()
        && check.expected == check.observed
        && check.expected.as_deref().is_some_and(valid_digest);
    if check.kind != "checksum" || check.matched != recomputed || !recomputed {
        return Err(EnforcementLoadError::Invalid(
            "source binding matrix contains an inconsistent check".into(),
        ));
    }
    Ok(())
}

fn decode_quality_ledger(
    bytes: &[u8],
    accepted: u64,
) -> Result<QualityLedgerRead, EnforcementLoadError> {
    let byte_possible = bytes.len().saturating_sub(5) / 8;
    if accepted > MAX_QUALITY_RECORDS || accepted > byte_possible as u64 {
        return Err(EnforcementLoadError::Invalid(
            "quality accepted count exceeds bound".into(),
        ));
    }
    if !bytes.starts_with(b"BWQ1\n") {
        return Err(EnforcementLoadError::Invalid(
            "invalid quality ledger header".into(),
        ));
    }
    let mut offset = 5usize;
    let mut outcomes = Vec::new();
    let mut seen = BTreeSet::new();
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| EnforcementLoadError::Invalid("torn quality frame".into()))?;
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(bytes[offset + 4..header_end].try_into().unwrap());
        offset = header_end;
        let payload_end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| EnforcementLoadError::Invalid("torn quality payload".into()))?;
        let payload = &bytes[offset..payload_end];
        if crc32fast::hash(payload) != crc {
            return Err(EnforcementLoadError::Invalid(
                "quality frame checksum mismatch".into(),
            ));
        }
        let outcome: QualityOutcome = serde_json::from_slice(payload)?;
        outcome
            .validate()
            .map_err(|error| EnforcementLoadError::Invalid(error.to_string()))?;
        if outcome.sequence == 0 || outcome.sequence > accepted || !seen.insert(outcome.sequence) {
            return Err(EnforcementLoadError::Invalid(
                "quality sequence mismatch".into(),
            ));
        }
        outcomes.push(outcome);
        offset = payload_end;
    }
    outcomes.sort_by_key(|outcome| outcome.sequence);
    let gaps = (1..=accepted)
        .filter(|sequence| !seen.contains(sequence))
        .collect::<Vec<_>>();
    if !gaps.is_empty() {
        return Err(EnforcementLoadError::Invalid("quality sequence gap".into()));
    }
    Ok(QualityLedgerRead {
        recovery: QualityRecovery::Clean {
            records: outcomes.len() as u64,
        },
        outcomes,
        gaps,
    })
}

fn protocol_from_traffic(protocol: ProtocolKind) -> Option<AuthorityProtocol> {
    match protocol {
        ProtocolKind::ChatCompletions => Some(AuthorityProtocol::ChatCompletions),
        ProtocolKind::Responses => Some(AuthorityProtocol::Responses),
        ProtocolKind::Embeddings | ProtocolKind::Unsupported => None,
    }
}

fn protocol_to_traffic(protocol: AuthorityProtocol) -> Option<ProtocolKind> {
    match protocol {
        AuthorityProtocol::ChatCompletions => Some(ProtocolKind::ChatCompletions),
        AuthorityProtocol::Responses => Some(ProtocolKind::Responses),
        AuthorityProtocol::Embeddings => None,
    }
}

fn joined(directory: &str, file: &str) -> Result<String, EnforcementLoadError> {
    if directory.is_empty() {
        return Err(EnforcementLoadError::UnsafePath);
    }
    Ok(format!("{directory}/{file}"))
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

fn canonical_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn structured_digest<T: serde::Serialize>(value: &T) -> Result<String, EnforcementLoadError> {
    Ok(plain_digest(&serde_json::to_vec(value)?))
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillWriteState {
    Armed,
    Bypass,
}

impl KillWriteState {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Armed => b"armed\n",
            Self::Bypass => b"bypass\n",
        }
    }
}

#[derive(Debug, Clone)]
pub struct KillStateReader {
    root: Arc<File>,
    components: Arc<Vec<CString>>,
    expected_uid: u32,
}

impl KillStateReader {
    pub fn open(root: &Path, relative: &str) -> Result<Self, EnforcementLoadError> {
        Self::open_for_uid(root, relative, effective_uid())
    }

    fn open_for_uid(
        root: &Path,
        relative: &str,
        expected_uid: u32,
    ) -> Result<Self, EnforcementLoadError> {
        let components = validated_relative_components(relative)?;
        if !root.is_absolute() || root.as_os_str().len() > bowline_core::enforcement::MAX_PATH_BYTES
        {
            return Err(EnforcementLoadError::UnsafePath);
        }
        let root = open_absolute_directory(root)?;
        validate_private_directory_for_uid(&root, expected_uid)?;
        Ok(Self {
            root: Arc::new(root),
            components: Arc::new(components),
            expected_uid,
        })
    }

    pub fn read_kill_state(&self) -> KillReadResult {
        match self.read_exact_state() {
            Ok(state) => state,
            Err(error) => kill_error_state(&error),
        }
    }

    fn read_exact_state(&self) -> Result<KillReadResult, EnforcementLoadError> {
        let mut current = self.root.try_clone()?;
        for component in &self.components[..self.components.len() - 1] {
            current = open_directory_at(&current, component)?;
            validate_private_directory_for_uid(&current, self.expected_uid)?;
        }
        let name = self.components.last().expect("validated path is non-empty");
        let descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_private_file_for_uid(&file, self.expected_uid)?;
        let metadata = file.metadata()?;
        if metadata.len() > b"bypass\n".len() as u64 {
            return Err(EnforcementLoadError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(b"bypass\n".len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        match bytes.as_slice() {
            b"armed\n" => Ok(KillReadResult::Armed),
            b"bypass\n" => Ok(KillReadResult::Bypass),
            _ => Ok(KillReadResult::Malformed),
        }
    }
}

fn kill_error_state(error: &EnforcementLoadError) -> KillReadResult {
    match error {
        EnforcementLoadError::UnsafePath | EnforcementLoadError::UnsafeFile => {
            KillReadResult::Unsafe
        }
        EnforcementLoadError::TooLarge | EnforcementLoadError::Invalid(_) => {
            KillReadResult::Malformed
        }
        EnforcementLoadError::Io(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            KillReadResult::Missing
        }
        EnforcementLoadError::Io(error)
            if error
                .raw_os_error()
                .is_some_and(|code| code == libc::ELOOP || code == libc::ENOTDIR) =>
        {
            KillReadResult::Unsafe
        }
        _ => KillReadResult::Unreadable,
    }
}

#[derive(Debug, Clone)]
pub struct BoundedKillStateReader {
    slots: Arc<tokio::sync::Semaphore>,
    sender: Arc<Mutex<Option<SyncSender<KillReadRequest>>>>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug)]
struct KillReadRequest {
    response: tokio::sync::oneshot::Sender<KillReadResult>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl BoundedKillStateReader {
    pub fn new(reader: KillStateReader, max_in_flight: usize) -> Self {
        let sender = if max_in_flight == 0 {
            None
        } else {
            let (sender, receiver) = sync_channel::<KillReadRequest>(max_in_flight);
            std::thread::Builder::new()
                .name("bowline-kill-reader".to_owned())
                .spawn(move || {
                    while let Ok(request) = receiver.recv() {
                        let _ = request.response.send(reader.read_kill_state());
                    }
                })
                .ok()
                .map(|_| sender)
        };
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
            sender: Arc::new(Mutex::new(sender)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.slots.close();
        self.sender
            .lock()
            .expect("kill reader mutex poisoned")
            .take();
    }

    pub async fn read_kill_state(&self) -> KillReadResult {
        if self.shutdown.load(Ordering::Acquire) {
            return KillReadResult::QueueUnavailable;
        }
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return KillReadResult::QueueUnavailable;
        };
        let (response, result) = tokio::sync::oneshot::channel();
        let request = KillReadRequest {
            response,
            _permit: permit,
        };
        let sent = match self
            .sender
            .lock()
            .expect("kill reader mutex poisoned")
            .as_ref()
        {
            Some(sender) => match sender.try_send(request) {
                Ok(()) => true,
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
            },
            None => false,
        };
        if !sent {
            return KillReadResult::QueueUnavailable;
        }
        result.await.unwrap_or(KillReadResult::QueueUnavailable)
    }
}

pub fn atomic_write_kill_state(
    root: &Path,
    relative: &str,
    state: KillWriteState,
) -> Result<(), EnforcementLoadError> {
    let components = validated_relative_components(relative)?;
    if !root.is_absolute() || root.as_os_str().len() > bowline_core::enforcement::MAX_PATH_BYTES {
        return Err(EnforcementLoadError::UnsafePath);
    }
    let mut current = open_absolute_directory(root)?;
    validate_private_directory(&current)?;
    for component in &components[..components.len() - 1] {
        current = open_directory_at(&current, component)?;
        validate_private_directory(&current)?;
    }
    let target = components.last().expect("validated path is non-empty");
    let temporary = CString::new(format!(".bowline-kill-{}", uuid::Uuid::new_v4()))
        .map_err(|_| EnforcementLoadError::UnsafePath)?;
    let descriptor = unsafe {
        libc::openat(
            current.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| -> Result<(), EnforcementLoadError> {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        file.write_all(state.bytes())?;
        file.sync_all()?;
        drop(file);
        let renamed = unsafe {
            libc::renameat(
                current.as_raw_fd(),
                temporary.as_ptr(),
                current.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if renamed != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        current.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(current.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

fn publish_private_file_exclusive(
    root: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<(), EnforcementLoadError> {
    let components = validated_relative_components(relative)?;
    if !root.is_absolute() || root.as_os_str().len() > bowline_core::enforcement::MAX_PATH_BYTES {
        return Err(EnforcementLoadError::UnsafePath);
    }
    let mut current = open_absolute_directory(root)?;
    validate_private_directory(&current)?;
    for component in &components[..components.len() - 1] {
        current = open_directory_at(&current, component)?;
        validate_private_directory(&current)?;
    }
    let target = components.last().expect("validated path is non-empty");
    let temporary = CString::new(format!(".bowline-promotion-{}", uuid::Uuid::new_v4()))
        .map_err(|_| EnforcementLoadError::UnsafePath)?;
    let descriptor = unsafe {
        libc::openat(
            current.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| -> Result<(), EnforcementLoadError> {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_private_file(&file)?;
        let linked = unsafe {
            libc::linkat(
                current.as_raw_fd(),
                temporary.as_ptr(),
                current.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        };
        if linked != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::unlinkat(current.as_raw_fd(), temporary.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::unlinkat(current.as_raw_fd(), target.as_ptr(), 0);
            }
            return Err(error.into());
        }
        if let Err(error) = current.sync_all() {
            unsafe {
                libc::unlinkat(current.as_raw_fd(), target.as_ptr(), 0);
            }
            let _ = current.sync_all();
            return Err(error.into());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(current.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

fn validated_relative_components(relative: &str) -> Result<Vec<CString>, EnforcementLoadError> {
    if relative.is_empty()
        || relative.len() > bowline_core::enforcement::MAX_PATH_BYTES
        || Path::new(relative).is_absolute()
        || relative.chars().any(char::is_control)
    {
        return Err(EnforcementLoadError::UnsafePath);
    }
    Path::new(relative)
        .components()
        .map(|component| match component {
            Component::Normal(name) => {
                CString::new(name.as_encoded_bytes()).map_err(|_| EnforcementLoadError::UnsafePath)
            }
            _ => Err(EnforcementLoadError::UnsafePath),
        })
        .collect()
}

pub fn read_private_bundle_file(
    root: &Path,
    relative: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, EnforcementLoadError> {
    read_private_bundle_file_inner(root, relative, max_bytes, |_| {})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateReadPhase {
    Root,
    Directory(usize),
    File,
}

fn read_private_bundle_file_inner<F>(
    root: &Path,
    relative: &str,
    max_bytes: usize,
    mut hook: F,
) -> Result<Vec<u8>, EnforcementLoadError>
where
    F: FnMut(PrivateReadPhase),
{
    if !root.is_absolute()
        || root.as_os_str().len() > bowline_core::enforcement::MAX_PATH_BYTES
        || relative.is_empty()
        || relative.len() > bowline_core::enforcement::MAX_PATH_BYTES
        || Path::new(relative).is_absolute()
        || relative.chars().any(char::is_control)
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(EnforcementLoadError::UnsafePath);
    }
    let mut current = open_absolute_directory(root)?;
    validate_private_directory(&current)?;
    hook(PrivateReadPhase::Root);
    let components = Path::new(relative).components().collect::<Vec<_>>();
    for (index, component) in components[..components.len().saturating_sub(1)]
        .iter()
        .enumerate()
    {
        let Component::Normal(name) = component else {
            return Err(EnforcementLoadError::UnsafePath);
        };
        let name =
            CString::new(name.as_encoded_bytes()).map_err(|_| EnforcementLoadError::UnsafePath)?;
        current = open_directory_at(&current, &name)?;
        validate_private_directory(&current)?;
        hook(PrivateReadPhase::Directory(index));
    }
    let Some(Component::Normal(name)) = components.last() else {
        return Err(EnforcementLoadError::UnsafePath);
    };
    let name =
        CString::new(name.as_encoded_bytes()).map_err(|_| EnforcementLoadError::UnsafePath)?;
    let descriptor = unsafe {
        libc::openat(
            current.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_file(&file)?;
    hook(PrivateReadPhase::File);
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes as u64 {
        return Err(EnforcementLoadError::TooLarge);
    }
    let probe_bytes = max_bytes
        .checked_add(1)
        .ok_or(EnforcementLoadError::TooLarge)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(probe_bytes as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(EnforcementLoadError::TooLarge);
    }
    Ok(bytes)
}

fn open_absolute_directory(path: &Path) -> Result<File, EnforcementLoadError> {
    let root = CString::new("/").expect("root path has no NUL");
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut current = unsafe { File::from_raw_fd(descriptor) };
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_encoded_bytes())
                    .map_err(|_| EnforcementLoadError::UnsafePath)?;
                current = open_directory_at(&current, &name)?;
            }
            _ => return Err(EnforcementLoadError::UnsafePath),
        }
    }
    Ok(current)
}

fn open_directory_at(parent: &File, name: &CString) -> Result<File, EnforcementLoadError> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_private_directory(directory: &File) -> Result<(), EnforcementLoadError> {
    validate_private_directory_for_uid(directory, effective_uid())
}

fn validate_private_directory_for_uid(
    directory: &File,
    expected_uid: u32,
) -> Result<(), EnforcementLoadError> {
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != expected_uid
    {
        return Err(EnforcementLoadError::UnsafeFile);
    }
    Ok(())
}

fn validate_private_file(file: &File) -> Result<(), EnforcementLoadError> {
    validate_private_file_for_uid(file, effective_uid())
}

fn validate_private_file_for_uid(
    file: &File,
    expected_uid: u32,
) -> Result<(), EnforcementLoadError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.uid() != expected_uid
    {
        return Err(EnforcementLoadError::UnsafeFile);
    }
    Ok(())
}

#[cfg(test)]
fn read_private_bundle_file_with_hook<F>(
    root: &Path,
    relative: &str,
    max_bytes: usize,
    hook: F,
) -> Result<Vec<u8>, EnforcementLoadError>
where
    F: FnMut(PrivateReadPhase),
{
    read_private_bundle_file_inner(root, relative, max_bytes, hook)
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

use std::os::fd::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::PathBuf,
    };

    fn private_root() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        (temp, root)
    }

    fn private_file(path: &Path, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    #[test]
    fn enforcement_loader_rejects_impossible_accepted_before_iteration() {
        assert!(decode_quality_ledger(b"BWQ1\n", u64::MAX).is_err());
        assert!(decode_quality_ledger(b"BWQ1\n", MAX_QUALITY_RECORDS + 1).is_err());
    }

    #[test]
    fn enforcement_loader_rejects_attacker_owned_private_directory_and_file_metadata() {
        let (_temp, root) = private_root();
        let directory = File::open(&root).unwrap();
        let file = private_file(&root.join("value"), b"trusted");
        let attacker_uid = effective_uid().checked_add(1).unwrap();
        assert!(validate_private_directory_for_uid(&directory, attacker_uid).is_err());
        assert!(validate_private_file_for_uid(&file, attacker_uid).is_err());
        assert!(KillStateReader::open_for_uid(&root, "state", attacker_uid).is_err());
        assert_eq!(
            kill_error_state(&EnforcementLoadError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            ))),
            KillReadResult::Unreadable
        );
    }

    #[test]
    fn enforcement_loader_descriptor_walk_survives_root_directory_and_file_swaps() {
        for swap in ["root", "directory", "file"] {
            let (_temp, base) = private_root();
            let root = base.join("evidence");
            let directory = root.join("child");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            private_file(&directory.join("value"), b"trusted");
            let mut swapped = false;
            let bytes = read_private_bundle_file_with_hook(&root, "child/value", 16, |phase| {
                if swapped {
                    return;
                }
                let trigger = matches!(
                    (swap, phase),
                    ("root", PrivateReadPhase::Root)
                        | ("directory", PrivateReadPhase::Directory(0))
                        | ("file", PrivateReadPhase::File)
                );
                if !trigger {
                    return;
                }
                swapped = true;
                match swap {
                    "root" => {
                        fs::rename(&root, base.join("old-root")).unwrap();
                        fs::create_dir(&root).unwrap();
                        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                        fs::create_dir(root.join("child")).unwrap();
                        fs::set_permissions(root.join("child"), fs::Permissions::from_mode(0o700))
                            .unwrap();
                        private_file(&root.join("child/value"), b"attacker");
                    }
                    "directory" => {
                        fs::rename(&directory, root.join("old-child")).unwrap();
                        fs::create_dir(&directory).unwrap();
                        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
                        private_file(&directory.join("value"), b"attacker");
                    }
                    "file" => {
                        fs::rename(directory.join("value"), directory.join("old-value")).unwrap();
                        private_file(&directory.join("value"), b"attacker");
                    }
                    _ => unreachable!(),
                }
            })
            .unwrap();
            assert_eq!(bytes, b"trusted", "{swap} swap changed opened evidence");
        }
    }

    #[test]
    fn enforcement_loader_reader_accepts_exact_byte_bounds_and_rejects_max_plus_one() {
        let cases = [
            ("economics-manifest", MAX_MANIFEST_BYTES),
            ("dimensions.csv", MAX_ARTIFACT_BYTES),
            ("opportunities.csv", MAX_ARTIFACT_BYTES),
            ("reconciliation.csv", MAX_ARTIFACT_BYTES),
            ("report.html", MAX_ARTIFACT_BYTES),
            ("report.json", MAX_ARTIFACT_BYTES),
            ("report.md", MAX_ARTIFACT_BYTES),
            ("quality-manifest", MAX_MANIFEST_BYTES),
            ("quality-report", MAX_MANIFEST_BYTES),
            ("quality-ledger", MAX_QUALITY_LEDGER_BYTES),
        ];
        for (name, max) in cases {
            let (_temp, root) = private_root();
            let path = root.join(name);
            let file = private_file(&path, b"");
            file.set_len(max as u64).unwrap();
            drop(file);
            assert_eq!(
                read_private_bundle_file(&root, name, max).unwrap().len(),
                max,
                "exact {name}"
            );
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(max as u64 + 1)
                .unwrap();
            assert!(
                matches!(
                    read_private_bundle_file(&root, name, max),
                    Err(EnforcementLoadError::TooLarge)
                ),
                "max+1 {name}"
            );
        }
    }

    #[test]
    fn enforcement_loader_reader_rejects_unrepresentable_probe_bound() {
        let (_temp, root) = private_root();
        private_file(&root.join("value"), b"x");

        assert!(matches!(
            read_private_bundle_file(&root, "value", usize::MAX),
            Err(EnforcementLoadError::TooLarge)
        ));
    }

    #[test]
    fn enforcement_loader_fifo_without_writer_is_promptly_rejected_as_unsafe_file() {
        use std::{sync::mpsc, time::Duration};

        let (_temp, root) = private_root();
        let fifo = root.join("blocked.fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = read_private_bundle_file(&root, "blocked.fifo", 16);
            let _ = sender.send(result);
        });
        let result = receiver
            .recv_timeout(Duration::from_millis(250))
            .expect("FIFO open blocked instead of promptly rejecting");
        assert!(matches!(result, Err(EnforcementLoadError::UnsafeFile)));
    }

    #[tokio::test]
    async fn bounded_kill_reader_queue_saturation_removes_authority() {
        let (_temp, root) = private_root();
        private_file(&root.join("state"), b"armed\n");
        let reader = BoundedKillStateReader::new(KillStateReader::open(&root, "state").unwrap(), 1);
        let held = Arc::clone(&reader.slots).try_acquire_owned().unwrap();
        assert_eq!(
            reader.read_kill_state().await,
            KillReadResult::QueueUnavailable
        );
        drop(held);
        assert_eq!(reader.read_kill_state().await, KillReadResult::Armed);
    }
}
