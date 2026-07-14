use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    billing::{validate_normalized_rows, BillingRow, MAX_BILLING_TIMESTAMP_MS},
    quality::{PromotionVerdict, QualityProtocol},
    quality_report::{quality_report_v2_digest, QualityReportV2},
    report::{historical_policy_exposure, PolicyExposure, ReportDimensions},
    supply::TaskClass,
    traffic::{CoverageStatus, ProtocolKind},
};

pub const ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const YEAR_MS: u64 = 31_556_952_000;
pub const MAX_ANALYSIS_RUNS: usize = 256;
pub const MAX_ANALYSIS_RECORDS: usize = 1_000_000;
pub const MAX_ANALYSIS_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PPM: u64 = 1_000_000;
pub const MAX_EXACT_TOKEN_COUNT: u64 = 9_007_199_254_740_991;
pub const MAX_ANALYSIS_DURATION_MS: u64 = YEAR_MS;
pub const MAX_DIMENSION_VALUE_BYTES: usize = 256;
pub const MAX_GENERAL_TAGS: usize = 64;
pub const MAX_GENERAL_TAG_BYTES: usize = 256;
pub const MAX_GENERAL_TAG_AGGREGATE_BYTES: usize = 8 * 1024;
pub const MAX_FEASIBLE_IDS: usize = 256;
pub const MAX_RATE_CATALOG_ENTRIES: usize = 4_096;
pub const MAX_COST_RATE_USD_PER_MTOK: f64 = 1_000_000_000.0;
pub const MAX_REPORT_ROWS: usize = 4_096;
pub const MAX_ANALYSIS_YAML_BYTES: usize = 64 * 1024;
pub const MAX_QUALITY_SOURCE_BINDING_BYTES: usize = 838;
pub const MAX_EVIDENCE_BINDING_BYTES: usize = 216_232;
pub const MAX_QUALITY_REPORT_BINDING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisMode {
    ModeledOnly,
    BillingReconciled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicsAnalysis {
    pub schema_version: u32,
    pub as_of_ms: u64,
    pub traffic_run_id: String,
    pub mode: AnalysisMode,
    pub billing_run_id: Option<String>,
    pub quality_run_ids: Vec<String>,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub require_request_count: bool,
    pub require_input_tokens: bool,
    pub require_output_tokens: bool,
    pub request_tolerance_ppm: u64,
    pub input_token_tolerance_ppm: u64,
    pub output_token_tolerance_ppm: u64,
    pub minimum_record_coverage_ppm: u64,
    pub minimum_qualified_charge_coverage_ppm: u64,
    pub maximum_charge_variance_ppm: u64,
    pub minimum_duration_ms: u64,
    pub minimum_supported_records: u64,
    pub annualize: bool,
    pub representative_window_acknowledged: bool,
}

impl EconomicsAnalysis {
    pub fn from_yaml(input: &str) -> Result<Self, EconomicsError> {
        if input.len() > MAX_ANALYSIS_YAML_BYTES {
            return Err(EconomicsError::InputLimit);
        }
        let value: Self = serde_yaml::from_str(input)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EconomicsError> {
        let mut run_ids = BTreeSet::new();
        if self.schema_version != ANALYSIS_SCHEMA_VERSION
            || !safe_run_id(&self.traffic_run_id)
            || !run_ids.insert(self.traffic_run_id.as_str())
            || self.quality_run_ids.len() > MAX_ANALYSIS_RUNS
            || self.window_start_ms >= self.window_end_ms
            || self.window_end_ms > self.as_of_ms
            || self.as_of_ms > MAX_BILLING_TIMESTAMP_MS
            || self.minimum_duration_ms == 0
            || self.minimum_duration_ms > MAX_ANALYSIS_DURATION_MS
            || self.minimum_supported_records == 0
            || self.minimum_supported_records > MAX_ANALYSIS_RECORDS as u64
            || self.window_end_ms - self.window_start_ms > MAX_ANALYSIS_DURATION_MS
            || self.quality_run_ids.is_empty()
            || [
                self.request_tolerance_ppm,
                self.input_token_tolerance_ppm,
                self.output_token_tolerance_ppm,
                self.minimum_record_coverage_ppm,
                self.minimum_qualified_charge_coverage_ppm,
                self.maximum_charge_variance_ppm,
            ]
            .into_iter()
            .any(|value| value > MAX_PPM)
            || self
                .quality_run_ids
                .iter()
                .any(|id| !safe_run_id(id) || !run_ids.insert(id))
        {
            return Err(EconomicsError::InvalidAnalysis);
        }
        match self.mode {
            AnalysisMode::ModeledOnly => {
                if self.billing_run_id.is_some() || self.annualize {
                    return Err(EconomicsError::InvalidAnalysis);
                }
            }
            AnalysisMode::BillingReconciled => {
                let billing = self
                    .billing_run_id
                    .as_deref()
                    .ok_or(EconomicsError::InvalidAnalysis)?;
                if !safe_run_id(billing) || !run_ids.insert(billing) {
                    return Err(EconomicsError::InvalidAnalysis);
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, EconomicsError> {
        self.validate()?;
        Ok(domain_digest(
            b"bowline.economics.analysis.v1",
            &serde_json::to_vec(self)?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostRate {
    pub input_per_mtok_usd: f64,
    pub output_per_mtok_usd: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostRateMicros {
    pub input_per_mtok_micros: u64,
    pub output_per_mtok_micros: u64,
}

impl CostRateMicros {
    fn from_rate(rate: CostRate) -> Result<Self, EconomicsError> {
        Ok(Self {
            input_per_mtok_micros: float_usd_to_micros(rate.input_per_mtok_usd)?,
            output_per_mtok_micros: float_usd_to_micros(rate.output_per_mtok_usd)?,
        })
    }

    pub fn cost_micros(self, input: u64, output: u64) -> Result<u64, EconomicsError> {
        let input_cost = u128::from(input)
            .checked_mul(u128::from(self.input_per_mtok_micros))
            .ok_or(EconomicsError::ArithmeticOverflow)?;
        let output_cost = u128::from(output)
            .checked_mul(u128::from(self.output_per_mtok_micros))
            .ok_or(EconomicsError::ArithmeticOverflow)?;
        let rounded = input_cost
            .checked_add(output_cost)
            .and_then(|value| value.checked_add(500_000))
            .ok_or(EconomicsError::ArithmeticOverflow)?
            / 1_000_000;
        u64::try_from(rounded).map_err(|_| EconomicsError::ArithmeticOverflow)
    }
}

impl CostRate {
    fn validate(self) -> Result<(), EconomicsError> {
        if self.input_per_mtok_usd.is_finite()
            && self.input_per_mtok_usd >= 0.0
            && self.input_per_mtok_usd <= MAX_COST_RATE_USD_PER_MTOK
            && self.output_per_mtok_usd.is_finite()
            && self.output_per_mtok_usd >= 0.0
            && self.output_per_mtok_usd <= MAX_COST_RATE_USD_PER_MTOK
        {
            Ok(())
        } else {
            Err(EconomicsError::InvalidCostRate)
        }
    }

    fn cost_micros(self, input: u64, output: u64) -> Result<u64, EconomicsError> {
        self.validate()?;
        let value = (input as f64 / 1_000_000.0) * self.input_per_mtok_usd
            + (output as f64 / 1_000_000.0) * self.output_per_mtok_usd;
        float_usd_to_micros(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcedModeledDeltaStatus {
    Available,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedModeledDelta {
    pub status: EnforcedModeledDeltaStatus,
    pub observed_actual_cost_micros: u64,
    pub approved_counterfactual_cost_micros: u64,
    pub enforced_modeled_delta_micros: i128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicsRecord {
    pub id: String,
    pub sequence: u64,
    pub ts_ms: u64,
    pub coverage_status: CoverageStatus,
    pub dimensions: ReportDimensions,
    pub workload_identity_digest: String,
    pub task_class: TaskClass,
    pub protocol: ProtocolKind,
    pub actual_supply_id: Option<String>,
    pub candidate_supply_id: Option<String>,
    pub recorded_feasible_ids: Vec<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub usage_observed: bool,
    pub recorded_actual_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityJoinEvidence {
    pub run_id: String,
    pub schema_version: u32,
    pub completed_at_ms: u64,
    pub valid_until_ms: u64,
    pub workload_identity_digest: Option<String>,
    pub task_class: TaskClass,
    pub protocol: ProtocolKind,
    pub candidate_supply_id: String,
    pub effective_verdict: PromotionVerdict,
    pub manifest_valid: bool,
    pub outcomes_digest_valid: bool,
    pub report_digest_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct QualityJoinKey {
    workload_identity_digest: String,
    task_class: TaskClass,
    protocol: ProtocolKind,
    candidate_supply_id: String,
}

impl QualityJoinKey {
    fn new(
        workload_identity_digest: &str,
        task_class: TaskClass,
        protocol: ProtocolKind,
        candidate_supply_id: &str,
    ) -> Self {
        Self {
            workload_identity_digest: workload_identity_digest.to_owned(),
            task_class,
            protocol,
            candidate_supply_id: candidate_supply_id.to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QualityJoinIndex {
    entries: BTreeMap<QualityJoinKey, QualityJoinEvidence>,
    legacy: BTreeSet<(TaskClass, ProtocolKind, String)>,
    as_of_ms: u64,
}

impl QualityJoinIndex {
    pub fn new(entries: &[QualityJoinEvidence], as_of_ms: u64) -> Result<Self, EconomicsError> {
        if entries.len() > MAX_ANALYSIS_RUNS.saturating_mul(MAX_ANALYSIS_RUNS) {
            return Err(EconomicsError::InputLimit);
        }
        let mut index = BTreeMap::new();
        let mut legacy = BTreeSet::new();
        for entry in entries {
            if !safe_run_id(&entry.run_id)
                || entry.completed_at_ms > as_of_ms
                || entry.completed_at_ms > entry.valid_until_ms
                || !safe_id(&entry.candidate_supply_id)
            {
                return Err(EconomicsError::InvalidQualityEvidence);
            }
            if entry.schema_version == 1 {
                if entry.workload_identity_digest.is_some()
                    || !legacy.insert((
                        entry.task_class,
                        entry.protocol,
                        entry.candidate_supply_id.clone(),
                    ))
                {
                    return Err(EconomicsError::DuplicateQualityJoin);
                }
                continue;
            }
            let workload_identity_digest = entry
                .workload_identity_digest
                .as_deref()
                .filter(|digest| valid_digest(digest))
                .ok_or(EconomicsError::InvalidQualityEvidence)?;
            if entry.schema_version != 2 {
                return Err(EconomicsError::InvalidQualityEvidence);
            }
            let key = QualityJoinKey::new(
                workload_identity_digest,
                entry.task_class,
                entry.protocol,
                &entry.candidate_supply_id,
            );
            if index.insert(key, entry.clone()).is_some() {
                return Err(EconomicsError::DuplicateQualityJoin);
            }
        }
        Ok(Self {
            entries: index,
            legacy,
            as_of_ms,
        })
    }

    fn lookup(&self, key: &QualityJoinKey) -> QualityJoinResult {
        let Some(entry) = self.entries.get(key) else {
            return if self.legacy.contains(&(
                key.task_class,
                key.protocol,
                key.candidate_supply_id.clone(),
            )) {
                QualityJoinResult::NonJoinable
            } else {
                QualityJoinResult::Missing
            };
        };
        if !entry.manifest_valid || !entry.outcomes_digest_valid || !entry.report_digest_valid {
            QualityJoinResult::Mismatch
        } else if self.as_of_ms > entry.valid_until_ms {
            QualityJoinResult::Stale(entry.clone())
        } else if entry.effective_verdict != PromotionVerdict::Eligible {
            QualityJoinResult::NotEligible(entry.clone())
        } else {
            QualityJoinResult::Eligible(entry.clone())
        }
    }
}

enum QualityJoinResult {
    Missing,
    NonJoinable,
    Mismatch,
    Stale(QualityJoinEvidence),
    NotEligible(QualityJoinEvidence),
    Eligible(QualityJoinEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBindings {
    pub analysis_digest: String,
    pub config_digest: String,
    pub recomputed_config_digest: String,
    pub traffic_records_digest: String,
    pub traffic_manifest_digest: String,
    pub recomputed_traffic_manifest_digest: String,
    pub traffic_recovery_digest: String,
    pub recomputed_traffic_recovery_digest: String,
    pub traffic_manifest_recovery_digest: String,
    pub recomputed_traffic_manifest_recovery_digest: String,
    pub billing_rows_digest: Option<String>,
    pub billing_manifest_digest: Option<String>,
    pub recomputed_billing_manifest_digest: Option<String>,
    pub billing_recovery_digest: Option<String>,
    pub recomputed_billing_recovery_digest: Option<String>,
    pub billing_manifest_recovery_digest: Option<String>,
    pub recomputed_billing_manifest_recovery_digest: Option<String>,
    pub registry_digest: String,
    pub traffic_registry_digest: String,
    pub billing_registry_digest: Option<String>,
    pub owned_cost_digest: String,
    pub traffic_owned_cost_digest: String,
    pub policy_digest: String,
    pub traffic_policy_digest: String,
    pub quality_sources: Vec<QualitySourceBinding>,
    pub traffic_integrity_complete: bool,
    pub billing_integrity_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualitySourceBinding {
    pub run_id: String,
    pub schema_version: u32,
    pub manifest_digest: String,
    pub recomputed_manifest_digest: String,
    pub outcomes_digest: String,
    pub recomputed_outcomes_digest: String,
    pub report_digest: String,
    pub recomputed_report_digest: String,
    pub registry_digest: String,
    pub owned_cost_digest: String,
    pub policy_digest: String,
    pub join_projection_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTrafficEvidence {
    pub run_id: String,
    pub records_digest: String,
    pub manifest_digest: String,
    pub recovery_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedBillingEvidence {
    pub run_id: String,
    pub rows_digest: String,
    pub manifest_digest: String,
    pub recovery_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedEvidence {
    pub traffic: SelectedTrafficEvidence,
    pub billing: Option<SelectedBillingEvidence>,
    pub quality: Vec<QualitySourceBinding>,
}

impl SelectedEvidence {
    pub fn validate(&self) -> Result<(), EconomicsError> {
        let traffic_valid = safe_run_id(&self.traffic.run_id)
            && [
                &self.traffic.records_digest,
                &self.traffic.manifest_digest,
                &self.traffic.recovery_digest,
            ]
            .into_iter()
            .all(|value| valid_digest(value));
        let billing_valid = self.billing.as_ref().is_none_or(|billing| {
            safe_run_id(&billing.run_id)
                && [
                    &billing.rows_digest,
                    &billing.manifest_digest,
                    &billing.recovery_digest,
                ]
                .into_iter()
                .all(|value| valid_digest(value))
        });
        let quality_ids = self
            .quality
            .iter()
            .map(|source| source.run_id.as_str())
            .collect::<BTreeSet<_>>();
        if !traffic_valid
            || !billing_valid
            || self.quality.len() > MAX_ANALYSIS_RUNS
            || quality_ids.len() != self.quality.len()
        {
            return Err(EconomicsError::InvalidEvidenceBinding);
        }
        self.quality
            .iter()
            .try_fold(0usize, |aggregate, source| {
                aggregate
                    .checked_add(validate_quality_source(source)?)
                    .ok_or(EconomicsError::InputLimit)
            })
            .and_then(|bytes| {
                (bytes <= MAX_EVIDENCE_BINDING_BYTES)
                    .then_some(())
                    .ok_or(EconomicsError::InputLimit)
            })
    }
}

#[derive(Debug, Clone)]
pub struct EconomicsInput {
    pub analysis: EconomicsAnalysis,
    pub records: Vec<EconomicsRecord>,
    pub billing_rows: Vec<BillingRow>,
    pub quality_reports: Vec<QualityReportV2>,
    pub legacy_quality: Vec<QualityJoinEvidence>,
    pub build_provenance: BuildProvenance,
    pub rates: BTreeMap<String, CostRate>,
    pub bindings: EvidenceBindings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProvenance {
    pub package_version: String,
    pub source_revision: String,
}

impl BuildProvenance {
    pub fn validate(&self) -> Result<(), EconomicsError> {
        let package_ok = !self.package_version.is_empty()
            && self.package_version.len() <= MAX_ANALYSIS_IDENTIFIER_BYTES
            && self
                .package_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'));
        let revision_ok = self.source_revision == "unavailable"
            || ((self.source_revision.len() == 40 || self.source_revision.len() == 64)
                && self
                    .source_revision
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()));
        if package_ok && revision_ok {
            Ok(())
        } else {
            Err(EconomicsError::InvalidAnalysis)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Blocker {
    SourceChecksumMismatch,
    RegistryDigestMismatch,
    OwnedCostDigestMismatch,
    PolicyDigestMismatch,
    TrafficIncomplete,
    BillingIncomplete,
    BillingNotRequested,
    ModeledOnly,
    UnsupportedEvidence,
    MissingAttribution,
    MissingUsage,
    PriceUnknown,
    RecordedActualCostMismatch,
    DimensionIncomplete,
    PolicyViolation,
    PolicyUnknown,
    CandidateNotFeasible,
    SameSupply,
    NonPositiveDelta,
    ReconciliationIncomplete,
    QualityMissing,
    QualityNonJoinable,
    QualityEvidenceMismatch,
    QualityStale,
    QualityNotEligible,
    InsufficientDuration,
    InsufficientRecords,
    RepresentativenessNotAcknowledged,
    AnnualizationNotRequested,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReconciliationState {
    NotRequested,
    Incomplete,
    Qualified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationException {
    pub code: String,
    pub supply_id: Option<String>,
    pub row_id: Option<String>,
    pub record_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationReport {
    pub state: ReconciliationState,
    pub eligible_records: u64,
    pub matched_records: u64,
    pub unmatched_records: u64,
    pub total_provider_rows: u64,
    pub matched_provider_rows: u64,
    pub unmatched_provider_rows: u64,
    pub qualified_provider_rows: u64,
    pub total_imported_charge_micros: u64,
    pub matched_imported_charge_micros: u64,
    pub qualified_imported_charge_micros: u64,
    pub modeled_actual_cost_micros: Option<u64>,
    pub record_coverage_ppm: Option<u64>,
    pub row_presence_charge_coverage_ppm: Option<u64>,
    pub qualified_charge_coverage_ppm: Option<u64>,
    pub charge_variance_micros: Option<i128>,
    pub charge_variance_ppm: Option<u64>,
    pub request_delta: Option<i128>,
    pub input_token_delta: Option<i128>,
    pub output_token_delta: Option<i128>,
    pub request_count_available_rows: u64,
    pub request_count_total_rows: u64,
    pub input_token_available_rows: u64,
    pub input_token_total_rows: u64,
    pub output_token_available_rows: u64,
    pub output_token_total_rows: u64,
    pub rows: Vec<BillingRowReconciliation>,
    pub exceptions: Vec<ReconciliationException>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingRowReconciliation {
    pub row_id: String,
    pub supply_id: String,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub imported_charge_micros: u64,
    pub present: bool,
    pub qualified: bool,
    pub matched_records: u64,
    pub modeled_actual_cost_micros: Option<u64>,
    pub request_delta: Option<i128>,
    pub input_token_delta: Option<i128>,
    pub output_token_delta: Option<i128>,
}

impl ReconciliationReport {
    fn supply_qualified(&self, supply_id: &str) -> bool {
        let rows = self
            .rows
            .iter()
            .filter(|row| row.supply_id == supply_id)
            .collect::<Vec<_>>();
        !rows.is_empty()
            && rows
                .iter()
                .all(|row| row.present && row.qualified && row.modeled_actual_cost_micros.is_some())
    }
}

impl ReconciliationReport {
    fn not_requested() -> Self {
        Self {
            state: ReconciliationState::NotRequested,
            eligible_records: 0,
            matched_records: 0,
            unmatched_records: 0,
            total_provider_rows: 0,
            matched_provider_rows: 0,
            unmatched_provider_rows: 0,
            qualified_provider_rows: 0,
            total_imported_charge_micros: 0,
            matched_imported_charge_micros: 0,
            qualified_imported_charge_micros: 0,
            modeled_actual_cost_micros: None,
            record_coverage_ppm: None,
            row_presence_charge_coverage_ppm: None,
            qualified_charge_coverage_ppm: None,
            charge_variance_micros: None,
            charge_variance_ppm: None,
            request_delta: None,
            input_token_delta: None,
            output_token_delta: None,
            request_count_available_rows: 0,
            request_count_total_rows: 0,
            input_token_available_rows: 0,
            input_token_total_rows: 0,
            output_token_available_rows: 0,
            output_token_total_rows: 0,
            rows: Vec::new(),
            exceptions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpportunityKey {
    pub app: String,
    pub team: String,
    pub environment: String,
    pub cost_center: String,
    pub general_tags: Vec<String>,
    pub task_class: TaskClass,
    pub protocol: ProtocolKind,
    pub actual_supply_id: String,
    pub candidate_supply_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEvidenceSummary {
    pub run_id: String,
    pub verdict: PromotionVerdict,
    pub completed_at_ms: u64,
    pub age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpportunityRow {
    pub key: OpportunityKey,
    #[serde(default)]
    pub workload_identity_digest: String,
    pub record_count: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub actual_cost_micros: Option<u64>,
    pub candidate_cost_micros: Option<u64>,
    #[serde(default)]
    pub actual_rate_micros: Option<CostRateMicros>,
    #[serde(default)]
    pub candidate_rate_micros: Option<CostRateMicros>,
    pub observed_delta_micros: Option<i128>,
    pub annualized_delta_micros: Option<u64>,
    pub compliant_records: u64,
    pub violation_records: u64,
    pub unknown_policy_records: u64,
    pub policy_violation_reason: Option<String>,
    pub quality: Option<QualityEvidenceSummary>,
    pub reconciliation_state: ReconciliationState,
    pub eligible: bool,
    pub status: String,
    pub blockers: Vec<Blocker>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionSummary {
    pub dimensions: ReportDimensions,
    pub task_class: TaskClass,
    pub protocol: ProtocolKind,
    pub actual_supply_id: String,
    pub record_count: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub modeled_actual_cost_micros: Option<u64>,
    pub compliant_records: u64,
    pub violation_records: u64,
    pub unknown_policy_records: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DimensionKey {
    app: String,
    team: String,
    environment: String,
    cost_center: String,
    general_tags: Vec<String>,
    task_class: TaskClass,
    protocol: ProtocolKind,
    actual_supply_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBindingCheck {
    pub source: String,
    pub field: String,
    pub kind: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub matched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionableEconomicsReport {
    pub schema_version: u32,
    pub mode: AnalysisMode,
    pub as_of_ms: u64,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub complete: bool,
    pub build_provenance: BuildProvenance,
    pub global_blockers: Vec<Blocker>,
    pub source_bindings: Vec<SourceBindingCheck>,
    pub selected_evidence: SelectedEvidence,
    pub reconciliation: ReconciliationReport,
    pub dimensions: Vec<DimensionSummary>,
    pub opportunities: Vec<OpportunityRow>,
}

#[derive(Clone)]
struct ReconciledRow {
    matched_records: u64,
    bowline_input: u64,
    bowline_output: u64,
    modeled_actual_micros: i128,
    economics_complete: bool,
}

impl Default for ReconciledRow {
    fn default() -> Self {
        Self {
            matched_records: 0,
            bowline_input: 0,
            bowline_output: 0,
            modeled_actual_micros: 0,
            economics_complete: true,
        }
    }
}

struct OpportunityAccumulator {
    records: Vec<EconomicsRecord>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    actual_cost: Option<i128>,
    candidate_cost: Option<i128>,
    blockers: BTreeSet<Blocker>,
    compliant: u64,
    violation: u64,
    unknown: u64,
}

impl Default for OpportunityAccumulator {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            input_tokens: Some(0),
            output_tokens: Some(0),
            actual_cost: Some(0),
            candidate_cost: Some(0),
            blockers: BTreeSet::new(),
            compliant: 0,
            violation: 0,
            unknown: 0,
        }
    }
}

pub fn analyze(mut input: EconomicsInput) -> Result<ActionableEconomicsReport, EconomicsError> {
    input.analysis.validate()?;
    input.build_provenance.validate()?;
    validate_bindings(&input.bindings)?;
    if input.records.len() > MAX_ANALYSIS_RECORDS || input.billing_rows.len() > MAX_ANALYSIS_RECORDS
    {
        return Err(EconomicsError::InputLimit);
    }
    if input.billing_rows.len() > MAX_REPORT_ROWS {
        return Err(EconomicsError::ReportRowLimit);
    }
    if input.rates.len() > MAX_RATE_CATALOG_ENTRIES
        || input.rates.keys().any(|id| !safe_id(id))
        || input.bindings.quality_sources.len() > MAX_ANALYSIS_RUNS
        || input.quality_reports.len() > MAX_ANALYSIS_RUNS
        || input
            .quality_reports
            .iter()
            .try_fold(0usize, |total, report| {
                total.checked_add(report.candidates.len())
            })
            .is_none_or(|candidates| candidates > MAX_REPORT_ROWS)
        || input
            .quality_reports
            .iter()
            .try_fold(0usize, |total, report| {
                total.checked_add(serde_json::to_vec(report).ok()?.len())
            })
            .is_none_or(|bytes| bytes > MAX_QUALITY_REPORT_BINDING_BYTES)
    {
        return Err(EconomicsError::InputLimit);
    }
    validate_records(&input.records, &input.analysis)?;
    input.records.sort_by_key(|record| record.sequence);
    if input
        .records
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Err(EconomicsError::DuplicateRecordSequence);
    }
    for rate in input.rates.values().copied() {
        rate.validate()?;
    }

    let selected_evidence = selected_evidence(&input)?;
    let selected_quality = select_quality(&input)?;
    let mut global_blockers = BTreeSet::new();
    let source_bindings = source_matrix(&input, &selected_quality, &mut global_blockers);
    let quality_index = QualityJoinIndex::new(&selected_quality, input.analysis.as_of_ms)?;

    let reconciliation = match input.analysis.mode {
        AnalysisMode::ModeledOnly => {
            if !input.billing_rows.is_empty() {
                return Err(EconomicsError::UnexpectedBillingRows);
            }
            ReconciliationReport::not_requested()
        }
        AnalysisMode::BillingReconciled => {
            validate_tiling(&input.billing_rows, &input.records, &input.analysis)?;
            reconcile(&input)?
        }
    };
    if reconciliation.state == ReconciliationState::Incomplete {
        global_blockers.insert(Blocker::ReconciliationIncomplete);
    }
    if !input.bindings.traffic_integrity_complete {
        global_blockers.insert(Blocker::TrafficIncomplete);
    }
    if input.analysis.mode == AnalysisMode::BillingReconciled
        && !input.bindings.billing_integrity_complete
    {
        global_blockers.insert(Blocker::BillingIncomplete);
    }

    let mut grouped: BTreeMap<OpportunityKey, OpportunityAccumulator> = BTreeMap::new();
    for record in input.records.iter().filter(|record| {
        record.ts_ms >= input.analysis.window_start_ms
            && record.ts_ms < input.analysis.window_end_ms
    }) {
        let actual = record
            .actual_supply_id
            .clone()
            .unwrap_or_else(|| "not-available".into());
        let candidate = record
            .candidate_supply_id
            .clone()
            .unwrap_or_else(|| "not-available".into());
        let key = OpportunityKey {
            app: record.dimensions.app.clone(),
            team: record.dimensions.team.clone(),
            environment: record.dimensions.environment.clone(),
            cost_center: record.dimensions.cost_center.clone(),
            general_tags: record.dimensions.general_tags.clone(),
            task_class: record.task_class,
            protocol: record.protocol,
            actual_supply_id: actual,
            candidate_supply_id: candidate,
        };
        if !grouped.contains_key(&key) && grouped.len() >= MAX_REPORT_ROWS {
            return Err(EconomicsError::ReportRowLimit);
        }
        let group = grouped.entry(key).or_default();
        accumulate_record(group, record, &input.rates)?;
    }

    let mut opportunities = grouped
        .into_iter()
        .map(|(key, group)| {
            finish_opportunity(
                key,
                group,
                &input.analysis,
                &reconciliation,
                &quality_index,
                &global_blockers,
                &input.rates,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    opportunities.sort_by(opportunity_order);
    let dimensions = dimension_summaries(&input.records, &input.analysis, &input.rates)?;
    let global_blockers = global_blockers.into_iter().collect::<Vec<_>>();
    let complete = global_blockers.is_empty();
    Ok(ActionableEconomicsReport {
        schema_version: ANALYSIS_SCHEMA_VERSION,
        mode: input.analysis.mode,
        as_of_ms: input.analysis.as_of_ms,
        window_start_ms: input.analysis.window_start_ms,
        window_end_ms: input.analysis.window_end_ms,
        complete,
        build_provenance: input.build_provenance,
        global_blockers,
        source_bindings,
        selected_evidence,
        reconciliation,
        dimensions,
        opportunities,
    })
}

fn selected_evidence(input: &EconomicsInput) -> Result<SelectedEvidence, EconomicsError> {
    if input
        .analysis
        .quality_run_ids
        .iter()
        .map(String::as_str)
        .ne(input
            .bindings
            .quality_sources
            .iter()
            .map(|source| source.run_id.as_str()))
    {
        return Err(EconomicsError::InvalidEvidenceBinding);
    }
    let billing = match (
        input.analysis.billing_run_id.as_ref(),
        input.bindings.billing_rows_digest.as_ref(),
        input.bindings.billing_manifest_digest.as_ref(),
        input.bindings.billing_recovery_digest.as_ref(),
    ) {
        (Some(run_id), Some(rows), Some(manifest), Some(recovery)) => {
            Some(SelectedBillingEvidence {
                run_id: run_id.clone(),
                rows_digest: rows.clone(),
                manifest_digest: manifest.clone(),
                recovery_digest: recovery.clone(),
            })
        }
        (None, None, None, None) => None,
        _ => return Err(EconomicsError::InvalidEvidenceBinding),
    };
    let selected = SelectedEvidence {
        traffic: SelectedTrafficEvidence {
            run_id: input.analysis.traffic_run_id.clone(),
            records_digest: input.bindings.traffic_records_digest.clone(),
            manifest_digest: input.bindings.traffic_manifest_digest.clone(),
            recovery_digest: input.bindings.traffic_recovery_digest.clone(),
        },
        billing,
        quality: input.bindings.quality_sources.clone(),
    };
    selected.validate()?;
    Ok(selected)
}

fn validate_records(
    records: &[EconomicsRecord],
    analysis: &EconomicsAnalysis,
) -> Result<(), EconomicsError> {
    for record in records {
        let feasible = record.recorded_feasible_ids.iter().collect::<BTreeSet<_>>();
        let general_tag_bytes = record
            .dimensions
            .general_tags
            .iter()
            .try_fold(0usize, |total, tag| total.checked_add(tag.len()));
        if !safe_id(&record.id)
            || record.sequence == 0
            || record.ts_ms > analysis.as_of_ms
            || !valid_digest(&record.workload_identity_digest)
            || record
                .actual_supply_id
                .as_deref()
                .is_some_and(|id| !safe_id(id))
            || record
                .candidate_supply_id
                .as_deref()
                .is_some_and(|id| !safe_id(id))
            || !bounded_dimension(&record.dimensions.app)
            || !bounded_dimension(&record.dimensions.team)
            || !bounded_dimension(&record.dimensions.environment)
            || !bounded_dimension(&record.dimensions.cost_center)
            || record.dimensions.general_tags.len() > MAX_GENERAL_TAGS
            || record.dimensions.general_tags.iter().any(|tag| {
                tag.is_empty()
                    || tag.len() > MAX_GENERAL_TAG_BYTES
                    || tag.chars().any(char::is_control)
            })
            || record
                .dimensions
                .general_tags
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || general_tag_bytes.is_none_or(|bytes| bytes > MAX_GENERAL_TAG_AGGREGATE_BYTES)
            || record.recorded_feasible_ids.len() > MAX_FEASIBLE_IDS
            || feasible.len() != record.recorded_feasible_ids.len()
            || record.recorded_feasible_ids.iter().any(|id| !safe_id(id))
            || record
                .input_tokens
                .is_some_and(|value| value > MAX_EXACT_TOKEN_COUNT)
            || record
                .output_tokens
                .is_some_and(|value| value > MAX_EXACT_TOKEN_COUNT)
            || record
                .recorded_actual_cost_usd
                .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(EconomicsError::InvalidRecord);
        }
    }
    Ok(())
}

fn select_quality(input: &EconomicsInput) -> Result<Vec<QualityJoinEvidence>, EconomicsError> {
    let selected = input
        .analysis
        .quality_run_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut supplied = input
        .quality_reports
        .iter()
        .map(|report| report.run_id.clone())
        .collect::<BTreeSet<_>>();
    for entry in &input.legacy_quality {
        if entry.schema_version != 1
            || entry.workload_identity_digest.is_some()
            || !entry.manifest_valid
            || !entry.outcomes_digest_valid
            || !entry.report_digest_valid
            || !supplied.insert(entry.run_id.clone())
        {
            return Err(EconomicsError::InvalidQualityEvidence);
        }
    }
    if selected != supplied
        || supplied.len() != input.quality_reports.len() + input.legacy_quality.len()
    {
        return Err(EconomicsError::QualityRunMismatch);
    }
    let mut entries = Vec::new();
    entries.extend(input.legacy_quality.iter().cloned());
    for report in &input.quality_reports {
        if report.schema_version != 2
            || report.as_of_ms != report.completed_at_ms
            || report.completed_at_ms > input.analysis.as_of_ms
        {
            return Err(EconomicsError::InvalidQualityEvidence);
        }
        for candidate in &report.candidates {
            entries.push(QualityJoinEvidence {
                run_id: report.run_id.clone(),
                schema_version: report.schema_version,
                completed_at_ms: report.completed_at_ms,
                valid_until_ms: report.valid_until_ms,
                workload_identity_digest: Some(candidate.workload_identity_digest.clone()),
                task_class: candidate.evidence.task_class,
                protocol: match candidate.evidence.protocol {
                    QualityProtocol::Chat => ProtocolKind::ChatCompletions,
                    QualityProtocol::Responses => ProtocolKind::Responses,
                },
                candidate_supply_id: candidate.evidence.candidate_supply_id.clone(),
                effective_verdict: candidate.evidence.assessment.effective_verdict,
                manifest_valid: report.reconciled
                    && report.clean_shutdown
                    && !report.cancelled
                    && report.writer_healthy,
                outcomes_digest_valid: valid_digest(&report.outcomes_digest),
                report_digest_valid: quality_report_v2_digest(report).is_ok(),
            });
        }
    }
    Ok(entries)
}

fn validate_tiling(
    rows: &[BillingRow],
    records: &[EconomicsRecord],
    analysis: &EconomicsAnalysis,
) -> Result<(), EconomicsError> {
    if rows.is_empty() {
        return Err(EconomicsError::BillingWindowNotTiled);
    }
    let mut by_supply: BTreeMap<&str, Vec<&BillingRow>> = BTreeMap::new();
    for row in rows {
        if row.period_start_ms < analysis.window_start_ms
            || row.period_end_ms > analysis.window_end_ms
        {
            return Err(EconomicsError::BillingWindowNotTiled);
        }
        by_supply.entry(&row.supply_id).or_default().push(row);
    }
    for supply_rows in by_supply.values_mut() {
        supply_rows.sort_by_key(|row| (row.period_start_ms, row.period_end_ms, &row.row_id));
        let mut cursor = analysis.window_start_ms;
        for row in supply_rows.iter() {
            if row.period_start_ms != cursor || row.period_end_ms <= row.period_start_ms {
                return Err(EconomicsError::BillingWindowNotTiled);
            }
            cursor = row.period_end_ms;
        }
        if cursor != analysis.window_end_ms {
            return Err(EconomicsError::BillingWindowNotTiled);
        }
    }
    for record in records.iter().filter(|record| {
        record.coverage_status == CoverageStatus::Supported
            && record.ts_ms >= analysis.window_start_ms
            && record.ts_ms < analysis.window_end_ms
    }) {
        if let Some(actual) = record.actual_supply_id.as_deref() {
            if !by_supply.contains_key(actual) {
                return Err(EconomicsError::BillingWindowNotTiled);
            }
        }
    }
    Ok(())
}

fn reconcile(input: &EconomicsInput) -> Result<ReconciliationReport, EconomicsError> {
    let analysis = &input.analysis;
    let eligible = input
        .records
        .iter()
        .filter(|record| {
            record.coverage_status == CoverageStatus::Supported
                && record.ts_ms >= analysis.window_start_ms
                && record.ts_ms < analysis.window_end_ms
        })
        .collect::<Vec<_>>();
    let mut per_row = vec![ReconciledRow::default(); input.billing_rows.len()];
    let mut exceptions = Vec::with_capacity(MAX_REPORT_ROWS);
    let mut matched_records = 0u64;
    for record in &eligible {
        let Some(actual) = record.actual_supply_id.as_deref() else {
            push_report_exception(
                &mut exceptions,
                exception("missing-attribution", None, None, Some(&record.id)),
            )?;
            continue;
        };
        let matches = input
            .billing_rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                row.supply_id == actual
                    && row.period_start_ms <= record.ts_ms
                    && record.ts_ms < row.period_end_ms
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            push_report_exception(
                &mut exceptions,
                exception(
                    if matches.is_empty() {
                        "unmatched-bowline-record"
                    } else {
                        "multiple-provider-rows"
                    },
                    Some(actual),
                    None,
                    Some(&record.id),
                ),
            )?;
            continue;
        }
        let (index, row) = matches[0];
        let slot = &mut per_row[index];
        slot.matched_records = checked_add_u64(slot.matched_records, 1)?;
        if record.usage_observed {
            if let (Some(input_tokens), Some(output_tokens), Some(rate)) = (
                record.input_tokens,
                record.output_tokens,
                input.rates.get(actual).copied(),
            ) {
                slot.bowline_input = checked_add_u64(slot.bowline_input, input_tokens)?;
                slot.bowline_output = checked_add_u64(slot.bowline_output, output_tokens)?;
                let recomputed = rate.cost_micros(input_tokens, output_tokens)?;
                slot.modeled_actual_micros = slot
                    .modeled_actual_micros
                    .checked_add(i128::from(recomputed))
                    .ok_or(EconomicsError::ArithmeticOverflow)?;
                let recorded = record
                    .recorded_actual_cost_usd
                    .map(float_usd_to_micros)
                    .transpose()?;
                if recorded != Some(recomputed) {
                    slot.economics_complete = false;
                    push_report_exception(
                        &mut exceptions,
                        exception(
                            "recorded-actual-cost-mismatch",
                            Some(actual),
                            Some(&row.row_id),
                            Some(&record.id),
                        ),
                    )?;
                }
            } else {
                slot.economics_complete = false;
                push_report_exception(
                    &mut exceptions,
                    exception(
                        "price-or-usage-incomplete",
                        Some(actual),
                        Some(&row.row_id),
                        Some(&record.id),
                    ),
                )?;
            }
        } else {
            slot.economics_complete = false;
            push_report_exception(
                &mut exceptions,
                exception(
                    "usage-not-observed",
                    Some(actual),
                    Some(&row.row_id),
                    Some(&record.id),
                ),
            )?;
        }
        matched_records = checked_add_u64(matched_records, 1)?;
    }

    let mut matched_rows = 0u64;
    let mut qualified_rows = 0u64;
    let mut total_charge = 0u64;
    let mut matched_charge = 0u64;
    let mut qualified_charge = 0u64;
    let mut modeled_total = 0i128;
    let mut modeled_complete = true;
    let mut request_bowline = 0i128;
    let mut request_provider = 0i128;
    let mut request_available = true;
    let mut input_bowline = 0i128;
    let mut input_provider = 0i128;
    let mut input_available = true;
    let mut output_bowline = 0i128;
    let mut output_provider = 0i128;
    let mut output_available = true;
    let total_provider_rows =
        u64::try_from(input.billing_rows.len()).map_err(|_| EconomicsError::InputLimit)?;
    let request_count_available_rows = u64::try_from(
        input
            .billing_rows
            .iter()
            .filter(|row| row.request_count.is_some())
            .count(),
    )
    .map_err(|_| EconomicsError::InputLimit)?;
    let input_token_available_rows = u64::try_from(
        input
            .billing_rows
            .iter()
            .filter(|row| row.input_tokens.is_some())
            .count(),
    )
    .map_err(|_| EconomicsError::InputLimit)?;
    let output_token_available_rows = u64::try_from(
        input
            .billing_rows
            .iter()
            .filter(|row| row.output_tokens.is_some())
            .count(),
    )
    .map_err(|_| EconomicsError::InputLimit)?;
    let mut row_summaries = Vec::with_capacity(input.billing_rows.len());
    for (row, matched) in input.billing_rows.iter().zip(&per_row) {
        let charge = row.charge_usd_micros.get();
        total_charge = checked_add_u64(total_charge, charge)?;
        if matched.matched_records == 0 {
            optional_delta_accumulate(
                0,
                row.request_count,
                &mut request_bowline,
                &mut request_provider,
                &mut request_available,
            )?;
            optional_delta_accumulate(
                0,
                row.input_tokens,
                &mut input_bowline,
                &mut input_provider,
                &mut input_available,
            )?;
            optional_delta_accumulate(
                0,
                row.output_tokens,
                &mut output_bowline,
                &mut output_provider,
                &mut output_available,
            )?;
            push_report_exception(
                &mut exceptions,
                exception(
                    "unmatched-provider-row",
                    Some(&row.supply_id),
                    Some(&row.row_id),
                    None,
                ),
            )?;
            push_reconciliation_row(
                &mut row_summaries,
                BillingRowReconciliation {
                    row_id: row.row_id.clone(),
                    supply_id: row.supply_id.clone(),
                    period_start_ms: row.period_start_ms,
                    period_end_ms: row.period_end_ms,
                    imported_charge_micros: charge,
                    present: false,
                    qualified: false,
                    matched_records: 0,
                    modeled_actual_cost_micros: None,
                    request_delta: row.request_count.map(|count| -i128::from(count)),
                    input_token_delta: row.input_tokens.map(|count| -i128::from(count)),
                    output_token_delta: row.output_tokens.map(|count| -i128::from(count)),
                },
            )?;
            continue;
        }
        matched_rows = checked_add_u64(matched_rows, 1)?;
        matched_charge = checked_add_u64(matched_charge, charge)?;
        modeled_total = modeled_total
            .checked_add(matched.modeled_actual_micros)
            .ok_or(EconomicsError::ArithmeticOverflow)?;
        modeled_complete &= matched.economics_complete;
        let request_ok = count_qualified(
            matched.matched_records,
            row.request_count,
            analysis.require_request_count,
            analysis.request_tolerance_ppm,
        )?;
        let input_ok = count_qualified(
            matched.bowline_input,
            row.input_tokens,
            analysis.require_input_tokens,
            analysis.input_token_tolerance_ppm,
        )?;
        let output_ok = count_qualified(
            matched.bowline_output,
            row.output_tokens,
            analysis.require_output_tokens,
            analysis.output_token_tolerance_ppm,
        )?;
        let row_modeled = matched
            .economics_complete
            .then(|| u64::try_from(matched.modeled_actual_micros).ok())
            .flatten();
        let row_charge_within = match row_modeled {
            Some(modeled) => ppm_within(
                modeled.abs_diff(charge),
                charge,
                analysis.maximum_charge_variance_ppm,
            )?,
            None => false,
        };
        let qualified =
            request_ok && input_ok && output_ok && matched.economics_complete && row_charge_within;
        if qualified {
            qualified_rows = checked_add_u64(qualified_rows, 1)?;
            qualified_charge = checked_add_u64(qualified_charge, charge)?;
        } else {
            push_report_exception(
                &mut exceptions,
                exception(
                    if !matched.economics_complete {
                        "row-economics-incomplete"
                    } else if (analysis.require_request_count && row.request_count.is_none())
                        || (analysis.require_input_tokens && row.input_tokens.is_none())
                        || (analysis.require_output_tokens && row.output_tokens.is_none())
                    {
                        "required-count-missing"
                    } else if !request_ok || !input_ok || !output_ok {
                        "count-tolerance-exceeded"
                    } else {
                        "row-charge-variance-exceeded"
                    },
                    Some(&row.supply_id),
                    Some(&row.row_id),
                    None,
                ),
            )?;
        }
        optional_delta_accumulate(
            matched.matched_records,
            row.request_count,
            &mut request_bowline,
            &mut request_provider,
            &mut request_available,
        )?;
        optional_delta_accumulate(
            matched.bowline_input,
            row.input_tokens,
            &mut input_bowline,
            &mut input_provider,
            &mut input_available,
        )?;
        optional_delta_accumulate(
            matched.bowline_output,
            row.output_tokens,
            &mut output_bowline,
            &mut output_provider,
            &mut output_available,
        )?;
        push_reconciliation_row(
            &mut row_summaries,
            BillingRowReconciliation {
                row_id: row.row_id.clone(),
                supply_id: row.supply_id.clone(),
                period_start_ms: row.period_start_ms,
                period_end_ms: row.period_end_ms,
                imported_charge_micros: charge,
                present: true,
                qualified,
                matched_records: matched.matched_records,
                modeled_actual_cost_micros: row_modeled,
                request_delta: optional_signed_delta(matched.matched_records, row.request_count),
                input_token_delta: optional_signed_delta(matched.bowline_input, row.input_tokens),
                output_token_delta: optional_signed_delta(
                    matched.bowline_output,
                    row.output_tokens,
                ),
            },
        )?;
    }
    row_summaries.sort_by(|left, right| {
        (
            left.period_start_ms,
            left.period_end_ms,
            left.supply_id.as_str(),
            left.row_id.as_str(),
        )
            .cmp(&(
                right.period_start_ms,
                right.period_end_ms,
                right.supply_id.as_str(),
                right.row_id.as_str(),
            ))
    });
    exceptions.sort_by(|left, right| {
        (&left.code, &left.supply_id, &left.row_id, &left.record_id).cmp(&(
            &right.code,
            &right.supply_id,
            &right.row_id,
            &right.record_id,
        ))
    });
    let eligible_records = u64::try_from(eligible.len()).map_err(|_| EconomicsError::InputLimit)?;
    let record_coverage = ratio_ppm(matched_records, eligible_records)?;
    let row_coverage = ratio_ppm(matched_charge, total_charge)?;
    let qualified_coverage = ratio_ppm(qualified_charge, total_charge)?;
    let modeled_actual = if modeled_complete {
        u64::try_from(modeled_total).ok()
    } else {
        None
    };
    let charge_variance =
        modeled_actual.map(|modeled| i128::from(modeled) - i128::from(total_charge));
    let charge_variance_ppm = match (charge_variance, total_charge) {
        (Some(0), 0) => Some(0),
        (Some(_), 0) => None,
        (Some(delta), denominator) => Some(ppm_value(delta.unsigned_abs(), denominator)?),
        _ => None,
    };
    let charge_delta = charge_variance.and_then(|value| u64::try_from(value.unsigned_abs()).ok());
    let charge_within = match charge_delta {
        Some(delta) => ppm_within(delta, total_charge, analysis.maximum_charge_variance_ppm)?,
        None => false,
    };
    let thresholds_pass = ratio_at_least(
        matched_records,
        eligible_records,
        analysis.minimum_record_coverage_ppm,
    )? && ratio_at_least(
        qualified_charge,
        total_charge,
        analysis.minimum_qualified_charge_coverage_ppm,
    )? && charge_within
        && modeled_actual.is_some()
        && eligible_records > 0;
    Ok(ReconciliationReport {
        state: if thresholds_pass {
            ReconciliationState::Qualified
        } else {
            ReconciliationState::Incomplete
        },
        eligible_records,
        matched_records,
        unmatched_records: eligible_records - matched_records,
        total_provider_rows,
        matched_provider_rows: matched_rows,
        unmatched_provider_rows: total_provider_rows - matched_rows,
        qualified_provider_rows: qualified_rows,
        total_imported_charge_micros: total_charge,
        matched_imported_charge_micros: matched_charge,
        qualified_imported_charge_micros: qualified_charge,
        modeled_actual_cost_micros: modeled_actual,
        record_coverage_ppm: record_coverage,
        row_presence_charge_coverage_ppm: row_coverage,
        qualified_charge_coverage_ppm: qualified_coverage,
        charge_variance_micros: charge_variance,
        charge_variance_ppm,
        request_delta: request_available.then_some(request_bowline - request_provider),
        input_token_delta: input_available.then_some(input_bowline - input_provider),
        output_token_delta: output_available.then_some(output_bowline - output_provider),
        request_count_available_rows,
        request_count_total_rows: total_provider_rows,
        input_token_available_rows,
        input_token_total_rows: total_provider_rows,
        output_token_available_rows,
        output_token_total_rows: total_provider_rows,
        rows: row_summaries,
        exceptions,
    })
}

fn optional_signed_delta(observed: u64, provider: Option<u64>) -> Option<i128> {
    provider.map(|provider| i128::from(observed) - i128::from(provider))
}

fn count_qualified(
    observed: u64,
    provider: Option<u64>,
    required: bool,
    tolerance_ppm: u64,
) -> Result<bool, EconomicsError> {
    match provider {
        Some(provider) => ppm_within(observed.abs_diff(provider), provider, tolerance_ppm),
        None => Ok(!required),
    }
}

fn optional_delta_accumulate(
    observed: u64,
    provider: Option<u64>,
    observed_total: &mut i128,
    provider_total: &mut i128,
    available: &mut bool,
) -> Result<(), EconomicsError> {
    if let Some(provider) = provider {
        *observed_total = observed_total
            .checked_add(i128::from(observed))
            .ok_or(EconomicsError::ArithmeticOverflow)?;
        *provider_total = provider_total
            .checked_add(i128::from(provider))
            .ok_or(EconomicsError::ArithmeticOverflow)?;
    } else {
        *available = false;
    }
    Ok(())
}

fn accumulate_record(
    group: &mut OpportunityAccumulator,
    record: &EconomicsRecord,
    rates: &BTreeMap<String, CostRate>,
) -> Result<(), EconomicsError> {
    group.records.push(record.clone());
    if record.coverage_status != CoverageStatus::Supported {
        group.blockers.insert(Blocker::UnsupportedEvidence);
    }
    if !record.dimensions.complete {
        group.blockers.insert(Blocker::DimensionIncomplete);
    }
    match record_policy_exposure(record) {
        PolicyExposure::Compliant => {
            group.compliant = checked_add_u64(group.compliant, 1)?;
        }
        PolicyExposure::Violation => {
            group.violation = checked_add_u64(group.violation, 1)?;
            group.blockers.insert(Blocker::PolicyViolation);
        }
        PolicyExposure::Unknown => {
            group.unknown = checked_add_u64(group.unknown, 1)?;
            group.blockers.insert(Blocker::PolicyUnknown);
        }
    }
    let (Some(input_tokens), Some(output_tokens)) = (record.input_tokens, record.output_tokens)
    else {
        group.blockers.insert(Blocker::MissingUsage);
        clear_usage_and_costs(group);
        return Ok(());
    };
    if !record.usage_observed {
        group.blockers.insert(Blocker::MissingUsage);
        clear_usage_and_costs(group);
        return Ok(());
    }
    checked_optional_sum(&mut group.input_tokens, input_tokens)?;
    checked_optional_sum(&mut group.output_tokens, output_tokens)?;
    let (Some(actual), Some(candidate)) = (
        record.actual_supply_id.as_deref(),
        record.candidate_supply_id.as_deref(),
    ) else {
        group.blockers.insert(Blocker::MissingAttribution);
        clear_costs(group);
        return Ok(());
    };
    if actual == candidate {
        group.blockers.insert(Blocker::SameSupply);
    }
    if !record
        .recorded_feasible_ids
        .iter()
        .any(|id| id == candidate)
    {
        group.blockers.insert(Blocker::CandidateNotFeasible);
    }
    let (Some(actual_rate), Some(candidate_rate)) =
        (rates.get(actual).copied(), rates.get(candidate).copied())
    else {
        group.blockers.insert(Blocker::PriceUnknown);
        clear_costs(group);
        return Ok(());
    };
    let actual_cost = actual_rate.cost_micros(input_tokens, output_tokens)?;
    let candidate_cost = candidate_rate.cost_micros(input_tokens, output_tokens)?;
    let recorded = record
        .recorded_actual_cost_usd
        .map(float_usd_to_micros)
        .transpose()?;
    if recorded != Some(actual_cost) {
        group.blockers.insert(Blocker::RecordedActualCostMismatch);
        clear_costs(group);
        return Ok(());
    }
    checked_optional_i128_sum(&mut group.actual_cost, i128::from(actual_cost))?;
    checked_optional_i128_sum(&mut group.candidate_cost, i128::from(candidate_cost))?;
    Ok(())
}

fn record_policy_exposure(record: &EconomicsRecord) -> PolicyExposure {
    historical_policy_exposure(
        record.coverage_status,
        record.actual_supply_id.as_deref(),
        &record.recorded_feasible_ids,
    )
}

fn clear_costs(group: &mut OpportunityAccumulator) {
    group.actual_cost = None;
    group.candidate_cost = None;
}

fn clear_usage_and_costs(group: &mut OpportunityAccumulator) {
    group.input_tokens = None;
    group.output_tokens = None;
    clear_costs(group);
}

fn finish_opportunity(
    key: OpportunityKey,
    group: OpportunityAccumulator,
    analysis: &EconomicsAnalysis,
    reconciliation: &ReconciliationReport,
    quality_index: &QualityJoinIndex,
    global_blockers: &BTreeSet<Blocker>,
    rates: &BTreeMap<String, CostRate>,
) -> Result<OpportunityRow, EconomicsError> {
    let mut blockers = group.blockers;
    blockers.extend(global_blockers.iter().copied());
    let actual_cost = group
        .actual_cost
        .and_then(|value| u64::try_from(value).ok());
    let candidate_cost = group
        .candidate_cost
        .and_then(|value| u64::try_from(value).ok());
    let delta = match (group.actual_cost, group.candidate_cost) {
        (Some(actual), Some(candidate)) => actual.checked_sub(candidate),
        _ => None,
    };
    if delta.is_some_and(|value| value <= 0) {
        blockers.insert(Blocker::NonPositiveDelta);
    }
    let first = group.records.first().ok_or(EconomicsError::InvalidRecord)?;
    if group
        .records
        .iter()
        .any(|record| record.workload_identity_digest != first.workload_identity_digest)
    {
        blockers.insert(Blocker::QualityEvidenceMismatch);
    }
    let quality_key = QualityJoinKey::new(
        &first.workload_identity_digest,
        key.task_class,
        key.protocol,
        &key.candidate_supply_id,
    );
    let quality = match quality_index.lookup(&quality_key) {
        QualityJoinResult::Missing => {
            blockers.insert(Blocker::QualityMissing);
            None
        }
        QualityJoinResult::NonJoinable => {
            blockers.insert(Blocker::QualityNonJoinable);
            None
        }
        QualityJoinResult::Mismatch => {
            blockers.insert(Blocker::QualityEvidenceMismatch);
            None
        }
        QualityJoinResult::Stale(entry) => {
            blockers.insert(Blocker::QualityStale);
            Some(quality_summary(&entry, analysis.as_of_ms))
        }
        QualityJoinResult::NotEligible(entry) => {
            blockers.insert(Blocker::QualityNotEligible);
            Some(quality_summary(&entry, analysis.as_of_ms))
        }
        QualityJoinResult::Eligible(entry) => Some(quality_summary(&entry, analysis.as_of_ms)),
    };
    match analysis.mode {
        AnalysisMode::ModeledOnly => {
            blockers.insert(Blocker::ModeledOnly);
            blockers.insert(Blocker::BillingNotRequested);
        }
        AnalysisMode::BillingReconciled => {
            if reconciliation.state != ReconciliationState::Qualified
                || !reconciliation.supply_qualified(&key.actual_supply_id)
            {
                blockers.insert(Blocker::ReconciliationIncomplete);
            }
        }
    }
    let eligible = blockers.is_empty() && delta.is_some_and(|value| value > 0);
    let duration = analysis.window_end_ms - analysis.window_start_ms;
    let duration_sufficient = duration >= analysis.minimum_duration_ms;
    if !duration_sufficient {
        blockers.insert(Blocker::InsufficientDuration);
    }
    let records_sufficient = reconciliation.eligible_records >= analysis.minimum_supported_records;
    if !records_sufficient {
        blockers.insert(Blocker::InsufficientRecords);
    }
    if !analysis.representative_window_acknowledged {
        blockers.insert(Blocker::RepresentativenessNotAcknowledged);
    }
    if !analysis.annualize {
        blockers.insert(Blocker::AnnualizationNotRequested);
    }
    let annualization_gates = eligible
        && analysis.annualize
        && analysis.representative_window_acknowledged
        && duration_sufficient
        && records_sufficient;
    let annualized = if annualization_gates {
        match annualize_micros(delta.unwrap_or_default(), duration, YEAR_MS) {
            Ok(value) => Some(value),
            Err(_) => {
                blockers.insert(Blocker::ArithmeticOverflow);
                None
            }
        }
    } else {
        None
    };
    let blockers = blockers.into_iter().collect::<Vec<_>>();
    let status = match analysis.mode {
        AnalysisMode::ModeledOnly => "modeled-only",
        AnalysisMode::BillingReconciled if eligible => "billing-reconciled-eligible",
        AnalysisMode::BillingReconciled => "billing-reconciled-incomplete",
    }
    .to_owned();
    let actual_rate_micros = rates
        .get(&key.actual_supply_id)
        .copied()
        .map(CostRateMicros::from_rate)
        .transpose()?;
    let candidate_rate_micros = rates
        .get(&key.candidate_supply_id)
        .copied()
        .map(CostRateMicros::from_rate)
        .transpose()?;
    Ok(OpportunityRow {
        key,
        workload_identity_digest: first.workload_identity_digest.clone(),
        record_count: u64::try_from(group.records.len()).map_err(|_| EconomicsError::InputLimit)?,
        input_tokens: group.input_tokens,
        output_tokens: group.output_tokens,
        actual_cost_micros: actual_cost,
        candidate_cost_micros: candidate_cost,
        actual_rate_micros,
        candidate_rate_micros,
        observed_delta_micros: delta,
        annualized_delta_micros: annualized,
        compliant_records: group.compliant,
        violation_records: group.violation,
        unknown_policy_records: group.unknown,
        policy_violation_reason: (group.violation > 0)
            .then(|| "actual-supply-not-in-recorded-feasible-set".to_owned()),
        quality,
        reconciliation_state: reconciliation.state,
        eligible,
        status,
        blockers,
    })
}

fn quality_summary(entry: &QualityJoinEvidence, as_of_ms: u64) -> QualityEvidenceSummary {
    QualityEvidenceSummary {
        run_id: entry.run_id.clone(),
        verdict: entry.effective_verdict,
        completed_at_ms: entry.completed_at_ms,
        age_ms: as_of_ms.saturating_sub(entry.completed_at_ms),
    }
}

fn dimension_summaries(
    records: &[EconomicsRecord],
    analysis: &EconomicsAnalysis,
    rates: &BTreeMap<String, CostRate>,
) -> Result<Vec<DimensionSummary>, EconomicsError> {
    let mut grouped: BTreeMap<DimensionKey, DimensionSummary> = BTreeMap::new();
    for record in records.iter().filter(|record| {
        record.ts_ms >= analysis.window_start_ms && record.ts_ms < analysis.window_end_ms
    }) {
        let dimensions = record.dimensions.clone();
        let key = DimensionKey {
            app: dimensions.app.clone(),
            team: dimensions.team.clone(),
            environment: dimensions.environment.clone(),
            cost_center: dimensions.cost_center.clone(),
            general_tags: dimensions.general_tags.clone(),
            task_class: record.task_class,
            protocol: record.protocol,
            actual_supply_id: record
                .actual_supply_id
                .clone()
                .unwrap_or_else(|| "not-available".to_owned()),
        };
        if !grouped.contains_key(&key) && grouped.len() >= MAX_REPORT_ROWS {
            return Err(EconomicsError::ReportRowLimit);
        }
        let summary = grouped.entry(key).or_insert(DimensionSummary {
            dimensions,
            task_class: record.task_class,
            protocol: record.protocol,
            actual_supply_id: record
                .actual_supply_id
                .clone()
                .unwrap_or_else(|| "not-available".to_owned()),
            record_count: 0,
            input_tokens: Some(0),
            output_tokens: Some(0),
            modeled_actual_cost_micros: Some(0),
            compliant_records: 0,
            violation_records: 0,
            unknown_policy_records: 0,
        });
        summary.record_count = checked_add_u64(summary.record_count, 1)?;
        match record_policy_exposure(record) {
            PolicyExposure::Compliant => {
                summary.compliant_records = checked_add_u64(summary.compliant_records, 1)?;
            }
            PolicyExposure::Violation => {
                summary.violation_records = checked_add_u64(summary.violation_records, 1)?;
            }
            PolicyExposure::Unknown => {
                summary.unknown_policy_records =
                    checked_add_u64(summary.unknown_policy_records, 1)?;
            }
        }
        match (
            record.usage_observed,
            record.input_tokens,
            record.output_tokens,
            record.actual_supply_id.as_deref(),
        ) {
            (true, Some(input), Some(output), Some(actual)) => {
                checked_optional_sum(&mut summary.input_tokens, input)?;
                checked_optional_sum(&mut summary.output_tokens, output)?;
                if let Some(rate) = rates.get(actual).copied() {
                    let recomputed = rate.cost_micros(input, output)?;
                    let recorded = record
                        .recorded_actual_cost_usd
                        .map(float_usd_to_micros)
                        .transpose()?;
                    if recorded == Some(recomputed) {
                        checked_optional_sum(&mut summary.modeled_actual_cost_micros, recomputed)?;
                    } else {
                        summary.modeled_actual_cost_micros = None;
                    }
                } else {
                    summary.modeled_actual_cost_micros = None;
                }
            }
            _ => {
                summary.input_tokens = None;
                summary.output_tokens = None;
                summary.modeled_actual_cost_micros = None;
            }
        }
    }
    Ok(grouped.into_values().collect())
}

fn opportunity_order(left: &OpportunityRow, right: &OpportunityRow) -> std::cmp::Ordering {
    right
        .eligible
        .cmp(&left.eligible)
        .then_with(|| {
            right
                .annualized_delta_micros
                .cmp(&left.annualized_delta_micros)
        })
        .then_with(|| right.observed_delta_micros.cmp(&left.observed_delta_micros))
        .then_with(|| right.record_count.cmp(&left.record_count))
        .then_with(|| left.key.cmp(&right.key))
}

fn source_matrix(
    input: &EconomicsInput,
    selected_quality: &[QualityJoinEvidence],
    blockers: &mut BTreeSet<Blocker>,
) -> Vec<SourceBindingCheck> {
    let bindings = &input.bindings;
    let mut checks = Vec::new();
    add_check(
        &mut checks,
        "analysis",
        "analysis-manifest",
        Some(bindings.analysis_digest.clone()),
        input.analysis.digest().ok(),
        blockers,
        Blocker::SourceChecksumMismatch,
    );
    add_check(
        &mut checks,
        "traffic",
        "selected-records",
        Some(bindings.traffic_records_digest.clone()),
        canonical_traffic_records_digest(&input.records).ok(),
        blockers,
        Blocker::SourceChecksumMismatch,
    );
    add_check(
        &mut checks,
        "traffic",
        "manifest",
        Some(bindings.traffic_manifest_digest.clone()),
        Some(bindings.recomputed_traffic_manifest_digest.clone()),
        blockers,
        Blocker::SourceChecksumMismatch,
    );
    add_check(
        &mut checks,
        "traffic",
        "recovery",
        Some(bindings.traffic_recovery_digest.clone()),
        Some(bindings.recomputed_traffic_recovery_digest.clone()),
        blockers,
        Blocker::SourceChecksumMismatch,
    );
    add_check(
        &mut checks,
        "traffic",
        "manifest-recovery",
        Some(bindings.traffic_manifest_recovery_digest.clone()),
        Some(bindings.recomputed_traffic_manifest_recovery_digest.clone()),
        blockers,
        Blocker::SourceChecksumMismatch,
    );
    add_check(
        &mut checks,
        "config",
        "configuration",
        Some(bindings.config_digest.clone()),
        Some(bindings.recomputed_config_digest.clone()),
        blockers,
        Blocker::SourceChecksumMismatch,
    );
    add_check(
        &mut checks,
        "traffic",
        "registry",
        Some(bindings.registry_digest.clone()),
        Some(bindings.traffic_registry_digest.clone()),
        blockers,
        Blocker::RegistryDigestMismatch,
    );
    if input.analysis.mode == AnalysisMode::BillingReconciled {
        add_check(
            &mut checks,
            "billing",
            "normalized-rows",
            bindings.billing_rows_digest.clone(),
            canonical_billing_rows_digest(&input.billing_rows).ok(),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            "billing",
            "manifest",
            bindings.billing_manifest_digest.clone(),
            bindings.recomputed_billing_manifest_digest.clone(),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            "billing",
            "recovery",
            bindings.billing_recovery_digest.clone(),
            bindings.recomputed_billing_recovery_digest.clone(),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            "billing",
            "manifest-recovery",
            bindings.billing_manifest_recovery_digest.clone(),
            bindings.recomputed_billing_manifest_recovery_digest.clone(),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            "billing",
            "registry",
            Some(bindings.registry_digest.clone()),
            bindings.billing_registry_digest.clone(),
            blockers,
            Blocker::RegistryDigestMismatch,
        );
    }
    add_check(
        &mut checks,
        "traffic",
        "owned-cost",
        Some(bindings.owned_cost_digest.clone()),
        Some(bindings.traffic_owned_cost_digest.clone()),
        blockers,
        Blocker::OwnedCostDigestMismatch,
    );
    add_check(
        &mut checks,
        "traffic",
        "policy",
        Some(bindings.policy_digest.clone()),
        Some(bindings.traffic_policy_digest.clone()),
        blockers,
        Blocker::PolicyDigestMismatch,
    );
    let selected_runs = input
        .analysis
        .quality_run_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let bound_runs = bindings
        .quality_sources
        .iter()
        .map(|source| source.run_id.clone())
        .collect::<BTreeSet<_>>();
    if selected_runs != bound_runs || bound_runs.len() != bindings.quality_sources.len() {
        blockers.insert(Blocker::QualityEvidenceMismatch);
    }
    for source in &bindings.quality_sources {
        let report = input
            .quality_reports
            .iter()
            .find(|report| report.run_id == source.run_id);
        if source.schema_version != 2 {
            blockers.insert(Blocker::QualityNonJoinable);
        }
        if report.is_none_or(|report| report.schema_version != source.schema_version) {
            blockers.insert(Blocker::QualityEvidenceMismatch);
        }
        add_check(
            &mut checks,
            &source.run_id,
            "manifest",
            Some(source.manifest_digest.clone()),
            Some(source.recomputed_manifest_digest.clone()),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "registry",
            Some(bindings.registry_digest.clone()),
            Some(source.registry_digest.clone()),
            blockers,
            Blocker::RegistryDigestMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "report-registry",
            Some(source.registry_digest.clone()),
            report.map(|report| report.provenance.registry_digest.clone()),
            blockers,
            Blocker::RegistryDigestMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "owned-cost",
            Some(bindings.owned_cost_digest.clone()),
            Some(source.owned_cost_digest.clone()),
            blockers,
            Blocker::OwnedCostDigestMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "report-owned-cost",
            Some(source.owned_cost_digest.clone()),
            report.and_then(|report| report.provenance.owned_cost_digest.clone()),
            blockers,
            Blocker::OwnedCostDigestMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "policy",
            Some(bindings.policy_digest.clone()),
            Some(source.policy_digest.clone()),
            blockers,
            Blocker::PolicyDigestMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "report-policy",
            Some(source.policy_digest.clone()),
            report.map(|report| report.provenance.policy_digest.clone()),
            blockers,
            Blocker::PolicyDigestMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "outcomes",
            Some(source.outcomes_digest.clone()),
            Some(source.recomputed_outcomes_digest.clone()),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "report-outcomes",
            Some(source.outcomes_digest.clone()),
            report.map(|report| report.outcomes_digest.clone()),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "report-source",
            Some(source.report_digest.clone()),
            Some(source.recomputed_report_digest.clone()),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        add_check(
            &mut checks,
            &source.run_id,
            "report-document",
            Some(source.report_digest.clone()),
            report.and_then(|report| quality_report_v2_digest(report).ok()),
            blockers,
            Blocker::SourceChecksumMismatch,
        );
        let projections = selected_quality
            .iter()
            .filter(|entry| entry.run_id == source.run_id)
            .cloned()
            .collect::<Vec<_>>();
        add_check(
            &mut checks,
            &source.run_id,
            "join-projection",
            Some(source.join_projection_digest.clone()),
            (!projections.is_empty())
                .then(|| canonical_quality_projection_digest(&projections).ok())
                .flatten(),
            blockers,
            Blocker::QualityEvidenceMismatch,
        );
    }
    checks
}

fn validate_bindings(bindings: &EvidenceBindings) -> Result<(), EconomicsError> {
    let required = [
        &bindings.analysis_digest,
        &bindings.config_digest,
        &bindings.recomputed_config_digest,
        &bindings.traffic_records_digest,
        &bindings.traffic_manifest_digest,
        &bindings.recomputed_traffic_manifest_digest,
        &bindings.traffic_recovery_digest,
        &bindings.recomputed_traffic_recovery_digest,
        &bindings.traffic_manifest_recovery_digest,
        &bindings.recomputed_traffic_manifest_recovery_digest,
        &bindings.registry_digest,
        &bindings.traffic_registry_digest,
        &bindings.owned_cost_digest,
        &bindings.traffic_owned_cost_digest,
        &bindings.policy_digest,
        &bindings.traffic_policy_digest,
    ];
    if required.into_iter().any(|value| !valid_digest(value))
        || [
            bindings.billing_rows_digest.as_deref(),
            bindings.billing_manifest_digest.as_deref(),
            bindings.recomputed_billing_manifest_digest.as_deref(),
            bindings.billing_recovery_digest.as_deref(),
            bindings.recomputed_billing_recovery_digest.as_deref(),
            bindings.billing_manifest_recovery_digest.as_deref(),
            bindings
                .recomputed_billing_manifest_recovery_digest
                .as_deref(),
            bindings.billing_registry_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| !valid_digest(value))
    {
        return Err(EconomicsError::InvalidEvidenceBinding);
    }
    let mut aggregate = required
        .into_iter()
        .try_fold(0usize, |sum, value| sum.checked_add(value.len()))
        .ok_or(EconomicsError::InputLimit)?;
    for value in [
        bindings.billing_rows_digest.as_deref(),
        bindings.billing_manifest_digest.as_deref(),
        bindings.recomputed_billing_manifest_digest.as_deref(),
        bindings.billing_recovery_digest.as_deref(),
        bindings.recomputed_billing_recovery_digest.as_deref(),
        bindings.billing_manifest_recovery_digest.as_deref(),
        bindings
            .recomputed_billing_manifest_recovery_digest
            .as_deref(),
        bindings.billing_registry_digest.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        aggregate = aggregate
            .checked_add(value.len())
            .ok_or(EconomicsError::InputLimit)?;
    }
    for source in &bindings.quality_sources {
        let bytes = validate_quality_source(source)?;
        aggregate = aggregate
            .checked_add(bytes)
            .ok_or(EconomicsError::InputLimit)?;
    }
    if aggregate > MAX_EVIDENCE_BINDING_BYTES {
        return Err(EconomicsError::InputLimit);
    }
    Ok(())
}

fn validate_quality_source(source: &QualitySourceBinding) -> Result<usize, EconomicsError> {
    let digests = [
        &source.manifest_digest,
        &source.recomputed_manifest_digest,
        &source.outcomes_digest,
        &source.recomputed_outcomes_digest,
        &source.report_digest,
        &source.recomputed_report_digest,
        &source.registry_digest,
        &source.owned_cost_digest,
        &source.policy_digest,
        &source.join_projection_digest,
    ];
    let bytes = digests
        .into_iter()
        .try_fold(source.run_id.len(), |sum, value| {
            sum.checked_add(value.len())
        })
        .ok_or(EconomicsError::InputLimit)?;
    if !safe_run_id(&source.run_id)
        || !matches!(source.schema_version, 1 | 2)
        || digests.into_iter().any(|value| !valid_digest(value))
        || bytes > MAX_QUALITY_SOURCE_BINDING_BYTES
    {
        return Err(EconomicsError::InvalidEvidenceBinding);
    }
    Ok(bytes)
}

pub fn canonical_quality_projection_digest(
    entries: &[QualityJoinEvidence],
) -> Result<String, EconomicsError> {
    if entries.is_empty() || entries.len() > MAX_REPORT_ROWS {
        return Err(EconomicsError::InvalidQualityEvidence);
    }
    let mut ordered = entries.to_vec();
    ordered.sort_by(|left, right| {
        (
            left.run_id.as_str(),
            left.workload_identity_digest.as_deref(),
            left.task_class,
            left.protocol,
            left.candidate_supply_id.as_str(),
        )
            .cmp(&(
                right.run_id.as_str(),
                right.workload_identity_digest.as_deref(),
                right.task_class,
                right.protocol,
                right.candidate_supply_id.as_str(),
            ))
    });
    Ok(domain_digest(
        b"bowline.economics.quality-join-projection.v1",
        &serde_json::to_vec(&ordered)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn add_check(
    checks: &mut Vec<SourceBindingCheck>,
    source: &str,
    field: &str,
    expected: Option<String>,
    observed: Option<String>,
    blockers: &mut BTreeSet<Blocker>,
    blocker: Blocker,
) {
    let matched =
        expected.is_some() && expected == observed && expected.as_deref().is_some_and(valid_digest);
    if !matched {
        blockers.insert(blocker);
    }
    checks.push(SourceBindingCheck {
        source: source.to_owned(),
        field: field.to_owned(),
        kind: "checksum".to_owned(),
        expected,
        observed,
        matched,
    });
}

pub fn float_usd_to_micros(value: f64) -> Result<u64, EconomicsError> {
    if !value.is_finite() || value < 0.0 {
        return Err(EconomicsError::InvalidMoney);
    }
    let micros = value * 1_000_000.0;
    // `u64::MAX as f64` rounds to exactly 2^64, which is the exclusive upper bound.
    // Reject equality before the float-to-int cast can saturate it to u64::MAX.
    if !micros.is_finite() || micros >= u64::MAX as f64 {
        return Err(EconomicsError::ArithmeticOverflow);
    }
    Ok(micros.round_ties_even() as u64)
}

pub fn ppm_within(
    absolute_delta: u64,
    denominator: u64,
    tolerance_ppm: u64,
) -> Result<bool, EconomicsError> {
    if tolerance_ppm > MAX_PPM {
        return Err(EconomicsError::InvalidAnalysis);
    }
    if denominator == 0 {
        return Ok(absolute_delta == 0);
    }
    let left = i128::from(absolute_delta)
        .checked_mul(i128::from(MAX_PPM))
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    let right = i128::from(denominator)
        .checked_mul(i128::from(tolerance_ppm))
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    Ok(left <= right)
}

pub fn annualize_micros(
    delta_micros: i128,
    window_ms: u64,
    year_ms: u64,
) -> Result<u64, EconomicsError> {
    if delta_micros < 0 || window_ms == 0 || year_ms == 0 {
        return Err(EconomicsError::InvalidAnnualization);
    }
    let numerator = delta_micros
        .checked_mul(i128::from(year_ms))
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    let rounded = div_round_ties_even(numerator, i128::from(window_ms))?;
    u64::try_from(rounded).map_err(|_| EconomicsError::ArithmeticOverflow)
}

fn div_round_ties_even(numerator: i128, denominator: i128) -> Result<i128, EconomicsError> {
    if numerator < 0 || denominator <= 0 {
        return Err(EconomicsError::InvalidAnnualization);
    }
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let doubled = remainder
        .checked_mul(2)
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    if doubled > denominator || (doubled == denominator && quotient % 2 != 0) {
        quotient
            .checked_add(1)
            .ok_or(EconomicsError::ArithmeticOverflow)
    } else {
        Ok(quotient)
    }
}

fn ratio_ppm(numerator: u64, denominator: u64) -> Result<Option<u64>, EconomicsError> {
    if denominator == 0 {
        return Ok(None);
    }
    ppm_value(u128::from(numerator), denominator).map(Some)
}

fn ratio_at_least(
    numerator: u64,
    denominator: u64,
    minimum_ppm: u64,
) -> Result<bool, EconomicsError> {
    if denominator == 0 || minimum_ppm > MAX_PPM {
        return Ok(false);
    }
    let left = u128::from(numerator)
        .checked_mul(u128::from(MAX_PPM))
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    let right = u128::from(denominator)
        .checked_mul(u128::from(minimum_ppm))
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    Ok(left >= right)
}

fn ppm_value(numerator: u128, denominator: u64) -> Result<u64, EconomicsError> {
    let scaled = numerator
        .checked_mul(u128::from(MAX_PPM))
        .ok_or(EconomicsError::ArithmeticOverflow)?;
    let value = scaled / u128::from(denominator);
    u64::try_from(value).map_err(|_| EconomicsError::ArithmeticOverflow)
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, EconomicsError> {
    left.checked_add(right)
        .ok_or(EconomicsError::ArithmeticOverflow)
}

fn checked_optional_sum(total: &mut Option<u64>, value: u64) -> Result<(), EconomicsError> {
    if let Some(current) = total {
        *current = checked_add_u64(*current, value)?;
    }
    Ok(())
}

fn checked_optional_i128_sum(total: &mut Option<i128>, value: i128) -> Result<(), EconomicsError> {
    if let Some(current) = total {
        *current = current
            .checked_add(value)
            .ok_or(EconomicsError::ArithmeticOverflow)?;
    }
    Ok(())
}

fn exception(
    code: &str,
    supply: Option<&str>,
    row: Option<&str>,
    record: Option<&str>,
) -> ReconciliationException {
    ReconciliationException {
        code: code.to_owned(),
        supply_id: supply.map(ToOwned::to_owned),
        row_id: row.map(ToOwned::to_owned),
        record_id: record.map(ToOwned::to_owned),
    }
}

fn push_report_exception(
    exceptions: &mut Vec<ReconciliationException>,
    value: ReconciliationException,
) -> Result<(), EconomicsError> {
    if exceptions.len() >= MAX_REPORT_ROWS {
        return Err(EconomicsError::ReportRowLimit);
    }
    exceptions.push(value);
    Ok(())
}

fn push_reconciliation_row(
    rows: &mut Vec<BillingRowReconciliation>,
    value: BillingRowReconciliation,
) -> Result<(), EconomicsError> {
    if rows.len() >= MAX_REPORT_ROWS {
        return Err(EconomicsError::ReportRowLimit);
    }
    rows.push(value);
    Ok(())
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ANALYSIS_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn safe_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ANALYSIS_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn bounded_dimension(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DIMENSION_VALUE_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn canonical_traffic_records_digest(
    records: &[EconomicsRecord],
) -> Result<String, EconomicsError> {
    if records.len() > MAX_ANALYSIS_RECORDS {
        return Err(EconomicsError::InputLimit);
    }
    let mut records = records.iter().collect::<Vec<_>>();
    records.sort_by_key(|record| record.sequence);
    if records
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Err(EconomicsError::DuplicateRecordSequence);
    }
    let mut hasher = Sha256::new();
    frame_digest(&mut hasher, b"bowline.economics.selected-traffic.v1");
    for record in records {
        frame_digest(&mut hasher, &serde_json::to_vec(record)?);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn canonical_billing_rows_digest(rows: &[BillingRow]) -> Result<String, EconomicsError> {
    let mut rows = rows.to_vec();
    rows.sort_by(|left, right| {
        (
            left.period_start_ms,
            left.period_end_ms,
            left.supply_id.as_str(),
            left.row_id.as_str(),
        )
            .cmp(&(
                right.period_start_ms,
                right.period_end_ms,
                right.supply_id.as_str(),
                right.row_id.as_str(),
            ))
    });
    validate_normalized_rows(rows)
        .map(|validated| validated.canonical_digest().to_owned())
        .map_err(|_| EconomicsError::InvalidBillingEvidence)
}

fn frame_digest(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[derive(Debug, Error)]
pub enum EconomicsError {
    #[error("invalid economics analysis manifest")]
    InvalidAnalysis,
    #[error("economics input limit exceeded")]
    InputLimit,
    #[error("economics report row limit exceeded")]
    ReportRowLimit,
    #[error("invalid economics record")]
    InvalidRecord,
    #[error("invalid enforced modeled delta evidence")]
    InvalidEnforcedModeledDelta,
    #[error("duplicate economics record sequence")]
    DuplicateRecordSequence,
    #[error("invalid economics cost rate")]
    InvalidCostRate,
    #[error("invalid modeled money")]
    InvalidMoney,
    #[error("invalid quality evidence")]
    InvalidQualityEvidence,
    #[error("invalid economics evidence binding")]
    InvalidEvidenceBinding,
    #[error("duplicate quality join")]
    DuplicateQualityJoin,
    #[error("selected quality runs do not match supplied runs")]
    QualityRunMismatch,
    #[error("billing rows must exactly tile the analysis window")]
    BillingWindowNotTiled,
    #[error("invalid canonical billing evidence")]
    InvalidBillingEvidence,
    #[error("modeled-only analysis forbids billing rows")]
    UnexpectedBillingRows,
    #[error("economics arithmetic overflow")]
    ArithmeticOverflow,
    #[error("invalid annualization")]
    InvalidAnnualization,
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl EconomicsError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAnalysis => "invalid-analysis",
            Self::InputLimit => "input-limit",
            Self::ReportRowLimit => "report-row-limit",
            Self::InvalidRecord => "invalid-record",
            Self::InvalidEnforcedModeledDelta => "invalid-enforced-modeled-delta",
            Self::DuplicateRecordSequence => "duplicate-record-sequence",
            Self::InvalidCostRate => "invalid-cost-rate",
            Self::InvalidMoney => "invalid-money",
            Self::InvalidQualityEvidence => "invalid-quality-evidence",
            Self::InvalidEvidenceBinding => "invalid-evidence-binding",
            Self::DuplicateQualityJoin => "duplicate-quality-join",
            Self::QualityRunMismatch => "quality-run-mismatch",
            Self::BillingWindowNotTiled => "billing-window-not-tiled",
            Self::InvalidBillingEvidence => "invalid-billing-evidence",
            Self::UnexpectedBillingRows => "unexpected-billing-rows",
            Self::ArithmeticOverflow => "arithmetic-overflow",
            Self::InvalidAnnualization => "invalid-annualization",
            Self::Yaml(_) => "analysis-yaml",
            Self::Json(_) => "analysis-json",
        }
    }
}
