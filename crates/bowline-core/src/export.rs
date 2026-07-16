use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ledger::DecisionRecord,
    report::{
        historical_policy_exposure, Confidence, PolicyExposure, ProtocolCoverage, ShadowReport,
    },
    run::RunManifest,
    supply::TaskClass,
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};

pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleV1 {
    pub evidence_schema_version: u32,
    pub generated_from: EvidenceGeneratedFromV1,
    pub disclosure: EvidenceDisclosureV1,
    pub runs: Vec<EvidenceRunV1>,
    pub decisions: Vec<EvidenceDecisionV1>,
    pub coverage: EvidenceCoverageV1,
    pub aggregates: ShadowReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGeneratedFromV1 {
    pub run_id: String,
    pub feed_version: String,
    pub policy_digest: String,
    pub registry_digest: String,
    pub attribution_digest: Option<String>,
    pub owned_cost_digest: Option<String>,
    pub passive_profile_digest: Option<String>,
    pub passive_input_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDisclosureV1 {
    pub complete: bool,
    pub integrity_warnings: Vec<String>,
    pub coverage_gaps: Vec<String>,
    pub confidence_legend: Vec<EvidenceConfidenceLegendV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfidenceLegendV1 {
    pub confidence: Confidence,
    pub meaning: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRunV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub clean_shutdown: bool,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub truncated: u64,
    pub unmapped: u64,
    pub unpriceable: u64,
    pub records_digest: Option<String>,
    pub segment_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDecisionV1 {
    pub decision_ref: String,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub protocol: ProtocolKind,
    pub observation_source: ObservationSource,
    pub coverage_status: CoverageStatus,
    pub coverage_reason: Option<String>,
    pub task_class: TaskClass,
    pub actual_supply_id: Option<String>,
    pub shadow_supply_id: Option<String>,
    pub actual_est_cost_usd: Option<f64>,
    pub shadow_est_cost_usd: Option<f64>,
    pub policy_exposure: PolicyExposure,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCoverageV1 {
    pub protocol_coverage: ProtocolCoverage,
    pub decisions: Vec<EvidenceDecisionCoverageV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDecisionCoverageV1 {
    pub decision_ref: String,
    pub coverage_status: CoverageStatus,
    pub coverage_reason: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceExportError {
    #[error("decision record belongs to a different run")]
    RunMismatch,
    #[error("decision record has no stable run sequence")]
    MissingSequence,
    #[error("decision record has an invalid or duplicate run sequence")]
    InvalidSequence,
    #[error("run segment count does not fit the export schema")]
    SegmentCountOverflow,
}

pub fn build_evidence_bundle_v1(
    manifest: &RunManifest,
    records: &[DecisionRecord],
    registry_feed_version: &str,
    report: ShadowReport,
) -> Result<EvidenceBundleV1, EvidenceExportError> {
    let mut sequences = BTreeSet::new();
    let mut decisions = Vec::with_capacity(records.len());
    for record in records {
        if record.run_id.as_deref() != Some(manifest.run_id.as_str()) {
            return Err(EvidenceExportError::RunMismatch);
        }
        let sequence = record
            .sequence
            .filter(|sequence| *sequence > 0)
            .ok_or(EvidenceExportError::MissingSequence)?;
        if sequence > manifest.accepted || !sequences.insert(sequence) {
            return Err(EvidenceExportError::InvalidSequence);
        }
        decisions.push(EvidenceDecisionV1 {
            decision_ref: format!("{}:{sequence}", manifest.run_id),
            sequence,
            observed_at_ms: record.ts_ms,
            protocol: record.protocol,
            observation_source: record.observation_source,
            coverage_status: record.coverage_status,
            coverage_reason: record.coverage_reason.clone(),
            task_class: record.decision.task_class,
            actual_supply_id: record.actual.supply_id.clone(),
            shadow_supply_id: record
                .decision
                .shadow
                .as_ref()
                .map(|placement| placement.supply_id.clone()),
            actual_est_cost_usd: record.actual.est_cost_usd,
            shadow_est_cost_usd: record
                .decision
                .shadow
                .as_ref()
                .and_then(|placement| placement.est_cost_usd),
            policy_exposure: historical_policy_exposure(
                record.coverage_status,
                record.actual.supply_id.as_deref(),
                &record.decision.feasible_ids,
            ),
        });
    }
    let decision_coverage = decisions
        .iter()
        .map(|decision| EvidenceDecisionCoverageV1 {
            decision_ref: decision.decision_ref.clone(),
            coverage_status: decision.coverage_status,
            coverage_reason: decision.coverage_reason.clone(),
        })
        .collect();
    let disclosure = EvidenceDisclosureV1 {
        complete: report.complete,
        integrity_warnings: integrity_warnings(manifest, &report),
        coverage_gaps: coverage_gaps(&report.protocol_coverage),
        confidence_legend: confidence_legend(),
    };
    let segment_count = u64::try_from(manifest.segments.len())
        .map_err(|_| EvidenceExportError::SegmentCountOverflow)?;

    Ok(EvidenceBundleV1 {
        evidence_schema_version: EVIDENCE_SCHEMA_VERSION,
        generated_from: EvidenceGeneratedFromV1 {
            run_id: manifest.run_id.clone(),
            feed_version: registry_feed_version.to_string(),
            policy_digest: manifest.policy_digest.clone(),
            registry_digest: manifest.registry_digest.clone(),
            attribution_digest: manifest.attribution_digest.clone(),
            owned_cost_digest: manifest.owned_cost_digest.clone(),
            passive_profile_digest: manifest.passive_profile_digest.clone(),
            passive_input_digest: manifest.passive_input_digest.clone(),
        },
        disclosure,
        runs: vec![EvidenceRunV1 {
            schema_version: manifest.schema_version,
            run_id: manifest.run_id.clone(),
            started_at_ms: manifest.started_at_ms,
            ended_at_ms: manifest.ended_at_ms,
            clean_shutdown: manifest.clean_shutdown,
            accepted: manifest.accepted,
            recorded: manifest.recorded,
            dropped: manifest.dropped,
            truncated: manifest.truncated,
            unmapped: manifest.unmapped,
            unpriceable: manifest.unpriceable,
            records_digest: manifest.records_digest.clone(),
            segment_count,
        }],
        coverage: EvidenceCoverageV1 {
            protocol_coverage: report.protocol_coverage.clone(),
            decisions: decision_coverage,
        },
        decisions,
        aggregates: report,
    })
}

fn integrity_warnings(manifest: &RunManifest, report: &ShadowReport) -> Vec<String> {
    let integrity = &report.data_integrity;
    let mut warnings = Vec::new();
    if !manifest.clean_shutdown {
        warnings.push("unclean-shutdown".into());
    }
    if !manifest.writer_healthy {
        warnings.push("writer-unhealthy".into());
    }
    if integrity.dropped > 0 {
        warnings.push("dropped-records".into());
    }
    if integrity.missing_sequences > 0 {
        warnings.push("missing-sequences".into());
    }
    if integrity.truncated > 0 {
        warnings.push("accounting-truncated".into());
    }
    if integrity.unmapped > 0 {
        warnings.push("unmapped-supply".into());
    }
    if integrity.unpriceable > 0 {
        warnings.push("unpriceable-supply".into());
    }
    if integrity.recovery_issues > 0 {
        warnings.push("ledger-recovery".into());
    }
    if manifest.recorded != report.generated_from_records {
        warnings.push("record-count-mismatch".into());
    }
    warnings
}

fn coverage_gaps(coverage: &ProtocolCoverage) -> Vec<String> {
    let mut gaps = coverage
        .by_status
        .iter()
        .filter(|(status, count)| **status != CoverageStatus::Supported && **count > 0)
        .map(|(status, count)| format!("status:{}:{count}", enum_name(status)))
        .collect::<Vec<_>>();
    gaps.extend(
        coverage
            .by_reason
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(reason, count)| format!("reason:{reason}:{count}")),
    );
    gaps
}

fn enum_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn confidence_legend() -> Vec<EvidenceConfidenceLegendV1> {
    [
        (
            Confidence::Observed,
            "directly observed from the recorded outcome",
        ),
        (
            Confidence::Declared,
            "derived from operator-declared registry or owned-cost inputs",
        ),
        (
            Confidence::CanaryVerified,
            "supported by matching canary evidence",
        ),
        (
            Confidence::Unverified,
            "modeled or not independently verified",
        ),
    ]
    .into_iter()
    .map(|(confidence, meaning)| EvidenceConfidenceLegendV1 {
        confidence,
        meaning: meaning.into(),
    })
    .collect()
}
