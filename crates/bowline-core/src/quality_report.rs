use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    quality::{PromotionVerdict, QualityEvidenceOverlay},
    quality_run::{QualityLedgerRead, QualityOutcome, QualityProvenance, QualityRunManifest},
};

pub const QUALITY_REPORT_SCHEMA_VERSION: u32 = 1;
pub const QUALITY_REPORT_SCHEMA_VERSION_V2: u32 = 2;
pub const QUALITY_REPORT_FILE: &str = "quality-report.json";
const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
const OUTCOMES_DIGEST_DOMAIN: &[u8] = b"bowline-quality-outcomes-v1";
const REPORT_DIGEST_DOMAIN: &[u8] = b"bowline-quality-completion-report-v1";
const REPORT_V2_DIGEST_DOMAIN: &[u8] = b"bowline-quality-completion-report-v2";
const WORKLOAD_IDENTITY_DIGEST_DOMAIN: &[u8] = b"bowline-quality-workload-identity-v2";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityReport {
    pub schema_version: u32,
    pub run_id: String,
    pub as_of_ms: u64,
    pub completed_at_ms: u64,
    pub valid_until_ms: u64,
    pub stale: bool,
    pub clean_shutdown: bool,
    pub cancelled: bool,
    pub writer_healthy: bool,
    pub reconciled: bool,
    pub recorded_outcomes: u64,
    pub outcomes_digest: String,
    pub objective_evaluators: bool,
    pub subjective_judge_configured: bool,
    pub subjective_judge_required: bool,
    pub provenance: QualityProvenance,
    pub candidates: Vec<QualityEvidenceOverlay>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEvidenceOverlayV2 {
    pub workload_identity_digest: String,
    #[serde(flatten)]
    pub evidence: QualityEvidenceOverlay,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityReportV2 {
    pub schema_version: u32,
    pub run_id: String,
    pub as_of_ms: u64,
    pub completed_at_ms: u64,
    pub valid_until_ms: u64,
    pub stale: bool,
    pub clean_shutdown: bool,
    pub cancelled: bool,
    pub writer_healthy: bool,
    pub reconciled: bool,
    pub recorded_outcomes: u64,
    pub outcomes_digest: String,
    pub objective_evaluators: bool,
    pub subjective_judge_configured: bool,
    pub subjective_judge_required: bool,
    pub provenance: QualityProvenance,
    pub workload_identity_digest: String,
    pub candidates: Vec<QualityEvidenceOverlayV2>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QualityReportDocument {
    V1(QualityReport),
    V2(QualityReportV2),
}

impl QualityReportDocument {
    /// Schema-v1 reports remain verifiable but have no resolved workload identity and therefore
    /// cannot participate in an economics join.
    pub fn joinable_workload_identity_digest(&self) -> Option<&str> {
        match self {
            Self::V1(_) => None,
            Self::V2(report) => Some(&report.workload_identity_digest),
        }
    }
}

#[derive(Debug, Error)]
pub enum QualityReportError {
    #[error("invalid quality report")]
    Invalid,
    #[error("quality report exceeds byte limit")]
    TooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn quality_workload_identity_digest(
    protocol: crate::quality::QualityProtocol,
    app: &str,
    resolved_tags: &[String],
) -> Result<String, QualityReportError> {
    if !crate::identifier::is_bounded_identifier(app) {
        return Err(QualityReportError::Invalid);
    }
    let mut tags = resolved_tags.to_vec();
    tags.sort();
    if tags
        .iter()
        .any(|tag| !crate::identifier::is_bounded_identifier(tag))
        || tags.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(QualityReportError::Invalid);
    }
    let fields = std::iter::once(protocol.route().as_bytes())
        .chain(std::iter::once(app.as_bytes()))
        .chain(tags.iter().map(String::as_bytes));
    let mut hasher = Sha256::new();
    hasher.update(WORKLOAD_IDENTITY_DIGEST_DOMAIN);
    hasher.update([0]);
    for field in fields {
        let length = u64::try_from(field.len()).map_err(|_| QualityReportError::Invalid)?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

impl QualityReport {
    pub fn new(
        manifest: &QualityRunManifest,
        mut candidates: Vec<QualityEvidenceOverlay>,
        as_of_ms: u64,
        judge_configured: bool,
        judge_required: bool,
        outcomes_digest: String,
    ) -> Result<Self, QualityReportError> {
        let completed_at_ms = manifest
            .completed_at_ms
            .ok_or(QualityReportError::Invalid)?;
        candidates.sort_by(|left, right| left.candidate_supply_id.cmp(&right.candidate_supply_id));
        let report = Self {
            schema_version: QUALITY_REPORT_SCHEMA_VERSION,
            run_id: manifest.run_id.clone(),
            as_of_ms,
            completed_at_ms,
            valid_until_ms: manifest.valid_until_ms,
            stale: as_of_ms > manifest.valid_until_ms,
            clean_shutdown: manifest.clean_shutdown,
            cancelled: manifest.cancelled,
            writer_healthy: manifest.writer_healthy,
            reconciled: manifest.reconciled(),
            recorded_outcomes: manifest.recorded,
            outcomes_digest,
            objective_evaluators: true,
            subjective_judge_configured: judge_configured,
            subjective_judge_required: judge_required,
            provenance: manifest.provenance.clone(),
            candidates,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn at_as_of(&self, as_of_ms: u64) -> Self {
        let mut report = self.clone();
        report.as_of_ms = as_of_ms;
        report.stale = as_of_ms > report.valid_until_ms;
        for candidate in &mut report.candidates {
            candidate.assessment.stale = report.stale;
            candidate.assessment.effective_verdict =
                effective_verdict(candidate.assessment.completion_verdict, report.stale);
        }
        report
    }

    fn validate(&self) -> Result<(), QualityReportError> {
        let mut supplies = BTreeSet::new();
        if self.schema_version != QUALITY_REPORT_SCHEMA_VERSION
            || self.candidates.is_empty()
            || self.completed_at_ms > self.valid_until_ms
            || self.stale != (self.as_of_ms > self.valid_until_ms)
            || !self.objective_evaluators
            || !valid_digest(&self.outcomes_digest)
            || self.subjective_judge_required && !self.subjective_judge_configured
            || self.candidates.iter().any(|candidate| {
                !supplies.insert(candidate.candidate_supply_id.as_str())
                    || candidate.completed_at_ms != self.completed_at_ms
                    || candidate.valid_until_ms != self.valid_until_ms
                    || candidate.dataset_digest != self.provenance.dataset_digest
                    || candidate.evaluator_digest != self.provenance.evaluator_digest
                    || candidate.assessment.stale != self.stale
                    || candidate.assessment.effective_verdict
                        != effective_verdict(candidate.assessment.completion_verdict, self.stale)
            })
        {
            return Err(QualityReportError::Invalid);
        }
        Ok(())
    }
}

impl QualityReportV2 {
    pub fn from_v1(
        report: QualityReport,
        workload_identity_digest: String,
    ) -> Result<Self, QualityReportError> {
        report.validate()?;
        if !valid_digest(&workload_identity_digest) {
            return Err(QualityReportError::Invalid);
        }
        let candidates = report
            .candidates
            .into_iter()
            .map(|evidence| QualityEvidenceOverlayV2 {
                workload_identity_digest: workload_identity_digest.clone(),
                evidence,
            })
            .collect();
        let value = Self {
            schema_version: QUALITY_REPORT_SCHEMA_VERSION_V2,
            run_id: report.run_id,
            as_of_ms: report.as_of_ms,
            completed_at_ms: report.completed_at_ms,
            valid_until_ms: report.valid_until_ms,
            stale: report.stale,
            clean_shutdown: report.clean_shutdown,
            cancelled: report.cancelled,
            writer_healthy: report.writer_healthy,
            reconciled: report.reconciled,
            recorded_outcomes: report.recorded_outcomes,
            outcomes_digest: report.outcomes_digest,
            objective_evaluators: report.objective_evaluators,
            subjective_judge_configured: report.subjective_judge_configured,
            subjective_judge_required: report.subjective_judge_required,
            provenance: report.provenance,
            workload_identity_digest,
            candidates,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn at_as_of(&self, as_of_ms: u64) -> Self {
        let mut report = self.clone();
        report.as_of_ms = as_of_ms;
        report.stale = as_of_ms > report.valid_until_ms;
        for candidate in &mut report.candidates {
            candidate.evidence.assessment.stale = report.stale;
            candidate.evidence.assessment.effective_verdict = effective_verdict(
                candidate.evidence.assessment.completion_verdict,
                report.stale,
            );
        }
        report
    }

    fn validate(&self) -> Result<(), QualityReportError> {
        let mut supplies = BTreeSet::new();
        if self.schema_version != QUALITY_REPORT_SCHEMA_VERSION_V2
            || !valid_digest(&self.workload_identity_digest)
            || self.candidates.is_empty()
            || self.completed_at_ms > self.valid_until_ms
            || self.stale != (self.as_of_ms > self.valid_until_ms)
            || !self.objective_evaluators
            || !valid_digest(&self.outcomes_digest)
            || self.subjective_judge_required && !self.subjective_judge_configured
            || self.candidates.iter().any(|candidate| {
                let evidence = &candidate.evidence;
                candidate.workload_identity_digest != self.workload_identity_digest
                    || !supplies.insert(evidence.candidate_supply_id.as_str())
                    || evidence.completed_at_ms != self.completed_at_ms
                    || evidence.valid_until_ms != self.valid_until_ms
                    || evidence.dataset_digest != self.provenance.dataset_digest
                    || evidence.evaluator_digest != self.provenance.evaluator_digest
                    || evidence.assessment.stale != self.stale
                    || evidence.assessment.effective_verdict
                        != effective_verdict(evidence.assessment.completion_verdict, self.stale)
            })
        {
            return Err(QualityReportError::Invalid);
        }
        Ok(())
    }
}

pub fn write_quality_report(
    directory: &Path,
    report: &QualityReport,
) -> Result<(), QualityReportError> {
    report.validate()?;
    let payload = serde_json::to_vec_pretty(report)?;
    if payload.len() > MAX_REPORT_BYTES {
        return Err(QualityReportError::TooLarge);
    }
    let temporary = directory.join(format!(".quality-report-{}.tmp", Uuid::new_v4()));
    let target = directory.join(QUALITY_REPORT_FILE);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        fs::rename(&temporary, &target)?;
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn write_quality_report_v2(
    directory: &Path,
    report: &QualityReportV2,
) -> Result<(), QualityReportError> {
    report.validate()?;
    write_report_payload(directory, &serde_json::to_vec_pretty(report)?)
}

fn write_report_payload(directory: &Path, payload: &[u8]) -> Result<(), QualityReportError> {
    if payload.len() > MAX_REPORT_BYTES {
        return Err(QualityReportError::TooLarge);
    }
    let temporary = directory.join(format!(".quality-report-{}.tmp", Uuid::new_v4()));
    let target = directory.join(QUALITY_REPORT_FILE);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(payload)?;
        file.sync_all()?;
        fs::rename(&temporary, &target)?;
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn load_quality_report(directory: &Path) -> Result<QualityReport, QualityReportError> {
    let path = directory.join(QUALITY_REPORT_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_REPORT_BYTES as u64
    {
        return Err(QualityReportError::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(QualityReportError::TooLarge);
    }
    let report: QualityReport = serde_json::from_slice(&bytes)?;
    report.validate()?;
    Ok(report)
}

pub fn load_quality_report_document(
    directory: &Path,
) -> Result<QualityReportDocument, QualityReportError> {
    let path = directory.join(QUALITY_REPORT_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_REPORT_BYTES as u64
    {
        return Err(QualityReportError::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(QualityReportError::TooLarge);
    }
    parse_quality_report_document(&bytes)
}

pub fn parse_quality_report_document(
    bytes: &[u8],
) -> Result<QualityReportDocument, QualityReportError> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(QualityReportError::TooLarge);
    }
    let raw: serde_json::Value = serde_json::from_slice(bytes)?;
    match raw
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(1) => {
            let report: QualityReport = serde_json::from_value(raw)?;
            report.validate()?;
            Ok(QualityReportDocument::V1(report))
        }
        Some(2) => {
            let report: QualityReportV2 = serde_json::from_value(raw)?;
            report.validate()?;
            Ok(QualityReportDocument::V2(report))
        }
        _ => Err(QualityReportError::Invalid),
    }
}

pub fn validate_quality_report_evidence(
    report: &QualityReport,
    manifest: &QualityRunManifest,
    ledger: &QualityLedgerRead,
) -> Result<(), QualityReportError> {
    report.validate()?;
    let manifest_outcomes_digest = manifest
        .outcomes_digest
        .as_deref()
        .ok_or(QualityReportError::Invalid)?;
    let manifest_report_digest = manifest
        .quality_report_digest
        .as_deref()
        .ok_or(QualityReportError::Invalid)?;
    let actual_outcomes_digest = canonical_outcomes_digest(&ledger.outcomes)?;
    let actual_report_digest = quality_report_digest(report)?;
    if report.run_id != manifest.run_id
        || report.completed_at_ms
            != manifest
                .completed_at_ms
                .ok_or(QualityReportError::Invalid)?
        || report.valid_until_ms != manifest.valid_until_ms
        || report.provenance != manifest.provenance
        || report.clean_shutdown != manifest.clean_shutdown
        || report.cancelled != manifest.cancelled
        || report.writer_healthy != manifest.writer_healthy
        || report.reconciled != manifest.reconciled()
        || report.recorded_outcomes != manifest.recorded
        || report.recorded_outcomes != ledger.outcomes.len() as u64
        || report.as_of_ms != report.completed_at_ms
        || report.outcomes_digest != actual_outcomes_digest
        || manifest_outcomes_digest != actual_outcomes_digest
        || manifest_report_digest != actual_report_digest
        || !ledger.gaps.is_empty()
    {
        return Err(QualityReportError::Invalid);
    }
    Ok(())
}

pub fn validate_quality_report_v2_evidence(
    report: &QualityReportV2,
    manifest: &QualityRunManifest,
    ledger: &QualityLedgerRead,
) -> Result<(), QualityReportError> {
    report.validate()?;
    let manifest_outcomes_digest = manifest
        .outcomes_digest
        .as_deref()
        .ok_or(QualityReportError::Invalid)?;
    let manifest_report_digest = manifest
        .quality_report_digest
        .as_deref()
        .ok_or(QualityReportError::Invalid)?;
    let actual_outcomes_digest = canonical_outcomes_digest(&ledger.outcomes)?;
    let actual_report_digest = quality_report_v2_digest(report)?;
    if report.run_id != manifest.run_id
        || report.completed_at_ms
            != manifest
                .completed_at_ms
                .ok_or(QualityReportError::Invalid)?
        || report.valid_until_ms != manifest.valid_until_ms
        || report.provenance != manifest.provenance
        || report.clean_shutdown != manifest.clean_shutdown
        || report.cancelled != manifest.cancelled
        || report.writer_healthy != manifest.writer_healthy
        || report.reconciled != manifest.reconciled()
        || report.recorded_outcomes != manifest.recorded
        || report.recorded_outcomes != ledger.outcomes.len() as u64
        || report.as_of_ms != report.completed_at_ms
        || report.outcomes_digest != actual_outcomes_digest
        || manifest_outcomes_digest != actual_outcomes_digest
        || manifest_report_digest != actual_report_digest
        || !ledger.gaps.is_empty()
    {
        return Err(QualityReportError::Invalid);
    }
    Ok(())
}

pub fn canonical_outcomes_digest(
    outcomes: &[QualityOutcome],
) -> Result<String, QualityReportError> {
    let mut ordered: Vec<_> = outcomes.iter().collect();
    ordered.sort_by_key(|outcome| outcome.sequence);
    if ordered
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Err(QualityReportError::Invalid);
    }
    let payload = serde_json::to_vec(&ordered)?;
    Ok(domain_digest(OUTCOMES_DIGEST_DOMAIN, &payload))
}

pub fn quality_report_digest(report: &QualityReport) -> Result<String, QualityReportError> {
    report.validate()?;
    let payload = serde_json::to_vec(report)?;
    Ok(domain_digest(REPORT_DIGEST_DOMAIN, &payload))
}

pub fn quality_report_v2_digest(report: &QualityReportV2) -> Result<String, QualityReportError> {
    report.validate()?;
    let payload = serde_json::to_vec(report)?;
    Ok(domain_digest(REPORT_V2_DIGEST_DOMAIN, &payload))
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn render_quality_markdown(report: &QualityReport) -> String {
    let mut output = String::new();
    output.push_str("# Bowline Quality Evidence\n\n");
    output.push_str(&format!("- Run: `{}`\n", report.run_id));
    output.push_str(&format!("- As of (ms): `{}`\n", report.as_of_ms));
    output.push_str(&format!("- Completed (ms): `{}`\n", report.completed_at_ms));
    output.push_str(&format!("- Expires (ms): `{}`\n", report.valid_until_ms));
    output.push_str(&format!("- Stale: `{}`\n", report.stale));
    output.push_str(&format!(
        "- Subjective judge: `{}` (required: `{}`)\n\n",
        report.subjective_judge_configured, report.subjective_judge_required
    ));
    for candidate in &report.candidates {
        let assessment = &candidate.assessment;
        let metrics = &assessment.metrics;
        output.push_str(&format!("## `{}`\n\n", candidate.candidate_supply_id));
        output.push_str(&format!(
            "- Completion verdict: `{:?}`\n- Effective verdict: `{:?}`\n",
            assessment.completion_verdict, assessment.effective_verdict
        ));
        output.push_str(&format!(
            "- Gates: `{}`\n",
            serde_json::to_string(&assessment.gates).unwrap_or_default()
        ));
        output.push_str(&format!(
            "- Blockers: `{}`\n",
            serde_json::to_string(&assessment.blockers).unwrap_or_default()
        ));
        output.push_str(&format!(
            "- Samples/pass: `{}/{}`\n- Pass rate: `{:?}`\n- Wilson lower 95%: `{:?}`\n- p95 latency (ms): `{:?}`\n- Candidate error rate: `{:?}`\n- Candidate cost (USD): `{:?}`\n- Judge cost (USD): `{:?}`\n\n",
            metrics.quality_pass_count,
            metrics.quality_sample_count,
            metrics.observed_pass_rate,
            metrics.wilson_lower_95,
            metrics.p95_latency_ms,
            metrics.candidate_error_rate,
            metrics.candidate_cost_usd,
            metrics.judge_cost_usd,
        ));
    }
    output.push_str("## Provenance\n\n");
    output.push_str(&format!(
        "```json\n{}\n```\n",
        serde_json::to_string_pretty(&report.provenance).unwrap_or_default()
    ));
    output
}

pub fn render_quality_markdown_v2(report: &QualityReportV2) -> String {
    let mut output = String::new();
    output.push_str("# Bowline Quality Evidence\n\n");
    output.push_str(&format!("- Run: `{}`\n", report.run_id));
    output.push_str(&format!("- As of (ms): `{}`\n", report.as_of_ms));
    output.push_str(&format!("- Completed (ms): `{}`\n", report.completed_at_ms));
    output.push_str(&format!("- Expires (ms): `{}`\n", report.valid_until_ms));
    output.push_str(&format!("- Stale: `{}`\n", report.stale));
    output.push_str(&format!(
        "- Subjective judge: `{}` (required: `{}`)\n\n",
        report.subjective_judge_configured, report.subjective_judge_required
    ));
    for candidate in &report.candidates {
        let evidence = &candidate.evidence;
        let assessment = &evidence.assessment;
        let metrics = &assessment.metrics;
        output.push_str(&format!("## `{}`\n\n", evidence.candidate_supply_id));
        output.push_str(&format!(
            "- Completion verdict: `{:?}`\n- Effective verdict: `{:?}`\n",
            assessment.completion_verdict, assessment.effective_verdict
        ));
        output.push_str(&format!(
            "- Gates: `{}`\n- Blockers: `{}`\n",
            serde_json::to_string(&assessment.gates).unwrap_or_default(),
            serde_json::to_string(&assessment.blockers).unwrap_or_default()
        ));
        output.push_str(&format!(
            "- Samples/pass: `{}/{}`\n- Pass rate: `{:?}`\n- Wilson lower 95%: `{:?}`\n- p95 latency (ms): `{:?}`\n- Candidate error rate: `{:?}`\n- Candidate cost (USD): `{:?}`\n- Judge cost (USD): `{:?}`\n\n",
            metrics.quality_pass_count,
            metrics.quality_sample_count,
            metrics.observed_pass_rate,
            metrics.wilson_lower_95,
            metrics.p95_latency_ms,
            metrics.candidate_error_rate,
            metrics.candidate_cost_usd,
            metrics.judge_cost_usd,
        ));
    }
    output.push_str("## Provenance\n\n");
    output.push_str(&format!(
        "```json\n{}\n```\n",
        serde_json::to_string_pretty(&report.provenance).unwrap_or_default()
    ));
    output
}

fn effective_verdict(completion: PromotionVerdict, stale: bool) -> PromotionVerdict {
    if stale
        && matches!(
            completion,
            PromotionVerdict::Eligible
                | PromotionVerdict::QualityFailed
                | PromotionVerdict::CostUnknown
        )
    {
        PromotionVerdict::InsufficientEvidence
    } else {
        completion
    }
}

#[cfg(test)]
mod schema_v2_identity_tests {
    use super::quality_workload_identity_digest;
    use crate::policy::{PolicyBundle, WorkloadIdentity};
    use crate::quality::QualityProtocol;

    #[test]
    fn workload_digest_is_order_independent_but_identity_and_boundaries_matter() {
        let left = quality_workload_identity_digest(
            QualityProtocol::Responses,
            "support",
            &["team:ops".into(), "environment:prod".into()],
        )
        .unwrap();
        let reordered = quality_workload_identity_digest(
            QualityProtocol::Responses,
            "support",
            &["environment:prod".into(), "team:ops".into()],
        )
        .unwrap();
        assert_eq!(left, reordered);
        assert_ne!(
            left,
            quality_workload_identity_digest(
                QualityProtocol::Chat,
                "support",
                &["environment:prod".into(), "team:ops".into()],
            )
            .unwrap()
        );
        assert_ne!(
            quality_workload_identity_digest(QualityProtocol::Responses, "ab", &["c".into()],)
                .unwrap(),
            quality_workload_identity_digest(QualityProtocol::Responses, "a", &["bc".into()],)
                .unwrap()
        );
    }

    #[test]
    fn workload_digest_rejects_duplicate_or_unbounded_resolved_tags() {
        assert!(quality_workload_identity_digest(
            QualityProtocol::Responses,
            "support",
            &["team:ops".into(), "team:ops".into()],
        )
        .is_err());
        assert!(quality_workload_identity_digest(
            QualityProtocol::Responses,
            "support",
            &["x".repeat(129)],
        )
        .is_err());
    }

    #[test]
    fn workload_digest_uses_policy_resolved_not_raw_tags() {
        let policy = PolicyBundle::from_yaml(
            "version: 1\nidentities:\n  - match: {app: support}\n    tags: [team:ops, environment:prod]\nrules:\n  - name: default\n    default: true\n",
        )
        .unwrap();
        let raw = WorkloadIdentity {
            api_key_digest: Some("sha256:not-part-of-quality-workload".into()),
            route: "/v1/responses".into(),
            app: Some("support".into()),
            tags: vec!["task:summarize".into()],
        };
        let resolved = policy.resolve_tags(&raw);
        let resolved_digest =
            quality_workload_identity_digest(QualityProtocol::Responses, "support", &resolved)
                .unwrap();
        let raw_digest =
            quality_workload_identity_digest(QualityProtocol::Responses, "support", &raw.tags)
                .unwrap();
        assert_ne!(resolved_digest, raw_digest);
        assert_eq!(resolved.len(), 3);
    }
}
