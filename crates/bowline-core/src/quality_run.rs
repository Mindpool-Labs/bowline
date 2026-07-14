use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{BufWriter, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    quality::{EvaluatorKind, EvaluatorStatus, QualityProtocol},
    supply::TaskClass,
};

pub const QUALITY_RUN_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const LEDGER_FILE: &str = "outcomes.bwq";
const LOCK_FILE: &str = ".quality-writer.lock";
const LEDGER_LOCK_FILE: &str = ".quality-ledger.lock";
const MAGIC: &[u8; 5] = b"BWQ1\n";
const FRAME_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityProvenance {
    pub dataset_manifest_digest: String,
    pub cases_digest: String,
    pub dataset_digest: String,
    pub evaluator_digest: String,
    pub candidate_config_digest: String,
    pub policy_digest: String,
    pub registry_digest: String,
    pub owned_cost_digest: Option<String>,
    pub judge_model_digest: Option<String>,
    pub judge_rubric_digest: Option<String>,
    pub judge_template_digest: Option<String>,
    pub judge_config_digest: Option<String>,
    #[serde(default)]
    pub judge_endpoint_digest: Option<String>,
    pub judge_authorization_reference_digest: Option<String>,
}

impl QualityProvenance {
    pub fn digest(&self) -> Result<String, QualityRunError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).expect("QualityProvenance serializes");
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    fn validate(&self) -> Result<(), QualityRunError> {
        let judge_digests = [
            self.judge_model_digest.as_ref(),
            self.judge_rubric_digest.as_ref(),
            self.judge_template_digest.as_ref(),
            self.judge_config_digest.as_ref(),
            self.judge_endpoint_digest.as_ref(),
            self.judge_authorization_reference_digest.as_ref(),
        ];
        let judge_present = judge_digests.iter().filter(|value| value.is_some()).count();
        if judge_present != 0 && judge_present != judge_digests.len() {
            return Err(QualityRunError::InvalidManifest);
        }
        for digest in [
            Some(&self.dataset_manifest_digest),
            Some(&self.cases_digest),
            Some(&self.dataset_digest),
            Some(&self.evaluator_digest),
            Some(&self.candidate_config_digest),
            Some(&self.policy_digest),
            Some(&self.registry_digest),
            self.owned_cost_digest.as_ref(),
            self.judge_model_digest.as_ref(),
            self.judge_rubric_digest.as_ref(),
            self.judge_template_digest.as_ref(),
            self.judge_config_digest.as_ref(),
            self.judge_endpoint_digest.as_ref(),
            self.judge_authorization_reference_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityAttemptStatus {
    Completed,
    CandidateError,
    EvaluatorError,
    JudgeError,
    Cancelled,
    InternalError,
}

impl QualityAttemptStatus {
    fn is_error(self) -> bool {
        matches!(
            self,
            Self::CandidateError | Self::EvaluatorError | Self::JudgeError | Self::InternalError
        )
    }

    pub(crate) fn is_normalized_response(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::EvaluatorError | Self::JudgeError
        )
    }
}

impl CandidateErrorKind {
    fn reason(self) -> QualityReasonCode {
        match self {
            Self::Timeout => QualityReasonCode::Timeout,
            Self::Transport => QualityReasonCode::Transport,
            Self::Disconnect => QualityReasonCode::Disconnect,
            Self::HttpStatus => QualityReasonCode::HttpStatus,
            Self::ResponseTooLarge => QualityReasonCode::ResponseTooLarge,
            Self::InvalidResponse => QualityReasonCode::InvalidResponse,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateErrorKind {
    Timeout,
    Transport,
    Disconnect,
    HttpStatus,
    ResponseTooLarge,
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityReasonCode {
    Timeout,
    Transport,
    Disconnect,
    HttpStatus,
    ResponseTooLarge,
    InvalidResponse,
    MissingUsage,
    EvaluatorError,
    JudgeError,
    WriterError,
    InternalError,
    SchedulerError,
    Cancelled,
    CostCeilingExceeded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeOutcomeEvidence {
    pub required: bool,
    pub subjective: bool,
    pub status: EvaluatorStatus,
    pub score: Option<f64>,
    pub threshold: f64,
    pub error_code: Option<JudgeErrorCode>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JudgeErrorCode {
    Timeout,
    Transport,
    Disconnect,
    HttpStatus,
    ResponseTooLarge,
    InvalidResponse,
    MissingUsage,
    SchedulerError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityEvaluatorErrorCode {
    Mismatch,
    MissingText,
    RegexInvalid,
    InvalidAssistantJson,
    SchemaInvalid,
    FieldMissing,
    ExpectedMissing,
    ToolCallCount,
    ToolCallMissing,
    EvaluatorError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEvaluatorEvidence {
    pub evaluator_id: String,
    pub kind: EvaluatorKind,
    pub status: EvaluatorStatus,
    pub error_code: Option<QualityEvaluatorErrorCode>,
    pub required: bool,
    pub subjective: bool,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CostEvaluatorStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostEvaluatorEvidence {
    pub evaluator_id: String,
    pub required: bool,
    pub status: CostEvaluatorStatus,
    pub observed_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityOutcome {
    pub sequence: u64,
    pub case_id: String,
    pub candidate_supply_id: String,
    pub candidate_model: String,
    pub protocol: QualityProtocol,
    pub task_class: TaskClass,
    pub dispatched: bool,
    pub status: QualityAttemptStatus,
    pub reason: Option<QualityReasonCode>,
    pub candidate_error: Option<CandidateErrorKind>,
    pub latency_ms: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub candidate_cost_usd: Option<f64>,
    pub evaluator_outcomes: Vec<QualityEvaluatorEvidence>,
    pub cost_evaluators: Vec<CostEvaluatorEvidence>,
    pub judge: Option<JudgeOutcomeEvidence>,
    pub dataset_digest: String,
    pub evaluator_digest: String,
}

impl QualityOutcome {
    pub(crate) fn promotion_semantics_valid(&self) -> bool {
        let status_consistent = match self.status {
            QualityAttemptStatus::Completed => {
                self.dispatched
                    && matches!(
                        self.reason,
                        None | Some(QualityReasonCode::MissingUsage)
                            | Some(QualityReasonCode::CostCeilingExceeded)
                    )
            }
            QualityAttemptStatus::CandidateError => {
                self.dispatched
                    && self
                        .candidate_error
                        .is_some_and(|kind| self.reason == Some(kind.reason()))
            }
            QualityAttemptStatus::EvaluatorError => {
                self.dispatched && self.reason == Some(QualityReasonCode::EvaluatorError)
            }
            QualityAttemptStatus::JudgeError => {
                self.dispatched && self.reason == Some(QualityReasonCode::JudgeError)
            }
            QualityAttemptStatus::Cancelled => self.reason == Some(QualityReasonCode::Cancelled),
            QualityAttemptStatus::InternalError => {
                matches!(
                    self.reason,
                    Some(
                        QualityReasonCode::WriterError
                            | QualityReasonCode::InternalError
                            | QualityReasonCode::SchedulerError
                    )
                )
            }
        };
        status_consistent
            && (self.status == QualityAttemptStatus::CandidateError)
                == self.candidate_error.is_some()
            && (!self.status.is_normalized_response() || self.latency_ms.is_some())
            && self.judge.as_ref().is_none_or(|judge| {
                judge.subjective
                    && judge.threshold.is_finite()
                    && (0.0..=1.0).contains(&judge.threshold)
                    && match judge.status {
                        EvaluatorStatus::Pass => judge.score.is_some_and(|score| {
                            score.is_finite()
                                && (0.0..=1.0).contains(&score)
                                && score >= judge.threshold
                        }),
                        EvaluatorStatus::Fail => judge.score.is_some_and(|score| {
                            score.is_finite()
                                && (0.0..=1.0).contains(&score)
                                && score < judge.threshold
                        }),
                        EvaluatorStatus::Error => judge.score.is_none(),
                    }
                    && (judge.status == EvaluatorStatus::Error) == judge.error_code.is_some()
                    && (judge.input_tokens.is_some() == judge.output_tokens.is_some())
                    && (judge.status == EvaluatorStatus::Error || judge.input_tokens.is_some())
            })
    }

    pub fn validate(&self) -> Result<(), QualityRunError> {
        if self.sequence == 0
            || !opaque_id(&self.case_id)
            || self.candidate_supply_id.is_empty()
            || self.candidate_supply_id.len() > 512
            || self.candidate_model.is_empty()
            || self.candidate_model.len() > 512
        {
            return Err(QualityRunError::InvalidOutcome);
        }
        validate_digest(&self.dataset_digest)?;
        validate_digest(&self.evaluator_digest)?;
        if !self.promotion_semantics_valid() {
            return Err(QualityRunError::InvalidOutcome);
        }
        if self
            .candidate_cost_usd
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(QualityRunError::InvalidOutcome);
        }
        for evaluator in &self.evaluator_outcomes {
            if !opaque_id(&evaluator.evaluator_id)
                || evaluator.subjective
                || evaluator.kind == EvaluatorKind::CostCeiling
                || (evaluator.status == EvaluatorStatus::Error) != evaluator.error_code.is_some()
            {
                return Err(QualityRunError::InvalidOutcome);
            }
        }
        for evaluator in &self.cost_evaluators {
            if !opaque_id(&evaluator.evaluator_id)
                || evaluator
                    .observed_cost_usd
                    .is_some_and(|value| !value.is_finite() || value < 0.0)
                || (evaluator.status == CostEvaluatorStatus::Unknown
                    && evaluator.observed_cost_usd.is_some())
                || (evaluator.status != CostEvaluatorStatus::Unknown
                    && evaluator.observed_cost_usd.is_none())
            {
                return Err(QualityRunError::InvalidOutcome);
            }
        }
        if let Some(judge) = &self.judge {
            if !judge.subjective
                || !judge.threshold.is_finite()
                || !(0.0..=1.0).contains(&judge.threshold)
                || judge
                    .score
                    .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
                || match judge.status {
                    EvaluatorStatus::Pass => {
                        !judge.score.is_some_and(|score| score >= judge.threshold)
                    }
                    EvaluatorStatus::Fail => {
                        !judge.score.is_some_and(|score| score < judge.threshold)
                    }
                    EvaluatorStatus::Error => judge.score.is_some(),
                }
                || judge
                    .cost_usd
                    .is_some_and(|value| !value.is_finite() || value < 0.0)
                || judge.input_tokens.is_some() != judge.output_tokens.is_some()
                || (judge.status != EvaluatorStatus::Error && judge.input_tokens.is_none())
                || (judge.status == EvaluatorStatus::Error) != judge.error_code.is_some()
            {
                return Err(QualityRunError::InvalidOutcome);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualityRunPlan {
    pub planned_request_upper_bound: u64,
    pub reserved_candidate_credits: u64,
    pub reserved_judge_credits: u64,
    pub max_age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityRunManifest {
    pub schema_version: u32,
    pub binary_version: String,
    pub run_id: String,
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub valid_until_ms: u64,
    pub clean_shutdown: bool,
    pub cancelled: bool,
    pub provenance: QualityProvenance,
    pub planned_request_upper_bound: u64,
    pub reserved_candidate_credits: u64,
    pub reserved_judge_credits: u64,
    pub candidate_dispatches: u64,
    pub judge_dispatches: u64,
    pub unused_judge_credits: u64,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub completed: u64,
    pub errors: u64,
    pub cancelled_outcomes: u64,
    pub next_sequence: u64,
    pub writer_healthy: bool,
    pub writer_error: Option<QualityReasonCode>,
    pub last_flush_at_ms: Option<u64>,
    #[serde(default)]
    pub outcomes_digest: Option<String>,
    #[serde(default)]
    pub quality_report_digest: Option<String>,
}

impl QualityRunManifest {
    pub fn reconciled(&self) -> bool {
        self.accepted == self.recorded.saturating_add(self.dropped)
            && self.recorded
                == self
                    .completed
                    .saturating_add(self.errors)
                    .saturating_add(self.cancelled_outcomes)
            && self.accepted <= self.reserved_candidate_credits
            && self.candidate_dispatches <= self.reserved_candidate_credits
            && self
                .judge_dispatches
                .saturating_add(self.unused_judge_credits)
                == self.reserved_judge_credits
    }

    pub fn validate(&self) -> Result<(), QualityRunError> {
        if self.schema_version != QUALITY_RUN_SCHEMA_VERSION {
            return Err(QualityRunError::UnsupportedSchema(self.schema_version));
        }
        self.provenance.validate()?;
        let planned = self
            .reserved_candidate_credits
            .checked_add(self.reserved_judge_credits)
            .ok_or(QualityRunError::InvalidManifest)?;
        let resolved = self
            .recorded
            .checked_add(self.dropped)
            .ok_or(QualityRunError::InvalidManifest)?;
        let terminal = self
            .completed
            .checked_add(self.errors)
            .and_then(|value| value.checked_add(self.cancelled_outcomes))
            .ok_or(QualityRunError::InvalidManifest)?;
        let judge_accounted = self
            .judge_dispatches
            .checked_add(self.unused_judge_credits)
            .ok_or(QualityRunError::InvalidManifest)?;
        let valid = Uuid::parse_str(&self.run_id).is_ok()
            && opaque_id(&self.binary_version)
            && planned == self.planned_request_upper_bound
            && self.accepted <= self.reserved_candidate_credits
            && self.candidate_dispatches <= self.accepted
            && resolved <= self.accepted
            && terminal <= self.recorded
            && self.next_sequence == self.accepted.saturating_add(1)
            && judge_accounted <= self.reserved_judge_credits
            && self.writer_healthy == self.writer_error.is_none()
            && self.outcomes_digest.is_some() == self.quality_report_digest.is_some();
        if !valid {
            return Err(QualityRunError::InvalidManifest);
        }
        if let (Some(outcomes_digest), Some(report_digest)) =
            (&self.outcomes_digest, &self.quality_report_digest)
        {
            validate_digest(outcomes_digest)?;
            validate_digest(report_digest)?;
            if self.completed_at_ms.is_none() {
                return Err(QualityRunError::InvalidManifest);
            }
        }
        match self.completed_at_ms {
            None if self.clean_shutdown || self.cancelled => {
                return Err(QualityRunError::InvalidManifest)
            }
            Some(completed_at_ms)
                if completed_at_ms < self.started_at_ms
                    || completed_at_ms > self.valid_until_ms
                    || self.last_flush_at_ms.is_none() =>
            {
                return Err(QualityRunError::InvalidManifest)
            }
            _ => {}
        }
        if self.valid_until_ms < self.started_at_ms {
            return Err(QualityRunError::InvalidManifest);
        }
        if self.clean_shutdown && (self.cancelled || !self.writer_healthy || !self.reconciled()) {
            return Err(QualityRunError::InvalidManifest);
        }
        Ok(())
    }
}

pub struct QualityRunStore {
    directory: PathBuf,
    manifest_path: PathBuf,
    max_age_ms: u64,
    _lock: File,
    manifest: Mutex<QualityRunManifest>,
    resolved_sequences: Mutex<BTreeSet<u64>>,
}

impl QualityRunStore {
    pub fn create(
        directory: &Path,
        provenance: QualityProvenance,
        plan: QualityRunPlan,
    ) -> Result<Self, QualityRunError> {
        Self::create_with_run_id(directory, Uuid::new_v4().to_string(), provenance, plan)
    }

    pub fn create_under(
        root: &Path,
        provenance: QualityProvenance,
        plan: QualityRunPlan,
    ) -> Result<Self, QualityRunError> {
        validate_plan(plan)?;
        provenance.validate()?;
        let run_id = Uuid::new_v4().to_string();
        let directory = root.join(&run_id);
        Self::create_with_run_id(&directory, run_id, provenance, plan)
    }

    fn create_with_run_id(
        directory: &Path,
        run_id: String,
        provenance: QualityProvenance,
        plan: QualityRunPlan,
    ) -> Result<Self, QualityRunError> {
        validate_plan(plan)?;
        provenance.validate()?;
        let started_at_ms = now_ms();
        let valid_until_ms = started_at_ms
            .checked_add(plan.max_age_ms)
            .ok_or(QualityRunError::InvalidPlan)?;
        create_private_dir(directory)?;
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(LOCK_FILE))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    QualityRunError::WriterExists
                } else {
                    QualityRunError::Io(error)
                }
            })?;
        let manifest_path = directory.join(MANIFEST_FILE);
        if manifest_path.exists() {
            return Err(QualityRunError::WriterExists);
        }
        let manifest = QualityRunManifest {
            schema_version: QUALITY_RUN_SCHEMA_VERSION,
            binary_version: crate::VERSION.to_owned(),
            run_id,
            started_at_ms,
            completed_at_ms: None,
            valid_until_ms,
            clean_shutdown: false,
            cancelled: false,
            provenance,
            planned_request_upper_bound: plan.planned_request_upper_bound,
            reserved_candidate_credits: plan.reserved_candidate_credits,
            reserved_judge_credits: plan.reserved_judge_credits,
            candidate_dispatches: 0,
            judge_dispatches: 0,
            unused_judge_credits: 0,
            accepted: 0,
            recorded: 0,
            dropped: 0,
            completed: 0,
            errors: 0,
            cancelled_outcomes: 0,
            next_sequence: 1,
            writer_healthy: true,
            writer_error: None,
            last_flush_at_ms: None,
            outcomes_digest: None,
            quality_report_digest: None,
        };
        atomic_write_json(directory, &manifest_path, &manifest)?;
        Ok(Self {
            directory: directory.to_owned(),
            manifest_path,
            max_age_ms: plan.max_age_ms,
            _lock: lock,
            manifest: Mutex::new(manifest),
            resolved_sequences: Mutex::new(BTreeSet::new()),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn snapshot(&self) -> QualityRunManifest {
        self.lock_manifest().clone()
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn open_ledger(&self) -> Result<(QualityLedger, QualityRecovery), QualityRunError> {
        QualityLedger::open(&self.directory)
    }

    pub fn accept(&self) -> Result<u64, QualityRunError> {
        let mut manifest = self.lock_manifest();
        if manifest.accepted >= manifest.reserved_candidate_credits {
            return Err(QualityRunError::CandidateCreditLimit);
        }
        let sequence = manifest.next_sequence;
        manifest.next_sequence = checked_add(manifest.next_sequence, "next_sequence")?;
        manifest.accepted = checked_add(manifest.accepted, "accepted")?;
        Ok(sequence)
    }

    pub fn candidate_dispatched(&self) -> Result<(), QualityRunError> {
        let mut manifest = self.lock_manifest();
        if manifest.candidate_dispatches >= manifest.reserved_candidate_credits {
            return Err(QualityRunError::CandidateCreditLimit);
        }
        manifest.candidate_dispatches =
            checked_add(manifest.candidate_dispatches, "candidate_dispatches")?;
        Ok(())
    }

    pub fn judge_dispatched(&self) -> Result<(), QualityRunError> {
        let mut manifest = self.lock_manifest();
        if manifest.judge_dispatches >= manifest.reserved_judge_credits {
            return Err(QualityRunError::JudgeCreditLimit);
        }
        manifest.judge_dispatches = checked_add(manifest.judge_dispatches, "judge_dispatches")?;
        Ok(())
    }

    pub fn unused_judge_credit(&self) -> Result<(), QualityRunError> {
        let mut manifest = self.lock_manifest();
        if manifest.unused_judge_credits >= manifest.reserved_judge_credits {
            return Err(QualityRunError::JudgeCreditLimit);
        }
        manifest.unused_judge_credits =
            checked_add(manifest.unused_judge_credits, "unused_judge_credits")?;
        Ok(())
    }

    pub fn recorded(
        &self,
        sequence: u64,
        status: QualityAttemptStatus,
    ) -> Result<(), QualityRunError> {
        self.resolve(sequence)?;
        let mut manifest = self.lock_manifest();
        manifest.recorded = checked_add(manifest.recorded, "recorded")?;
        match status {
            QualityAttemptStatus::Completed => {
                manifest.completed = checked_add(manifest.completed, "completed")?;
            }
            QualityAttemptStatus::Cancelled => {
                manifest.cancelled_outcomes =
                    checked_add(manifest.cancelled_outcomes, "cancelled_outcomes")?;
            }
            status if status.is_error() => {
                manifest.errors = checked_add(manifest.errors, "errors")?;
            }
            _ => return Err(QualityRunError::InvalidStatus),
        }
        Ok(())
    }

    pub fn dropped(&self, sequence: u64) -> Result<(), QualityRunError> {
        self.resolve(sequence)?;
        let mut manifest = self.lock_manifest();
        manifest.dropped = checked_add(manifest.dropped, "dropped")?;
        Ok(())
    }

    fn resolve(&self, sequence: u64) -> Result<(), QualityRunError> {
        let manifest = self.lock_manifest();
        if sequence == 0 || sequence >= manifest.next_sequence {
            return Err(QualityRunError::SequenceOutOfRange(sequence));
        }
        drop(manifest);
        if !self.lock_resolved().insert(sequence) {
            return Err(QualityRunError::DuplicateSequence(sequence));
        }
        Ok(())
    }

    pub fn set_writer_error(&self) {
        let mut manifest = self.lock_manifest();
        manifest.writer_healthy = false;
        manifest.writer_error = Some(QualityReasonCode::WriterError);
    }

    pub fn flush(&self) -> Result<(), QualityRunError> {
        let manifest = {
            let mut manifest = self.lock_manifest();
            manifest.last_flush_at_ms = Some(now_ms());
            manifest.clone()
        };
        atomic_write_json(&self.directory, &self.manifest_path, &manifest)
    }

    pub fn finish(&self, cancelled: bool) -> Result<QualityRunManifest, QualityRunError> {
        self.finish_at(cancelled, now_ms())
    }

    fn finish_at(
        &self,
        cancelled: bool,
        completed_at_ms: u64,
    ) -> Result<QualityRunManifest, QualityRunError> {
        let valid_until_ms = completed_at_ms
            .checked_add(self.max_age_ms)
            .ok_or(QualityRunError::InvalidManifest)?;
        let manifest = {
            let mut manifest = self.lock_manifest();
            if completed_at_ms < manifest.started_at_ms {
                return Err(QualityRunError::InvalidManifest);
            }
            manifest.cancelled = cancelled;
            manifest.completed_at_ms = Some(completed_at_ms);
            manifest.valid_until_ms = valid_until_ms;
            manifest.last_flush_at_ms = Some(completed_at_ms);
            manifest.clean_shutdown =
                !cancelled && manifest.writer_healthy && manifest.reconciled();
            manifest.clone()
        };
        manifest.validate()?;
        atomic_write_json(&self.directory, &self.manifest_path, &manifest)?;
        Ok(manifest)
    }

    pub fn load_manifest(path: &Path) -> Result<QualityRunManifest, QualityRunError> {
        let mut source = Vec::new();
        File::open(path)?.read_to_end(&mut source)?;
        let manifest: QualityRunManifest = serde_json::from_slice(&source)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn bind_quality_report(
        directory: &Path,
        outcomes_digest: String,
        quality_report_digest: String,
    ) -> Result<QualityRunManifest, QualityRunError> {
        validate_digest(&outcomes_digest)?;
        validate_digest(&quality_report_digest)?;
        let path = directory.join(MANIFEST_FILE);
        let binding_lock = OpenOptions::new().read(true).write(true).open(&path)?;
        binding_lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => QualityRunError::WriterExists,
            std::fs::TryLockError::Error(error) => QualityRunError::Io(error),
        })?;
        let mut manifest = Self::load_manifest(&path)?;
        if manifest.completed_at_ms.is_none()
            || manifest.outcomes_digest.is_some()
            || manifest.quality_report_digest.is_some()
        {
            return Err(QualityRunError::InvalidManifest);
        }
        manifest.outcomes_digest = Some(outcomes_digest);
        manifest.quality_report_digest = Some(quality_report_digest);
        manifest.validate()?;
        atomic_write_json(directory, &path, &manifest)?;
        Ok(manifest)
    }

    fn lock_manifest(&self) -> std::sync::MutexGuard<'_, QualityRunManifest> {
        self.manifest
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn lock_resolved(&self) -> std::sync::MutexGuard<'_, BTreeSet<u64>> {
        self.resolved_sequences
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityRecovery {
    Absent,
    Clean { records: u64 },
    TornTail { records: u64, discarded_bytes: u64 },
    Corrupt { records: u64, at_offset: u64 },
    Undecodable { records: u64, at_offset: u64 },
}

impl QualityRecovery {
    fn blocks_append(&self) -> bool {
        matches!(self, Self::Corrupt { .. } | Self::Undecodable { .. })
    }
}

pub struct QualityLedger {
    writer: BufWriter<File>,
    _lock: File,
    refusal: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QualityLedgerRead {
    pub outcomes: Vec<QualityOutcome>,
    pub recovery: QualityRecovery,
    pub gaps: Vec<u64>,
}

impl QualityLedger {
    fn open(directory: &Path) -> Result<(Self, QualityRecovery), QualityRunError> {
        let scan = scan(directory, false)?;
        create_private_dir(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join(LEDGER_LOCK_FILE))?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => QualityRunError::WriterExists,
            std::fs::TryLockError::Error(error) => QualityRunError::Io(error),
        })?;
        let path = directory.join(LEDGER_FILE);
        if let Some(length) = scan.truncate_to {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(length)?;
            file.sync_data()?;
        } else if matches!(scan.recovery, QualityRecovery::Absent) {
            write_header(&path)?;
        }
        let file = OpenOptions::new()
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)?;
        Ok((
            Self {
                writer: BufWriter::new(file),
                _lock: lock,
                refusal: scan.recovery.blocks_append(),
            },
            scan.recovery,
        ))
    }

    pub fn append(&mut self, outcome: &QualityOutcome) -> Result<(), QualityRunError> {
        if self.refusal {
            return Err(QualityRunError::AppendRefused);
        }
        outcome.validate()?;
        self.writer.write_all(&encode_frame(outcome)?)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), QualityRunError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    pub fn read_all(directory: &Path, accepted: u64) -> Result<QualityLedgerRead, QualityRunError> {
        let mut scan = scan(directory, true)?;
        let mut seen = HashSet::new();
        for outcome in &scan.outcomes {
            if outcome.sequence == 0 || outcome.sequence > accepted {
                return Err(QualityRunError::SequenceOutOfRange(outcome.sequence));
            }
            if !seen.insert(outcome.sequence) {
                return Err(QualityRunError::DuplicateSequence(outcome.sequence));
            }
        }
        scan.outcomes.sort_by_key(|outcome| outcome.sequence);
        let gaps = (1..=accepted)
            .filter(|sequence| !seen.contains(sequence))
            .collect();
        Ok(QualityLedgerRead {
            outcomes: scan.outcomes,
            recovery: scan.recovery,
            gaps,
        })
    }
}

struct Scan {
    outcomes: Vec<QualityOutcome>,
    recovery: QualityRecovery,
    truncate_to: Option<u64>,
}

fn scan(directory: &Path, decode: bool) -> Result<Scan, QualityRunError> {
    let path = directory.join(LEDGER_FILE);
    if !path.exists() {
        return Ok(Scan {
            outcomes: Vec::new(),
            recovery: QualityRecovery::Absent,
            truncate_to: None,
        });
    }
    let bytes = fs::read(&path)?;
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Ok(Scan {
            outcomes: Vec::new(),
            recovery: QualityRecovery::Corrupt {
                records: 0,
                at_offset: 0,
            },
            truncate_to: None,
        });
    }
    let mut offset = MAGIC.len();
    let mut outcomes = Vec::new();
    let mut records = 0u64;
    while offset < bytes.len() {
        let frame_start = offset;
        if bytes.len() - offset < FRAME_HEADER_LEN {
            return Ok(Scan {
                outcomes,
                recovery: QualityRecovery::TornTail {
                    records,
                    discarded_bytes: (bytes.len() - frame_start) as u64,
                },
                truncate_to: Some(frame_start as u64),
            });
        }
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        offset += FRAME_HEADER_LEN;
        if bytes.len() - offset < length {
            return Ok(Scan {
                outcomes,
                recovery: QualityRecovery::TornTail {
                    records,
                    discarded_bytes: (bytes.len() - frame_start) as u64,
                },
                truncate_to: Some(frame_start as u64),
            });
        }
        let payload = &bytes[offset..offset + length];
        if crc32fast::hash(payload) != expected_crc {
            return Ok(Scan {
                outcomes,
                recovery: QualityRecovery::Corrupt {
                    records,
                    at_offset: frame_start as u64,
                },
                truncate_to: None,
            });
        }
        if decode {
            match serde_json::from_slice::<QualityOutcome>(payload)
                .ok()
                .filter(|outcome| outcome.validate().is_ok())
            {
                Some(outcome) => outcomes.push(outcome),
                None => {
                    return Ok(Scan {
                        outcomes,
                        recovery: QualityRecovery::Undecodable {
                            records,
                            at_offset: frame_start as u64,
                        },
                        truncate_to: None,
                    })
                }
            }
        } else if serde_json::from_slice::<QualityOutcome>(payload)
            .ok()
            .is_none_or(|outcome| outcome.validate().is_err())
        {
            return Ok(Scan {
                outcomes,
                recovery: QualityRecovery::Undecodable {
                    records,
                    at_offset: frame_start as u64,
                },
                truncate_to: None,
            });
        }
        records += 1;
        offset += length;
    }
    Ok(Scan {
        outcomes,
        recovery: QualityRecovery::Clean { records },
        truncate_to: None,
    })
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, QualityRunError> {
    let payload = serde_json::to_vec(value)?;
    let length = u32::try_from(payload.len()).map_err(|_| QualityRunError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn write_header(path: &Path) -> Result<(), QualityRunError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(MAGIC)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), QualityRunError> {
    if !path.exists() {
        DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn atomic_write_json<T: Serialize>(
    directory: &Path,
    path: &Path,
    value: &T,
) -> Result<(), QualityRunError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let temporary = directory.join(format!(".manifest-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn checked_add(value: u64, field: &'static str) -> Result<u64, QualityRunError> {
    value
        .checked_add(1)
        .ok_or(QualityRunError::CounterOverflow(field))
}

fn validate_plan(plan: QualityRunPlan) -> Result<(), QualityRunError> {
    if plan
        .reserved_candidate_credits
        .checked_add(plan.reserved_judge_credits)
        != Some(plan.planned_request_upper_bound)
    {
        return Err(QualityRunError::InvalidPlan);
    }
    Ok(())
}

fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_digest(value: &str) -> Result<(), QualityRunError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(QualityRunError::InvalidDigest);
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(QualityRunError::InvalidDigest);
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Error)]
pub enum QualityRunError {
    #[error("quality writer already exists")]
    WriterExists,
    #[error("invalid quality run plan")]
    InvalidPlan,
    #[error("invalid quality run manifest")]
    InvalidManifest,
    #[error("candidate credit limit reached")]
    CandidateCreditLimit,
    #[error("judge credit limit reached")]
    JudgeCreditLimit,
    #[error("sequence out of range: {0}")]
    SequenceOutOfRange(u64),
    #[error("duplicate sequence: {0}")]
    DuplicateSequence(u64),
    #[error("invalid outcome status")]
    InvalidStatus,
    #[error("invalid content-free quality outcome")]
    InvalidOutcome,
    #[error("invalid quality evidence digest")]
    InvalidDigest,
    #[error("counter overflow: {0}")]
    CounterOverflow(&'static str),
    #[error("quality ledger refuses append after corruption or schema drift")]
    AppendRefused,
    #[error("quality frame too large")]
    FrameTooLarge,
    #[error("unsupported quality manifest schema: {0}")]
    UnsupportedSchema(u32),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::{EvaluatorKind, EvaluatorStatus};
    use proptest::prelude::*;
    use std::io::{Seek, SeekFrom};

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn provenance() -> QualityProvenance {
        QualityProvenance {
            dataset_manifest_digest: digest('a'),
            cases_digest: digest('b'),
            dataset_digest: digest('c'),
            evaluator_digest: digest('d'),
            candidate_config_digest: digest('e'),
            policy_digest: digest('f'),
            registry_digest: digest('1'),
            owned_cost_digest: Some(digest('2')),
            judge_model_digest: None,
            judge_rubric_digest: None,
            judge_template_digest: None,
            judge_config_digest: None,
            judge_endpoint_digest: None,
            judge_authorization_reference_digest: None,
        }
    }

    fn plan(candidate: u64) -> QualityRunPlan {
        QualityRunPlan {
            planned_request_upper_bound: candidate,
            reserved_candidate_credits: candidate,
            reserved_judge_credits: 0,
            max_age_ms: 60_000,
        }
    }

    pub(crate) fn outcome(sequence: u64, status: QualityAttemptStatus) -> QualityOutcome {
        QualityOutcome {
            sequence,
            case_id: format!("case-{sequence}"),
            candidate_supply_id: "owned/candidate".into(),
            candidate_model: "candidate".into(),
            protocol: QualityProtocol::Responses,
            task_class: TaskClass::Mechanical,
            dispatched: true,
            status,
            reason: None,
            candidate_error: None,
            latency_ms: Some(10),
            input_tokens: Some(10),
            output_tokens: Some(5),
            candidate_cost_usd: Some(0.01),
            evaluator_outcomes: vec![QualityEvaluatorEvidence {
                evaluator_id: "answer".into(),
                kind: EvaluatorKind::ExactMatch,
                status: EvaluatorStatus::Pass,
                error_code: None,
                required: true,
                subjective: false,
                latency_ms: None,
            }],
            cost_evaluators: Vec::new(),
            judge: None,
            dataset_digest: digest('3'),
            evaluator_digest: digest('4'),
        }
    }

    #[test]
    fn completion_expiry_is_checked_and_completion_relative() {
        let temp = tempfile::tempdir().unwrap();
        let store = QualityRunStore::create(
            &temp.path().join("complete"),
            provenance(),
            QualityRunPlan {
                planned_request_upper_bound: 0,
                reserved_candidate_credits: 0,
                reserved_judge_credits: 0,
                max_age_ms: 1,
            },
        )
        .unwrap();
        let completed_at_ms = store.snapshot().started_at_ms + 2;
        let manifest = store.finish_at(false, completed_at_ms).unwrap();
        assert_eq!(manifest.completed_at_ms, Some(completed_at_ms));
        assert_eq!(manifest.valid_until_ms, completed_at_ms + 1);

        let overflow = QualityRunStore::create(
            &temp.path().join("overflow"),
            provenance(),
            QualityRunPlan {
                planned_request_upper_bound: 0,
                reserved_candidate_credits: 0,
                reserved_judge_credits: 0,
                max_age_ms: 1,
            },
        )
        .unwrap();
        assert!(matches!(
            overflow.finish_at(false, u64::MAX),
            Err(QualityRunError::InvalidManifest)
        ));
        assert_eq!(overflow.snapshot().completed_at_ms, None);

        let regressed = QualityRunStore::create(
            &temp.path().join("regressed"),
            provenance(),
            QualityRunPlan {
                planned_request_upper_bound: 0,
                reserved_candidate_credits: 0,
                reserved_judge_credits: 0,
                max_age_ms: 1,
            },
        )
        .unwrap();
        let before_start = regressed.snapshot().started_at_ms - 1;
        assert!(matches!(
            regressed.finish_at(false, before_start),
            Err(QualityRunError::InvalidManifest)
        ));
        assert_eq!(regressed.snapshot().completed_at_ms, None);
    }

    #[test]
    fn private_framed_store_recovery_and_sequence_contract() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("quality-runs/run");
        let store = QualityRunStore::create(&run, provenance(), plan(3)).unwrap();
        assert!(matches!(
            QualityRunStore::create(&run, provenance(), plan(3)),
            Err(QualityRunError::WriterExists)
        ));
        assert_eq!(
            fs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(store.manifest_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            [
                store.accept().unwrap(),
                store.accept().unwrap(),
                store.accept().unwrap()
            ],
            [1, 2, 3]
        );

        let (mut ledger, recovery) = QualityLedger::open(&run).unwrap();
        assert_eq!(recovery, QualityRecovery::Absent);
        ledger
            .append(&outcome(3, QualityAttemptStatus::Completed))
            .unwrap();
        ledger
            .append(&outcome(1, QualityAttemptStatus::Completed))
            .unwrap();
        ledger.flush().unwrap();
        assert_eq!(
            fs::metadata(run.join(LEDGER_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        store.recorded(3, QualityAttemptStatus::Completed).unwrap();
        store.recorded(1, QualityAttemptStatus::Completed).unwrap();
        store.dropped(2).unwrap();
        assert!(store.finish(false).unwrap().clean_shutdown);
        let read = QualityLedger::read_all(&run, 3).unwrap();
        assert_eq!(
            read.outcomes
                .iter()
                .map(|item| item.sequence)
                .collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(read.gaps, [2]);

        let duplicate_dir = temp.path().join("duplicate");
        let (mut duplicate, _) = QualityLedger::open(&duplicate_dir).unwrap();
        duplicate
            .append(&outcome(1, QualityAttemptStatus::Completed))
            .unwrap();
        duplicate
            .append(&outcome(1, QualityAttemptStatus::Completed))
            .unwrap();
        duplicate.flush().unwrap();
        assert!(matches!(
            QualityLedger::read_all(&duplicate_dir, 2),
            Err(QualityRunError::DuplicateSequence(1))
        ));
        assert!(matches!(
            QualityLedger::read_all(&run, 2),
            Err(QualityRunError::SequenceOutOfRange(3))
        ));

        let torn_dir = temp.path().join("torn");
        let (mut torn, _) = QualityLedger::open(&torn_dir).unwrap();
        torn.append(&outcome(1, QualityAttemptStatus::Completed))
            .unwrap();
        torn.flush().unwrap();
        drop(torn);
        OpenOptions::new()
            .append(true)
            .open(torn_dir.join(LEDGER_FILE))
            .unwrap()
            .write_all(&[1, 2, 3])
            .unwrap();
        let (_, torn_recovery) = QualityLedger::open(&torn_dir).unwrap();
        assert!(matches!(
            torn_recovery,
            QualityRecovery::TornTail { records: 1, .. }
        ));

        let corrupt_dir = temp.path().join("corrupt");
        let (mut corrupt, _) = QualityLedger::open(&corrupt_dir).unwrap();
        corrupt
            .append(&outcome(1, QualityAttemptStatus::Completed))
            .unwrap();
        corrupt.flush().unwrap();
        drop(corrupt);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(corrupt_dir.join(LEDGER_FILE))
            .unwrap();
        file.seek(SeekFrom::Start((MAGIC.len() + FRAME_HEADER_LEN) as u64))
            .unwrap();
        file.write_all(b"!").unwrap();
        file.sync_all().unwrap();
        let (mut refused, recovery) = QualityLedger::open(&corrupt_dir).unwrap();
        assert!(matches!(
            recovery,
            QualityRecovery::Corrupt { records: 0, .. }
        ));
        assert!(matches!(
            refused.append(&outcome(2, QualityAttemptStatus::Completed)),
            Err(QualityRunError::AppendRefused)
        ));

        let undecodable_dir = temp.path().join("undecodable");
        create_private_dir(&undecodable_dir).unwrap();
        write_header(&undecodable_dir.join(LEDGER_FILE)).unwrap();
        OpenOptions::new()
            .append(true)
            .open(undecodable_dir.join(LEDGER_FILE))
            .unwrap()
            .write_all(&encode_frame(&serde_json::json!({"not":"outcome"})).unwrap())
            .unwrap();
        let (_, recovery) = QualityLedger::open(&undecodable_dir).unwrap();
        assert!(matches!(
            recovery,
            QualityRecovery::Undecodable { records: 0, .. }
        ));
    }

    #[test]
    fn manifest_reconciliation_and_provenance_contract() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("run");
        let store = QualityRunStore::create(
            &run,
            provenance(),
            QualityRunPlan {
                planned_request_upper_bound: 4,
                reserved_candidate_credits: 2,
                reserved_judge_credits: 2,
                max_age_ms: 99,
            },
        )
        .unwrap();
        let one = store.accept().unwrap();
        let two = store.accept().unwrap();
        store.candidate_dispatched().unwrap();
        store.candidate_dispatched().unwrap();
        store.judge_dispatched().unwrap();
        store.unused_judge_credit().unwrap();
        store
            .recorded(one, QualityAttemptStatus::Completed)
            .unwrap();
        store.dropped(two).unwrap();
        let manifest = store.finish(false).unwrap();
        assert!(manifest.clean_shutdown && manifest.reconciled());
        assert_eq!(
            (
                manifest.accepted,
                manifest.recorded,
                manifest.dropped,
                manifest.completed
            ),
            (2, 1, 1, 1)
        );
        let loaded = QualityRunStore::load_manifest(store.manifest_path()).unwrap();
        assert_eq!(loaded, manifest);
        let bound = QualityRunStore::bind_quality_report(&run, digest('7'), digest('8')).unwrap();
        assert_eq!(bound.outcomes_digest.as_deref(), Some(digest('7').as_str()));
        assert_eq!(
            bound.quality_report_digest.as_deref(),
            Some(digest('8').as_str())
        );
        assert!(matches!(
            QualityRunStore::bind_quality_report(&run, digest('7'), digest('8')),
            Err(QualityRunError::InvalidManifest)
        ));
        let mut one_binding: serde_json::Value =
            serde_json::from_slice(&fs::read(store.manifest_path()).unwrap()).unwrap();
        one_binding["quality_report_digest"] = serde_json::Value::Null;
        fs::write(
            store.manifest_path(),
            serde_json::to_vec(&one_binding).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            QualityRunStore::load_manifest(store.manifest_path()),
            Err(QualityRunError::InvalidManifest)
        ));

        let cancelled = temp.path().join("cancelled");
        let store = QualityRunStore::create(&cancelled, provenance(), plan(1)).unwrap();
        let sequence = store.accept().unwrap();
        store
            .recorded(sequence, QualityAttemptStatus::Cancelled)
            .unwrap();
        let manifest = store.finish(true).unwrap();
        assert!(manifest.cancelled && !manifest.clean_shutdown && manifest.reconciled());

        let incomplete = temp.path().join("incomplete");
        let store = QualityRunStore::create(&incomplete, provenance(), plan(1)).unwrap();
        store.accept().unwrap();
        assert!(!store.finish(false).unwrap().clean_shutdown);
        let unhealthy = temp.path().join("unhealthy");
        let store = QualityRunStore::create(&unhealthy, provenance(), plan(0)).unwrap();
        store.set_writer_error();
        assert!(!store.finish(false).unwrap().clean_shutdown);

        let baseline = provenance();
        let baseline_digest = baseline.digest().unwrap();
        type ProvenanceMutation = Box<dyn Fn(&mut QualityProvenance)>;
        let mutations: Vec<ProvenanceMutation> = vec![
            Box::new(|v| v.dataset_manifest_digest.push('x')),
            Box::new(|v| v.cases_digest.push('x')),
            Box::new(|v| v.dataset_digest.push('x')),
            Box::new(|v| v.evaluator_digest.push('x')),
            Box::new(|v| v.candidate_config_digest.push('x')),
            Box::new(|v| v.policy_digest.push('x')),
            Box::new(|v| v.registry_digest.push('x')),
            Box::new(|v| v.owned_cost_digest = Some("changed".into())),
            Box::new(|v| v.judge_model_digest = Some("changed".into())),
            Box::new(|v| v.judge_rubric_digest = Some("changed".into())),
            Box::new(|v| v.judge_template_digest = Some("changed".into())),
            Box::new(|v| v.judge_config_digest = Some("changed".into())),
            Box::new(|v| v.judge_endpoint_digest = Some("changed".into())),
            Box::new(|v| v.judge_authorization_reference_digest = Some("changed".into())),
        ];
        for mutate in mutations {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(changed.digest().unwrap_or_default(), baseline_digest);
        }

        let mut partial = provenance();
        partial.judge_model_digest = Some(digest('9'));
        assert!(partial.digest().is_err());
        assert!(matches!(
            QualityRunStore::create(&temp.path().join("partial-judge"), partial, plan(0)),
            Err(QualityRunError::InvalidManifest | QualityRunError::InvalidDigest)
        ));

        let partial_load = temp.path().join("partial-load");
        let mut complete_judge = provenance();
        complete_judge.judge_model_digest = Some(digest('3'));
        complete_judge.judge_rubric_digest = Some(digest('4'));
        complete_judge.judge_template_digest = Some(digest('5'));
        complete_judge.judge_config_digest = Some(digest('6'));
        complete_judge.judge_endpoint_digest = Some(digest('7'));
        complete_judge.judge_authorization_reference_digest = Some(digest('8'));
        let complete = QualityRunStore::create(&partial_load, complete_judge, plan(0)).unwrap();
        complete.finish(false).unwrap();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(complete.manifest_path()).unwrap()).unwrap();
        manifest["provenance"]["judge_endpoint_digest"] = serde_json::Value::Null;
        fs::write(
            complete.manifest_path(),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            QualityRunStore::load_manifest(complete.manifest_path()),
            Err(QualityRunError::InvalidManifest)
        ));
    }

    #[test]
    fn quality_evidence_is_content_free_and_traffic_independent() {
        let encoded = serde_json::to_value(outcome(1, QualityAttemptStatus::Completed)).unwrap();
        let object = encoded.as_object().unwrap();
        for forbidden in [
            "request",
            "response",
            "expected",
            "regex",
            "schema",
            "arguments",
            "rubric",
            "prompt",
            "endpoint",
            "authorization",
            "prose",
            "decision",
            "placement",
        ] {
            assert!(!object.contains_key(forbidden), "leaked {forbidden}");
        }
        assert!(serde_json::from_value::<crate::ledger::DecisionRecord>(encoded.clone()).is_err());
        let serialized = serde_json::to_string(&encoded).unwrap();
        assert!(!serialized.contains("customer secret"));
    }

    #[test]
    fn outcome_status_and_judge_evidence_are_semantically_strict() {
        let mut undispatched = outcome(1, QualityAttemptStatus::Completed);
        undispatched.dispatched = false;
        assert!(matches!(
            undispatched.validate(),
            Err(QualityRunError::InvalidOutcome)
        ));

        let mut candidate_error = outcome(1, QualityAttemptStatus::CandidateError);
        candidate_error.dispatched = false;
        candidate_error.candidate_error = Some(CandidateErrorKind::Timeout);
        candidate_error.reason = Some(QualityReasonCode::Timeout);
        assert!(matches!(
            candidate_error.validate(),
            Err(QualityRunError::InvalidOutcome)
        ));

        let mut judge = outcome(1, QualityAttemptStatus::Completed);
        judge.judge = Some(JudgeOutcomeEvidence {
            required: true,
            subjective: true,
            status: EvaluatorStatus::Pass,
            score: None,
            threshold: 0.5,
            error_code: None,
            input_tokens: Some(2),
            output_tokens: Some(1),
            cost_usd: Some(0.01),
        });
        assert!(matches!(
            judge.validate(),
            Err(QualityRunError::InvalidOutcome)
        ));
        for (status, score, valid) in [
            (EvaluatorStatus::Pass, Some(0.5), true),
            (EvaluatorStatus::Pass, Some(0.49), false),
            (EvaluatorStatus::Fail, Some(0.49), true),
            (EvaluatorStatus::Fail, Some(0.5), false),
            (EvaluatorStatus::Error, None, true),
            (EvaluatorStatus::Error, Some(0.1), false),
        ] {
            let mut judged = outcome(1, QualityAttemptStatus::Completed);
            judged.judge = Some(JudgeOutcomeEvidence {
                required: true,
                subjective: true,
                status,
                score,
                threshold: 0.5,
                error_code: (status == EvaluatorStatus::Error)
                    .then_some(JudgeErrorCode::InvalidResponse),
                input_tokens: Some(2),
                output_tokens: Some(1),
                cost_usd: Some(0.01),
            });
            assert_eq!(
                judged.validate().is_ok(),
                valid,
                "judge {status:?}/{score:?}"
            );
        }
    }

    #[test]
    fn persisted_semantic_invalidity_is_rejected_on_read() {
        let temp = tempfile::tempdir().unwrap();
        let store = QualityRunStore::create(temp.path(), provenance(), plan(1)).unwrap();
        store.flush().unwrap();
        let baseline = serde_json::to_value(store.snapshot()).unwrap();
        assert!(QualityRunStore::load_manifest(store.manifest_path()).is_ok());
        type ManifestMutation = Box<dyn Fn(&mut serde_json::Value)>;
        let invalid_manifests: Vec<(&str, ManifestMutation)> = vec![
            (
                "run-id",
                Box::new(|value| value["run_id"] = serde_json::json!("not-a-uuid")),
            ),
            (
                "digest",
                Box::new(|value| value["provenance"]["policy_digest"] = serde_json::json!("bad")),
            ),
            (
                "plan",
                Box::new(|value| value["planned_request_upper_bound"] = serde_json::json!(2)),
            ),
            (
                "sequence",
                Box::new(|value| value["next_sequence"] = serde_json::json!(9)),
            ),
            (
                "active-clean",
                Box::new(|value| value["clean_shutdown"] = serde_json::json!(true)),
            ),
            (
                "writer",
                Box::new(|value| value["writer_healthy"] = serde_json::json!(false)),
            ),
        ];
        for (name, mutate) in invalid_manifests {
            let mut manifest = baseline.clone();
            mutate(&mut manifest);
            fs::write(
                store.manifest_path(),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            assert!(
                QualityRunStore::load_manifest(store.manifest_path()).is_err(),
                "accepted invalid manifest {name}"
            );
        }

        let ledger_dir = temp.path().join("ledger");
        create_private_dir(&ledger_dir).unwrap();
        write_header(&ledger_dir.join(LEDGER_FILE)).unwrap();
        let mut invalid_outcomes = Vec::new();
        let mut status = outcome(1, QualityAttemptStatus::Completed);
        status.dispatched = false;
        invalid_outcomes.push(("status", status));
        let mut digest = outcome(1, QualityAttemptStatus::Completed);
        digest.dataset_digest = "bad".into();
        invalid_outcomes.push(("digest", digest));
        let mut id = outcome(1, QualityAttemptStatus::Completed);
        id.case_id = "contains whitespace".into();
        invalid_outcomes.push(("id", id));
        let mut finite = outcome(1, QualityAttemptStatus::Completed);
        finite.candidate_cost_usd = Some(-0.01);
        invalid_outcomes.push(("finite", finite));
        for (index, (name, invalid)) in invalid_outcomes.into_iter().enumerate() {
            let directory = ledger_dir.join(index.to_string());
            create_private_dir(&directory).unwrap();
            write_header(&directory.join(LEDGER_FILE)).unwrap();
            OpenOptions::new()
                .append(true)
                .open(directory.join(LEDGER_FILE))
                .unwrap()
                .write_all(&encode_frame(&invalid).unwrap())
                .unwrap();
            let read = QualityLedger::read_all(&directory, 1).unwrap();
            assert!(
                matches!(
                    read.recovery,
                    QualityRecovery::Undecodable { records: 0, .. }
                ),
                "accepted invalid outcome {name}"
            );
            assert!(read.outcomes.is_empty());
        }
    }

    #[test]
    fn second_quality_ledger_writer_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let (first, _) = QualityLedger::open(temp.path()).unwrap();
        assert!(matches!(
            QualityLedger::open(temp.path()),
            Err(QualityRunError::WriterExists)
        ));
        drop(first);
        assert!(QualityLedger::open(temp.path()).is_ok());
    }

    #[test]
    fn reservation_overflow_is_invalid_before_creation() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("overflow");
        assert!(matches!(
            QualityRunStore::create(
                &run,
                provenance(),
                QualityRunPlan {
                    planned_request_upper_bound: u64::MAX,
                    reserved_candidate_credits: u64::MAX,
                    reserved_judge_credits: 1,
                    max_age_ms: 60_000,
                },
            ),
            Err(QualityRunError::InvalidPlan)
        ));
        assert!(!run.exists(), "overflowing plan created run state");
    }

    proptest! {
        #[test]
        fn framed_outcomes_roundtrip_in_completion_order_then_sort(order in prop::collection::vec(1u64..32, 1..32)) {
            let mut unique = Vec::new();
            for sequence in order { if !unique.contains(&sequence) { unique.push(sequence); } }
            let max = *unique.iter().max().unwrap();
            let temp = tempfile::tempdir().unwrap();
            let (mut ledger, _) = QualityLedger::open(temp.path()).unwrap();
            for sequence in &unique { ledger.append(&outcome(*sequence, QualityAttemptStatus::Completed)).unwrap(); }
            ledger.flush().unwrap();
            let read = QualityLedger::read_all(temp.path(), max).unwrap();
            prop_assert!(read.outcomes.windows(2).all(|pair| pair[0].sequence < pair[1].sequence));
        }
    }
}
