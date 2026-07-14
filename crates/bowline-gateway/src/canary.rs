use std::{
    collections::{HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    time::{Duration, Instant},
};

use bowline_core::{
    quality::{
        evaluate_case, normalize_candidate_response, EvaluatorKind, EvaluatorStatus,
        LoadedQualityDataset, QualityProtocol, QualityRequest,
    },
    quality_run::{
        CandidateErrorKind, CostEvaluatorEvidence, CostEvaluatorStatus, QualityAttemptStatus,
        QualityEvaluatorErrorCode, QualityEvaluatorEvidence, QualityOutcome, QualityReasonCode,
        QualityRunManifest,
    },
    supply::{Price, Registry},
};
use futures_util::StreamExt;
use reqwest::{header::HeaderValue, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Semaphore;
use url::Url;

use crate::{
    judge::{
        execute_judge, prepare_judge, scheduler_error as judge_scheduler_error,
        timeout as judge_timeout, validate_judge_config, JudgeConfig, PreparedJudge,
    },
    provenance_digest::{digest, CANDIDATE_CONFIG_DOMAIN},
    quality_writer::{ManagedQualityWriter, ManagedQualityWriterError},
};

pub const MAX_CANDIDATES: usize = 64;
pub const MAX_CANARY_BYTES: usize = 1024 * 1024;
pub const MAX_CONCURRENCY: usize = 64;
pub const MAX_REQUESTS: u64 = 10_000;
pub const MAX_WALL_TIME_MS: u64 = 3_600_000;
pub const MAX_TIMEOUT_MS: u64 = 300_000;
pub const MAX_SHUTDOWN_GRACE_MS: u64 = 60_000;
pub const MAX_OBSERVED_TOKENS: u64 = 1_000_000_000;
pub const MAX_OBSERVED_COST_USD: f64 = 1_000_000.0;
pub const MAX_PROMOTION_AGE_MS: u64 = 31_536_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    pub version: u32,
    pub candidates: Vec<CandidateConfig>,
    pub runner: RunnerConfig,
    pub promotion: PromotionConfig,
    #[serde(default)]
    pub judge: Option<JudgeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateConfig {
    pub supply_id: String,
    pub base_url: String,
    pub authorization_env: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    #[serde(default)]
    pub send_customer_content: bool,
    pub concurrency: usize,
    pub per_candidate_concurrency: usize,
    pub max_requests: u64,
    pub max_wall_time_ms: u64,
    pub request_timeout_ms: u64,
    pub shutdown_grace_ms: u64,
    pub max_response_bytes: usize,
    pub max_observed_tokens: u64,
    pub max_observed_cost_usd: f64,
    pub writer_queue_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionConfig {
    pub min_samples: u64,
    pub min_pass_rate: f64,
    pub min_wilson_lower_95: f64,
    pub max_error_rate: f64,
    pub max_p95_latency_ms: u64,
    pub max_age_ms: u64,
}

#[derive(Clone)]
pub struct PreparedCanary {
    pub config: CanaryConfig,
    candidates: Vec<PreparedCandidate>,
    pub candidate_config_digest: String,
    pub(crate) judge: Option<PreparedJudge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeProvenanceDigests {
    pub model_digest: String,
    pub rubric_digest: String,
    pub template_digest: String,
    pub config_digest: String,
    pub endpoint_digest: String,
    pub authorization_reference_digest: String,
}

#[derive(Clone)]
struct PreparedCandidate {
    supply_id: String,
    model: String,
    endpoint: String,
    authorization: HeaderValue,
    price: Option<Price>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRunSummary {
    pub schema_version: u32,
    pub run_id: String,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub completed: u64,
    pub errors: u64,
    pub cancelled_outcomes: u64,
    pub candidate_dispatches: u64,
    pub judge_dispatches: u64,
    pub unused_judge_credits: u64,
    pub clean_shutdown: bool,
    pub cancelled: bool,
    pub writer_healthy: bool,
    pub observed_tokens: u64,
    pub observed_cost_usd: f64,
    pub candidate_observed_tokens: u64,
    pub judge_observed_tokens: u64,
    pub candidate_observed_cost_usd: f64,
    pub judge_observed_cost_usd: f64,
}

#[derive(Debug, Error)]
pub enum CanaryError {
    #[error("invalid canary configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid candidate configuration for {0}")]
    Candidate(String),
    #[error("candidate authorization is unavailable for {0}")]
    Authorization(String),
    #[error("candidate execution failed")]
    Execution,
    #[error(transparent)]
    Writer(#[from] ManagedQualityWriterError),
}

pub fn parse_canary_config(bytes: &[u8]) -> Result<CanaryConfig, CanaryError> {
    if bytes.len() > MAX_CANARY_BYTES {
        return Err(CanaryError::Invalid("canary file exceeds byte limit"));
    }
    let mut config: CanaryConfig =
        serde_yaml::from_slice(bytes).map_err(|_| CanaryError::Invalid("invalid YAML"))?;
    validate_config(&config)?;
    config
        .candidates
        .sort_by(|left, right| left.supply_id.cmp(&right.supply_id));
    Ok(config)
}

pub fn prepare_canary<F>(
    config: CanaryConfig,
    registry: &Registry,
    resolve_env: F,
) -> Result<PreparedCanary, CanaryError>
where
    F: FnMut(&str) -> Option<String>,
{
    prepare_canary_with_rubric(config, registry, None, resolve_env)
}

pub fn prepare_canary_with_rubric<F>(
    mut config: CanaryConfig,
    registry: &Registry,
    rubric: Option<&[u8]>,
    mut resolve_env: F,
) -> Result<PreparedCanary, CanaryError>
where
    F: FnMut(&str) -> Option<String>,
{
    validate_config(&config)?;
    config
        .candidates
        .sort_by(|left, right| left.supply_id.cmp(&right.supply_id));
    let mut candidates = Vec::with_capacity(config.candidates.len());
    for candidate in &config.candidates {
        validate_id(&candidate.supply_id)
            .map_err(|_| CanaryError::Candidate(candidate.supply_id.clone()))?;
        validate_env_name(&candidate.authorization_env)
            .map_err(|_| CanaryError::Candidate(candidate.supply_id.clone()))?;
        let entry = registry
            .by_id(&candidate.supply_id)
            .ok_or_else(|| CanaryError::Candidate(candidate.supply_id.clone()))?;
        validate_base_url(&candidate.base_url, config.runner.send_customer_content)
            .map_err(|_| CanaryError::Candidate(candidate.supply_id.clone()))?;
        let authorization = resolve_env(&candidate.authorization_env)
            .ok_or_else(|| CanaryError::Authorization(candidate.authorization_env.clone()))?;
        if authorization.is_empty()
            || authorization.len() > 8192
            || authorization.contains(['\r', '\n'])
        {
            return Err(CanaryError::Authorization(
                candidate.authorization_env.clone(),
            ));
        }
        let authorization = HeaderValue::from_str(&authorization)
            .map_err(|_| CanaryError::Authorization(candidate.authorization_env.clone()))?;
        let endpoint = candidate.base_url.trim_end_matches('/').to_owned();
        candidates.push(PreparedCandidate {
            supply_id: candidate.supply_id.clone(),
            model: entry.model.clone(),
            endpoint,
            authorization,
            price: entry.price,
        });
    }
    let judge = match config.judge.clone() {
        Some(judge) => Some(
            prepare_judge(
                judge,
                registry,
                rubric.ok_or(CanaryError::Invalid("judge rubric unavailable"))?,
                &mut resolve_env,
            )
            .map_err(|_| CanaryError::Invalid("judge configuration"))?,
        ),
        None => None,
    };
    let mut candidate_config = config.clone();
    candidate_config.judge = None;
    let normalized =
        serde_json::to_vec(&candidate_config).map_err(|_| CanaryError::Invalid("config"))?;
    let candidate_config_digest = digest(CANDIDATE_CONFIG_DOMAIN, &[&normalized]);
    Ok(PreparedCanary {
        config,
        candidates,
        candidate_config_digest,
        judge,
    })
}

impl PreparedCanary {
    pub fn judge_provenance(&self) -> Option<JudgeProvenanceDigests> {
        self.judge.as_ref().map(|judge| JudgeProvenanceDigests {
            model_digest: judge.model_digest.clone(),
            rubric_digest: judge.rubric_digest.clone(),
            template_digest: judge.template_digest.clone(),
            config_digest: judge.config_digest.clone(),
            endpoint_digest: judge.endpoint_digest.clone(),
            authorization_reference_digest: judge.authorization_reference_digest.clone(),
        })
    }

    pub fn candidate_request_count(&self, case_count: usize) -> Result<u64, CanaryError> {
        let candidates = u64::try_from(self.candidates.len())
            .map_err(|_| CanaryError::Invalid("candidate count"))?;
        let cases = u64::try_from(case_count).map_err(|_| CanaryError::Invalid("case count"))?;
        candidates
            .checked_mul(cases)
            .ok_or(CanaryError::Invalid("request count overflow"))
    }

    pub fn judge_request_count(&self, case_count: usize) -> Result<u64, CanaryError> {
        Ok(if self.judge.is_some() {
            self.candidate_request_count(case_count)?
        } else {
            0
        })
    }
}

pub fn planned_candidate_requests(
    prepared: &PreparedCanary,
    case_count: usize,
) -> Result<u64, CanaryError> {
    let count = prepared
        .candidate_request_count(case_count)?
        .checked_add(prepared.judge_request_count(case_count)?)
        .ok_or(CanaryError::Invalid("request count overflow"))?;
    if count == 0 || count > prepared.config.runner.max_requests {
        return Err(CanaryError::Invalid("planned requests exceed max_requests"));
    }
    Ok(count)
}

pub async fn run_canary(
    prepared: PreparedCanary,
    dataset: Arc<LoadedQualityDataset>,
    writer: ManagedQualityWriter,
) -> Result<(CanaryRunSummary, bool), CanaryError> {
    let planned = planned_candidate_requests(&prepared, dataset.cases.len())?;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(
            prepared.config.runner.request_timeout_ms,
        ))
        .build()
        .map_err(|_| CanaryError::Execution)?;
    let started = Instant::now();
    let wall = Duration::from_millis(prepared.config.runner.max_wall_time_ms);
    let mut candidate_observed_tokens = 0u64;
    let mut judge_observed_tokens = 0u64;
    let mut candidate_observed_cost = 0.0f64;
    let mut judge_observed_cost = 0.0f64;
    let mut cancelled = false;
    let mut writer_failed = false;
    let mut jobs = VecDeque::new();
    let mut sequences = vec![vec![0u64; dataset.cases.len()]; prepared.candidates.len()];
    for (candidate_index, candidate_sequences) in sequences.iter_mut().enumerate() {
        for (case_index, allocated_sequence) in candidate_sequences.iter_mut().enumerate() {
            let sequence = writer.accept()?;
            let expected = (candidate_index as u64)
                .checked_mul(dataset.cases.len() as u64)
                .and_then(|value| value.checked_add(case_index as u64))
                .and_then(|value| value.checked_add(1))
                .ok_or(CanaryError::Invalid("sequence overflow"))?;
            if sequence != expected || sequence > planned {
                return Err(CanaryError::Invalid("sequence allocation drift"));
            }
            *allocated_sequence = sequence;
        }
    }
    for case_index in 0..dataset.cases.len() {
        for (candidate_index, candidate_sequences) in sequences.iter().enumerate() {
            let sequence = candidate_sequences[case_index];
            jobs.push_back((sequence, candidate_index, case_index));
        }
    }
    let global = Arc::new(Semaphore::new(prepared.config.runner.concurrency));
    let per_candidate: Vec<_> = prepared
        .candidates
        .iter()
        .map(|_| {
            Arc::new(Semaphore::new(
                prepared.config.runner.per_candidate_concurrency,
            ))
        })
        .collect();
    let judge_concurrency = prepared
        .judge
        .as_ref()
        .map(|judge| Arc::new(Semaphore::new(judge.config.concurrency)));
    let mut in_flight = futures_util::stream::FuturesUnordered::new();
    let stop_dispatch = Arc::new(AtomicBool::new(
        prepared.config.runner.max_observed_cost_usd == 0.0,
    ));
    loop {
        while !stop_dispatch.load(AtomicOrdering::Acquire)
            && in_flight.len() < prepared.config.runner.concurrency
            && !jobs.is_empty()
        {
            let (sequence, candidate_index, case_index) = jobs.pop_front().unwrap();
            let candidate = prepared.candidates[candidate_index].clone();
            let dataset = Arc::clone(&dataset);
            let client = client.clone();
            let writer = writer.clone();
            let global = Arc::clone(&global);
            let per_candidate = Arc::clone(&per_candidate[candidate_index]);
            let request_timeout = prepared.config.runner.request_timeout_ms;
            let max_response_bytes = prepared.config.runner.max_response_bytes;
            let max_observed_tokens = prepared.config.runner.max_observed_tokens;
            let max_observed_cost_usd = prepared.config.runner.max_observed_cost_usd;
            let stop_dispatch = Arc::clone(&stop_dispatch);
            let judge = prepared.judge.clone();
            let judge_concurrency = judge_concurrency.clone();
            in_flight.push(async move {
                let candidate_permit = per_candidate.acquire_owned().await.expect("semaphore open");
                let global_permit = global
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore open");
                if stop_dispatch.load(AtomicOrdering::Acquire) {
                    return (
                        cancelled_outcome(
                            sequence,
                            &candidate,
                            &dataset.cases[case_index],
                            &dataset,
                        ),
                        true,
                    );
                }
                if started.elapsed() >= wall {
                    stop_dispatch.store(true, AtomicOrdering::Release);
                    return (
                        cancelled_outcome(
                            sequence,
                            &candidate,
                            &dataset.cases[case_index],
                            &dataset,
                        ),
                        true,
                    );
                }
                if !writer.snapshot().writer_healthy {
                    stop_dispatch.store(true, AtomicOrdering::Release);
                    return (
                        cancelled_outcome(
                            sequence,
                            &candidate,
                            &dataset.cases[case_index],
                            &dataset,
                        ),
                        true,
                    );
                }
                if writer.candidate_dispatched().is_err() {
                    stop_dispatch.store(true, AtomicOrdering::Release);
                    return (
                        internal_outcome(
                            sequence,
                            &candidate,
                            &dataset.cases[case_index],
                            &dataset,
                        ),
                        false,
                    );
                }
                let remaining = wall.saturating_sub(started.elapsed());
                let timeout = remaining.min(Duration::from_millis(request_timeout));
                let wall_bounded = remaining <= Duration::from_millis(request_timeout);
                let mut execution = match tokio::time::timeout(
                    timeout,
                    execute_one(
                        &client,
                        &candidate,
                        &dataset.cases[case_index],
                        &dataset,
                        timeout,
                        max_response_bytes,
                        sequence,
                    ),
                )
                .await
                {
                    Ok(execution) => execution,
                    Err(_) => CandidateExecution {
                        outcome: candidate_error(
                            sequence,
                            &candidate,
                            &dataset.cases[case_index],
                            &dataset,
                            CandidateErrorKind::Timeout,
                            timeout,
                        ),
                        observed: None,
                    },
                };
                let mut wall_cancelled = wall_bounded
                    && started.elapsed() >= wall
                    && execution.outcome.status == QualityAttemptStatus::CandidateError
                    && execution.outcome.candidate_error == Some(CandidateErrorKind::Timeout);
                if wall_cancelled {
                    let outcome = &mut execution.outcome;
                    outcome.status = QualityAttemptStatus::Cancelled;
                    outcome.reason = Some(QualityReasonCode::Cancelled);
                    outcome.candidate_error = None;
                    outcome.input_tokens = None;
                    outcome.output_tokens = None;
                    outcome.candidate_cost_usd = None;
                    outcome.evaluator_outcomes.clear();
                    outcome.cost_evaluators.clear();
                }
                let candidate_chain_tokens = execution
                    .outcome
                    .input_tokens
                    .zip(execution.outcome.output_tokens)
                    .map_or(0, |(input, output)| input.saturating_add(output));
                let candidate_chain_cost = execution.outcome.candidate_cost_usd.unwrap_or(0.0);
                if candidate_chain_tokens >= max_observed_tokens
                    || candidate_chain_cost >= max_observed_cost_usd
                {
                    stop_dispatch.store(true, AtomicOrdering::Release);
                }
                if !wall_cancelled {
                    if let (Some(judge), Some(observed), Some(judge_concurrency)) =
                        (judge, execution.observed.as_ref(), judge_concurrency)
                    {
                        drop(candidate_permit);
                        drop(global_permit);
                        let remaining = wall.saturating_sub(started.elapsed());
                        let permits = tokio::time::timeout(remaining, async {
                            let judge = judge_concurrency
                                .acquire_owned()
                                .await
                                .expect("judge semaphore open");
                            let global =
                                global.acquire_owned().await.expect("global semaphore open");
                            (judge, global)
                        })
                        .await;
                        let judge_execution = match permits {
                            Err(_) => {
                                wall_cancelled = true;
                                stop_dispatch.store(true, AtomicOrdering::Release);
                                if writer.unused_judge_credit().is_err() {
                                    stop_dispatch.store(true, AtomicOrdering::Release);
                                }
                                judge_scheduler_error(&judge)
                            }
                            Ok((_judge_permit, _global_permit)) => {
                                if writer.judge_dispatched().is_err() {
                                    if writer.unused_judge_credit().is_err() {
                                        stop_dispatch.store(true, AtomicOrdering::Release);
                                    }
                                    judge_scheduler_error(&judge)
                                } else {
                                    let remaining = wall.saturating_sub(started.elapsed());
                                    let timeout = remaining.min(Duration::from_millis(
                                        judge.config.request_timeout_ms,
                                    ));
                                    let result = match tokio::time::timeout(
                                        timeout,
                                        execute_judge(
                                            &client,
                                            &judge,
                                            &dataset.cases[case_index],
                                            observed,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(execution) => execution,
                                        Err(_) => judge_timeout(&judge),
                                    };
                                    if started.elapsed() >= wall
                                        && result.evidence.error_code
                                            == Some(
                                                bowline_core::quality_run::JudgeErrorCode::Timeout,
                                            )
                                    {
                                        wall_cancelled = true;
                                        stop_dispatch.store(true, AtomicOrdering::Release);
                                    }
                                    result
                                }
                            }
                        };
                        let required_error = judge_execution.evidence.required
                            && judge_execution.evidence.status == EvaluatorStatus::Error;
                        execution.outcome.judge = Some(judge_execution.evidence);
                        if required_error {
                            execution.outcome.status = QualityAttemptStatus::JudgeError;
                            execution.outcome.reason = Some(QualityReasonCode::JudgeError);
                        }
                        let judge_tokens = execution
                            .outcome
                            .judge
                            .as_ref()
                            .and_then(|judge| judge.input_tokens.zip(judge.output_tokens))
                            .map_or(0, |(input, output)| input.saturating_add(output));
                        let judge_cost = execution
                            .outcome
                            .judge
                            .as_ref()
                            .and_then(|judge| judge.cost_usd)
                            .unwrap_or(0.0);
                        if candidate_chain_tokens.saturating_add(judge_tokens)
                            >= max_observed_tokens
                            || candidate_chain_cost + judge_cost >= max_observed_cost_usd
                        {
                            stop_dispatch.store(true, AtomicOrdering::Release);
                        }
                    }
                }
                (execution.outcome, wall_cancelled)
            });
        }
        let Some((outcome, wall_cancelled)) = in_flight.next().await else {
            break;
        };
        cancelled |= wall_cancelled;
        if prepared.judge.is_some()
            && outcome.judge.is_none()
            && writer.unused_judge_credit().is_err()
        {
            writer_failed = true;
            stop_dispatch.store(true, AtomicOrdering::Release);
        }
        if let (Some(input), Some(output)) = (outcome.input_tokens, outcome.output_tokens) {
            candidate_observed_tokens = candidate_observed_tokens
                .saturating_add(input)
                .saturating_add(output);
        }
        if let Some(cost) = outcome.candidate_cost_usd {
            candidate_observed_cost += cost;
        }
        if let Some(judge) = &outcome.judge {
            if let (Some(input), Some(output)) = (judge.input_tokens, judge.output_tokens) {
                judge_observed_tokens = judge_observed_tokens
                    .saturating_add(input)
                    .saturating_add(output);
            }
            if let Some(cost) = judge.cost_usd {
                judge_observed_cost += cost;
            }
        }
        if writer.try_record(outcome).is_err() {
            writer_failed = true;
            stop_dispatch.store(true, AtomicOrdering::Release);
        }
        if cancelled
            || candidate_observed_tokens.saturating_add(judge_observed_tokens)
                >= prepared.config.runner.max_observed_tokens
            || candidate_observed_cost + judge_observed_cost
                >= prepared.config.runner.max_observed_cost_usd
        {
            stop_dispatch.store(true, AtomicOrdering::Release);
        }
    }
    if stop_dispatch.load(AtomicOrdering::Acquire) || !jobs.is_empty() {
        cancelled = true;
        while let Some((sequence, candidate_index, case_index)) = jobs.pop_front() {
            let outcome = cancelled_outcome(
                sequence,
                &prepared.candidates[candidate_index],
                &dataset.cases[case_index],
                &dataset,
            );
            if prepared.judge.is_some() && writer.unused_judge_credit().is_err() {
                writer_failed = true;
            }
            if writer.try_record(outcome).is_err() {
                writer_failed = true;
            }
        }
    }
    let manifest = writer
        .shutdown(
            cancelled,
            Duration::from_millis(prepared.config.runner.shutdown_grace_ms),
        )
        .await?;
    let summary = summary(
        &manifest,
        candidate_observed_tokens,
        judge_observed_tokens,
        candidate_observed_cost,
        judge_observed_cost,
    );
    Ok((
        summary,
        writer_failed || cancelled || !manifest.clean_shutdown,
    ))
}

struct CandidateExecution {
    outcome: QualityOutcome,
    observed: Option<bowline_core::quality::ObservedCandidateResponse>,
}

async fn execute_one(
    client: &Client,
    candidate: &PreparedCandidate,
    case: &bowline_core::quality::QualityCase,
    dataset: &LoadedQualityDataset,
    timeout: Duration,
    max_response_bytes: usize,
    sequence: u64,
) -> CandidateExecution {
    let started = Instant::now();
    let request = match request_body(&case.request, &candidate.model) {
        Ok(request) => request,
        Err(_) => {
            return failed_candidate_execution(candidate_error(
                sequence,
                candidate,
                case,
                dataset,
                CandidateErrorKind::InvalidResponse,
                started.elapsed(),
            ))
        }
    };
    let route = dataset.manifest.protocol.route().trim_start_matches("/v1/");
    let url = format!("{}/{route}", candidate.endpoint.trim_end_matches('/'));
    let response = tokio::time::timeout(
        timeout,
        client
            .post(url)
            .header(
                reqwest::header::AUTHORIZATION,
                candidate.authorization.clone(),
            )
            .json(&request)
            .send(),
    )
    .await;
    let response = match response {
        Err(_) => {
            return failed_candidate_execution(candidate_error(
                sequence,
                candidate,
                case,
                dataset,
                CandidateErrorKind::Timeout,
                started.elapsed(),
            ))
        }
        Ok(Err(error)) => {
            let kind = if error.is_connect() {
                CandidateErrorKind::Transport
            } else {
                CandidateErrorKind::Disconnect
            };
            return failed_candidate_execution(candidate_error(
                sequence,
                candidate,
                case,
                dataset,
                kind,
                started.elapsed(),
            ));
        }
        Ok(Ok(response)) => response,
    };
    if !response.status().is_success() {
        return failed_candidate_execution(candidate_error(
            sequence,
            candidate,
            case,
            dataset,
            CandidateErrorKind::HttpStatus,
            started.elapsed(),
        ));
    }
    let body = match bounded_body(response, max_response_bytes).await {
        Ok(body) => body,
        Err(kind) => {
            return failed_candidate_execution(candidate_error(
                sequence,
                candidate,
                case,
                dataset,
                kind,
                started.elapsed(),
            ))
        }
    };
    let latency_ms = millis(started.elapsed());
    let usage = usage(dataset.manifest.protocol, &body);
    let cost = usage.and_then(|(input, output)| {
        candidate
            .price
            .map(|price| price_cost(price, input, output))
    });
    let observed =
        match normalize_candidate_response(dataset.manifest.protocol, &body, latency_ms, cost) {
            Ok(observed) => observed,
            Err(_) => {
                return failed_candidate_execution(candidate_error(
                    sequence,
                    candidate,
                    case,
                    dataset,
                    CandidateErrorKind::InvalidResponse,
                    started.elapsed(),
                ))
            }
        };
    let evaluated = evaluate_case(case, &dataset.evaluators, &observed);
    let mut evaluator_outcomes = Vec::new();
    let mut cost_evaluators = Vec::new();
    let mut required_error = false;
    let mut cost_failed = false;
    for outcome in evaluated.outcomes {
        if outcome.kind == EvaluatorKind::CostCeiling {
            let status = match outcome.status {
                EvaluatorStatus::Pass => CostEvaluatorStatus::Pass,
                EvaluatorStatus::Fail => {
                    cost_failed = true;
                    CostEvaluatorStatus::Fail
                }
                EvaluatorStatus::Error => CostEvaluatorStatus::Unknown,
            };
            cost_evaluators.push(CostEvaluatorEvidence {
                evaluator_id: outcome.evaluator_id,
                required: outcome.required,
                status,
                observed_cost_usd: (status != CostEvaluatorStatus::Unknown)
                    .then_some(cost.unwrap_or(0.0)),
            });
        } else {
            if outcome.required && outcome.status == EvaluatorStatus::Error {
                required_error = true;
            }
            evaluator_outcomes.push(QualityEvaluatorEvidence {
                evaluator_id: outcome.evaluator_id,
                kind: outcome.kind,
                status: outcome.status,
                error_code: (outcome.status == EvaluatorStatus::Error)
                    .then(|| evaluator_error(outcome.error_code.as_deref())),
                required: outcome.required,
                subjective: false,
                latency_ms: outcome.latency_ms,
            });
        }
    }
    let (status, reason) = if required_error {
        (
            QualityAttemptStatus::EvaluatorError,
            Some(QualityReasonCode::EvaluatorError),
        )
    } else if cost_failed {
        (
            QualityAttemptStatus::Completed,
            Some(QualityReasonCode::CostCeilingExceeded),
        )
    } else if usage.is_none() {
        (
            QualityAttemptStatus::Completed,
            Some(QualityReasonCode::MissingUsage),
        )
    } else {
        (QualityAttemptStatus::Completed, None)
    };
    let outcome = QualityOutcome {
        sequence,
        case_id: case.case_id.clone(),
        candidate_supply_id: candidate.supply_id.clone(),
        candidate_model: candidate.model.clone(),
        protocol: dataset.manifest.protocol,
        task_class: dataset.manifest.task_class,
        dispatched: true,
        status,
        reason,
        candidate_error: None,
        latency_ms: Some(latency_ms),
        input_tokens: usage.map(|value| value.0),
        output_tokens: usage.map(|value| value.1),
        candidate_cost_usd: cost,
        evaluator_outcomes,
        cost_evaluators,
        judge: None,
        dataset_digest: dataset.digests.dataset_digest.clone(),
        evaluator_digest: dataset.digests.evaluator_digest.clone(),
    };
    CandidateExecution {
        outcome,
        observed: Some(observed),
    }
}

fn failed_candidate_execution(outcome: QualityOutcome) -> CandidateExecution {
    CandidateExecution {
        outcome,
        observed: None,
    }
}

async fn bounded_body(
    response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, CandidateErrorKind> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| CandidateErrorKind::Disconnect)?;
        if body.len().saturating_add(chunk.len()) > max {
            return Err(CandidateErrorKind::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn request_body(request: &QualityRequest, model: &str) -> Result<Value, CanaryError> {
    let mut value = match request {
        QualityRequest::Chat(request) => serde_json::to_value(request),
        QualityRequest::Responses(request) => serde_json::to_value(request),
    }
    .map_err(|_| CanaryError::Execution)?;
    let object = value.as_object_mut().ok_or(CanaryError::Execution)?;
    object.insert("model".into(), Value::String(model.to_owned()));
    object.insert("stream".into(), Value::Bool(false));
    Ok(value)
}

fn usage(protocol: QualityProtocol, body: &[u8]) -> Option<(u64, u64)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let usage = value.get("usage")?;
    let (input, output) = match protocol {
        QualityProtocol::Chat => (
            usage
                .get("prompt_tokens")
                .or_else(|| usage.get("input_tokens")),
            usage
                .get("completion_tokens")
                .or_else(|| usage.get("output_tokens")),
        ),
        QualityProtocol::Responses => (
            usage
                .get("input_tokens")
                .or_else(|| usage.get("prompt_tokens")),
            usage
                .get("output_tokens")
                .or_else(|| usage.get("completion_tokens")),
        ),
    };
    Some((input?.as_u64()?, output?.as_u64()?))
}

fn price_cost(price: Price, input: u64, output: u64) -> f64 {
    (input as f64 * price.input_per_mtok_usd + output as f64 * price.output_per_mtok_usd)
        / 1_000_000.0
}

fn candidate_error(
    sequence: u64,
    candidate: &PreparedCandidate,
    case: &bowline_core::quality::QualityCase,
    dataset: &LoadedQualityDataset,
    kind: CandidateErrorKind,
    elapsed: Duration,
) -> QualityOutcome {
    QualityOutcome {
        sequence,
        case_id: case.case_id.clone(),
        candidate_supply_id: candidate.supply_id.clone(),
        candidate_model: candidate.model.clone(),
        protocol: dataset.manifest.protocol,
        task_class: dataset.manifest.task_class,
        dispatched: true,
        status: QualityAttemptStatus::CandidateError,
        reason: Some(candidate_reason(kind)),
        candidate_error: Some(kind),
        latency_ms: Some(millis(elapsed)),
        input_tokens: None,
        output_tokens: None,
        candidate_cost_usd: None,
        evaluator_outcomes: Vec::new(),
        cost_evaluators: Vec::new(),
        judge: None,
        dataset_digest: dataset.digests.dataset_digest.clone(),
        evaluator_digest: dataset.digests.evaluator_digest.clone(),
    }
}

fn cancelled_outcome(
    sequence: u64,
    candidate: &PreparedCandidate,
    case: &bowline_core::quality::QualityCase,
    dataset: &LoadedQualityDataset,
) -> QualityOutcome {
    QualityOutcome {
        sequence,
        case_id: case.case_id.clone(),
        candidate_supply_id: candidate.supply_id.clone(),
        candidate_model: candidate.model.clone(),
        protocol: dataset.manifest.protocol,
        task_class: dataset.manifest.task_class,
        dispatched: false,
        status: QualityAttemptStatus::Cancelled,
        reason: Some(QualityReasonCode::Cancelled),
        candidate_error: None,
        latency_ms: None,
        input_tokens: None,
        output_tokens: None,
        candidate_cost_usd: None,
        evaluator_outcomes: Vec::new(),
        cost_evaluators: Vec::new(),
        judge: None,
        dataset_digest: dataset.digests.dataset_digest.clone(),
        evaluator_digest: dataset.digests.evaluator_digest.clone(),
    }
}

fn internal_outcome(
    sequence: u64,
    candidate: &PreparedCandidate,
    case: &bowline_core::quality::QualityCase,
    dataset: &LoadedQualityDataset,
) -> QualityOutcome {
    QualityOutcome {
        sequence,
        case_id: case.case_id.clone(),
        candidate_supply_id: candidate.supply_id.clone(),
        candidate_model: candidate.model.clone(),
        protocol: dataset.manifest.protocol,
        task_class: dataset.manifest.task_class,
        dispatched: false,
        status: QualityAttemptStatus::InternalError,
        reason: Some(QualityReasonCode::SchedulerError),
        candidate_error: None,
        latency_ms: None,
        input_tokens: None,
        output_tokens: None,
        candidate_cost_usd: None,
        evaluator_outcomes: Vec::new(),
        cost_evaluators: Vec::new(),
        judge: None,
        dataset_digest: dataset.digests.dataset_digest.clone(),
        evaluator_digest: dataset.digests.evaluator_digest.clone(),
    }
}

fn candidate_reason(kind: CandidateErrorKind) -> QualityReasonCode {
    match kind {
        CandidateErrorKind::Timeout => QualityReasonCode::Timeout,
        CandidateErrorKind::Transport => QualityReasonCode::Transport,
        CandidateErrorKind::Disconnect => QualityReasonCode::Disconnect,
        CandidateErrorKind::HttpStatus => QualityReasonCode::HttpStatus,
        CandidateErrorKind::ResponseTooLarge => QualityReasonCode::ResponseTooLarge,
        CandidateErrorKind::InvalidResponse => QualityReasonCode::InvalidResponse,
    }
}

fn evaluator_error(code: Option<&str>) -> QualityEvaluatorErrorCode {
    match code {
        Some("missing-text") => QualityEvaluatorErrorCode::MissingText,
        Some("regex-invalid") => QualityEvaluatorErrorCode::RegexInvalid,
        Some("invalid-assistant-json") => QualityEvaluatorErrorCode::InvalidAssistantJson,
        Some("schema-invalid") => QualityEvaluatorErrorCode::SchemaInvalid,
        Some("field-missing") => QualityEvaluatorErrorCode::FieldMissing,
        Some("expected-missing") => QualityEvaluatorErrorCode::ExpectedMissing,
        Some("tool-call-count") => QualityEvaluatorErrorCode::ToolCallCount,
        Some("tool-call-missing") => QualityEvaluatorErrorCode::ToolCallMissing,
        _ => QualityEvaluatorErrorCode::EvaluatorError,
    }
}

fn summary(
    manifest: &QualityRunManifest,
    candidate_observed_tokens: u64,
    judge_observed_tokens: u64,
    candidate_observed_cost_usd: f64,
    judge_observed_cost_usd: f64,
) -> CanaryRunSummary {
    CanaryRunSummary {
        schema_version: 1,
        run_id: manifest.run_id.clone(),
        accepted: manifest.accepted,
        recorded: manifest.recorded,
        dropped: manifest.dropped,
        completed: manifest.completed,
        errors: manifest.errors,
        cancelled_outcomes: manifest.cancelled_outcomes,
        candidate_dispatches: manifest.candidate_dispatches,
        judge_dispatches: manifest.judge_dispatches,
        unused_judge_credits: manifest.unused_judge_credits,
        clean_shutdown: manifest.clean_shutdown,
        cancelled: manifest.cancelled,
        writer_healthy: manifest.writer_healthy,
        observed_tokens: candidate_observed_tokens.saturating_add(judge_observed_tokens),
        observed_cost_usd: candidate_observed_cost_usd + judge_observed_cost_usd,
        candidate_observed_tokens,
        judge_observed_tokens,
        candidate_observed_cost_usd,
        judge_observed_cost_usd,
    }
}

fn validate_config(config: &CanaryConfig) -> Result<(), CanaryError> {
    if config.version != 1
        || config.candidates.is_empty()
        || config.candidates.len() > MAX_CANDIDATES
    {
        return Err(CanaryError::Invalid("version or candidate count"));
    }
    let mut ids = HashSet::new();
    if config
        .candidates
        .iter()
        .any(|candidate| !ids.insert(&candidate.supply_id))
    {
        return Err(CanaryError::Invalid("duplicate candidate"));
    }
    let runner = &config.runner;
    if !(1..=MAX_CONCURRENCY).contains(&runner.concurrency)
        || runner.per_candidate_concurrency == 0
        || runner.per_candidate_concurrency > runner.concurrency
        || !(1..=MAX_REQUESTS).contains(&runner.max_requests)
        || !(1..=MAX_WALL_TIME_MS).contains(&runner.max_wall_time_ms)
        || !(1..=MAX_TIMEOUT_MS).contains(&runner.request_timeout_ms)
        || runner.request_timeout_ms > runner.max_wall_time_ms
        || !(1..=MAX_SHUTDOWN_GRACE_MS).contains(&runner.shutdown_grace_ms)
        || runner.max_response_bytes == 0
        || runner.max_response_bytes > bowline_core::quality::MAX_RESPONSE_BYTES
        || runner.max_observed_tokens == 0
        || runner.max_observed_tokens > MAX_OBSERVED_TOKENS
        || !runner.max_observed_cost_usd.is_finite()
        || !(0.0..=MAX_OBSERVED_COST_USD).contains(&runner.max_observed_cost_usd)
        || runner.writer_queue_capacity == 0
        || runner.writer_queue_capacity > 65_536
    {
        return Err(CanaryError::Invalid("runner bounds"));
    }
    let promotion = &config.promotion;
    if !(1..=MAX_REQUESTS).contains(&promotion.min_samples)
        || !unit(promotion.min_pass_rate)
        || !unit(promotion.min_wilson_lower_95)
        || !unit(promotion.max_error_rate)
        || !(1..=MAX_WALL_TIME_MS).contains(&promotion.max_p95_latency_ms)
        || !(1..=MAX_PROMOTION_AGE_MS).contains(&promotion.max_age_ms)
    {
        return Err(CanaryError::Invalid("promotion bounds"));
    }
    if config.judge.as_ref().is_some_and(|judge| {
        validate_judge_config(judge, runner.concurrency, runner.max_wall_time_ms).is_err()
    }) {
        return Err(CanaryError::Invalid("judge bounds"));
    }
    Ok(())
}

pub(crate) fn validate_base_url(source: &str, acknowledged: bool) -> Result<Url, ()> {
    bowline_core::config::validate_credential_free_endpoint(source, acknowledged, true)
        .map_err(|_| ())
}

pub(crate) fn validate_id(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn validate_env_name(value: &str) -> Result<(), ()> {
    let mut bytes = value.bytes();
    if value.len() > 128
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(());
    }
    Ok(())
}

fn unit(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality_writer::{
        spawn_managed_quality_writer, spawn_paused_managed_quality_writer,
        ManagedQualityWriterError, ManagedQualityWriterOptions,
    };
    use axum::{
        body::Body,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::Response,
        routing::post,
        Json, Router,
    };
    use bowline_core::{
        quality::load_quality_dataset,
        quality_run::{QualityProvenance, QualityRunPlan},
    };
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    #[derive(Default)]
    struct EndpointState {
        active: AtomicUsize,
        maximum: AtomicUsize,
        calls: Mutex<HashMap<String, usize>>,
        active_models: Mutex<HashMap<String, usize>>,
        maximum_models: Mutex<HashMap<String, usize>>,
    }

    #[derive(Default)]
    struct ChatEndpointState {
        calls: AtomicUsize,
        authorization: Mutex<Option<String>>,
        request: Mutex<Option<Value>>,
    }

    async fn endpoint(
        State(state): State<Arc<EndpointState>>,
        Json(body): Json<Value>,
    ) -> Response<Body> {
        let input = body
            .get("input")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        *state
            .calls
            .lock()
            .unwrap()
            .entry(input.clone())
            .or_default() += 1;
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.maximum.fetch_max(active, Ordering::SeqCst);
        let model_active = {
            let mut active = state.active_models.lock().unwrap();
            let value = active.entry(model.clone()).or_default();
            *value += 1;
            *value
        };
        state
            .maximum_models
            .lock()
            .unwrap()
            .entry(model.clone())
            .and_modify(|value| *value = (*value).max(model_active))
            .or_insert(model_active);
        let delay = if input == "slow" {
            150
        } else if input == "timeout" {
            250
        } else {
            40
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        state.active.fetch_sub(1, Ordering::SeqCst);
        *state.active_models.lock().unwrap().get_mut(&model).unwrap() -= 1;
        match input.as_str() {
            "http-500" => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap(),
            "invalid" => Response::new(Body::from("not-json")),
            "oversize" => Response::new(Body::from("x".repeat(2048))),
            "disconnect" => {
                let stream = futures_util::stream::once(async {
                    Err::<bytes::Bytes, std::io::Error>(std::io::Error::other("disconnect"))
                });
                Response::new(Body::from_stream(stream))
            }
            "responses-alias" => {
                let response = serde_json::json!({
                    "output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],
                    "usage":{"prompt_tokens":7,"completion_tokens":3}
                });
                Response::new(Body::from(serde_json::to_vec(&response).unwrap()))
            }
            _ => {
                let response = serde_json::json!({
                    "output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],
                    "usage":{"input_tokens":4,"output_tokens":2}
                });
                Response::new(Body::from(serde_json::to_vec(&response).unwrap()))
            }
        }
    }

    async fn chat_endpoint(
        State(state): State<Arc<ChatEndpointState>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response<Body> {
        state.calls.fetch_add(1, Ordering::SeqCst);
        *state.authorization.lock().unwrap() = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        *state.request.lock().unwrap() = Some(body);
        Response::new(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "choices":[{"message":{
                    "content":"ok",
                    "tool_calls":[{"type":"function","function":{
                        "name":"lookup","arguments":"{\"id\":1}"
                    }}]
                }}],
                "usage":{"input_tokens":11,"output_tokens":5}
            }))
            .unwrap(),
        ))
    }

    async fn fake_endpoint() -> (String, Arc<EndpointState>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(EndpointState::default());
        let app = Router::new()
            .route("/v1/responses", post(endpoint))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/v1/"), state, task)
    }

    fn dataset(inputs: &[&str]) -> Arc<LoadedQualityDataset> {
        let manifest = b"version: 1\ndataset_id: synthetic\nprotocol: responses\ncases_file: cases.jsonl\ntask_class: mechanical\npolicy_identity:\n  app: test\n  tags: [test]\n";
        let cases = inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                serde_json::json!({"case_id":format!("case-{index}"),"request":{"input":input},"expected":{"answer":"ok"}}).to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let evaluators = b"version: 1\nevaluators:\n  - { id: answer, kind: exact-match, expected_key: answer, required: true }\n";
        Arc::new(load_quality_dataset(manifest, cases.as_bytes(), evaluators).unwrap())
    }

    fn chat_dataset() -> Arc<LoadedQualityDataset> {
        let manifest = b"version: 1\ndataset_id: synthetic-chat\nprotocol: chat\ncases_file: cases.jsonl\ntask_class: mechanical\npolicy_identity:\n  app: test\n  tags: [test]\n";
        let cases = serde_json::json!({
            "case_id":"chat-case",
            "request":{
                "messages":[{"role":"user","content":"status"}],
                "tools":[{"type":"function","function":{
                    "name":"lookup","parameters":{"type":"object"}
                }}]
            },
            "expected":{"answer":"ok","tool_name":"lookup","tool_arguments":{"id":1}}
        })
        .to_string();
        let evaluators = b"version: 1\nevaluators:\n  - { id: answer, kind: exact-match, expected_key: answer, required: true }\n  - { id: tool, kind: tool-call, call_index: 0, expected_name_key: tool_name, expected_arguments_key: tool_arguments, require_total_calls: 1, required: true }\n";
        Arc::new(load_quality_dataset(manifest, cases.as_bytes(), evaluators).unwrap())
    }

    fn registry(price: bool) -> Registry {
        Registry::from_json(&serde_json::json!({
            "feed_version":"test",
            "entries":[{
                "id":"public/candidate","model":"candidate-model","location":"test",
                "attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},
                "price": if price { serde_json::json!({"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0}) } else { Value::Null },
                "ratings":{},"available":true
            }]
        }).to_string()).unwrap()
    }

    fn two_candidate_registry() -> Registry {
        let mut value = serde_json::to_value(registry(true)).unwrap();
        let entries = value["entries"].as_array_mut().unwrap();
        let mut second = entries[0].clone();
        second["id"] = Value::String("public/candidate-b".into());
        second["model"] = Value::String("candidate-model-b".into());
        entries.push(second);
        Registry::from_json(&value.to_string()).unwrap()
    }

    fn two_candidates(base_url: &str) -> PreparedCanary {
        prepare_canary(
            CanaryConfig {
                version: 1,
                candidates: vec![
                    CandidateConfig {
                        supply_id: "public/candidate-b".into(),
                        base_url: base_url.into(),
                        authorization_env: "BOWLINE_TEST_AUTH_B".into(),
                    },
                    CandidateConfig {
                        supply_id: "public/candidate".into(),
                        base_url: base_url.into(),
                        authorization_env: "BOWLINE_TEST_AUTH_A".into(),
                    },
                ],
                runner: RunnerConfig {
                    send_customer_content: false,
                    concurrency: 4,
                    per_candidate_concurrency: 2,
                    max_requests: 100,
                    max_wall_time_ms: 2_000,
                    request_timeout_ms: 500,
                    shutdown_grace_ms: 1_000,
                    max_response_bytes: 1024,
                    max_observed_tokens: 10_000,
                    max_observed_cost_usd: 10.0,
                    writer_queue_capacity: 64,
                },
                promotion: PromotionConfig {
                    min_samples: 1,
                    min_pass_rate: 0.0,
                    min_wilson_lower_95: 0.0,
                    max_error_rate: 1.0,
                    max_p95_latency_ms: 2_000,
                    max_age_ms: 60_000,
                },
                judge: None,
            },
            &two_candidate_registry(),
            |_| Some("Bearer secret-value".into()),
        )
        .unwrap()
    }

    fn build_prepared(
        base_url: &str,
        price: bool,
        concurrency: usize,
        per_candidate: usize,
    ) -> PreparedCanary {
        prepare_canary(
            CanaryConfig {
                version: 1,
                candidates: vec![CandidateConfig {
                    supply_id: "public/candidate".into(),
                    base_url: base_url.into(),
                    authorization_env: "BOWLINE_TEST_AUTH".into(),
                }],
                runner: RunnerConfig {
                    send_customer_content: false,
                    concurrency,
                    per_candidate_concurrency: per_candidate,
                    max_requests: 100,
                    max_wall_time_ms: 2_000,
                    request_timeout_ms: 100,
                    shutdown_grace_ms: 1_000,
                    max_response_bytes: 1024,
                    max_observed_tokens: 10_000,
                    max_observed_cost_usd: 10.0,
                    writer_queue_capacity: 64,
                },
                promotion: PromotionConfig {
                    min_samples: 1,
                    min_pass_rate: 0.0,
                    min_wilson_lower_95: 0.0,
                    max_error_rate: 1.0,
                    max_p95_latency_ms: 2_000,
                    max_age_ms: 60_000,
                },
                judge: None,
            },
            &registry(price),
            |_| Some("Bearer secret-value".into()),
        )
        .unwrap()
    }

    fn provenance(data: &LoadedQualityDataset, prepared: &PreparedCanary) -> QualityProvenance {
        QualityProvenance {
            dataset_manifest_digest: data.digests.dataset_manifest_digest.clone(),
            cases_digest: data.digests.cases_digest.clone(),
            dataset_digest: data.digests.dataset_digest.clone(),
            evaluator_digest: data.digests.evaluator_digest.clone(),
            candidate_config_digest: prepared.candidate_config_digest.clone(),
            policy_digest: format!("sha256:{}", "a".repeat(64)),
            registry_digest: format!("sha256:{}", "b".repeat(64)),
            owned_cost_digest: Some(format!("sha256:{}", "c".repeat(64))),
            judge_model_digest: None,
            judge_rubric_digest: None,
            judge_template_digest: None,
            judge_config_digest: None,
            judge_endpoint_digest: None,
            judge_authorization_reference_digest: None,
        }
    }

    fn build_writer(
        temp: &tempfile::TempDir,
        data: &LoadedQualityDataset,
        prepared: &PreparedCanary,
        queue: usize,
    ) -> ManagedQualityWriter {
        let planned = planned_candidate_requests(prepared, data.cases.len()).unwrap();
        spawn_managed_quality_writer(ManagedQualityWriterOptions {
            root: temp.path().join("quality-runs"),
            provenance: provenance(data, prepared),
            plan: QualityRunPlan {
                planned_request_upper_bound: planned,
                reserved_candidate_credits: planned,
                reserved_judge_credits: 0,
                max_age_ms: 60_000,
            },
            queue_capacity: queue,
        })
        .unwrap()
    }

    #[test]
    fn strict_config_and_atomic_preflight() {
        assert!(parse_canary_config(b"version: 2").is_err());
        assert!(validate_base_url("http://example.com/v1/", true).is_err());
        for endpoint in [
            "http://127.0.0.1:1/v1/",
            "http://[::1]:1/v1/",
            "http://localhost:1/v1/",
        ] {
            assert!(validate_base_url(endpoint, false).is_ok(), "{endpoint}");
        }
        for endpoint in [
            "http://192.0.2.1:1/v1/",
            "http://[2001:db8::1]:1/v1/",
            "http://example.com/v1/",
            "http://user@127.0.0.1:1/v1/",
            "http://127.0.0.1:1/not-v1?token=x",
        ] {
            assert!(validate_base_url(endpoint, true).is_err(), "{endpoint}");
        }
        assert!(validate_base_url("https://user@example.com/v1/", true).is_err());
        assert!(validate_base_url("https://example.com/v1/?token=x", true).is_err());
        assert!(validate_base_url("https://example.com/v1/#fragment", true).is_err());

        let base = build_prepared("http://127.0.0.1:1/v1/", true, 2, 1).config;
        let mut duplicate = base.clone();
        duplicate.candidates.push(duplicate.candidates[0].clone());
        assert!(prepare_canary(duplicate, &registry(true), |_| Some("Bearer x".into())).is_err());
        let mut remote = base.clone();
        remote.candidates[0].base_url = "https://example.com/v1/".into();
        assert!(
            prepare_canary(remote.clone(), &registry(true), |_| Some("Bearer x".into())).is_err()
        );
        remote.runner.send_customer_content = true;
        assert!(prepare_canary(remote, &registry(true), |_| Some("Bearer x".into())).is_ok());
        assert!(prepare_canary(base.clone(), &registry(true), |_| Some(
            "Bearer x\r\nInjected: y".into()
        ))
        .is_err());
        let first = prepare_canary(base.clone(), &registry(true), |_| {
            Some("Bearer first-secret".into())
        })
        .unwrap();
        let second = prepare_canary(base.clone(), &registry(true), |_| {
            Some("Bearer second-secret".into())
        })
        .unwrap();
        assert_eq!(
            first.candidate_config_digest,
            second.candidate_config_digest
        );
        let normalized_candidate_config = serde_json::to_vec(&first.config).unwrap();
        assert_eq!(
            first.candidate_config_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::CANDIDATE_CONFIG_DOMAIN,
                &[&normalized_candidate_config],
            )
        );
        assert!(!format!("{:?}", first.config).contains("first-secret"));
        let mut unknown = base.clone();
        unknown.candidates[0].supply_id = "public/unknown".into();
        assert!(prepare_canary(unknown, &registry(true), |_| Some("Bearer x".into())).is_err());
        for mutate in [
            |config: &mut CanaryConfig| config.runner.concurrency = 0,
            |config: &mut CanaryConfig| config.runner.per_candidate_concurrency = 3,
            |config: &mut CanaryConfig| config.runner.max_requests = 0,
            |config: &mut CanaryConfig| {
                config.runner.request_timeout_ms = config.runner.max_wall_time_ms + 1
            },
            |config: &mut CanaryConfig| {
                config.runner.max_response_bytes = bowline_core::quality::MAX_RESPONSE_BYTES + 1
            },
            |config: &mut CanaryConfig| config.promotion.min_pass_rate = f64::NAN,
        ] {
            let mut invalid = base.clone();
            mutate(&mut invalid);
            assert!(prepare_canary(invalid, &registry(true), |_| Some("Bearer x".into())).is_err());
        }
    }

    #[test]
    fn credential_material_is_rejected_from_candidate_paths() {
        for path in [
            "token",
            "api-token",
            "key",
            "api_key",
            "secret",
            "client-secret",
            "password",
            "auth",
            "authorization",
            "credential",
            "credentials",
            "Bearer",
            "sk-live-123",
        ] {
            let source = format!("https://example.com/{path}/v1/");
            assert!(validate_base_url(&source, true).is_err(), "accepted {path}");
        }
        for path in ["tenant", "monkey", "author", "secretariat", "v1"] {
            let source = if path == "v1" {
                "https://example.com/v1/".to_owned()
            } else {
                format!("https://example.com/{path}/v1/")
            };
            assert!(validate_base_url(&source, true).is_ok(), "rejected {path}");
        }
    }

    #[test]
    fn runtime_bound_table_covers_every_compiled_config_field() {
        type Mutation = (&'static str, fn(&mut CanaryConfig));

        let base = build_prepared("http://127.0.0.1:1/v1/", true, 2, 1).config;
        let invalid: Vec<Mutation> = vec![
            ("version", |value| value.version = 2),
            ("candidate-empty", |value| value.candidates.clear()),
            ("candidate-supply", |value| {
                value.candidates[0].supply_id.clear()
            }),
            ("candidate-url", |value| {
                value.candidates[0].base_url = "ftp://example.com/v1/".into()
            }),
            ("candidate-env", |value| {
                value.candidates[0].authorization_env = "bad-env".into()
            }),
            ("concurrency-min", |value| value.runner.concurrency = 0),
            ("concurrency-max", |value| {
                value.runner.concurrency = MAX_CONCURRENCY + 1
            }),
            ("per-candidate-min", |value| {
                value.runner.per_candidate_concurrency = 0
            }),
            ("per-candidate-max", |value| {
                value.runner.per_candidate_concurrency = value.runner.concurrency + 1
            }),
            ("requests-min", |value| value.runner.max_requests = 0),
            ("requests-max", |value| {
                value.runner.max_requests = MAX_REQUESTS + 1
            }),
            ("wall-min", |value| value.runner.max_wall_time_ms = 0),
            ("wall-max", |value| {
                value.runner.max_wall_time_ms = MAX_WALL_TIME_MS + 1
            }),
            ("timeout-min", |value| value.runner.request_timeout_ms = 0),
            ("timeout-max", |value| {
                value.runner.request_timeout_ms = MAX_TIMEOUT_MS + 1
            }),
            ("shutdown-min", |value| value.runner.shutdown_grace_ms = 0),
            ("shutdown-max", |value| {
                value.runner.shutdown_grace_ms = MAX_SHUTDOWN_GRACE_MS + 1
            }),
            ("response-min", |value| value.runner.max_response_bytes = 0),
            ("response-max", |value| {
                value.runner.max_response_bytes = bowline_core::quality::MAX_RESPONSE_BYTES + 1
            }),
            ("tokens-min", |value| value.runner.max_observed_tokens = 0),
            ("tokens-max", |value| {
                value.runner.max_observed_tokens = MAX_OBSERVED_TOKENS + 1
            }),
            ("cost-negative", |value| {
                value.runner.max_observed_cost_usd = -1.0
            }),
            ("cost-max", |value| {
                value.runner.max_observed_cost_usd = MAX_OBSERVED_COST_USD + 1.0
            }),
            ("cost-nan", |value| {
                value.runner.max_observed_cost_usd = f64::NAN
            }),
            ("queue-min", |value| value.runner.writer_queue_capacity = 0),
            ("queue-max", |value| {
                value.runner.writer_queue_capacity = 65_537
            }),
            ("samples-min", |value| value.promotion.min_samples = 0),
            ("samples-max", |value| {
                value.promotion.min_samples = MAX_REQUESTS + 1
            }),
            ("pass-rate", |value| value.promotion.min_pass_rate = 1.1),
            ("wilson", |value| {
                value.promotion.min_wilson_lower_95 = f64::NAN
            }),
            ("error-rate", |value| value.promotion.max_error_rate = -0.1),
            ("latency-min", |value| {
                value.promotion.max_p95_latency_ms = 0
            }),
            ("latency-max", |value| {
                value.promotion.max_p95_latency_ms = MAX_WALL_TIME_MS + 1
            }),
            ("age-min", |value| value.promotion.max_age_ms = 0),
            ("age-max", |value| {
                value.promotion.max_age_ms = MAX_PROMOTION_AGE_MS + 1
            }),
        ];
        for (name, mutate) in invalid {
            let mut value = base.clone();
            mutate(&mut value);
            assert!(
                prepare_canary(value, &registry(true), |_| Some("Bearer x".into())).is_err(),
                "bound not enforced: {name}"
            );
        }
        assert!(!base.runner.send_customer_content);
        let mut remote = base.clone();
        remote.candidates[0].base_url = "https://example.com/v1/".into();
        assert!(
            prepare_canary(remote.clone(), &registry(true), |_| Some("Bearer x".into())).is_err()
        );
        remote.runner.send_customer_content = true;
        assert!(prepare_canary(remote, &registry(true), |_| Some("Bearer x".into())).is_ok());

        assert!(parse_canary_config(&vec![b'x'; MAX_CANARY_BYTES + 1]).is_err());
        let mut too_many = build_prepared("http://127.0.0.1:1/v1/", true, 2, 1).config;
        let candidate = too_many.candidates[0].clone();
        too_many.candidates = (0..=MAX_CANDIDATES)
            .map(|index| CandidateConfig {
                supply_id: format!("candidate-{index}"),
                ..candidate.clone()
            })
            .collect();
        assert!(prepare_canary(too_many, &registry(true), |_| Some("Bearer x".into())).is_err());
        assert!(prepare_canary(base.clone(), &registry(true), |_| None).is_err());
        assert!(
            prepare_canary(base.clone(), &registry(true), |_| Some("x".repeat(8_193))).is_err()
        );
        let mut request_limited = build_prepared("http://127.0.0.1:1/v1/", true, 2, 1);
        request_limited.config.runner.max_requests = 1;
        assert!(planned_candidate_requests(&request_limited, 2).is_err());
    }

    #[tokio::test]
    async fn responses_usage_accepts_both_token_alias_pairs() {
        let (base_url, _state, server) = fake_endpoint().await;
        let data = dataset(&["responses-alias"]);
        let prepared = build_prepared(&base_url, true, 1, 1);
        let temp = tempfile::tempdir().unwrap();
        let writer = build_writer(&temp, &data, &prepared, 4);
        let (summary, incomplete) = run_canary(prepared, data, writer).await.unwrap();
        assert!(!incomplete);
        assert_eq!(summary.observed_tokens, 10);
        assert_eq!(summary.observed_cost_usd, 0.000013);
        server.abort();
    }

    #[tokio::test]
    async fn chat_endpoint_is_exact_non_streaming_authorized_and_normalized() {
        let state = Arc::new(ChatEndpointState::default());
        let app = Router::new()
            .route("/v1/chat/completions", post(chat_endpoint))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let data = chat_dataset();
        let prepared = build_prepared(&format!("http://{address}/v1/"), true, 1, 1);
        let temp = tempfile::tempdir().unwrap();
        let writer = build_writer(&temp, &data, &prepared, 4);
        let directory = writer.directory().to_owned();
        let (summary, incomplete) = run_canary(prepared, data, writer).await.unwrap();
        assert!(!incomplete && summary.clean_shutdown);
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.authorization.lock().unwrap().as_deref(),
            Some("Bearer secret-value")
        );
        let request = state.request.lock().unwrap().clone().unwrap();
        assert_eq!(request["model"], "candidate-model");
        assert_eq!(request["stream"], false);
        assert_eq!(request["messages"][0]["content"], "status");
        let outcomes = bowline_core::quality_run::QualityLedger::read_all(&directory, 1).unwrap();
        let outcome = &outcomes.outcomes[0];
        assert_eq!(
            (outcome.input_tokens, outcome.output_tokens),
            (Some(11), Some(5))
        );
        assert!(outcome
            .evaluator_outcomes
            .iter()
            .all(|item| item.status == EvaluatorStatus::Pass));
        assert!(!format!("{summary:?}").contains("secret-value"));
        server.abort();
    }

    #[tokio::test]
    async fn shared_continuation_is_rechecked_after_waiting_for_permits() {
        let (base_url, state, server) = fake_endpoint().await;
        let inputs = (0..32)
            .map(|index| format!("race-{index}"))
            .collect::<Vec<_>>();
        let refs = inputs.iter().map(String::as_str).collect::<Vec<_>>();
        let data = dataset(&refs);
        let mut prepared = build_prepared(&base_url, true, 64, 1);
        prepared.config.runner.max_observed_tokens = 5;
        let temp = tempfile::tempdir().unwrap();
        let writer = build_writer(&temp, &data, &prepared, 64);
        let (summary, incomplete) = run_canary(prepared, data, writer).await.unwrap();
        assert!(incomplete && summary.cancelled);
        assert_eq!(summary.accepted, summary.recorded + summary.dropped);
        assert_eq!(summary.candidate_dispatches, 1);
        assert_eq!(summary.cancelled_outcomes, 31);
        assert_eq!(state.calls.lock().unwrap().values().sum::<usize>(), 1);

        let zero_data = dataset(&["zero-1", "zero-2"]);
        let mut zero = build_prepared(&base_url, true, 64, 1);
        zero.config.runner.max_observed_cost_usd = 0.0;
        let zero_temp = tempfile::tempdir().unwrap();
        let zero_writer = build_writer(&zero_temp, &zero_data, &zero, 8);
        let (summary, incomplete) = run_canary(zero, zero_data, zero_writer).await.unwrap();
        assert!(incomplete && summary.cancelled);
        assert_eq!(summary.candidate_dispatches, 0);
        assert_eq!(summary.cancelled_outcomes, 2);
        assert_eq!(summary.observed_cost_usd, 0.0);
        server.abort();
    }

    #[tokio::test]
    async fn writer_failure_stops_pending_permit_jobs() {
        let (base_url, state, server) = fake_endpoint().await;
        let inputs = (0..16)
            .map(|index| format!("writer-race-{index}"))
            .collect::<Vec<_>>();
        let refs = inputs.iter().map(String::as_str).collect::<Vec<_>>();
        let data = dataset(&refs);
        let prepared = build_prepared(&base_url, true, 64, 1);
        let temp = tempfile::tempdir().unwrap();
        let planned = planned_candidate_requests(&prepared, data.cases.len()).unwrap();
        let (writer, release) = spawn_paused_managed_quality_writer(ManagedQualityWriterOptions {
            root: temp.path().join("quality-runs"),
            provenance: provenance(&data, &prepared),
            plan: QualityRunPlan {
                planned_request_upper_bound: planned,
                reserved_candidate_credits: planned,
                reserved_judge_credits: 0,
                max_age_ms: 60_000,
            },
            queue_capacity: 1,
        })
        .unwrap();
        let release_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            release.send(()).unwrap();
        });
        let (summary, incomplete) = run_canary(prepared, data, writer).await.unwrap();
        release_task.await.unwrap();
        assert!(incomplete && !summary.writer_healthy);
        assert_eq!(summary.candidate_dispatches, 2);
        assert_eq!(state.calls.lock().unwrap().values().sum::<usize>(), 2);
        server.abort();
    }

    #[tokio::test]
    async fn shutdown_deadline_covers_a_blocked_shutdown_enqueue() {
        let data = dataset(&["blocked"]);
        let prepared = build_prepared("http://127.0.0.1:1/v1/", true, 1, 1);
        let temp = tempfile::tempdir().unwrap();
        let (writer, release) = spawn_paused_managed_quality_writer(ManagedQualityWriterOptions {
            root: temp.path().join("quality-runs"),
            provenance: provenance(&data, &prepared),
            plan: QualityRunPlan {
                planned_request_upper_bound: 1,
                reserved_candidate_credits: 1,
                reserved_judge_credits: 0,
                max_age_ms: 60_000,
            },
            queue_capacity: 1,
        })
        .unwrap();
        let sequence = writer.accept().unwrap();
        writer
            .try_record(cancelled_outcome(
                sequence,
                &prepared.candidates[0],
                &data.cases[0],
                &data,
            ))
            .unwrap();
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            writer.shutdown(true, Duration::from_millis(30)),
        )
        .await
        .expect("shutdown itself hung");
        assert!(matches!(
            result,
            Err(ManagedQualityWriterError::ShutdownTimeout)
        ));
        assert!(started.elapsed() < Duration::from_millis(200));
        release.send(()).unwrap();
    }

    #[tokio::test]
    async fn adapters_are_non_streaming_single_dispatch_and_content_safe() {
        let request = QualityRequest::Responses(bowline_core::quality::QualityResponsesRequest {
            input: bowline_core::quality::QualityResponsesInput::Text("hello".into()),
            instructions: None,
            tools: Vec::new(),
            tool_choice: None,
            text: None,
            reasoning: None,
            temperature: None,
            top_p: None,
            max_output_tokens: Some(10),
        });
        let emitted = request_body(&request, "exact-model").unwrap();
        assert_eq!(emitted["model"], "exact-model");
        assert_eq!(emitted["stream"], false);
        assert!(format!("{emitted:?}").contains("hello"));

        let (base_url, state, server) = fake_endpoint().await;
        let data = dataset(&["slow", "fast-1", "fast-2", "fast-3"]);
        let prepared = two_candidates(&base_url);
        assert_eq!(
            prepared
                .config
                .candidates
                .iter()
                .map(|candidate| candidate.supply_id.as_str())
                .collect::<Vec<_>>(),
            vec!["public/candidate", "public/candidate-b"]
        );
        let temp = tempfile::tempdir().unwrap();
        let writer = build_writer(&temp, &data, &prepared, 64);
        let directory = writer.directory().to_owned();
        let (summary, incomplete) = run_canary(prepared, Arc::clone(&data), writer)
            .await
            .unwrap();
        assert!(!incomplete && summary.clean_shutdown);
        assert_eq!(
            state.maximum.load(Ordering::SeqCst),
            4,
            "global semaphore maximum"
        );
        assert_eq!(
            state
                .maximum_models
                .lock()
                .unwrap()
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![2, 2],
            "per-candidate semaphore maxima"
        );
        let raw = std::fs::read(directory.join("outcomes.bwq")).unwrap();
        let raw = String::from_utf8_lossy(&raw);
        assert!(
            raw.find("\"sequence\":2").unwrap() < raw.find("\"sequence\":1").unwrap(),
            "completion order not persisted"
        );
        let read = bowline_core::quality_run::QualityLedger::read_all(&directory, 8).unwrap();
        assert_eq!(
            read.outcomes
                .iter()
                .map(|item| item.sequence)
                .collect::<Vec<_>>(),
            (1..=8).collect::<Vec<_>>()
        );

        let errors = dataset(&["http-500", "invalid", "oversize", "disconnect", "timeout"]);
        let mut error_prepared = build_prepared(&base_url, true, 1, 1);
        error_prepared.config.runner.max_response_bytes = 128;
        error_prepared.config.runner.request_timeout_ms = 100;
        let error_temp = tempfile::tempdir().unwrap();
        let error_writer = build_writer(&error_temp, &errors, &error_prepared, 16);
        let (summary, incomplete) = run_canary(error_prepared, Arc::clone(&errors), error_writer)
            .await
            .unwrap();
        assert!(!incomplete && summary.clean_shutdown);
        assert_eq!(summary.errors, 5);
        for input in ["http-500", "invalid", "oversize", "disconnect", "timeout"] {
            assert_eq!(
                state.calls.lock().unwrap().get(input),
                Some(&1),
                "retried {input}"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn shared_budget_cancellation_and_quality_writer_lifecycle() {
        assert_eq!(
            price_cost(
                Price {
                    input_per_mtok_usd: 1.0,
                    output_per_mtok_usd: 2.0
                },
                2,
                1
            ),
            0.000004
        );
        assert_eq!(
            candidate_reason(CandidateErrorKind::Timeout),
            QualityReasonCode::Timeout
        );

        let (base_url, state, server) = fake_endpoint().await;
        let data = dataset(&["budget-1", "budget-2", "budget-3"]);
        let mut limited = build_prepared(&base_url, true, 1, 1);
        limited.config.runner.max_observed_tokens = 5;
        let temp = tempfile::tempdir().unwrap();
        let writer = build_writer(&temp, &data, &limited, 16);
        let (summary, incomplete) = run_canary(limited, Arc::clone(&data), writer)
            .await
            .unwrap();
        assert!(incomplete && summary.cancelled && !summary.clean_shutdown);
        assert_eq!(summary.candidate_dispatches, 1);
        assert_eq!(summary.cancelled_outcomes, 2);
        assert_eq!(
            summary.observed_tokens, 6,
            "one in-flight call may overshoot"
        );

        let cost_data = dataset(&["cost-1", "cost-2"]);
        let mut cost_prepared = build_prepared(&base_url, true, 1, 1);
        cost_prepared.config.runner.max_observed_cost_usd = 0.000001;
        let cost_temp = tempfile::tempdir().unwrap();
        let cost_writer = build_writer(&cost_temp, &cost_data, &cost_prepared, 16);
        let (summary, incomplete) = run_canary(cost_prepared, Arc::clone(&cost_data), cost_writer)
            .await
            .unwrap();
        assert!(incomplete && summary.cancelled);
        assert_eq!(summary.candidate_dispatches, 1);
        assert_eq!(summary.cancelled_outcomes, 1);
        assert_eq!(summary.observed_cost_usd, 0.000008);

        let unknown = dataset(&["unknown-1", "unknown-2"]);
        let mut unknown_prepared = build_prepared(&base_url, false, 1, 1);
        unknown_prepared.config.runner.max_observed_cost_usd = 0.000001;
        let unknown_temp = tempfile::tempdir().unwrap();
        let unknown_writer = build_writer(&unknown_temp, &unknown, &unknown_prepared, 16);
        let (summary, incomplete) =
            run_canary(unknown_prepared, Arc::clone(&unknown), unknown_writer)
                .await
                .unwrap();
        assert!(!incomplete && summary.clean_shutdown);
        assert_eq!(summary.candidate_dispatches, 2);
        assert_eq!(
            summary.observed_cost_usd, 0.0,
            "unknown cost incremented budget"
        );

        let invalid_data = dataset(&["writer"]);
        let invalid_prepared = build_prepared(&base_url, true, 1, 1);
        let invalid_temp = tempfile::tempdir().unwrap();
        let invalid_writer = build_writer(&invalid_temp, &invalid_data, &invalid_prepared, 4);
        let sequence = invalid_writer.accept().unwrap();
        let mut invalid = cancelled_outcome(
            sequence,
            &invalid_prepared.candidates[0],
            &invalid_data.cases[0],
            &invalid_data,
        );
        invalid.reason = None;
        invalid_writer.try_record(invalid).unwrap();
        let manifest = invalid_writer
            .shutdown(false, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!manifest.writer_healthy && !manifest.clean_shutdown && manifest.dropped == 1);

        let queue_temp = tempfile::tempdir().unwrap();
        let (paused, release) = spawn_paused_managed_quality_writer(ManagedQualityWriterOptions {
            root: queue_temp.path().join("quality-runs"),
            provenance: provenance(&invalid_data, &invalid_prepared),
            plan: QualityRunPlan {
                planned_request_upper_bound: 2,
                reserved_candidate_credits: 2,
                reserved_judge_credits: 0,
                max_age_ms: 60_000,
            },
            queue_capacity: 1,
        })
        .unwrap();
        let first = paused.accept().unwrap();
        let second = paused.accept().unwrap();
        paused
            .try_record(cancelled_outcome(
                first,
                &invalid_prepared.candidates[0],
                &invalid_data.cases[0],
                &invalid_data,
            ))
            .unwrap();
        assert!(matches!(
            paused.try_record(cancelled_outcome(
                second,
                &invalid_prepared.candidates[0],
                &invalid_data.cases[0],
                &invalid_data
            )),
            Err(ManagedQualityWriterError::QueueFull)
        ));
        release.send(()).unwrap();
        let manifest = paused
            .shutdown(false, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!manifest.writer_healthy && !manifest.clean_shutdown);
        assert_eq!(state.calls.lock().unwrap().get("budget-1"), Some(&1));
        server.abort();
    }
}
