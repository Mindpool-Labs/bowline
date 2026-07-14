use std::time::Instant;

use bowline_core::{
    quality::{EvaluatorStatus, ObservedCandidateResponse, QualityCase, QualityRequest},
    quality_run::{JudgeErrorCode, JudgeOutcomeEvidence},
    supply::{Price, Registry},
};
use futures_util::StreamExt;
use reqwest::{header::HeaderValue, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canary::{validate_base_url, validate_env_name, validate_id},
    provenance_digest::{
        digest, JUDGE_AUTHORIZATION_REFERENCE_DOMAIN, JUDGE_CONFIG_DOMAIN, JUDGE_ENDPOINT_DOMAIN,
        JUDGE_MODEL_DOMAIN, JUDGE_RUBRIC_DOMAIN, JUDGE_TEMPLATE_DOMAIN,
    },
};

pub const MAX_RUBRIC_BYTES: usize = 64 * 1024;
pub const JUDGE_TEMPLATE_VERSION: &str = "bowline-subjective-judge-v1";
pub const JUDGE_SYSTEM_INSTRUCTION: &str = "Bowline subjective quality judge v1. Evaluate only the supplied case, expected value, and candidate result against the rubric. Return exactly one JSON object with only a finite score from 0.0 through 1.0: {\"score\":0.0}. Do not return rationale or prose.";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeConfig {
    pub supply_id: String,
    pub base_url: String,
    pub authorization_env: String,
    pub rubric_file: String,
    pub required: bool,
    pub send_customer_content: bool,
    pub score_threshold: f64,
    pub concurrency: usize,
    pub request_timeout_ms: u64,
    pub max_response_bytes: usize,
}

#[derive(Clone)]
pub(crate) struct PreparedJudge {
    pub(crate) config: JudgeConfig,
    pub(crate) model: String,
    pub(crate) endpoint: String,
    pub(crate) authorization: HeaderValue,
    pub(crate) rubric: String,
    pub(crate) price: Option<Price>,
    pub(crate) model_digest: String,
    pub(crate) rubric_digest: String,
    pub(crate) template_digest: String,
    pub(crate) config_digest: String,
    pub(crate) endpoint_digest: String,
    pub(crate) authorization_reference_digest: String,
}

pub(crate) struct JudgeExecution {
    pub(crate) evidence: JudgeOutcomeEvidence,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct JudgeEgress<'a> {
    request: Value,
    expected: &'a std::collections::BTreeMap<String, Value>,
    candidate_text: &'a Option<String>,
    candidate_tool_calls: &'a [bowline_core::quality::ObservedToolCall],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScoreResponse {
    score: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeApiResponse {
    choices: Vec<JudgeChoice>,
    usage: JudgeUsage,
    #[serde(default)]
    #[serde(rename = "id")]
    _id: Option<String>,
    #[serde(default)]
    #[serde(rename = "object")]
    _object: Option<String>,
    #[serde(default)]
    #[serde(rename = "created")]
    _created: Option<u64>,
    #[serde(default)]
    #[serde(rename = "model")]
    _model: Option<String>,
    #[serde(default)]
    #[serde(rename = "system_fingerprint")]
    _system_fingerprint: Option<String>,
    #[serde(default)]
    #[serde(rename = "service_tier")]
    _service_tier: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeChoice {
    message: JudgeMessage,
    #[serde(default)]
    #[serde(rename = "index")]
    _index: Option<u64>,
    #[serde(default)]
    #[serde(rename = "finish_reason")]
    _finish_reason: Option<String>,
    #[serde(default)]
    #[serde(rename = "logprobs")]
    _logprobs: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
    #[serde(default)]
    #[serde(rename = "total_tokens")]
    _total_tokens: Option<u64>,
    #[serde(default)]
    #[serde(rename = "prompt_tokens_details")]
    _prompt_tokens_details: Option<Value>,
    #[serde(default)]
    #[serde(rename = "completion_tokens_details")]
    _completion_tokens_details: Option<Value>,
    #[serde(default)]
    #[serde(rename = "input_tokens_details")]
    _input_tokens_details: Option<Value>,
    #[serde(default)]
    #[serde(rename = "output_tokens_details")]
    _output_tokens_details: Option<Value>,
}

struct ParsedJudgeResponse {
    score: f64,
    input_tokens: u64,
    output_tokens: u64,
}

pub(crate) fn validate_judge_config(
    config: &JudgeConfig,
    global_concurrency: usize,
    wall_time_ms: u64,
) -> Result<(), ()> {
    if validate_id(&config.supply_id).is_err()
        || validate_env_name(&config.authorization_env).is_err()
        || !safe_relative_file(&config.rubric_file)
        || !config.send_customer_content
        || !config.score_threshold.is_finite()
        || !(0.0..=1.0).contains(&config.score_threshold)
        || config.concurrency == 0
        || config.concurrency > global_concurrency
        || config.request_timeout_ms == 0
        || config.request_timeout_ms > wall_time_ms
        || config.max_response_bytes == 0
        || config.max_response_bytes > bowline_core::quality::MAX_RESPONSE_BYTES
        || validate_base_url(&config.base_url, true).is_err()
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn prepare_judge<F>(
    config: JudgeConfig,
    registry: &Registry,
    rubric_bytes: &[u8],
    mut resolve_env: F,
) -> Result<PreparedJudge, ()>
where
    F: FnMut(&str) -> Option<String>,
{
    if rubric_bytes.is_empty() || rubric_bytes.len() > MAX_RUBRIC_BYTES {
        return Err(());
    }
    let rubric = std::str::from_utf8(rubric_bytes).map_err(|_| ())?;
    if rubric.contains('\0') {
        return Err(());
    }
    let entry = registry.by_id(&config.supply_id).ok_or(())?;
    let authorization = resolve_env(&config.authorization_env).ok_or(())?;
    if authorization.is_empty()
        || authorization.len() > 8192
        || authorization.contains(['\r', '\n'])
    {
        return Err(());
    }
    let authorization = HeaderValue::from_str(&authorization).map_err(|_| ())?;
    let normalized = serde_json::to_vec(&config).map_err(|_| ())?;
    Ok(PreparedJudge {
        model: entry.model.clone(),
        endpoint: config.base_url.trim_end_matches('/').to_owned(),
        authorization,
        rubric: rubric.to_owned(),
        price: entry.price,
        model_digest: digest(JUDGE_MODEL_DOMAIN, &[entry.model.as_bytes()]),
        rubric_digest: digest(JUDGE_RUBRIC_DOMAIN, &[rubric_bytes]),
        template_digest: digest(
            JUDGE_TEMPLATE_DOMAIN,
            &[
                JUDGE_TEMPLATE_VERSION.as_bytes(),
                JUDGE_SYSTEM_INSTRUCTION.as_bytes(),
            ],
        ),
        config_digest: digest(JUDGE_CONFIG_DOMAIN, &[&normalized]),
        endpoint_digest: digest(
            JUDGE_ENDPOINT_DOMAIN,
            &[config.base_url.trim_end_matches('/').as_bytes()],
        ),
        authorization_reference_digest: digest(
            JUDGE_AUTHORIZATION_REFERENCE_DOMAIN,
            &[config.authorization_env.as_bytes()],
        ),
        config,
    })
}

pub(crate) fn build_request(
    judge: &PreparedJudge,
    case: &QualityCase,
    observed: &ObservedCandidateResponse,
) -> Result<Value, ()> {
    let request = match &case.request {
        QualityRequest::Chat(request) => serde_json::to_value(request),
        QualityRequest::Responses(request) => serde_json::to_value(request),
    }
    .map_err(|_| ())?;
    let user = serde_json::to_string(&JudgeEgress {
        request,
        expected: &case.expected,
        candidate_text: &observed.text,
        candidate_tool_calls: &observed.tool_calls,
    })
    .map_err(|_| ())?;
    Ok(serde_json::json!({
        "model": judge.model,
        "stream": false,
        "messages": [
            {
                "role": "system",
                "content": format!("{JUDGE_SYSTEM_INSTRUCTION}\n\nRubric:\n{}", judge.rubric)
            },
            {"role": "user", "content": user}
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "bowline_subjective_score_v1",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {"score": {"type": "number", "minimum": 0.0, "maximum": 1.0}},
                    "required": ["score"],
                    "additionalProperties": false
                }
            }
        },
        "max_completion_tokens": 32
    }))
}

pub(crate) async fn execute_judge(
    client: &Client,
    judge: &PreparedJudge,
    case: &QualityCase,
    observed: &ObservedCandidateResponse,
) -> JudgeExecution {
    let started = Instant::now();
    let request = match build_request(judge, case, observed) {
        Ok(request) => request,
        Err(()) => return failed(judge, JudgeErrorCode::InvalidResponse, None, None),
    };
    let url = format!("{}/chat/completions", judge.endpoint.trim_end_matches('/'));
    let response = client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, judge.authorization.clone())
        .json(&request)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let code = if error.is_connect() {
                JudgeErrorCode::Transport
            } else {
                JudgeErrorCode::Disconnect
            };
            return failed(judge, code, None, None);
        }
    };
    if !response.status().is_success() {
        return failed(judge, JudgeErrorCode::HttpStatus, None, None);
    }
    let body = match bounded_body(response, judge.config.max_response_bytes).await {
        Ok(body) => body,
        Err(code) => return failed(judge, code, None, None),
    };
    let parsed = match parse_response(&body) {
        Some(parsed) => parsed,
        None if parse_usage(&body).is_none() => {
            return failed(judge, JudgeErrorCode::MissingUsage, None, None)
        }
        None => {
            let usage = parse_usage(&body);
            let cost = usage.and_then(|(input, output)| {
                judge.price.map(|price| price_cost(price, input, output))
            });
            return failed(judge, JudgeErrorCode::InvalidResponse, usage, cost);
        }
    };
    let input_tokens = parsed.input_tokens;
    let output_tokens = parsed.output_tokens;
    let score = parsed.score;
    let cost = judge
        .price
        .map(|price| price_cost(price, input_tokens, output_tokens));
    let status = if score >= judge.config.score_threshold {
        EvaluatorStatus::Pass
    } else {
        EvaluatorStatus::Fail
    };
    let _latency = started.elapsed();
    JudgeExecution {
        evidence: JudgeOutcomeEvidence {
            required: judge.config.required,
            subjective: true,
            status,
            score: Some(score),
            threshold: judge.config.score_threshold,
            error_code: None,
            input_tokens: Some(input_tokens),
            output_tokens: Some(output_tokens),
            cost_usd: cost,
        },
    }
}

pub(crate) fn timeout(judge: &PreparedJudge) -> JudgeExecution {
    failed(judge, JudgeErrorCode::Timeout, None, None)
}

pub(crate) fn scheduler_error(judge: &PreparedJudge) -> JudgeExecution {
    failed(judge, JudgeErrorCode::SchedulerError, None, None)
}

fn failed(
    judge: &PreparedJudge,
    error_code: JudgeErrorCode,
    usage: Option<(u64, u64)>,
    cost_usd: Option<f64>,
) -> JudgeExecution {
    JudgeExecution {
        evidence: JudgeOutcomeEvidence {
            required: judge.config.required,
            subjective: true,
            status: EvaluatorStatus::Error,
            score: None,
            threshold: judge.config.score_threshold,
            error_code: Some(error_code),
            input_tokens: usage.map(|value| value.0),
            output_tokens: usage.map(|value| value.1),
            cost_usd,
        },
    }
}

async fn bounded_body(response: reqwest::Response, max: usize) -> Result<Vec<u8>, JudgeErrorCode> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| JudgeErrorCode::Disconnect)?;
        if body.len().saturating_add(chunk.len()) > max {
            return Err(JudgeErrorCode::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_response(body: &[u8]) -> Option<ParsedJudgeResponse> {
    let response: JudgeApiResponse = serde_json::from_slice(body).ok()?;
    if response.choices.len() != 1 {
        return None;
    }
    let choice = response.choices.into_iter().next()?;
    if choice.message.role != "assistant" {
        return None;
    }
    let score: ScoreResponse = serde_json::from_str(&choice.message.content).ok()?;
    let score = score
        .score
        .is_finite()
        .then_some(score.score)
        .filter(|score| (0.0..=1.0).contains(score))?;
    let input_tokens = response
        .usage
        .prompt_tokens
        .or(response.usage.input_tokens)?;
    let output_tokens = response
        .usage
        .completion_tokens
        .or(response.usage.output_tokens)?;
    Some(ParsedJudgeResponse {
        score,
        input_tokens,
        output_tokens,
    })
}

fn parse_usage(body: &[u8]) -> Option<(u64, u64)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let usage = value.get("usage")?;
    let input = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))?
        .as_u64()?;
    let output = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))?
        .as_u64()?;
    Some((input, output))
}

#[cfg(test)]
fn score(body: &[u8]) -> Option<f64> {
    parse_response(body).map(|response| response.score)
}

fn price_cost(price: Price, input: u64, output: u64) -> f64 {
    (input as f64 * price.input_per_mtok_usd + output as f64 * price.output_per_mtok_usd)
        / 1_000_000.0
}

fn safe_relative_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.starts_with('~')
        && !value
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canary::{
            planned_candidate_requests, prepare_canary_with_rubric, run_canary, CanaryConfig,
            CanaryRunSummary, CandidateConfig, PreparedCanary, PromotionConfig, RunnerConfig,
        },
        quality_writer::{spawn_managed_quality_writer, ManagedQualityWriterOptions},
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
        config::OwnedCostCatalog,
        policy::PolicyBundle,
        quality::{
            assess_promotion, load_quality_dataset, LoadedQualityDataset, PromotionCriteria,
            PromotionInput, PromotionVerdict, PromotionWorkload,
        },
        quality_report::{canonical_outcomes_digest, QualityReport},
        quality_run::{
            QualityAttemptStatus, QualityLedger, QualityOutcome, QualityProvenance,
            QualityRunManifest, QualityRunPlan, QualityRunStore,
        },
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    #[derive(Default)]
    struct EndpointState {
        candidate_calls: AtomicUsize,
        judge_calls: AtomicUsize,
        active: AtomicUsize,
        maximum: AtomicUsize,
        judge_active: AtomicUsize,
        judge_maximum: AtomicUsize,
        mode: Mutex<String>,
        judge_requests: Mutex<Vec<Value>>,
        judge_authorizations: Mutex<Vec<String>>,
    }

    struct ActiveGuard {
        state: Arc<EndpointState>,
        judge: bool,
    }

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.state.active.fetch_sub(1, Ordering::SeqCst);
            if self.judge {
                self.state.judge_active.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    async fn candidate_endpoint(
        State(state): State<Arc<EndpointState>>,
        Json(_body): Json<Value>,
    ) -> Response<Body> {
        state.candidate_calls.fetch_add(1, Ordering::SeqCst);
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.maximum.fetch_max(active, Ordering::SeqCst);
        let _active = ActiveGuard {
            state: Arc::clone(&state),
            judge: false,
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        Response::new(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "output":[{"type":"message","content":[{"type":"output_text","text":"wrong"}]}],
                "usage":{"input_tokens":4,"output_tokens":2}
            }))
            .unwrap(),
        ))
    }

    async fn judge_endpoint(
        State(state): State<Arc<EndpointState>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response<Body> {
        state.judge_calls.fetch_add(1, Ordering::SeqCst);
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.maximum.fetch_max(active, Ordering::SeqCst);
        let judge_active = state.judge_active.fetch_add(1, Ordering::SeqCst) + 1;
        state
            .judge_maximum
            .fetch_max(judge_active, Ordering::SeqCst);
        let _active = ActiveGuard {
            state: Arc::clone(&state),
            judge: true,
        };
        state.judge_requests.lock().unwrap().push(body);
        state.judge_authorizations.lock().unwrap().push(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
        let mode = state.mode.lock().unwrap().clone();
        if mode == "timeout" {
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        } else if mode == "slow-pass" {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
        if mode == "http" {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
        if mode == "oversize" {
            return Response::new(Body::from("x".repeat(20_000)));
        }
        let content = match mode.as_str() {
            "low" => "{\"score\":0.1}",
            "invalid" => "score 0.9 because rationale",
            _ => "{\"score\":0.9}",
        };
        let mut response = serde_json::json!({
            "choices":[{"message":{"role":"assistant","content":content}}]
        });
        if mode != "missing-usage" {
            response["usage"] = serde_json::json!({"prompt_tokens":2,"completion_tokens":1});
        }
        Response::new(Body::from(serde_json::to_vec(&response).unwrap()))
    }

    async fn fake_endpoint() -> (String, Arc<EndpointState>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(EndpointState::default());
        let app = Router::new()
            .route("/v1/responses", post(candidate_endpoint))
            .route("/v1/chat/completions", post(judge_endpoint))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/v1/"), state, task)
    }

    fn registry(judge_price: bool) -> Registry {
        Registry::from_json(
            &serde_json::json!({
                "feed_version":"test",
                "entries":[
                    {"id":"public/candidate","model":"candidate-model","location":"test","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0},"ratings":{},"available":true},
                    {"id":"public/judge","model":"judge-model","location":"test","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price": if judge_price { serde_json::json!({"input_per_mtok_usd":3.0,"output_per_mtok_usd":4.0}) } else { Value::Null },"ratings":{},"available":true}
                ]
            })
            .to_string(),
        )
        .unwrap()
    }

    fn dataset(cases: usize) -> Arc<LoadedQualityDataset> {
        let manifest = b"version: 1\ndataset_id: judge-test\nprotocol: responses\ncases_file: cases.jsonl\ntask_class: mechanical\npolicy_identity:\n  app: support\n  tags: [test]\n";
        let rows = (0..cases)
            .map(|index| serde_json::json!({"case_id":format!("case-{index}"),"request":{"input":format!("prompt-{index}")},"expected":{"answer":"ok"}}).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let evaluators = b"version: 1\nevaluators:\n  - { id: answer, kind: exact-match, expected_key: answer, required: true }\n";
        Arc::new(load_quality_dataset(manifest, rows.as_bytes(), evaluators).unwrap())
    }

    fn prepared(
        base_url: &str,
        required: bool,
        max_tokens: u64,
        judge_price: bool,
    ) -> PreparedCanary {
        prepare_canary_with_rubric(
            CanaryConfig {
                version: 1,
                candidates: vec![CandidateConfig {
                    supply_id: "public/candidate".into(),
                    base_url: base_url.into(),
                    authorization_env: "BOWLINE_TEST_CANDIDATE_AUTH".into(),
                }],
                runner: RunnerConfig {
                    send_customer_content: false,
                    concurrency: 4,
                    per_candidate_concurrency: 1,
                    max_requests: 100,
                    max_wall_time_ms: 2_000,
                    request_timeout_ms: 500,
                    shutdown_grace_ms: 1_000,
                    max_response_bytes: 65_536,
                    max_observed_tokens: max_tokens,
                    max_observed_cost_usd: 10.0,
                    writer_queue_capacity: 32,
                },
                promotion: PromotionConfig {
                    min_samples: 1,
                    min_pass_rate: 0.0,
                    min_wilson_lower_95: 0.0,
                    max_error_rate: 1.0,
                    max_p95_latency_ms: 2_000,
                    max_age_ms: 60_000,
                },
                judge: Some(JudgeConfig {
                    supply_id: "public/judge".into(),
                    base_url: base_url.into(),
                    authorization_env: "BOWLINE_TEST_JUDGE_AUTH".into(),
                    rubric_file: "rubric.md".into(),
                    required,
                    send_customer_content: true,
                    score_threshold: 0.8,
                    concurrency: 1,
                    request_timeout_ms: 500,
                    max_response_bytes: 16_384,
                }),
            },
            &registry(judge_price),
            Some(b"Synthetic rubric only."),
            |_| Some("Bearer synthetic-secret".into()),
        )
        .unwrap()
    }

    fn provenance(data: &LoadedQualityDataset, prepared: &PreparedCanary) -> QualityProvenance {
        let judge = prepared.judge_provenance().unwrap();
        QualityProvenance {
            dataset_manifest_digest: data.digests.dataset_manifest_digest.clone(),
            cases_digest: data.digests.cases_digest.clone(),
            dataset_digest: data.digests.dataset_digest.clone(),
            evaluator_digest: data.digests.evaluator_digest.clone(),
            candidate_config_digest: prepared.candidate_config_digest.clone(),
            policy_digest: policy().digest().to_owned(),
            registry_digest: format!("sha256:{}", "b".repeat(64)),
            owned_cost_digest: Some(OwnedCostCatalog::default().normalized_digest().to_owned()),
            judge_model_digest: Some(judge.model_digest),
            judge_rubric_digest: Some(judge.rubric_digest),
            judge_template_digest: Some(judge.template_digest),
            judge_config_digest: Some(judge.config_digest),
            judge_endpoint_digest: Some(judge.endpoint_digest),
            judge_authorization_reference_digest: Some(judge.authorization_reference_digest),
        }
    }

    fn policy() -> PolicyBundle {
        PolicyBundle::from_yaml(
            "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n    require:\n      supply_class: [public-api]\n",
        )
        .unwrap()
    }

    async fn run_once(
        base_url: &str,
        state: &EndpointState,
        mode: &str,
        required: bool,
        cases: usize,
        max_tokens: u64,
        judge_price: bool,
    ) -> (CanaryRunSummary, bool, Vec<QualityOutcome>) {
        let (summary, incomplete, outcomes, _) = run_once_with_manifest(
            base_url,
            state,
            mode,
            required,
            cases,
            max_tokens,
            judge_price,
        )
        .await;
        (summary, incomplete, outcomes)
    }

    async fn run_once_with_manifest(
        base_url: &str,
        state: &EndpointState,
        mode: &str,
        required: bool,
        cases: usize,
        max_tokens: u64,
        judge_price: bool,
    ) -> (
        CanaryRunSummary,
        bool,
        Vec<QualityOutcome>,
        QualityRunManifest,
    ) {
        *state.mode.lock().unwrap() = mode.into();
        let data = dataset(cases);
        let prepared = prepared(base_url, required, max_tokens, judge_price);
        let candidate_credits = prepared.candidate_request_count(cases).unwrap();
        let judge_credits = prepared.judge_request_count(cases).unwrap();
        let planned = planned_candidate_requests(&prepared, cases).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let writer = spawn_managed_quality_writer(ManagedQualityWriterOptions {
            root: temp.path().join("quality-runs"),
            provenance: provenance(&data, &prepared),
            plan: QualityRunPlan {
                planned_request_upper_bound: planned,
                reserved_candidate_credits: candidate_credits,
                reserved_judge_credits: judge_credits,
                max_age_ms: 60_000,
            },
            queue_capacity: 32,
        })
        .unwrap();
        let directory = writer.directory().to_owned();
        let (summary, incomplete) = run_canary(prepared, data, writer).await.unwrap();
        let outcomes = QualityLedger::read_all(&directory, summary.accepted)
            .unwrap()
            .outcomes;
        let manifest = QualityRunStore::load_manifest(&directory.join("manifest.json")).unwrap();
        (summary, incomplete, outcomes, manifest)
    }

    fn runtime_report_verdict(
        manifest: &QualityRunManifest,
        outcomes: &[QualityOutcome],
        judge_required: bool,
        judge_price: bool,
    ) -> (PromotionVerdict, bowline_core::quality::GateResult) {
        let data = dataset(1);
        let registry = registry(judge_price);
        let owned_costs = OwnedCostCatalog::default();
        let overlay = assess_promotion(PromotionInput {
            manifest,
            outcomes,
            gaps: &[],
            policy: &policy(),
            registry: &registry,
            registry_digest: &manifest.provenance.registry_digest,
            owned_costs: &owned_costs,
            workload: &PromotionWorkload {
                app: data.manifest.policy_identity.app.clone(),
                tags: data.manifest.policy_identity.tags.clone(),
            },
            candidate_supply_id: "public/candidate",
            task_class: data.manifest.task_class,
            protocol: data.manifest.protocol,
            dataset_digest: &data.digests.dataset_digest,
            evaluator_digest: &data.digests.evaluator_digest,
            criteria: PromotionCriteria {
                min_samples: 1,
                min_pass_rate: 0.0,
                min_wilson_lower_95: 0.0,
                max_candidate_error_rate: 1.0,
                max_p95_latency_ms: 2_000,
            },
            judge_required,
            as_of_ms: manifest.completed_at_ms.unwrap(),
        })
        .unwrap();
        let report = QualityReport::new(
            manifest,
            vec![overlay],
            manifest.completed_at_ms.unwrap(),
            true,
            judge_required,
            canonical_outcomes_digest(outcomes).unwrap(),
        )
        .unwrap();
        (
            report.candidates[0].assessment.completion_verdict,
            report.candidates[0].assessment.gates.cost,
        )
    }

    #[test]
    fn optional_judge_boundary_is_strict_bounded_and_content_free() {
        let config = JudgeConfig {
            supply_id: "public/judge".into(),
            base_url: "http://127.0.0.1:2/v1/".into(),
            authorization_env: "BOWLINE_TEST_JUDGE_AUTHORIZATION".into(),
            rubric_file: "rubric.md".into(),
            required: true,
            send_customer_content: true,
            score_threshold: 0.8,
            concurrency: 1,
            request_timeout_ms: 500,
            max_response_bytes: 16_384,
        };
        assert!(validate_judge_config(&config, 2, 1_000).is_ok());
        for mutate in [
            |value: &mut JudgeConfig| value.send_customer_content = false,
            |value: &mut JudgeConfig| value.score_threshold = f64::NAN,
            |value: &mut JudgeConfig| value.concurrency = 0,
            |value: &mut JudgeConfig| value.request_timeout_ms = 0,
            |value: &mut JudgeConfig| value.max_response_bytes = 0,
            |value: &mut JudgeConfig| value.rubric_file = "../secret".into(),
            |value: &mut JudgeConfig| value.base_url = "https://example.com/token/v1/".into(),
        ] {
            let mut invalid = config.clone();
            mutate(&mut invalid);
            assert!(validate_judge_config(&invalid, 2, 1_000).is_err());
        }
        assert!(score(br#"{"id":"judge-1","object":"chat.completion","created":1,"model":"judge-model","system_fingerprint":"fp","service_tier":"default","choices":[{"index":0,"finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"{\"score\":0.8}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#).is_some());
        for invalid in [
            br#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"content":"{\"score\":0.8}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"user","content":"{\"score\":0.8}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"system","content":"{\"score\":0.8}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"assistant","content":[{"type":"text","text":"{\"score\":0.8}"}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"assistant","content":"{\"score\":0.8}","name":"extra"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"assistant","content":"{\"score\":0.8}"}},{"message":{"role":"assistant","content":"{\"score\":0.8}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"provider_extension":true,"choices":[{"message":{"role":"assistant","content":"{\"score\":0.8}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"assistant","content":"{\"score\":2}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"role":"assistant","content":"{\"score\":0.8,\"rationale\":\"x\"}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.as_slice(),
        ] {
            assert!(score(invalid).is_none());
        }
        assert!(!format!("{config:?}").contains("Bearer"));
        assert_eq!(config.request_timeout_ms, 500);
        assert!(serde_yaml::from_str::<JudgeConfig>(
            "supply_id: x\nbase_url: http://127.0.0.1/v1/\nauthorization_env: AUTH\nrubric_file: r\nrequired: true\nsend_customer_content: true\nscore_threshold: 0.5\nconcurrency: 1\nrequest_timeout_ms: 1\nmax_response_bytes: 1\nunknown: true\n"
        )
        .is_err());
        let first = prepare_judge(config.clone(), &registry(true), b"rubric-a", |_| {
            Some("Bearer first-secret".into())
        })
        .unwrap();
        let second = prepare_judge(config.clone(), &registry(true), b"rubric-b", |_| {
            Some("Bearer second-secret".into())
        })
        .unwrap();
        assert_ne!(first.rubric_digest, second.rubric_digest);
        assert_eq!(first.config_digest, second.config_digest);
        assert_eq!(
            first.authorization_reference_digest,
            second.authorization_reference_digest
        );
        let normalized_judge_config = serde_json::to_vec(&config).unwrap();
        assert_eq!(
            first.config_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::JUDGE_CONFIG_DOMAIN,
                &[&normalized_judge_config],
            )
        );
        assert_eq!(
            first.model_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::JUDGE_MODEL_DOMAIN,
                &[first.model.as_bytes()],
            )
        );
        assert_eq!(
            first.template_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::JUDGE_TEMPLATE_DOMAIN,
                &[
                    JUDGE_TEMPLATE_VERSION.as_bytes(),
                    JUDGE_SYSTEM_INSTRUCTION.as_bytes(),
                ],
            )
        );
        assert_eq!(
            first.rubric_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::JUDGE_RUBRIC_DOMAIN,
                &[b"rubric-a"],
            )
        );
        assert_eq!(
            first.endpoint_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::JUDGE_ENDPOINT_DOMAIN,
                &[first.endpoint.as_bytes()],
            )
        );
        assert_eq!(
            first.authorization_reference_digest,
            crate::provenance_digest::digest(
                crate::provenance_digest::JUDGE_AUTHORIZATION_REFERENCE_DOMAIN,
                &[config.authorization_env.as_bytes()],
            )
        );
        assert!(
            prepare_judge(config.clone(), &registry(true), b"", |_| Some(
                "Bearer x".into()
            ))
            .is_err()
        );
        assert!(prepare_judge(
            config.clone(),
            &registry(true),
            &[b'x'; MAX_RUBRIC_BYTES + 1],
            |_| Some("Bearer x".into())
        )
        .is_err());
        assert!(
            prepare_judge(config.clone(), &registry(true), b"rubric", |_| Some(
                "Bearer x\r\nInjected: y".into()
            ))
            .is_err()
        );
        assert!(prepare_judge(config, &registry(true), b"rubric", |_| None).is_err());
    }

    #[tokio::test]
    async fn judge_runtime_reservation_required_optional_and_budget_matrix() {
        let (base_url, state, server) = fake_endpoint().await;
        let candidate_start = state.candidate_calls.load(Ordering::SeqCst);
        let judge_start = state.judge_calls.load(Ordering::SeqCst);

        let (pass, incomplete, outcomes) =
            run_once(&base_url, &state, "pass", true, 1, 1_000, true).await;
        assert!(!incomplete && pass.candidate_dispatches == 1 && pass.judge_dispatches == 1);
        assert_eq!(pass.unused_judge_credits, 0);
        assert_eq!(
            (pass.candidate_observed_tokens, pass.judge_observed_tokens),
            (6, 3)
        );
        let judged = outcomes[0].judge.as_ref().unwrap();
        assert!(judged.subjective && judged.status == EvaluatorStatus::Pass);
        assert_eq!(
            (judged.input_tokens, judged.output_tokens),
            (Some(2), Some(1))
        );
        assert_eq!(
            outcomes[0].evaluator_outcomes[0].status,
            EvaluatorStatus::Fail
        );

        let (_, _, low) = run_once(&base_url, &state, "low", true, 1, 1_000, true).await;
        assert_eq!(low[0].judge.as_ref().unwrap().status, EvaluatorStatus::Fail);
        let (_, _, required_error) =
            run_once(&base_url, &state, "invalid", true, 1, 1_000, true).await;
        assert_eq!(required_error[0].status, QualityAttemptStatus::JudgeError);
        let (_, optional_incomplete, optional_error) =
            run_once(&base_url, &state, "invalid", false, 1, 1_000, true).await;
        assert!(!optional_incomplete);
        assert_eq!(optional_error[0].status, QualityAttemptStatus::Completed);
        assert_eq!(
            optional_error[0].judge.as_ref().unwrap().status,
            EvaluatorStatus::Error
        );
        let (_, _, missing_usage) =
            run_once(&base_url, &state, "missing-usage", true, 1, 1_000, true).await;
        assert_eq!(missing_usage[0].status, QualityAttemptStatus::JudgeError);
        let (_, _, http_error) = run_once(&base_url, &state, "http", true, 1, 1_000, true).await;
        assert_eq!(http_error[0].status, QualityAttemptStatus::JudgeError);
        let (_, _, timeout_error) =
            run_once(&base_url, &state, "timeout", true, 1, 1_000, true).await;
        assert_eq!(timeout_error[0].status, QualityAttemptStatus::JudgeError);
        let (_, _, oversize_error) =
            run_once(&base_url, &state, "oversize", true, 1, 1_000, true).await;
        assert_eq!(oversize_error[0].status, QualityAttemptStatus::JudgeError);

        let (bounded, bounded_incomplete, bounded_outcomes) =
            run_once(&base_url, &state, "pass", true, 2, 5, true).await;
        assert!(bounded_incomplete && bounded.cancelled);
        assert_eq!(
            (bounded.candidate_dispatches, bounded.judge_dispatches),
            (1, 1)
        );
        assert_eq!(
            (bounded.unused_judge_credits, bounded.cancelled_outcomes),
            (1, 1)
        );
        assert_eq!(
            (
                bounded.candidate_observed_tokens,
                bounded.judge_observed_tokens
            ),
            (6, 3)
        );
        assert_eq!(bounded_outcomes.len(), 2);

        let (_, _, unknown_cost, unknown_manifest) =
            run_once_with_manifest(&base_url, &state, "pass", true, 1, 1_000, false).await;
        assert_eq!(unknown_cost[0].judge.as_ref().unwrap().cost_usd, None);
        assert_eq!(
            runtime_report_verdict(&unknown_manifest, &unknown_cost, true, false),
            (
                PromotionVerdict::CostUnknown,
                bowline_core::quality::GateResult::Unknown
            )
        );
        let (_, _, optional_unknown, optional_unknown_manifest) =
            run_once_with_manifest(&base_url, &state, "pass", false, 1, 1_000, false).await;
        assert_eq!(
            runtime_report_verdict(&optional_unknown_manifest, &optional_unknown, false, false,),
            (
                PromotionVerdict::CostUnknown,
                bowline_core::quality::GateResult::Unknown
            )
        );
        let (_, _, optional_missing_usage, optional_missing_manifest) =
            run_once_with_manifest(&base_url, &state, "missing-usage", false, 1, 1_000, true).await;
        assert_eq!(
            runtime_report_verdict(
                &optional_missing_manifest,
                &optional_missing_usage,
                false,
                true,
            ),
            (
                PromotionVerdict::CostUnknown,
                bowline_core::quality::GateResult::Unknown
            )
        );
        let (concurrent, concurrent_incomplete, _) =
            run_once(&base_url, &state, "slow-pass", true, 4, 1_000, true).await;
        assert!(!concurrent_incomplete);
        assert_eq!(
            (concurrent.candidate_dispatches, concurrent.judge_dispatches),
            (4, 4)
        );
        assert_eq!(state.judge_maximum.load(Ordering::SeqCst), 1);
        assert!(state.maximum.load(Ordering::SeqCst) <= 4);

        let mut reservation = prepared(&base_url, true, 1_000, true);
        reservation.config.runner.max_requests = 1;
        assert!(planned_candidate_requests(&reservation, 1).is_err());
        assert_eq!(
            state.candidate_calls.load(Ordering::SeqCst) - candidate_start,
            16
        );
        assert_eq!(state.judge_calls.load(Ordering::SeqCst) - judge_start, 16);
        assert!(state
            .judge_authorizations
            .lock()
            .unwrap()
            .iter()
            .all(|value| value == "Bearer synthetic-secret"));
        let request = state.judge_requests.lock().unwrap().last().unwrap().clone();
        assert_eq!(request["model"], "judge-model");
        assert_eq!(request["stream"], false);
        let user: Value =
            serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(
            user.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "candidate_text",
                "candidate_tool_calls",
                "expected",
                "request"
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        let serialized = serde_json::to_string(&outcomes).unwrap();
        for forbidden in ["wrong", "Synthetic rubric", "rationale", "synthetic-secret"] {
            assert!(!serialized.contains(forbidden));
        }
        server.abort();
    }
}
