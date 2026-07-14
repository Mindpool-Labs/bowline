use std::collections::{BTreeMap, BTreeSet, HashSet};

use jsonschema::{Draft, JSONSchema};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::{
    config::OwnedCostCatalog,
    policy::{PolicyBundle, WorkloadIdentity},
    quality_run::{
        CandidateErrorKind, CostEvaluatorStatus, QualityAttemptStatus, QualityOutcome,
        QualityRunManifest,
    },
    supply::{Registry, SupplyClass, TaskClass},
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_EVALUATORS_BYTES: usize = 1024 * 1024;
pub const MAX_CASE_BYTES: usize = 1024 * 1024;
pub const MAX_CASES_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CASES: usize = 10_000;
pub const MAX_EVALUATORS: usize = 256;
pub const MAX_REQUEST_BYTES: usize = 512 * 1024;
pub const MAX_EXPECTED_BYTES: usize = 512 * 1024;
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_REGEX_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MESSAGES: usize = 128;
pub const MAX_TOOLS: usize = 64;
pub const MAX_STOP_STRINGS: usize = 4;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_NODES: usize = 10_000;
pub const MAX_TOKEN_LIMIT: u64 = 1_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QualityError {
    #[error("{document} exceeds the compiled byte limit")]
    InputTooLarge { document: &'static str },
    #[error("invalid {document} at line {line}")]
    Parse { document: &'static str, line: usize },
    #[error("unsupported {document} version")]
    Version { document: &'static str },
    #[error("invalid quality input: {0}")]
    Invalid(&'static str),
    #[error("duplicate opaque identifier")]
    DuplicateId,
    #[error("invalid candidate response: {0}")]
    InvalidResponse(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityProtocol {
    Chat,
    Responses,
}

impl QualityProtocol {
    pub fn route(self) -> &'static str {
        match self {
            Self::Chat => "/v1/chat/completions",
            Self::Responses => "/v1/responses",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualityPolicyIdentity {
    pub app: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualityDatasetManifest {
    pub version: u32,
    pub dataset_id: String,
    pub protocol: QualityProtocol,
    pub cases_file: String,
    pub task_class: TaskClass,
    pub policy_identity: QualityPolicyIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityCaseWire {
    pub case_id: String,
    pub request: Value,
    pub expected: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct QualityCase {
    pub case_id: String,
    pub request: QualityRequest,
    pub expected: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "protocol", content = "request")]
pub enum QualityRequest {
    Chat(QualityChatRequest),
    Responses(QualityResponsesRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityChatRequest {
    pub messages: Vec<QualityChatMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<QualityChatFunctionTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<QualityChatToolChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<QualityChatResponseFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityChatMessage {
    pub role: QualityMessageRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityMessageRole {
    System,
    Developer,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityChatFunctionTool {
    #[serde(rename = "type")]
    pub kind: QualityFunctionType,
    pub function: QualityChatFunction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityFunctionType {
    Function,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityChatFunction {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parameters: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum QualityChatToolChoice {
    Scalar(QualityScalarToolChoice),
    Named(QualityChatNamedToolChoice),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityScalarToolChoice {
    None,
    Auto,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityChatNamedToolChoice {
    #[serde(rename = "type")]
    pub kind: QualityFunctionType,
    pub function: QualityNamedFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityNamedFunction {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualityChatResponseFormat {
    JsonObject,
    JsonSchema {
        json_schema: QualityJsonSchemaFormat,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityJsonSchemaFormat {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    pub schema: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityResponsesRequest {
    pub input: QualityResponsesInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<QualityResponsesFunctionTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<QualityResponsesToolChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<QualityResponsesText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<QualityReasoning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum QualityResponsesInput {
    Text(String),
    Messages(Vec<QualityResponsesMessage>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityResponsesMessage {
    pub role: QualityResponsesRole,
    pub content: QualityResponsesContent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityResponsesRole {
    System,
    Developer,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum QualityResponsesContent {
    Text(String),
    Parts(Vec<QualityInputText>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityInputText {
    #[serde(rename = "type")]
    pub kind: QualityInputTextType,
    pub text: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QualityInputTextType {
    InputText,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityResponsesFunctionTool {
    #[serde(rename = "type")]
    pub kind: QualityFunctionType,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parameters: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum QualityResponsesToolChoice {
    Scalar(QualityScalarToolChoice),
    Named(QualityResponsesNamedToolChoice),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityResponsesNamedToolChoice {
    #[serde(rename = "type")]
    pub kind: QualityFunctionType,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityResponsesText {
    pub format: QualityResponsesTextFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualityResponsesTextFormat {
    Text,
    JsonObject,
    JsonSchema {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
        schema: Map<String, Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QualityReasoning {
    pub effort: QualityReasoningEffort,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualityReasoningEffort {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EvaluatorSpec {
    ExactMatch {
        id: String,
        expected_key: String,
        required: bool,
    },
    NormalizedMatch {
        id: String,
        expected_key: String,
        required: bool,
    },
    Regex {
        id: String,
        expected_key: String,
        required: bool,
    },
    JsonSchema {
        id: String,
        expected_key: String,
        required: bool,
    },
    Field {
        id: String,
        pointer: String,
        expected_key: String,
        required: bool,
    },
    ToolCall {
        id: String,
        call_index: usize,
        expected_name_key: String,
        expected_arguments_key: String,
        #[serde(default)]
        require_total_calls: Option<usize>,
        required: bool,
    },
    LatencyCeiling {
        id: String,
        max_ms: u64,
        required: bool,
    },
    CostCeiling {
        id: String,
        max_usd: f64,
        required: bool,
    },
}

impl EvaluatorSpec {
    pub fn id(&self) -> &str {
        match self {
            Self::ExactMatch { id, .. }
            | Self::NormalizedMatch { id, .. }
            | Self::Regex { id, .. }
            | Self::JsonSchema { id, .. }
            | Self::Field { id, .. }
            | Self::ToolCall { id, .. }
            | Self::LatencyCeiling { id, .. }
            | Self::CostCeiling { id, .. } => id,
        }
    }

    pub fn kind(&self) -> EvaluatorKind {
        match self {
            Self::ExactMatch { .. } => EvaluatorKind::ExactMatch,
            Self::NormalizedMatch { .. } => EvaluatorKind::NormalizedMatch,
            Self::Regex { .. } => EvaluatorKind::Regex,
            Self::JsonSchema { .. } => EvaluatorKind::JsonSchema,
            Self::Field { .. } => EvaluatorKind::Field,
            Self::ToolCall { .. } => EvaluatorKind::ToolCall,
            Self::LatencyCeiling { .. } => EvaluatorKind::LatencyCeiling,
            Self::CostCeiling { .. } => EvaluatorKind::CostCeiling,
        }
    }

    pub fn required(&self) -> bool {
        match self {
            Self::ExactMatch { required, .. }
            | Self::NormalizedMatch { required, .. }
            | Self::Regex { required, .. }
            | Self::JsonSchema { required, .. }
            | Self::Field { required, .. }
            | Self::ToolCall { required, .. }
            | Self::LatencyCeiling { required, .. }
            | Self::CostCeiling { required, .. } => *required,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluatorFile {
    version: u32,
    evaluators: Vec<EvaluatorSpec>,
}

pub struct CompiledEvaluator {
    pub spec: EvaluatorSpec,
    regexes: BTreeMap<String, Regex>,
    schemas: BTreeMap<String, JSONSchema>,
}

pub struct LoadedQualityDataset {
    pub manifest: QualityDatasetManifest,
    pub cases: Vec<QualityCase>,
    pub evaluators: Vec<CompiledEvaluator>,
    pub digests: QualityDigests,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualityDigests {
    pub dataset_manifest_digest: String,
    pub cases_digest: String,
    pub evaluator_digest: String,
    pub dataset_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObservedToolCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObservedCandidateResponse {
    pub text: Option<String>,
    pub structured: Option<Value>,
    pub tool_calls: Vec<ObservedToolCall>,
    pub latency_ms: u64,
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluatorKind {
    ExactMatch,
    NormalizedMatch,
    Regex,
    JsonSchema,
    Field,
    ToolCall,
    LatencyCeiling,
    CostCeiling,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluatorStatus {
    Pass,
    Fail,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorOutcome {
    pub evaluator_id: String,
    pub kind: EvaluatorKind,
    pub status: EvaluatorStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub required: bool,
    pub subjective: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaseEvaluation {
    pub required_passed: bool,
    pub outcomes: Vec<EvaluatorOutcome>,
}

pub fn load_quality_dataset(
    manifest_bytes: &[u8],
    cases_bytes: &[u8],
    evaluator_bytes: &[u8],
) -> Result<LoadedQualityDataset, QualityError> {
    limit(cases_bytes, MAX_CASES_BYTES, "dataset cases")?;
    limit(evaluator_bytes, MAX_EVALUATORS_BYTES, "evaluators")?;
    let manifest = parse_quality_dataset_manifest(manifest_bytes)?;

    let evaluator_file: EvaluatorFile =
        serde_yaml::from_slice(evaluator_bytes).map_err(|error| yaml_error("evaluators", error))?;
    if evaluator_file.version != 1 {
        return Err(QualityError::Version {
            document: "evaluators",
        });
    }
    if evaluator_file.evaluators.is_empty() || evaluator_file.evaluators.len() > MAX_EVALUATORS {
        return Err(QualityError::Invalid("invalid evaluator count"));
    }

    let mut cases = Vec::new();
    let mut case_ids = HashSet::new();
    for (index, line) in cases_bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        limit(line, MAX_CASE_BYTES, "dataset case")?;
        if cases.len() == MAX_CASES {
            return Err(QualityError::Invalid("too many dataset cases"));
        }
        let wire: QualityCaseWire =
            serde_json::from_slice(line).map_err(|_| QualityError::Parse {
                document: "dataset cases",
                line: index + 1,
            })?;
        validate_id(&wire.case_id)?;
        if !case_ids.insert(wire.case_id.clone()) {
            return Err(QualityError::DuplicateId);
        }
        validate_json(
            &Value::Object(wire.expected.clone().into_iter().collect()),
            MAX_EXPECTED_BYTES,
        )?;
        for key in wire.expected.keys() {
            validate_id(key)?;
        }
        validate_json(&wire.request, MAX_REQUEST_BYTES)?;
        let request = parse_request(manifest.protocol, wire.request)?;
        cases.push(QualityCase {
            case_id: wire.case_id,
            request,
            expected: wire.expected,
        });
    }
    if cases.is_empty() {
        return Err(QualityError::Invalid("dataset has no cases"));
    }

    let evaluators = compile_evaluators(evaluator_file.evaluators, &cases)?;
    let manifest_raw = Sha256::digest(manifest_bytes);
    let cases_raw = Sha256::digest(cases_bytes);
    let evaluator_raw = Sha256::digest(evaluator_bytes);
    let dataset_raw = tuple_digest(b"bowline-quality-dataset-v1", &[&manifest_raw, &cases_raw]);
    Ok(LoadedQualityDataset {
        manifest,
        cases,
        evaluators,
        digests: QualityDigests {
            dataset_manifest_digest: format!("sha256:{manifest_raw:x}"),
            cases_digest: format!("sha256:{cases_raw:x}"),
            evaluator_digest: format!("sha256:{evaluator_raw:x}"),
            dataset_digest: format!("sha256:{dataset_raw:x}"),
        },
    })
}

pub fn parse_quality_dataset_manifest(
    manifest_bytes: &[u8],
) -> Result<QualityDatasetManifest, QualityError> {
    limit(manifest_bytes, MAX_MANIFEST_BYTES, "dataset manifest")?;
    let manifest: QualityDatasetManifest = serde_yaml::from_slice(manifest_bytes)
        .map_err(|error| yaml_error("dataset manifest", error))?;
    if manifest.version != 1 {
        return Err(QualityError::Version {
            document: "dataset manifest",
        });
    }
    validate_id(&manifest.dataset_id)?;
    validate_id(&manifest.policy_identity.app)?;
    validate_cases_file(&manifest.cases_file)?;
    validate_tags(&manifest.policy_identity.tags)?;
    Ok(manifest)
}

fn yaml_error(document: &'static str, error: serde_yaml::Error) -> QualityError {
    QualityError::Parse {
        document,
        line: error.location().map_or(1, |location| location.line()),
    }
}

fn limit(bytes: &[u8], max: usize, document: &'static str) -> Result<(), QualityError> {
    (bytes.len() <= max)
        .then_some(())
        .ok_or(QualityError::InputTooLarge { document })
}

fn validate_id(value: &str) -> Result<(), QualityError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(QualityError::Invalid("invalid opaque identifier"));
    }
    Ok(())
}

fn validate_cases_file(value: &str) -> Result<(), QualityError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.starts_with('/')
        || value.starts_with('~')
        || value
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(QualityError::Invalid("invalid cases file"));
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> Result<(), QualityError> {
    if tags.len() > 128 {
        return Err(QualityError::Invalid("too many policy tags"));
    }
    for tag in tags {
        if tag.is_empty() || tag.len() > MAX_TEXT_BYTES {
            return Err(QualityError::Invalid("invalid policy tag"));
        }
    }
    Ok(())
}

fn validate_json(value: &Value, max_bytes: usize) -> Result<(), QualityError> {
    if serde_json::to_vec(value)
        .map_err(|_| QualityError::Invalid("invalid JSON value"))?
        .len()
        > max_bytes
    {
        return Err(QualityError::Invalid("JSON value exceeds byte limit"));
    }
    let mut stack = vec![(value, 1usize)];
    let mut nodes = 0usize;
    while let Some((current, depth)) = stack.pop() {
        nodes += 1;
        if depth > MAX_JSON_DEPTH {
            return Err(QualityError::Invalid("JSON value exceeds depth limit"));
        }
        if nodes > MAX_JSON_NODES {
            return Err(QualityError::Invalid("JSON value exceeds node limit"));
        }
        match current {
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(map) => stack.extend(map.values().map(|item| (item, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

fn reject_refs(value: &Value) -> Result<(), QualityError> {
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::Array(items) => stack.extend(items),
            Value::Object(map) => {
                if map.contains_key("$ref") {
                    return Err(QualityError::Invalid(
                        "JSON Schema references are forbidden",
                    ));
                }
                stack.extend(map.values());
            }
            _ => {}
        }
    }
    Ok(())
}

fn tuple_digest(domain: &[u8], values: &[&[u8]]) -> sha2::digest::Output<Sha256> {
    let mut digest = Sha256::new();
    digest.update(domain);
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.finalize()
}

fn parse_request(protocol: QualityProtocol, value: Value) -> Result<QualityRequest, QualityError> {
    match protocol {
        QualityProtocol::Chat => {
            let request: QualityChatRequest = serde_json::from_value(value)
                .map_err(|_| QualityError::Invalid("invalid chat request"))?;
            validate_chat_request(&request)?;
            Ok(QualityRequest::Chat(request))
        }
        QualityProtocol::Responses => {
            let request: QualityResponsesRequest = serde_json::from_value(value)
                .map_err(|_| QualityError::Invalid("invalid responses request"))?;
            validate_responses_request(&request)?;
            Ok(QualityRequest::Responses(request))
        }
    }
}

fn validate_text(value: &str) -> Result<(), QualityError> {
    if value.len() > MAX_TEXT_BYTES {
        Err(QualityError::Invalid("text exceeds byte limit"))
    } else {
        Ok(())
    }
}

fn validate_number(value: Option<f64>, max: f64, name: &'static str) -> Result<(), QualityError> {
    if value.is_some_and(|value| !value.is_finite() || value < 0.0 || value > max) {
        Err(QualityError::Invalid(name))
    } else {
        Ok(())
    }
}

fn validate_schema_map(map: &Map<String, Value>) -> Result<(), QualityError> {
    let value = Value::Object(map.clone());
    validate_json(&value, MAX_EXPECTED_BYTES)?;
    reject_refs(&value)
}

fn validate_chat_request(request: &QualityChatRequest) -> Result<(), QualityError> {
    if request.messages.is_empty()
        || request.messages.len() > MAX_MESSAGES
        || request.tools.len() > MAX_TOOLS
    {
        return Err(QualityError::Invalid("invalid chat message or tool count"));
    }
    for message in &request.messages {
        validate_text(&message.content)?;
    }
    for tool in &request.tools {
        validate_id(&tool.function.name)?;
        if let Some(description) = &tool.function.description {
            validate_text(description)?;
        }
        validate_schema_map(&tool.function.parameters)?;
    }
    if let Some(QualityChatToolChoice::Named(choice)) = &request.tool_choice {
        validate_id(&choice.function.name)?;
    }
    if let Some(QualityChatResponseFormat::JsonSchema { json_schema }) = &request.response_format {
        validate_id(&json_schema.name)?;
        validate_schema_map(&json_schema.schema)?;
    }
    validate_number(request.temperature, 2.0, "invalid temperature")?;
    validate_number(request.top_p, 1.0, "invalid top-p")?;
    if request
        .max_completion_tokens
        .is_some_and(|value| value == 0 || value > MAX_TOKEN_LIMIT)
    {
        return Err(QualityError::Invalid("invalid max completion tokens"));
    }
    if let Some(stop) = &request.stop {
        if stop.len() > MAX_STOP_STRINGS {
            return Err(QualityError::Invalid("too many stop strings"));
        }
        for item in stop {
            validate_text(item)?;
        }
    }
    Ok(())
}

fn validate_responses_request(request: &QualityResponsesRequest) -> Result<(), QualityError> {
    match &request.input {
        QualityResponsesInput::Text(text) => validate_text(text)?,
        QualityResponsesInput::Messages(messages) => {
            if messages.is_empty() || messages.len() > MAX_MESSAGES {
                return Err(QualityError::Invalid("invalid responses message count"));
            }
            for message in messages {
                match &message.content {
                    QualityResponsesContent::Text(text) => validate_text(text)?,
                    QualityResponsesContent::Parts(parts) => {
                        if parts.is_empty() || parts.len() > MAX_MESSAGES {
                            return Err(QualityError::Invalid("invalid responses content count"));
                        }
                        for part in parts {
                            validate_text(&part.text)?;
                        }
                    }
                }
            }
        }
    }
    if let Some(instructions) = &request.instructions {
        validate_text(instructions)?;
    }
    if request.tools.len() > MAX_TOOLS {
        return Err(QualityError::Invalid("too many tools"));
    }
    for tool in &request.tools {
        validate_id(&tool.name)?;
        if let Some(description) = &tool.description {
            validate_text(description)?;
        }
        validate_schema_map(&tool.parameters)?;
    }
    if let Some(QualityResponsesToolChoice::Named(choice)) = &request.tool_choice {
        validate_id(&choice.name)?;
    }
    if let Some(QualityResponsesText {
        format: QualityResponsesTextFormat::JsonSchema { name, schema, .. },
    }) = &request.text
    {
        validate_id(name)?;
        validate_schema_map(schema)?;
    }
    validate_number(request.temperature, 2.0, "invalid temperature")?;
    validate_number(request.top_p, 1.0, "invalid top-p")?;
    if request
        .max_output_tokens
        .is_some_and(|value| value == 0 || value > MAX_TOKEN_LIMIT)
    {
        return Err(QualityError::Invalid("invalid max output tokens"));
    }
    Ok(())
}

fn compile_evaluators(
    specs: Vec<EvaluatorSpec>,
    cases: &[QualityCase],
) -> Result<Vec<CompiledEvaluator>, QualityError> {
    let mut ids = HashSet::new();
    let mut compiled = Vec::with_capacity(specs.len());
    for spec in specs {
        validate_id(spec.id())?;
        if !ids.insert(spec.id().to_owned()) {
            return Err(QualityError::DuplicateId);
        }
        let (regexes, schemas) = match &spec {
            EvaluatorSpec::Regex { expected_key, .. } => {
                validate_id(expected_key)?;
                let mut values = BTreeMap::new();
                for case in cases {
                    let pattern = expected_string(case, expected_key)?;
                    if pattern.len() > MAX_REGEX_BYTES {
                        return Err(QualityError::Invalid("regex exceeds byte limit"));
                    }
                    let value =
                        Regex::new(pattern).map_err(|_| QualityError::Invalid("invalid regex"))?;
                    values.insert(case.case_id.clone(), value);
                }
                (values, BTreeMap::new())
            }
            EvaluatorSpec::JsonSchema { expected_key, .. } => {
                validate_id(expected_key)?;
                let mut values = BTreeMap::new();
                for case in cases {
                    let value = case
                        .expected
                        .get(expected_key)
                        .ok_or(QualityError::Invalid("missing expected key"))?;
                    if !value.is_object() {
                        return Err(QualityError::Invalid(
                            "JSON Schema expected value must be an object",
                        ));
                    }
                    validate_json(value, MAX_EXPECTED_BYTES)?;
                    reject_refs(value)?;
                    let validator = JSONSchema::options()
                        .with_draft(Draft::Draft202012)
                        .compile(value)
                        .map_err(|_| QualityError::Invalid("invalid JSON Schema"))?;
                    values.insert(case.case_id.clone(), validator);
                }
                (BTreeMap::new(), values)
            }
            _ => {
                validate_expected_contract(&spec, cases)?;
                (BTreeMap::new(), BTreeMap::new())
            }
        };
        compiled.push(CompiledEvaluator {
            spec,
            regexes,
            schemas,
        });
    }
    Ok(compiled)
}

fn validate_expected_contract(
    spec: &EvaluatorSpec,
    cases: &[QualityCase],
) -> Result<(), QualityError> {
    for case in cases {
        match spec {
            EvaluatorSpec::ExactMatch { expected_key, .. }
            | EvaluatorSpec::NormalizedMatch { expected_key, .. } => {
                expected_string(case, expected_key)?;
            }
            EvaluatorSpec::Field {
                expected_key,
                pointer,
                ..
            } => {
                validate_id(expected_key)?;
                validate_json_pointer(pointer)?;
                case.expected
                    .get(expected_key)
                    .ok_or(QualityError::Invalid("missing expected key"))?;
            }
            EvaluatorSpec::ToolCall {
                call_index,
                expected_name_key,
                expected_arguments_key,
                require_total_calls,
                ..
            } => {
                if *call_index >= MAX_TOOLS
                    || require_total_calls
                        .is_some_and(|value| value > MAX_TOOLS || value <= *call_index)
                {
                    return Err(QualityError::Invalid("invalid tool call count or index"));
                }
                validate_id(expected_name_key)?;
                validate_id(expected_arguments_key)?;
                validate_id(expected_string(case, expected_name_key)?)?;
                let arguments = case
                    .expected
                    .get(expected_arguments_key)
                    .ok_or(QualityError::Invalid("missing expected key"))?;
                if !arguments.is_object() {
                    return Err(QualityError::Invalid(
                        "tool arguments expected value must be an object",
                    ));
                }
                validate_json(arguments, MAX_EXPECTED_BYTES)?;
            }
            EvaluatorSpec::CostCeiling { max_usd, .. }
                if !max_usd.is_finite() || *max_usd < 0.0 =>
            {
                return Err(QualityError::Invalid("invalid cost ceiling"))
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_json_pointer(pointer: &str) -> Result<(), QualityError> {
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return Err(QualityError::Invalid("invalid JSON pointer"));
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                return Err(QualityError::Invalid("invalid JSON pointer"));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn expected_string<'a>(case: &'a QualityCase, key: &str) -> Result<&'a str, QualityError> {
    validate_id(key)?;
    case.expected
        .get(key)
        .and_then(Value::as_str)
        .ok_or(QualityError::Invalid("expected value must be a string"))
}

pub fn normalize_candidate_response(
    protocol: QualityProtocol,
    body: &[u8],
    latency_ms: u64,
    cost_usd: Option<f64>,
) -> Result<ObservedCandidateResponse, QualityError> {
    limit(body, MAX_RESPONSE_BYTES, "candidate response")?;
    if cost_usd.is_some_and(|value| !value.is_finite() || value < 0.0) {
        return Err(QualityError::InvalidResponse("invalid-cost"));
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|_| QualityError::InvalidResponse("invalid-json"))?;
    let (text, tool_calls) = match protocol {
        QualityProtocol::Chat => normalize_chat(&value)?,
        QualityProtocol::Responses => normalize_responses(&value)?,
    };
    if let Some(text) = &text {
        validate_text(text).map_err(|_| QualityError::InvalidResponse("response-text-limit"))?;
    }
    let structured = text
        .as_ref()
        .and_then(|text| serde_json::from_str(text).ok());
    if let Some(value) = &structured {
        validate_json(value, MAX_RESPONSE_BYTES)
            .map_err(|_| QualityError::InvalidResponse("response-json-limit"))?;
    }
    Ok(ObservedCandidateResponse {
        text,
        structured,
        tool_calls,
        latency_ms,
        cost_usd,
    })
}

fn normalize_chat(value: &Value) -> Result<(Option<String>, Vec<ObservedToolCall>), QualityError> {
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .ok_or(QualityError::InvalidResponse("chat-choices"))?;
    if choices.len() != 1 {
        return Err(QualityError::InvalidResponse("chat-choice-count"));
    }
    let message = choices[0]
        .get("message")
        .and_then(Value::as_object)
        .ok_or(QualityError::InvalidResponse("chat-message"))?;
    let text = match message.get("content") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        _ => return Err(QualityError::InvalidResponse("chat-content")),
    };
    let calls = normalize_tool_array(message.get("tool_calls"), true)?;
    Ok((text, calls))
}

fn normalize_responses(
    value: &Value,
) -> Result<(Option<String>, Vec<ObservedToolCall>), QualityError> {
    let output = value
        .get("output")
        .and_then(Value::as_array)
        .ok_or(QualityError::InvalidResponse("responses-output"))?;
    if output.len() > MAX_MESSAGES + MAX_TOOLS {
        return Err(QualityError::InvalidResponse("responses-output-limit"));
    }
    let mut text = String::new();
    let mut calls = Vec::new();
    for item in output {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                let content = item
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or(QualityError::InvalidResponse("responses-content"))?;
                for part in content {
                    if part.get("type").and_then(Value::as_str) != Some("output_text") {
                        return Err(QualityError::InvalidResponse("responses-output-item"));
                    }
                    text.push_str(
                        part.get("text")
                            .and_then(Value::as_str)
                            .ok_or(QualityError::InvalidResponse("responses-output-text"))?,
                    );
                }
            }
            Some("function_call") => calls.push(normalize_tool(item, false)?),
            _ => return Err(QualityError::InvalidResponse("responses-output-item")),
        }
    }
    if calls.len() > MAX_TOOLS {
        return Err(QualityError::InvalidResponse("tool-call-limit"));
    }
    Ok(((!text.is_empty()).then_some(text), calls))
}

fn normalize_tool_array(
    value: Option<&Value>,
    chat: bool,
) -> Result<Vec<ObservedToolCall>, QualityError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let calls = value
        .as_array()
        .ok_or(QualityError::InvalidResponse("tool-calls"))?;
    if calls.len() > MAX_TOOLS {
        return Err(QualityError::InvalidResponse("tool-call-limit"));
    }
    calls
        .iter()
        .map(|call| normalize_tool(call, chat))
        .collect()
}

fn normalize_tool(value: &Value, chat: bool) -> Result<ObservedToolCall, QualityError> {
    let source = if chat {
        if value.get("type").and_then(Value::as_str) != Some("function") {
            return Err(QualityError::InvalidResponse("tool-type"));
        }
        value
            .get("function")
            .ok_or(QualityError::InvalidResponse("tool-function"))?
    } else {
        value
    };
    let name = source
        .get("name")
        .and_then(Value::as_str)
        .ok_or(QualityError::InvalidResponse("tool-name"))?;
    validate_id(name).map_err(|_| QualityError::InvalidResponse("tool-name"))?;
    let raw = source
        .get("arguments")
        .and_then(Value::as_str)
        .ok_or(QualityError::InvalidResponse("tool-arguments"))?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(QualityError::InvalidResponse("tool-arguments-limit"));
    }
    let arguments: Value = serde_json::from_str(raw)
        .map_err(|_| QualityError::InvalidResponse("tool-arguments-json"))?;
    if !arguments.is_object() {
        return Err(QualityError::InvalidResponse("tool-arguments-type"));
    }
    validate_json(&arguments, MAX_RESPONSE_BYTES)
        .map_err(|_| QualityError::InvalidResponse("tool-arguments-limit"))?;
    Ok(ObservedToolCall {
        name: name.to_owned(),
        arguments,
    })
}

pub fn evaluate_case(
    case: &QualityCase,
    evaluators: &[CompiledEvaluator],
    observed: &ObservedCandidateResponse,
) -> CaseEvaluation {
    let mut outcomes = Vec::with_capacity(evaluators.len());
    for evaluator in evaluators {
        outcomes.push(evaluate_one(case, evaluator, observed));
    }
    let required_passed = outcomes
        .iter()
        .all(|outcome| !outcome.required || outcome.status == EvaluatorStatus::Pass);
    CaseEvaluation {
        required_passed,
        outcomes,
    }
}

fn evaluate_one(
    case: &QualityCase,
    evaluator: &CompiledEvaluator,
    observed: &ObservedCandidateResponse,
) -> EvaluatorOutcome {
    let spec = &evaluator.spec;
    let mut outcome = EvaluatorOutcome {
        evaluator_id: spec.id().to_owned(),
        kind: spec.kind(),
        status: EvaluatorStatus::Fail,
        error_code: None,
        required: spec.required(),
        subjective: false,
        latency_ms: None,
        cost_usd: None,
    };
    let status = match spec {
        EvaluatorSpec::ExactMatch { expected_key, .. } => {
            compare_text(case, expected_key, observed, false)
        }
        EvaluatorSpec::NormalizedMatch { expected_key, .. } => {
            compare_text(case, expected_key, observed, true)
        }
        EvaluatorSpec::Regex { .. } => {
            match (
                evaluator.regexes.get(&case.case_id),
                observed.text.as_deref(),
            ) {
                (Some(regex), Some(text)) if text.len() <= MAX_TEXT_BYTES => {
                    pass(regex.is_match(text))
                }
                (Some(_), None) => fail("missing-text"),
                _ => error("regex-invalid"),
            }
        }
        EvaluatorSpec::JsonSchema { .. } => {
            match (evaluator.schemas.get(&case.case_id), &observed.structured) {
                (Some(schema), Some(value)) => pass(schema.is_valid(value)),
                (Some(_), None) => fail("invalid-assistant-json"),
                _ => error("schema-invalid"),
            }
        }
        EvaluatorSpec::Field {
            pointer,
            expected_key,
            ..
        } => match (&observed.structured, case.expected.get(expected_key)) {
            (Some(value), Some(expected)) => match value.pointer(pointer) {
                Some(actual) => pass(actual == expected),
                None => fail("field-missing"),
            },
            (None, _) => fail("invalid-assistant-json"),
            _ => error("expected-missing"),
        },
        EvaluatorSpec::ToolCall {
            call_index,
            expected_name_key,
            expected_arguments_key,
            require_total_calls,
            ..
        } => {
            if require_total_calls.is_some_and(|count| observed.tool_calls.len() != count) {
                fail("tool-call-count")
            } else if let Some(call) = observed.tool_calls.get(*call_index) {
                match (
                    expected_string(case, expected_name_key),
                    case.expected.get(expected_arguments_key),
                ) {
                    (Ok(name), Some(arguments)) => {
                        pass(call.name == name && call.arguments == *arguments)
                    }
                    _ => error("expected-missing"),
                }
            } else {
                fail("tool-call-missing")
            }
        }
        EvaluatorSpec::LatencyCeiling { max_ms, .. } => {
            outcome.latency_ms = Some(observed.latency_ms);
            pass(observed.latency_ms <= *max_ms)
        }
        EvaluatorSpec::CostCeiling { max_usd, .. } => match observed.cost_usd {
            Some(cost) => {
                outcome.cost_usd = Some(cost);
                pass(cost <= *max_usd)
            }
            None => error("cost-unknown"),
        },
    };
    outcome.status = status.0;
    outcome.error_code = status.1.map(str::to_owned);
    outcome
}

fn compare_text(
    case: &QualityCase,
    expected_key: &str,
    observed: &ObservedCandidateResponse,
    normalized: bool,
) -> (EvaluatorStatus, Option<&'static str>) {
    match (
        expected_string(case, expected_key),
        observed.text.as_deref(),
    ) {
        (Ok(expected), Some(actual)) => {
            let equal = if normalized {
                normalize_text(expected) == normalize_text(actual)
            } else {
                expected == actual
            };
            pass(equal)
        }
        (Ok(_), None) => fail("missing-text"),
        _ => error("expected-missing"),
    }
}

fn normalize_text(value: &str) -> String {
    let normalized: String = value.replace("\r\n", "\n").nfkc().collect();
    normalized.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn pass(value: bool) -> (EvaluatorStatus, Option<&'static str>) {
    if value {
        (EvaluatorStatus::Pass, None)
    } else {
        fail("mismatch")
    }
}
fn fail(code: &'static str) -> (EvaluatorStatus, Option<&'static str>) {
    (EvaluatorStatus::Fail, Some(code))
}
fn error(code: &'static str) -> (EvaluatorStatus, Option<&'static str>) {
    (EvaluatorStatus::Error, Some(code))
}

pub const WILSON_Z_95: f64 = 1.959_963_984_540_054;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionCriteria {
    pub min_samples: u64,
    pub min_pass_rate: f64,
    pub min_wilson_lower_95: f64,
    pub max_candidate_error_rate: f64,
    pub max_p95_latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionWorkload {
    pub app: String,
    pub tags: Vec<String>,
}

pub struct PromotionInput<'a> {
    pub manifest: &'a QualityRunManifest,
    pub outcomes: &'a [QualityOutcome],
    pub gaps: &'a [u64],
    pub policy: &'a PolicyBundle,
    pub registry: &'a Registry,
    pub registry_digest: &'a str,
    pub owned_costs: &'a OwnedCostCatalog,
    pub workload: &'a PromotionWorkload,
    pub candidate_supply_id: &'a str,
    pub task_class: TaskClass,
    pub protocol: QualityProtocol,
    pub dataset_digest: &'a str,
    pub evaluator_digest: &'a str,
    pub criteria: PromotionCriteria,
    pub judge_required: bool,
    pub as_of_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionVerdict {
    PolicyFailed,
    CapacityFailed,
    InsufficientEvidence,
    CostUnknown,
    QualityFailed,
    Eligible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateResult {
    Pass,
    Fail,
    Insufficient,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionGates {
    pub policy: GateResult,
    pub capacity: GateResult,
    pub evidence: GateResult,
    pub cost: GateResult,
    pub quality: GateResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionBlocker {
    PolicyInfeasible,
    RegistryUnavailable,
    CandidateErrorRate,
    CandidateLatency,
    IncompleteRun,
    CancelledRun,
    SequenceGaps,
    WriterFailure,
    InsufficientDispatches,
    InsufficientQualitySamples,
    EmptyLatencySet,
    RequiredEvaluatorError,
    RequiredJudgeError,
    EvidenceMismatch,
    CostUnknown,
    CostCeilingExceeded,
    PassRate,
    WilsonLowerBound,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionMetrics {
    pub dispatched_attempts: u64,
    pub candidate_capacity_errors: u64,
    pub candidate_error_rate: Option<f64>,
    pub successful_latencies: u64,
    pub p95_latency_ms: Option<u64>,
    pub quality_sample_count: u64,
    pub quality_pass_count: u64,
    pub observed_pass_rate: Option<f64>,
    pub wilson_lower_95: Option<f64>,
    pub optional_evaluator_errors: u64,
    pub candidate_cost_usd: Option<f64>,
    pub judge_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionAssessment {
    pub completion_verdict: PromotionVerdict,
    pub effective_verdict: PromotionVerdict,
    pub stale: bool,
    pub gates: PromotionGates,
    pub blockers: Vec<PromotionBlocker>,
    pub metrics: PromotionMetrics,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEvidenceOverlay {
    pub overlay_key: String,
    pub candidate_supply_id: String,
    pub task_class: TaskClass,
    pub protocol: QualityProtocol,
    pub dataset_digest: String,
    pub evaluator_digest: String,
    pub completed_at_ms: u64,
    pub valid_until_ms: u64,
    pub assessment: PromotionAssessment,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum PromotionError {
    #[error("invalid promotion criteria")]
    InvalidCriteria,
    #[error("quality run is not completed")]
    MissingCompletionTime,
}

pub fn wilson_lower_95(passes: u64, samples: u64) -> Option<f64> {
    if samples == 0 {
        return None;
    }
    let n = samples as f64;
    let p = passes as f64 / n;
    let z2 = WILSON_Z_95 * WILSON_Z_95;
    let center = p + z2 / (2.0 * n);
    let margin = WILSON_Z_95 * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt();
    Some((center - margin) / (1.0 + z2 / n))
}

pub fn nearest_rank_p95(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (95usize.saturating_mul(sorted.len()).saturating_add(99)) / 100;
    sorted.get(rank.saturating_sub(1)).copied()
}

pub fn quality_overlay_key(
    supply_id: &str,
    task_class: TaskClass,
    protocol: QualityProtocol,
    dataset_digest: &str,
    evaluator_digest: &str,
) -> String {
    let task_class = task_class_label(task_class);
    let protocol = protocol_label(protocol);
    let fields = [
        supply_id.as_bytes(),
        task_class.as_bytes(),
        protocol.as_bytes(),
        dataset_digest.as_bytes(),
        evaluator_digest.as_bytes(),
    ];
    let mut digest = Sha256::new();
    digest.update(b"bowline-quality-overlay-v1");
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("sha256:{:x}", digest.finalize())
}

pub fn assess_promotion(
    input: PromotionInput<'_>,
) -> Result<QualityEvidenceOverlay, PromotionError> {
    validate_criteria(input.criteria)?;
    let completed_at_ms = input
        .manifest
        .completed_at_ms
        .ok_or(PromotionError::MissingCompletionTime)?;
    let identity = WorkloadIdentity {
        api_key_digest: None,
        route: input.protocol.route().to_owned(),
        app: Some(input.workload.app.clone()),
        tags: deduplicate_tags(&input.workload.tags),
    };
    let candidate = input.registry.by_id(input.candidate_supply_id);
    let evidence_matches = candidate.is_some_and(|_| {
        let mut sequences = BTreeSet::new();
        input.manifest.validate().is_ok()
            && input.manifest.provenance.dataset_digest == input.dataset_digest
            && input.manifest.provenance.evaluator_digest == input.evaluator_digest
            && input.manifest.provenance.policy_digest == input.policy.digest()
            && input.manifest.provenance.registry_digest == input.registry_digest
            && input.manifest.provenance.owned_cost_digest.as_deref()
                == Some(input.owned_costs.normalized_digest())
            && input.outcomes.iter().all(|outcome| {
                let model_matches = input
                    .registry
                    .by_id(&outcome.candidate_supply_id)
                    .is_some_and(|entry| outcome.candidate_model == entry.model);
                sequences.insert(outcome.sequence)
                    && (1..=input.manifest.accepted).contains(&outcome.sequence)
                    && outcome.validate().is_ok()
                    && model_matches
                    && outcome.protocol == input.protocol
                    && outcome.task_class == input.task_class
                    && outcome.dataset_digest == input.dataset_digest
                    && outcome.evaluator_digest == input.evaluator_digest
            })
    });
    let cost_basis_available = candidate.is_some_and(|entry| {
        entry.price.is_some()
            || (entry.attributes.class == SupplyClass::Owned
                && input
                    .owned_costs
                    .cost_per_mtok(input.candidate_supply_id)
                    .is_some())
    });
    let policy_pass = candidate.is_some_and(|_| {
        input
            .policy
            .feasible(&identity, input.registry)
            .iter()
            .any(|entry| entry.id == input.candidate_supply_id)
    });

    let all_raw_dispatches = input
        .outcomes
        .iter()
        .filter(|outcome| outcome.dispatched)
        .count() as u64;
    let dispatched_attempts = input
        .outcomes
        .iter()
        .filter(|outcome| {
            outcome.dispatched && outcome.candidate_supply_id == input.candidate_supply_id
        })
        .count() as u64;
    let candidate_capacity_errors = input
        .outcomes
        .iter()
        .filter(|outcome| {
            outcome.dispatched
                && outcome.candidate_supply_id == input.candidate_supply_id
                && outcome.status == QualityAttemptStatus::CandidateError
                && matches!(
                    outcome.candidate_error,
                    Some(
                        CandidateErrorKind::Timeout
                            | CandidateErrorKind::Transport
                            | CandidateErrorKind::Disconnect
                            | CandidateErrorKind::HttpStatus
                            | CandidateErrorKind::ResponseTooLarge
                            | CandidateErrorKind::InvalidResponse
                    )
                )
        })
        .count() as u64;
    let candidate_error_rate = (dispatched_attempts > 0)
        .then_some(candidate_capacity_errors as f64 / dispatched_attempts as f64);
    let latencies: Vec<u64> = input
        .outcomes
        .iter()
        .filter(|outcome| {
            outcome.dispatched
                && outcome.candidate_supply_id == input.candidate_supply_id
                && outcome.status.is_normalized_response()
        })
        .filter_map(|outcome| outcome.latency_ms)
        .collect();
    let p95_latency_ms = nearest_rank_p95(&latencies);

    let mut quality_sample_count = 0u64;
    let mut quality_pass_count = 0u64;
    let mut optional_evaluator_errors = 0u64;
    let mut required_evaluator_error = input.outcomes.iter().any(|outcome| {
        outcome.candidate_supply_id == input.candidate_supply_id
            && matches!(
                outcome.status,
                QualityAttemptStatus::EvaluatorError | QualityAttemptStatus::InternalError
            )
    });
    let mut required_judge_error = input.judge_required
        && input.outcomes.iter().any(|outcome| {
            outcome.candidate_supply_id == input.candidate_supply_id
                && outcome.status == QualityAttemptStatus::JudgeError
        });
    let cancelled_outcome = input.outcomes.iter().any(|outcome| {
        outcome.candidate_supply_id == input.candidate_supply_id
            && outcome.status == QualityAttemptStatus::Cancelled
    });
    let mut cost_unknown = false;
    let mut cost_failed = false;
    let mut total_cost = 0.0;
    let mut known_cost_count = 0u64;
    let mut judge_cost = 0.0;
    let mut known_judge_cost_count = 0u64;

    for outcome in input.outcomes {
        if outcome.candidate_supply_id != input.candidate_supply_id {
            continue;
        }
        for evaluator in &outcome.evaluator_outcomes {
            if !evaluator.required && evaluator.status == EvaluatorStatus::Error {
                optional_evaluator_errors += 1;
            }
        }
        if !outcome.dispatched || !outcome.status.is_normalized_response() {
            continue;
        }
        let mut complete = true;
        let mut passes = true;
        for evaluator in &outcome.evaluator_outcomes {
            if evaluator.required {
                match evaluator.status {
                    EvaluatorStatus::Pass => {}
                    EvaluatorStatus::Fail => passes = false,
                    EvaluatorStatus::Error => {
                        complete = false;
                        required_evaluator_error = true;
                    }
                }
            }
        }
        for evaluator in &outcome.cost_evaluators {
            if evaluator.required {
                match evaluator.status {
                    CostEvaluatorStatus::Pass => {}
                    CostEvaluatorStatus::Fail => cost_failed = true,
                    CostEvaluatorStatus::Unknown => cost_unknown = true,
                }
            }
        }
        if let Some(judge) = &outcome.judge {
            if let Some(cost) = judge.cost_usd {
                judge_cost += cost;
                known_judge_cost_count += 1;
            } else {
                cost_unknown = true;
            }
            if input.judge_required && !judge.required {
                complete = false;
                required_judge_error = true;
            } else if judge.required {
                match judge.status {
                    EvaluatorStatus::Pass => {}
                    EvaluatorStatus::Fail => passes = false,
                    EvaluatorStatus::Error => {
                        complete = false;
                        required_judge_error = true;
                    }
                }
            } else if judge.status == EvaluatorStatus::Error {
                optional_evaluator_errors += 1;
            }
        } else if input.judge_required {
            complete = false;
            required_judge_error = true;
        }
        if complete {
            quality_sample_count += 1;
            if passes {
                quality_pass_count += 1;
            }
        }
        if !cost_basis_available
            || outcome.input_tokens.is_none()
            || outcome.output_tokens.is_none()
            || outcome.candidate_cost_usd.is_none()
        {
            cost_unknown = true;
        } else if let Some(cost) = outcome.candidate_cost_usd {
            total_cost += cost;
            known_cost_count += 1;
        }
    }

    let observed_pass_rate = (quality_sample_count > 0)
        .then_some(quality_pass_count as f64 / quality_sample_count as f64);
    let wilson = wilson_lower_95(quality_pass_count, quality_sample_count);
    let mut blockers = BTreeSet::new();
    let policy_gate = if policy_pass {
        GateResult::Pass
    } else {
        blockers.insert(PromotionBlocker::PolicyInfeasible);
        GateResult::Fail
    };
    let mature_capacity = dispatched_attempts >= input.criteria.min_samples;
    let capacity_gate = if candidate.is_some_and(|entry| entry.available == Some(false)) {
        blockers.insert(PromotionBlocker::RegistryUnavailable);
        GateResult::Fail
    } else if mature_capacity
        && candidate_error_rate.is_some_and(|rate| rate > input.criteria.max_candidate_error_rate)
    {
        blockers.insert(PromotionBlocker::CandidateErrorRate);
        GateResult::Fail
    } else if mature_capacity
        && p95_latency_ms.is_some_and(|latency| latency > input.criteria.max_p95_latency_ms)
    {
        blockers.insert(PromotionBlocker::CandidateLatency);
        GateResult::Fail
    } else if !mature_capacity {
        blockers.insert(PromotionBlocker::InsufficientDispatches);
        GateResult::Insufficient
    } else if p95_latency_ms.is_none() {
        blockers.insert(PromotionBlocker::EmptyLatencySet);
        GateResult::Insufficient
    } else {
        GateResult::Pass
    };

    let mut evidence_pass = true;
    if !evidence_matches {
        blockers.insert(PromotionBlocker::EvidenceMismatch);
        evidence_pass = false;
    }
    if !input.manifest.clean_shutdown
        || !input.manifest.reconciled()
        || input.manifest.candidate_dispatches != all_raw_dispatches
    {
        blockers.insert(PromotionBlocker::IncompleteRun);
        evidence_pass = false;
    }
    if input.manifest.cancelled || cancelled_outcome {
        blockers.insert(PromotionBlocker::CancelledRun);
        evidence_pass = false;
    }
    if !input.manifest.writer_healthy {
        blockers.insert(PromotionBlocker::WriterFailure);
        evidence_pass = false;
    }
    if !input.gaps.is_empty() {
        blockers.insert(PromotionBlocker::SequenceGaps);
        evidence_pass = false;
    }
    if quality_sample_count < input.criteria.min_samples {
        blockers.insert(PromotionBlocker::InsufficientQualitySamples);
        evidence_pass = false;
    }
    if required_evaluator_error {
        blockers.insert(PromotionBlocker::RequiredEvaluatorError);
        evidence_pass = false;
    }
    if required_judge_error {
        blockers.insert(PromotionBlocker::RequiredJudgeError);
        evidence_pass = false;
    }
    if capacity_gate == GateResult::Insufficient {
        evidence_pass = false;
    }
    let evidence_gate = if evidence_pass {
        GateResult::Pass
    } else {
        GateResult::Insufficient
    };

    let cost_gate = if cost_unknown {
        blockers.insert(PromotionBlocker::CostUnknown);
        GateResult::Unknown
    } else if cost_failed {
        blockers.insert(PromotionBlocker::CostCeilingExceeded);
        GateResult::Fail
    } else {
        GateResult::Pass
    };

    let rate_failed = observed_pass_rate.is_some_and(|rate| rate < input.criteria.min_pass_rate);
    let wilson_failed = wilson.is_some_and(|value| value < input.criteria.min_wilson_lower_95);
    let quality_gate = if quality_sample_count < input.criteria.min_samples {
        GateResult::Insufficient
    } else if rate_failed || wilson_failed || cost_failed {
        if rate_failed {
            blockers.insert(PromotionBlocker::PassRate);
        }
        if wilson_failed {
            blockers.insert(PromotionBlocker::WilsonLowerBound);
        }
        GateResult::Fail
    } else {
        GateResult::Pass
    };

    let completion_verdict = if policy_gate == GateResult::Fail {
        PromotionVerdict::PolicyFailed
    } else if capacity_gate == GateResult::Fail {
        PromotionVerdict::CapacityFailed
    } else if evidence_gate != GateResult::Pass {
        PromotionVerdict::InsufficientEvidence
    } else if cost_gate == GateResult::Unknown {
        PromotionVerdict::CostUnknown
    } else if quality_gate == GateResult::Fail || cost_gate == GateResult::Fail {
        PromotionVerdict::QualityFailed
    } else {
        PromotionVerdict::Eligible
    };
    let stale = input.as_of_ms > input.manifest.valid_until_ms;
    let effective_verdict = if stale
        && matches!(
            completion_verdict,
            PromotionVerdict::Eligible
                | PromotionVerdict::QualityFailed
                | PromotionVerdict::CostUnknown
        ) {
        PromotionVerdict::InsufficientEvidence
    } else {
        completion_verdict
    };
    let assessment = PromotionAssessment {
        completion_verdict,
        effective_verdict,
        stale,
        gates: PromotionGates {
            policy: policy_gate,
            capacity: capacity_gate,
            evidence: evidence_gate,
            cost: cost_gate,
            quality: quality_gate,
        },
        blockers: blockers.into_iter().collect(),
        metrics: PromotionMetrics {
            dispatched_attempts,
            candidate_capacity_errors,
            candidate_error_rate,
            successful_latencies: latencies.len() as u64,
            p95_latency_ms,
            quality_sample_count,
            quality_pass_count,
            observed_pass_rate,
            wilson_lower_95: wilson,
            optional_evaluator_errors,
            candidate_cost_usd: (known_cost_count > 0).then_some(total_cost),
            judge_cost_usd: (known_judge_cost_count > 0).then_some(judge_cost),
        },
    };
    Ok(QualityEvidenceOverlay {
        overlay_key: quality_overlay_key(
            input.candidate_supply_id,
            input.task_class,
            input.protocol,
            input.dataset_digest,
            input.evaluator_digest,
        ),
        candidate_supply_id: input.candidate_supply_id.to_owned(),
        task_class: input.task_class,
        protocol: input.protocol,
        dataset_digest: input.dataset_digest.to_owned(),
        evaluator_digest: input.evaluator_digest.to_owned(),
        completed_at_ms,
        valid_until_ms: input.manifest.valid_until_ms,
        assessment,
    })
}

fn validate_criteria(criteria: PromotionCriteria) -> Result<(), PromotionError> {
    if criteria.min_samples == 0
        || !criteria.min_pass_rate.is_finite()
        || !(0.0..=1.0).contains(&criteria.min_pass_rate)
        || !criteria.min_wilson_lower_95.is_finite()
        || !(0.0..=1.0).contains(&criteria.min_wilson_lower_95)
        || !criteria.max_candidate_error_rate.is_finite()
        || !(0.0..=1.0).contains(&criteria.max_candidate_error_rate)
    {
        return Err(PromotionError::InvalidCriteria);
    }
    Ok(())
}

fn deduplicate_tags(tags: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for tag in tags {
        if !result.contains(tag) {
            result.push(tag.clone());
        }
    }
    result
}

fn task_class_label(value: TaskClass) -> &'static str {
    match value {
        TaskClass::Mechanical => "mechanical",
        TaskClass::HeavyLifting => "heavy-lifting",
        TaskClass::TasteSensitive => "taste-sensitive",
        TaskClass::Judgment => "judgment",
        TaskClass::Unclassified => "unclassified",
    }
}

fn protocol_label(value: QualityProtocol) -> &'static str {
    match value {
        QualityProtocol::Chat => "chat",
        QualityProtocol::Responses => "responses",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::quality_run::{JudgeOutcomeEvidence, QualityReasonCode};

    #[test]
    fn quality_report_is_advisory_content_free_and_freshness_aware() {
        let outcomes = vec![
            promotion_outcome(1, EvaluatorStatus::Pass),
            promotion_outcome(2, EvaluatorStatus::Pass),
        ];
        let manifest = promotion_manifest(&outcomes);
        let overlay = assess_fixture(
            &manifest,
            &outcomes,
            &[],
            Some(true),
            true,
            true,
            PromotionCriteria {
                min_samples: 2,
                min_pass_rate: 0.0,
                min_wilson_lower_95: 0.0,
                max_candidate_error_rate: 1.0,
                max_p95_latency_ms: 100,
            },
            false,
            900,
        );
        let report = crate::quality_report::QualityReport::new(
            &manifest,
            vec![overlay],
            900,
            false,
            false,
            crate::quality_report::canonical_outcomes_digest(&outcomes).unwrap(),
        )
        .unwrap();
        let v1_bytes = serde_json::to_vec(&report).unwrap();
        assert!(!String::from_utf8_lossy(&v1_bytes).contains("workload_identity_digest"));
        let workload_digest = crate::quality_report::quality_workload_identity_digest(
            QualityProtocol::Responses,
            "support",
            &["environment:prod".into(), "team:ops".into()],
        )
        .unwrap();
        let v2 = crate::quality_report::QualityReportV2::from_v1(
            report.clone(),
            workload_digest.clone(),
        )
        .unwrap();
        assert_eq!(v2.schema_version, 2);
        assert_eq!(v2.workload_identity_digest, workload_digest);
        assert!(v2
            .candidates
            .iter()
            .all(|candidate| candidate.workload_identity_digest == v2.workload_identity_digest));
        assert_ne!(
            crate::quality_report::quality_report_digest(&report).unwrap(),
            crate::quality_report::quality_report_v2_digest(&v2).unwrap()
        );
        let decoded =
            crate::quality_report::parse_quality_report_document(&serde_json::to_vec(&v2).unwrap())
                .unwrap();
        assert!(matches!(
            decoded,
            crate::quality_report::QualityReportDocument::V2(_)
        ));
        assert_eq!(
            decoded.joinable_workload_identity_digest(),
            Some(workload_digest.as_str())
        );
        let legacy = crate::quality_report::parse_quality_report_document(&v1_bytes).unwrap();
        assert!(matches!(
            legacy,
            crate::quality_report::QualityReportDocument::V1(_)
        ));
        assert_eq!(legacy.joinable_workload_identity_digest(), None);
        assert!(!report.stale);
        assert_eq!(
            report.candidates[0].assessment.completion_verdict,
            PromotionVerdict::Eligible
        );
        let stale = report.at_as_of(1_001);
        assert!(stale.stale);
        assert_eq!(
            stale.candidates[0].assessment.effective_verdict,
            PromotionVerdict::InsufficientEvidence
        );
        assert_eq!(
            stale.candidates[0].assessment.completion_verdict,
            PromotionVerdict::Eligible
        );
        let json = serde_json::to_string(&stale).unwrap();
        let markdown = crate::quality_report::render_quality_markdown(&stale);
        for forbidden in [
            "customer-secret",
            "request\"",
            "expected\"",
            "rubric\"",
            "rationale",
            "tool_arguments",
        ] {
            assert!(!json.contains(forbidden), "JSON leaked {forbidden}");
            assert!(!markdown.contains(forbidden), "Markdown leaked {forbidden}");
        }
        assert!(markdown.contains("Completion verdict"));
        assert!(markdown.contains("Wilson lower 95%"));
        assert!(markdown.contains("Provenance"));
        assert_eq!(
            markdown,
            crate::quality_report::render_quality_markdown(&stale)
        );
        let temp = tempfile::tempdir().unwrap();
        crate::quality_report::write_quality_report(temp.path(), &report).unwrap();
        let stored = crate::quality_report::load_quality_report(temp.path()).unwrap();
        assert_eq!(stored, report);
        let ledger = crate::quality_run::QualityLedgerRead {
            outcomes: outcomes.clone(),
            recovery: crate::quality_run::QualityRecovery::Clean { records: 2 },
            gaps: Vec::new(),
        };
        assert!(crate::quality_report::validate_quality_report_evidence(
            &stored, &manifest, &ledger
        )
        .is_err());
        let mut bound_manifest = manifest.clone();
        bound_manifest.outcomes_digest = Some(stored.outcomes_digest.clone());
        bound_manifest.quality_report_digest =
            Some(crate::quality_report::quality_report_digest(&stored).unwrap());
        crate::quality_report::validate_quality_report_evidence(&stored, &bound_manifest, &ledger)
            .unwrap();

        let mut changed_metrics = stored.clone();
        changed_metrics.candidates[0]
            .assessment
            .metrics
            .quality_pass_count = 0;
        assert!(crate::quality_report::validate_quality_report_evidence(
            &changed_metrics,
            &bound_manifest,
            &ledger,
        )
        .is_err());
        let mut changed_gate = stored.clone();
        changed_gate.candidates[0].assessment.gates.cost = GateResult::Unknown;
        assert!(crate::quality_report::validate_quality_report_evidence(
            &changed_gate,
            &bound_manifest,
            &ledger,
        )
        .is_err());
        let mut changed_blockers = stored.clone();
        changed_blockers.candidates[0]
            .assessment
            .blockers
            .push(PromotionBlocker::CostUnknown);
        assert!(crate::quality_report::validate_quality_report_evidence(
            &changed_blockers,
            &bound_manifest,
            &ledger,
        )
        .is_err());
        let mut changed_verdict = stored.clone();
        changed_verdict.candidates[0].assessment.completion_verdict = PromotionVerdict::CostUnknown;
        changed_verdict.candidates[0].assessment.effective_verdict = PromotionVerdict::CostUnknown;
        assert!(crate::quality_report::validate_quality_report_evidence(
            &changed_verdict,
            &bound_manifest,
            &ledger,
        )
        .is_err());

        let mut multi_candidate = stored.clone();
        let mut second_candidate = multi_candidate.candidates[0].clone();
        second_candidate.candidate_supply_id = "public/z-candidate".into();
        second_candidate.overlay_key = format!("sha256:{}", "9".repeat(64));
        multi_candidate.candidates.push(second_candidate);
        let mut multi_manifest = bound_manifest.clone();
        multi_manifest.quality_report_digest =
            Some(crate::quality_report::quality_report_digest(&multi_candidate).unwrap());
        crate::quality_report::validate_quality_report_evidence(
            &multi_candidate,
            &multi_manifest,
            &ledger,
        )
        .unwrap();
        multi_candidate.candidates.reverse();
        assert!(crate::quality_report::validate_quality_report_evidence(
            &multi_candidate,
            &multi_manifest,
            &ledger,
        )
        .is_err());

        let mut changed_ledger = ledger.clone();
        changed_ledger.outcomes[0].candidate_cost_usd = Some(0.02);
        assert!(crate::quality_report::validate_quality_report_evidence(
            &stored,
            &bound_manifest,
            &changed_ledger,
        )
        .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                std::fs::metadata(temp.path().join(crate::quality_report::QUALITY_REPORT_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn quality_report_storage_is_private_atomic_and_symlink_safe() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let outcomes = vec![promotion_outcome(1, EvaluatorStatus::Pass)];
        let manifest = promotion_manifest(&outcomes);
        let report = crate::quality_report::QualityReport::new(
            &manifest,
            vec![assess_fixture(
                &manifest,
                &outcomes,
                &[],
                Some(true),
                true,
                true,
                PromotionCriteria {
                    min_samples: 1,
                    min_pass_rate: 0.0,
                    min_wilson_lower_95: 0.0,
                    max_candidate_error_rate: 1.0,
                    max_p95_latency_ms: 100,
                },
                false,
                900,
            )],
            900,
            false,
            false,
            crate::quality_report::canonical_outcomes_digest(&outcomes).unwrap(),
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        symlink(&sentinel, temp.path().join(".quality-report.tmp")).unwrap();
        std::fs::write(
            temp.path().join(crate::quality_report::QUALITY_REPORT_FILE),
            b"old",
        )
        .unwrap();
        std::fs::set_permissions(
            temp.path().join(crate::quality_report::QUALITY_REPORT_FILE),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();

        crate::quality_report::write_quality_report(temp.path(), &report).unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        let target = temp.path().join(crate::quality_report::QUALITY_REPORT_FILE);
        let metadata = std::fs::symlink_metadata(&target).unwrap();
        assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        std::fs::remove_file(temp.path().join(".quality-report.tmp")).unwrap();
        let legacy_temp = temp.path().join(".quality-report.tmp");
        std::fs::write(&legacy_temp, b"legacy-temp").unwrap();
        std::fs::set_permissions(&legacy_temp, std::fs::Permissions::from_mode(0o666)).unwrap();
        crate::quality_report::write_quality_report(temp.path(), &report).unwrap();
        assert_eq!(std::fs::read(&legacy_temp).unwrap(), b"legacy-temp");

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(crate::quality_report::load_quality_report(temp.path()).is_err());

        std::fs::remove_file(&target).unwrap();
        symlink(&sentinel, &target).unwrap();
        assert!(crate::quality_report::load_quality_report(temp.path()).is_err());

        std::fs::remove_file(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        assert!(crate::quality_report::write_quality_report(temp.path(), &report).is_err());
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".quality-report-")
        }));
    }

    #[test]
    fn unknown_dispatched_judge_cost_reaches_report_verdict() {
        for required in [true, false] {
            let mut outcomes: Vec<_> = (1..=10)
                .map(|sequence| promotion_outcome(sequence, EvaluatorStatus::Pass))
                .collect();
            for outcome in &mut outcomes {
                outcome.judge = Some(crate::quality_run::JudgeOutcomeEvidence {
                    required,
                    subjective: true,
                    status: EvaluatorStatus::Pass,
                    score: Some(0.9),
                    threshold: 0.8,
                    error_code: None,
                    input_tokens: Some(2),
                    output_tokens: Some(1),
                    cost_usd: None,
                });
            }
            let manifest = promotion_manifest(&outcomes);
            let overlay = assess_fixture(
                &manifest,
                &outcomes,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                required,
                1_000,
            );
            let report = crate::quality_report::QualityReport::new(
                &manifest,
                vec![overlay],
                1_000,
                true,
                required,
                crate::quality_report::canonical_outcomes_digest(&outcomes).unwrap(),
            )
            .unwrap();
            assert_eq!(
                report.candidates[0].assessment.completion_verdict,
                PromotionVerdict::CostUnknown,
                "required={required}"
            );
            assert_eq!(
                report.candidates[0].assessment.gates.cost,
                GateResult::Unknown
            );
        }
    }

    const MANIFEST: &str = include_str!("../tests/fixtures/quality/dataset.yaml");
    const CASES: &str = include_str!("../tests/fixtures/quality/support-cases.jsonl");
    const EVALUATORS: &str = include_str!("../tests/fixtures/quality/evaluators.yaml");
    const PROMOTION_DATASET_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const PROMOTION_EVALUATOR_DIGEST: &str =
        "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    fn load_single_evaluator(
        expected: Value,
        evaluator: &str,
    ) -> Result<LoadedQualityDataset, QualityError> {
        let cases = serde_json::to_string(&json!({
            "case_id": "case",
            "request": {"input": "x"},
            "expected": expected,
        }))
        .unwrap();
        let evaluators = format!("version: 1\nevaluators:\n  - {evaluator}\n");
        load_quality_dataset(MANIFEST.as_bytes(), cases.as_bytes(), evaluators.as_bytes())
    }

    fn observed(text: Option<&str>, structured: Option<Value>) -> ObservedCandidateResponse {
        ObservedCandidateResponse {
            text: text.map(str::to_owned),
            structured,
            tool_calls: Vec::new(),
            latency_ms: 0,
            cost_usd: None,
        }
    }

    fn evaluate_single(
        expected: Value,
        evaluator: &str,
        observed: &ObservedCandidateResponse,
    ) -> Result<CaseEvaluation, QualityError> {
        let loaded = load_single_evaluator(expected, evaluator)?;
        Ok(evaluate_case(
            &loaded.cases[0],
            &loaded.evaluators,
            observed,
        ))
    }

    fn promotion_registry(available: Option<bool>, price: bool) -> Registry {
        Registry::from_json(
            &serde_json::to_string(&json!({
                "feed_version":"test",
                "entries":[{
                    "id":"public/candidate",
                    "model":"candidate",
                    "location":"test",
                    "attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},
                    "price": if price { json!({"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0}) } else { Value::Null },
                    "ratings":{},
                    "available":available
                }]
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn promotion_registry_digest(registry: &Registry) -> String {
        format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(registry).unwrap())
        )
    }

    fn promotion_policy(allow: bool) -> PolicyBundle {
        let supply_class = if allow { "public-api" } else { "owned" };
        PolicyBundle::from_yaml(&format!(
            "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n    require:\n      supply_class: [{supply_class}]\n"
        ))
        .unwrap()
    }

    fn promotion_outcome(sequence: u64, evaluator_status: EvaluatorStatus) -> QualityOutcome {
        QualityOutcome {
            sequence,
            case_id: format!("case-{sequence}"),
            candidate_supply_id: "public/candidate".into(),
            candidate_model: "candidate".into(),
            protocol: QualityProtocol::Responses,
            task_class: TaskClass::Mechanical,
            dispatched: true,
            status: QualityAttemptStatus::Completed,
            reason: None,
            candidate_error: None,
            latency_ms: Some(10 + sequence),
            input_tokens: Some(10),
            output_tokens: Some(5),
            candidate_cost_usd: Some(0.01),
            evaluator_outcomes: vec![crate::quality_run::QualityEvaluatorEvidence {
                evaluator_id: "answer".into(),
                kind: EvaluatorKind::ExactMatch,
                status: evaluator_status,
                error_code: (evaluator_status == EvaluatorStatus::Error)
                    .then_some(crate::quality_run::QualityEvaluatorErrorCode::EvaluatorError),
                required: true,
                subjective: false,
                latency_ms: None,
            }],
            cost_evaluators: Vec::new(),
            judge: None,
            dataset_digest: PROMOTION_DATASET_DIGEST.into(),
            evaluator_digest: PROMOTION_EVALUATOR_DIGEST.into(),
        }
    }

    fn promotion_manifest(outcomes: &[QualityOutcome]) -> crate::quality_run::QualityRunManifest {
        let accepted = outcomes.len() as u64;
        let completed = outcomes
            .iter()
            .filter(|outcome| outcome.status == QualityAttemptStatus::Completed)
            .count() as u64;
        let cancelled = outcomes
            .iter()
            .filter(|outcome| outcome.status == QualityAttemptStatus::Cancelled)
            .count() as u64;
        let errors = accepted - completed - cancelled;
        crate::quality_run::QualityRunManifest {
            schema_version: crate::quality_run::QUALITY_RUN_SCHEMA_VERSION,
            binary_version: crate::VERSION.into(),
            run_id: "00000000-0000-0000-0000-000000000001".into(),
            started_at_ms: 100,
            completed_at_ms: Some(900),
            valid_until_ms: 1_000,
            clean_shutdown: true,
            cancelled: false,
            provenance: crate::quality_run::QualityProvenance {
                dataset_manifest_digest: format!("sha256:{}", "a".repeat(64)),
                cases_digest: format!("sha256:{}", "b".repeat(64)),
                dataset_digest: PROMOTION_DATASET_DIGEST.into(),
                evaluator_digest: PROMOTION_EVALUATOR_DIGEST.into(),
                candidate_config_digest: format!("sha256:{}", "c".repeat(64)),
                policy_digest: "sha256:policy".into(),
                registry_digest: "sha256:registry".into(),
                owned_cost_digest: None,
                judge_model_digest: None,
                judge_rubric_digest: None,
                judge_template_digest: None,
                judge_config_digest: None,
                judge_endpoint_digest: None,
                judge_authorization_reference_digest: None,
            },
            planned_request_upper_bound: accepted,
            reserved_candidate_credits: accepted,
            reserved_judge_credits: 0,
            candidate_dispatches: outcomes.iter().filter(|outcome| outcome.dispatched).count()
                as u64,
            judge_dispatches: 0,
            unused_judge_credits: 0,
            accepted,
            recorded: accepted,
            dropped: 0,
            completed,
            errors,
            cancelled_outcomes: cancelled,
            next_sequence: accepted + 1,
            writer_healthy: true,
            writer_error: None,
            last_flush_at_ms: Some(900),
            outcomes_digest: None,
            quality_report_digest: None,
        }
    }

    fn promotion_criteria() -> PromotionCriteria {
        PromotionCriteria {
            min_samples: 2,
            min_pass_rate: 0.8,
            min_wilson_lower_95: 0.5,
            max_candidate_error_rate: 0.25,
            max_p95_latency_ms: 100,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assess_fixture(
        manifest: &crate::quality_run::QualityRunManifest,
        outcomes: &[QualityOutcome],
        gaps: &[u64],
        available: Option<bool>,
        price: bool,
        policy_allows: bool,
        criteria: PromotionCriteria,
        judge_required: bool,
        as_of_ms: u64,
    ) -> QualityEvidenceOverlay {
        let registry = promotion_registry(available, price);
        let policy = promotion_policy(policy_allows);
        let owned_costs = OwnedCostCatalog::default();
        let mut manifest = manifest.clone();
        if manifest.provenance.policy_digest == "sha256:policy" {
            manifest.provenance.policy_digest = policy.digest().to_owned();
        }
        if manifest.provenance.registry_digest == "sha256:registry" {
            manifest.provenance.registry_digest = promotion_registry_digest(&registry);
        }
        if manifest.provenance.owned_cost_digest.is_none() {
            manifest.provenance.owned_cost_digest =
                Some(owned_costs.normalized_digest().to_owned());
        }
        let workload = PromotionWorkload {
            app: "support".into(),
            tags: vec!["prod".into(), "prod".into(), "customer".into()],
        };
        assess_promotion(PromotionInput {
            manifest: &manifest,
            outcomes,
            gaps,
            policy: &policy,
            registry: &registry,
            registry_digest: &promotion_registry_digest(&registry),
            owned_costs: &owned_costs,
            workload: &workload,
            candidate_supply_id: "public/candidate",
            task_class: TaskClass::Mechanical,
            protocol: QualityProtocol::Responses,
            dataset_digest: PROMOTION_DATASET_DIGEST,
            evaluator_digest: PROMOTION_EVALUATOR_DIGEST,
            criteria,
            judge_required,
            as_of_ms,
        })
        .unwrap()
    }

    #[test]
    fn dataset_contract_is_strict_and_bounded() {
        let rejects = |manifest: &[u8], cases: &[u8], evaluators: &[u8]| {
            load_quality_dataset(manifest, cases, evaluators).is_err()
        };
        let simple_evaluator = b"version: 1\nevaluators:\n  - { id: answer, kind: exact-match, expected_key: answer, required: true }\n";
        let simple_case = b"{\"case_id\":\"case\",\"request\":{\"input\":\"x\"},\"expected\":{\"answer\":\"x\"}}\n";

        let manifest_version = MANIFEST.replace("version: 1", "version: 2");
        let manifest_unknown = format!("{MANIFEST}unknown: true\n");
        let manifest_type = MANIFEST.replace("version: 1", "version: one");
        let manifest_large = format!("{MANIFEST}#{}", "x".repeat(MAX_MANIFEST_BYTES));
        let evaluator_version = EVALUATORS.replace("version: 1", "version: 2");
        let evaluator_unknown =
            EVALUATORS.replacen("required: true }", "required: true, extra: true }", 1);
        let evaluator_large = format!("{EVALUATORS}#{}", "x".repeat(MAX_EVALUATORS_BYTES));
        let mut cases_count = String::new();
        for index in 0..=MAX_CASES {
            cases_count.push_str(
                &serde_json::to_string(&json!({
                    "case_id": format!("case-{index}"),
                    "request": {"input": "x"},
                    "expected": {"answer": "x"},
                }))
                .unwrap(),
            );
            cases_count.push('\n');
        }
        let case_count_rejected = matches!(
            load_quality_dataset(
                MANIFEST.as_bytes(),
                cases_count.as_bytes(),
                simple_evaluator,
            ),
            Err(QualityError::Invalid("too many dataset cases"))
        );
        let case_large = format!(
            "{{\"case_id\":\"case\",\"request\":{{\"input\":\"{}\"}},\"expected\":{{\"answer\":\"x\"}}}}",
            "x".repeat(MAX_CASE_BYTES)
        );
        let request_large = format!(
            "{{\"case_id\":\"case\",\"request\":{{\"input\":\"{}\"}},\"expected\":{{\"answer\":\"x\"}}}}",
            "x".repeat(MAX_REQUEST_BYTES)
        );
        let expected_large = format!(
            "{{\"case_id\":\"case\",\"request\":{{\"input\":\"x\"}},\"expected\":{{\"answer\":\"{}\"}}}}",
            "x".repeat(MAX_EXPECTED_BYTES)
        );
        let id_empty = MANIFEST.replace("support-regression-v1", "");
        let id_long = MANIFEST.replace(
            "support-regression-v1",
            &"a".repeat(MAX_IDENTIFIER_BYTES + 1),
        );
        let id_non_ascii = MANIFEST.replace("support-regression-v1", "café");
        let id_unsafe = MANIFEST.replace("support-regression-v1", "unsafe/id");
        let duplicate_cases = format!("{CASES}{CASES}");
        let duplicate_evaluators = EVALUATORS.replace("id: normalized", "id: exact");
        let missing_expected = CASES.replace("\"answer\":\"{\\\"status\\\":\\\"ok\\\"}\",", "");
        let wrong_expected = CASES.replace(
            "\"answer\":\"{\\\"status\\\":\\\"ok\\\"}\"",
            "\"answer\":42",
        );
        let chat_manifest = MANIFEST.replace("protocol: responses", "protocol: chat");
        let multimodal = serde_json::to_string(&json!({
            "case_id":"case",
            "request":{"input":[{"role":"user","content":[{"type":"input_image","image_url":"x"}]}]},
            "expected":{"answer":"x"}
        }))
        .unwrap();
        let too_many_chat = serde_json::to_string(&json!({
            "case_id":"case",
            "request":{"messages":(0..=MAX_MESSAGES).map(|_| json!({"role":"user","content":"x"})).collect::<Vec<_>>()},
            "expected":{"answer":"x"}
        }))
        .unwrap();
        let too_many_responses = serde_json::to_string(&json!({
            "case_id":"case",
            "request":{"input":(0..=MAX_MESSAGES).map(|_| json!({"role":"user","content":"x"})).collect::<Vec<_>>()},
            "expected":{"answer":"x"}
        }))
        .unwrap();
        let too_many_tools = serde_json::to_string(&json!({
            "case_id":"case",
            "request":{"input":"x","tools":(0..=MAX_TOOLS).map(|index| json!({"type":"function","name":format!("t{index}"),"parameters":{}})).collect::<Vec<_>>()},
            "expected":{"answer":"x"}
        }))
        .unwrap();
        let too_many_stops = serde_json::to_string(&json!({
            "case_id":"case",
            "request":{"messages":[{"role":"user","content":"x"}],"stop":["a","b","c","d","e"]},
            "expected":{"answer":"x"}
        }))
        .unwrap();
        let mut deep = json!(null);
        for _ in 0..MAX_JSON_DEPTH {
            deep = json!([deep]);
        }
        let too_many_nodes = Value::Array(vec![Value::Null; MAX_JSON_NODES]);
        let ref_root = CASES.replace(
            "{\"type\":\"object\",\"required\"",
            "{\"$ref\":\"https://invalid.example/schema\",\"type\":\"object\",\"required\"",
        );
        let ref_nested = CASES.replace(
            "{\"const\":\"ok\"}",
            "{\"allOf\":[{\"$ref\":\"file:///tmp/schema\"}],\"const\":\"ok\"}",
        );
        let line_error = match load_quality_dataset(
            MANIFEST.as_bytes(),
            b"{secret customer text",
            EVALUATORS.as_bytes(),
        ) {
            Err(error) => error.to_string() == "invalid dataset cases at line 1",
            Ok(_) => false,
        };

        let mut strict_results = vec![
            (
                "manifest-version",
                rejects(
                    manifest_version.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "manifest-unknown-field",
                rejects(
                    manifest_unknown.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "manifest-invalid-types",
                rejects(
                    manifest_type.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "manifest-bytes",
                rejects(
                    manifest_large.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "evaluator-version",
                rejects(
                    MANIFEST.as_bytes(),
                    CASES.as_bytes(),
                    evaluator_version.as_bytes(),
                ),
            ),
            (
                "evaluator-unknown-field",
                rejects(
                    MANIFEST.as_bytes(),
                    CASES.as_bytes(),
                    evaluator_unknown.as_bytes(),
                ),
            ),
            (
                "evaluator-bytes",
                rejects(
                    MANIFEST.as_bytes(),
                    CASES.as_bytes(),
                    evaluator_large.as_bytes(),
                ),
            ),
            ("case-count", case_count_rejected),
            (
                "case-bytes",
                rejects(MANIFEST.as_bytes(), case_large.as_bytes(), simple_evaluator),
            ),
            (
                "request-bytes",
                rejects(
                    MANIFEST.as_bytes(),
                    request_large.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "expected-bytes",
                rejects(
                    MANIFEST.as_bytes(),
                    expected_large.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "identifier-empty",
                rejects(id_empty.as_bytes(), CASES.as_bytes(), EVALUATORS.as_bytes()),
            ),
            (
                "identifier-too-long",
                rejects(id_long.as_bytes(), CASES.as_bytes(), EVALUATORS.as_bytes()),
            ),
            (
                "identifier-non-ascii",
                rejects(
                    id_non_ascii.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "identifier-unsafe-character",
                rejects(
                    id_unsafe.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "duplicate-case-id",
                rejects(
                    MANIFEST.as_bytes(),
                    duplicate_cases.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "duplicate-evaluator-id",
                rejects(
                    MANIFEST.as_bytes(),
                    CASES.as_bytes(),
                    duplicate_evaluators.as_bytes(),
                ),
            ),
            (
                "missing-expected-key",
                rejects(
                    MANIFEST.as_bytes(),
                    missing_expected.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "wrong-expected-type",
                rejects(
                    MANIFEST.as_bytes(),
                    wrong_expected.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "protocol-request-mismatch",
                rejects(
                    chat_manifest.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "multimodal-content",
                rejects(MANIFEST.as_bytes(), multimodal.as_bytes(), simple_evaluator),
            ),
            (
                "chat-message-count",
                rejects(
                    chat_manifest.as_bytes(),
                    too_many_chat.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "responses-message-count",
                rejects(
                    MANIFEST.as_bytes(),
                    too_many_responses.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "tool-count",
                rejects(
                    MANIFEST.as_bytes(),
                    too_many_tools.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "stop-count",
                rejects(
                    chat_manifest.as_bytes(),
                    too_many_stops.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "json-depth",
                validate_json(&deep, MAX_EXPECTED_BYTES).is_err(),
            ),
            (
                "json-node-count",
                validate_json(&too_many_nodes, MAX_EXPECTED_BYTES).is_err(),
            ),
            (
                "ref-at-root",
                rejects(
                    MANIFEST.as_bytes(),
                    ref_root.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "ref-nested",
                rejects(
                    MANIFEST.as_bytes(),
                    ref_nested.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            ("safe-jsonl-line-error", line_error),
        ];
        for field in [
            "url",
            "headers",
            "authorization",
            "model",
            "stream",
            "placement",
            "cost",
            "evidence",
        ] {
            let cases = format!(
                r#"{{"case_id":"case","request":{{"input":"x","{field}":true}},"expected":{{"answer":"x"}}}}"#
            );
            strict_results.push((
                field,
                rejects(MANIFEST.as_bytes(), cases.as_bytes(), simple_evaluator),
            ));
        }
        let evaluator_type = EVALUATORS.replace("version: 1", "version: one");
        let mut evaluator_count = String::from("version: 1\nevaluators:\n");
        for index in 0..=MAX_EVALUATORS {
            evaluator_count.push_str(&format!(
                "  - {{ id: e{index}, kind: exact-match, expected_key: answer, required: true }}\n"
            ));
        }
        let unsupported_protocol = MANIFEST.replace("protocol: responses", "protocol: embeddings");
        let text_bound = serde_json::to_string(&json!({
            "case_id":"case","request":{"input":"x".repeat(MAX_TEXT_BYTES + 1)},"expected":{"answer":"x"}
        })).unwrap();
        let request_case = |request: Value| {
            serde_json::to_string(&json!({
                "case_id":"case","request":request,"expected":{"answer":"x"}
            }))
            .unwrap()
        };
        let temperature_low = request_case(json!({"input":"x","temperature":-0.1}));
        let temperature_high = request_case(json!({"input":"x","temperature":2.1}));
        let top_p_high = request_case(json!({"input":"x","top_p":1.1}));
        let token_zero = request_case(json!({"input":"x","max_output_tokens":0}));
        let token_high = request_case(json!({"input":"x","max_output_tokens":MAX_TOKEN_LIMIT + 1}));
        let content_count = request_case(json!({
            "input":[{"role":"user","content":(0..=MAX_MESSAGES).map(|_| json!({"type":"input_text","text":"x"})).collect::<Vec<_>>()}]
        }));
        let unsafe_case_id = String::from_utf8(simple_case.to_vec())
            .unwrap()
            .replace("\"case\"", "\"unsafe/id\"");
        let unsafe_evaluator_id = String::from_utf8(simple_evaluator.to_vec())
            .unwrap()
            .replace("id: answer", "id: unsafe/id");
        let unsafe_expected_key = b"{\"case_id\":\"case\",\"request\":{\"input\":\"x\"},\"expected\":{\"answer\":\"x\",\"unsafe/key\":1}}";
        let unsafe_tool = request_case(
            json!({"input":"x","tools":[{"type":"function","name":"unsafe/name","parameters":{}}]}),
        );
        let chat_tool_ref = request_case(
            json!({"messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"tool","parameters":{"properties":{"x":{"$ref":"file:///tmp/x"}}}}}]}),
        );
        let chat_format_ref = request_case(
            json!({"messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"allOf":[{"$ref":"https://invalid.example/x"}]}}}}),
        );
        let responses_tool_ref = request_case(
            json!({"input":"x","tools":[{"type":"function","name":"tool","parameters":{"items":{"$ref":"file:///tmp/x"}}}]}),
        );
        let responses_format_ref = request_case(
            json!({"input":"x","text":{"format":{"type":"json_schema","name":"answer","schema":{"properties":{"x":{"$ref":"https://invalid.example/x"}}}}}}),
        );
        let cases_path = MANIFEST.replace("support-cases.jsonl", "../customer/cases.jsonl");
        let invalid_request_type =
            b"{\"case_id\":\"case\",\"request\":42,\"expected\":{\"answer\":\"x\"}}";
        let invalid_expected_type =
            b"{\"case_id\":\"case\",\"request\":{\"input\":\"x\"},\"expected\":[]}";
        strict_results.extend([
            (
                "evaluator-invalid-types",
                rejects(
                    MANIFEST.as_bytes(),
                    CASES.as_bytes(),
                    evaluator_type.as_bytes(),
                ),
            ),
            (
                "evaluator-count",
                rejects(MANIFEST.as_bytes(), simple_case, evaluator_count.as_bytes()),
            ),
            (
                "unsupported-protocol",
                rejects(
                    unsupported_protocol.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "text-bound",
                rejects(MANIFEST.as_bytes(), text_bound.as_bytes(), simple_evaluator),
            ),
            (
                "temperature-low",
                rejects(
                    MANIFEST.as_bytes(),
                    temperature_low.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "temperature-high",
                rejects(
                    MANIFEST.as_bytes(),
                    temperature_high.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "top-p-high",
                rejects(MANIFEST.as_bytes(), top_p_high.as_bytes(), simple_evaluator),
            ),
            (
                "token-zero",
                rejects(MANIFEST.as_bytes(), token_zero.as_bytes(), simple_evaluator),
            ),
            (
                "token-high",
                rejects(MANIFEST.as_bytes(), token_high.as_bytes(), simple_evaluator),
            ),
            (
                "responses-content-count",
                rejects(
                    MANIFEST.as_bytes(),
                    content_count.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "unsafe-case-id",
                rejects(
                    MANIFEST.as_bytes(),
                    unsafe_case_id.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "unsafe-evaluator-id",
                rejects(
                    MANIFEST.as_bytes(),
                    simple_case,
                    unsafe_evaluator_id.as_bytes(),
                ),
            ),
            (
                "unsafe-expected-key",
                rejects(MANIFEST.as_bytes(), unsafe_expected_key, simple_evaluator),
            ),
            (
                "unsafe-tool-id",
                rejects(
                    MANIFEST.as_bytes(),
                    unsafe_tool.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "chat-tool-schema-ref",
                rejects(
                    chat_manifest.as_bytes(),
                    chat_tool_ref.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "chat-format-schema-ref",
                rejects(
                    chat_manifest.as_bytes(),
                    chat_format_ref.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "responses-tool-schema-ref",
                rejects(
                    MANIFEST.as_bytes(),
                    responses_tool_ref.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "responses-format-schema-ref",
                rejects(
                    MANIFEST.as_bytes(),
                    responses_format_ref.as_bytes(),
                    simple_evaluator,
                ),
            ),
            (
                "chat-assistant-role",
                parse_request(
                    QualityProtocol::Chat,
                    json!({"messages":[{"role":"assistant","content":"x"}]}),
                )
                .is_ok(),
            ),
            (
                "cases-path-traversal",
                rejects(
                    cases_path.as_bytes(),
                    CASES.as_bytes(),
                    EVALUATORS.as_bytes(),
                ),
            ),
            (
                "request-invalid-types",
                rejects(MANIFEST.as_bytes(), invalid_request_type, simple_evaluator),
            ),
            (
                "expected-invalid-types",
                rejects(MANIFEST.as_bytes(), invalid_expected_type, simple_evaluator),
            ),
        ]);
        strict_results.extend([
            ("normalized-expected-type", load_single_evaluator(json!({"answer":1}), "{ id: normalized, kind: normalized-match, expected_key: answer, required: true }").is_err()),
            ("regex-expected-type", load_single_evaluator(json!({"regex":1}), "{ id: regex, kind: regex, expected_key: regex, required: true }").is_err()),
            ("schema-expected-type", load_single_evaluator(json!({"schema":[]}), "{ id: schema, kind: json-schema, expected_key: schema, required: true }").is_err()),
            ("tool-name-expected-type", load_single_evaluator(json!({"name":1,"arguments":{}}), "{ id: tool, kind: tool-call, call_index: 0, expected_name_key: name, expected_arguments_key: arguments, required: true }").is_err()),
            ("tool-arguments-expected-type", load_single_evaluator(json!({"name":"tool","arguments":[]}), "{ id: tool, kind: tool-call, call_index: 0, expected_name_key: name, expected_arguments_key: arguments, required: true }").is_err()),
            ("normalized-missing-key", load_single_evaluator(json!({}), "{ id: normalized, kind: normalized-match, expected_key: answer, required: true }").is_err()),
            ("regex-missing-key", load_single_evaluator(json!({}), "{ id: regex, kind: regex, expected_key: regex, required: true }").is_err()),
            ("schema-missing-key", load_single_evaluator(json!({}), "{ id: schema, kind: json-schema, expected_key: schema, required: true }").is_err()),
            ("tool-missing-key", load_single_evaluator(json!({"name":"tool"}), "{ id: tool, kind: tool-call, call_index: 0, expected_name_key: name, expected_arguments_key: arguments, required: true }").is_err()),
            ("field-missing-key", load_single_evaluator(json!({}), "{ id: field, kind: field, pointer: /x, expected_key: value, required: true }").is_err()),
            ("latency-forbids-expected", load_single_evaluator(json!({}), "{ id: latency, kind: latency-ceiling, max_ms: 1, expected_key: value, required: true }").is_err()),
            ("cost-forbids-expected", load_single_evaluator(json!({}), "{ id: cost, kind: cost-ceiling, max_usd: 1.0, expected_key: value, required: true }").is_err()),
        ]);
        assert_eq!(strict_results.len(), 72, "strict acceptance vector count");
        for (name, accepted) in strict_results {
            assert!(accepted, "strict acceptance vector failed: {name}");
        }

        let chat_shape = json!({
          "messages": [{"role":"user","content":"Return the status."}],
          "tools": [{"type":"function","function":{"name":"lookup","description":"Look up status","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}}}],
          "tool_choice": {"type":"function","function":{"name":"lookup"}},
          "response_format": {"type":"json_schema","json_schema":{"name":"answer","strict":true,"schema":{"type":"object"}}},
          "max_completion_tokens": 128
        });
        let responses_shape = json!({
          "input": [{"role":"user","content":[{"type":"input_text","text":"Return the status."}]}],
          "tools": [{"type":"function","name":"lookup","description":"Look up status","parameters":{"type":"object"},"strict":true}],
          "tool_choice": {"type":"function","name":"lookup"},
          "text": {"format":{"type":"json_schema","name":"answer","strict":true,"schema":{"type":"object"}}},
          "reasoning": {"effort":"low"},
          "max_output_tokens": 128
        });
        assert!(chat_shape.is_object() && responses_shape.is_object());

        let loaded =
            load_quality_dataset(MANIFEST.as_bytes(), CASES.as_bytes(), EVALUATORS.as_bytes())
                .unwrap();
        assert_eq!(loaded.cases.len(), 1);
        assert_eq!(loaded.evaluators.len(), 8);
        assert!(loaded.digests.dataset_digest.starts_with("sha256:"));
        assert_eq!(loaded.digests.dataset_digest.len(), 71);

        let chat: QualityChatRequest = serde_json::from_value(chat_shape.clone()).unwrap();
        validate_chat_request(&chat).unwrap();
        assert_eq!(serde_json::to_value(chat).unwrap(), chat_shape);
        let responses: QualityResponsesRequest =
            serde_json::from_value(responses_shape.clone()).unwrap();
        validate_responses_request(&responses).unwrap();
        assert_eq!(serde_json::to_value(responses).unwrap(), responses_shape);
        for role in ["system", "developer", "user"] {
            let request = json!({"input":[{"role":role,"content":"x"}]});
            assert!(
                parse_request(QualityProtocol::Responses, request).is_ok(),
                "role {role}"
            );
        }
        for role in ["assistant", "tool"] {
            let request = json!({"input":[{"role":role,"content":"x"}]});
            assert!(
                parse_request(QualityProtocol::Responses, request).is_err(),
                "role {role} must be rejected"
            );
        }

        assert_eq!(
            format!(
                "{:x}",
                tuple_digest(b"bowline-quality-dataset-v1", &[b"a", b"b"])
            ),
            "614f5e5c8159189934e7b963c2f8913dab3b416a55fb49f5e8d7ef95519026dd"
        );
    }

    #[test]
    fn deterministic_evaluator_vectors() {
        let mut executed = 0usize;
        macro_rules! vector {
            ($name:literal, $condition:expr) => {{
                executed += 1;
                assert!($condition, "evaluator acceptance vector failed: {}", $name);
            }};
        }

        let exact = "{ id: exact, kind: exact-match, expected_key: answer, required: true }";
        let normalized =
            "{ id: normalized, kind: normalized-match, expected_key: answer, required: true }";
        let regex = "{ id: regex, kind: regex, expected_key: regex, required: true }";
        let schema = "{ id: schema, kind: json-schema, expected_key: schema, required: true }";
        let field =
            "{ id: field, kind: field, pointer: /value, expected_key: value, required: true }";

        vector!(
            "exact-unicode",
            evaluate_single(json!({"answer":"é"}), exact, &observed(Some("é"), None))
                .unwrap()
                .required_passed
        );
        vector!(
            "exact-mismatch",
            !evaluate_single(
                json!({"answer":"é"}),
                exact,
                &observed(Some("e\u{301}"), None)
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "normalized-nfkc",
            evaluate_single(
                json!({"answer":"Ａ"}),
                normalized,
                &observed(Some("A"), None)
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "normalized-crlf",
            evaluate_single(
                json!({"answer":"a\r\nb"}),
                normalized,
                &observed(Some("a b"), None)
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "normalized-unicode-whitespace",
            evaluate_single(
                json!({"answer":" a\u{2003}\tb "}),
                normalized,
                &observed(Some("a b"), None)
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "normalized-no-case-fold",
            !evaluate_single(
                json!({"answer":"Case"}),
                normalized,
                &observed(Some("case"), None)
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "regex-match",
            evaluate_single(json!({"regex":"^a+$"}), regex, &observed(Some("aaa"), None))
                .unwrap()
                .required_passed
        );
        vector!(
            "regex-mismatch",
            !evaluate_single(json!({"regex":"^a+$"}), regex, &observed(Some("bbb"), None))
                .unwrap()
                .required_passed
        );
        vector!(
            "regex-invalid",
            load_single_evaluator(json!({"regex":"("}), regex).is_err()
        );
        vector!(
            "regex-pattern-bound",
            load_single_evaluator(json!({"regex":"x".repeat(MAX_REGEX_BYTES + 1)}), regex).is_err()
        );
        vector!("regex-input-bound", {
            let result = evaluate_single(
                json!({"regex":"x"}),
                regex,
                &observed(Some(&"x".repeat(MAX_TEXT_BYTES + 1)), None),
            )
            .unwrap();
            result.outcomes[0].status == EvaluatorStatus::Error
        });

        let prefix_schema =
            json!({"type":"array","prefixItems":[{"const":"first"}],"items":{"type":"integer"}});
        vector!("schema-draft-2020-12", {
            let pass = evaluate_single(
                json!({"schema":prefix_schema.clone()}),
                schema,
                &observed(None, Some(json!(["first", 1]))),
            )
            .unwrap()
            .required_passed;
            let fail = !evaluate_single(
                json!({"schema":prefix_schema}),
                schema,
                &observed(None, Some(json!(["wrong", 1]))),
            )
            .unwrap()
            .required_passed;
            pass && fail
        });
        vector!(
            "schema-invalid",
            load_single_evaluator(json!({"schema":{"type":5}}), schema).is_err()
        );
        vector!(
            "schema-ref-root",
            load_single_evaluator(
                json!({"schema":{"$ref":"https://invalid.example/schema"}}),
                schema
            )
            .is_err()
        );
        vector!(
            "schema-ref-nested",
            load_single_evaluator(
                json!({"schema":{"allOf":[{"properties":{"x":{"$ref":"file:///tmp/schema"}}}]}}),
                schema
            )
            .is_err()
        );
        vector!("schema-depth", {
            let mut deep = json!({"type":"string"});
            for _ in 0..MAX_JSON_DEPTH {
                deep = json!({"allOf":[deep]});
            }
            let schema_rejected = load_single_evaluator(json!({"schema":deep}), schema).is_err();
            let mut value = json!(null);
            for _ in 0..MAX_JSON_DEPTH {
                value = json!([value]);
            }
            let text = serde_json::to_string(&value).unwrap();
            let body = serde_json::to_vec(&json!({"output":[{"type":"message","content":[{"type":"output_text","text":text}]}]})).unwrap();
            schema_rejected
                && normalize_candidate_response(QualityProtocol::Responses, &body, 0, None).is_err()
        });
        vector!("schema-size", {
            let schema_rejected = load_single_evaluator(
                json!({"schema":{"description":"x".repeat(MAX_EXPECTED_BYTES)}}),
                schema,
            )
            .is_err();
            let nodes =
                serde_json::to_string(&Value::Array(vec![Value::Null; MAX_JSON_NODES])).unwrap();
            let node_body = serde_json::to_vec(&json!({"output":[{"type":"message","content":[{"type":"output_text","text":nodes}]}]})).unwrap();
            let byte_body = vec![b' '; MAX_RESPONSE_BYTES + 1];
            schema_rejected
                && normalize_candidate_response(QualityProtocol::Responses, &node_body, 0, None)
                    .is_err()
                && normalize_candidate_response(QualityProtocol::Responses, &byte_body, 0, None)
                    .is_err()
        });

        vector!("field-pointer", {
            let malformed = ["/a~2b", "/trailing~", "/bad~xescape"].iter().all(|pointer| {
                let evaluator = format!("{{ id: field, kind: field, pointer: {pointer}, expected_key: value, required: true }}");
                load_single_evaluator(json!({"value":"ok"}), &evaluator).is_err()
            });
            let escaped = [("/a~0b", "a~b"), ("/a~1b", "a/b")].iter().all(|(pointer, key)| {
                let evaluator = format!("{{ id: field, kind: field, pointer: {pointer}, expected_key: value, required: true }}");
                evaluate_single(json!({"value":"ok"}), &evaluator, &observed(None, Some(json!({*key:"ok"})))).unwrap().required_passed
            });
            malformed && escaped
        });
        vector!(
            "field-missing",
            !evaluate_single(
                json!({"value":1}),
                field,
                &observed(None, Some(json!({"other":1})))
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "field-type",
            !evaluate_single(
                json!({"value":1}),
                field,
                &observed(None, Some(json!({"value":"1"})))
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "field-object-order",
            evaluate_single(
                json!({"value":{"a":1,"b":2}}),
                field,
                &observed(None, Some(json!({"value":{"b":2,"a":1}})))
            )
            .unwrap()
            .required_passed
        );
        vector!(
            "field-array-order",
            !evaluate_single(
                json!({"value":[1,2]}),
                field,
                &observed(None, Some(json!({"value":[2,1]})))
            )
            .unwrap()
            .required_passed
        );

        vector!("chat-text-and-tools", {
            let body =
                serde_json::to_vec(&json!({"choices":[{"message":{"content":"ok","tool_calls":[
                    {"type":"function","function":{"name":"first","arguments":"{\"n\":1}"}},
                    {"type":"function","function":{"name":"second","arguments":"{\"n\":2}"}}
                ]}}]}))
                .unwrap();
            let response =
                normalize_candidate_response(QualityProtocol::Chat, &body, 0, None).unwrap();
            response.text.as_deref() == Some("ok")
                && response
                    .tool_calls
                    .iter()
                    .map(|call| call.name.as_str())
                    .collect::<Vec<_>>()
                    == ["first", "second"]
        });
        vector!(
            "chat-choice-count",
            normalize_candidate_response(QualityProtocol::Chat, br#"{"choices":[]}"#, 0, None)
                .is_err()
        );
        vector!("chat-malformed-tool-arguments", normalize_candidate_response(QualityProtocol::Chat, br#"{"choices":[{"message":{"content":null,"tool_calls":[{"type":"function","function":{"name":"tool","arguments":"{"}}]}}]}"#, 0, None).is_err());
        vector!("responses-text-and-tools", {
            let body = serde_json::to_vec(&json!({"output":[
                {"type":"message","content":[{"type":"output_text","text":"a"},{"type":"output_text","text":"b"}]},
                {"type":"function_call","name":"first","arguments":"{\"n\":1}"},
                {"type":"function_call","name":"second","arguments":"{\"n\":2}"}
            ]})).unwrap();
            let response =
                normalize_candidate_response(QualityProtocol::Responses, &body, 0, None).unwrap();
            response.text.as_deref() == Some("ab")
                && response
                    .tool_calls
                    .iter()
                    .map(|call| call.name.as_str())
                    .collect::<Vec<_>>()
                    == ["first", "second"]
        });
        vector!(
            "responses-unsupported-output",
            normalize_candidate_response(
                QualityProtocol::Responses,
                br#"{"output":[{"type":"image"}]}"#,
                0,
                None
            )
            .is_err()
        );
        vector!(
            "responses-malformed-tool-arguments",
            normalize_candidate_response(
                QualityProtocol::Responses,
                br#"{"output":[{"type":"function_call","name":"tool","arguments":"{"}]}"#,
                0,
                None
            )
            .is_err()
        );

        let tool = "{ id: tool, kind: tool-call, call_index: 1, expected_name_key: name, expected_arguments_key: arguments, require_total_calls: 2, required: true }";
        let calls = vec![
            ObservedToolCall {
                name: "first".into(),
                arguments: json!({"n":1}),
            },
            ObservedToolCall {
                name: "second".into(),
                arguments: json!({"b":2,"a":1}),
            },
        ];
        let mut tool_observed = observed(None, None);
        tool_observed.tool_calls = calls;
        vector!(
            "tool-call-index",
            evaluate_single(
                json!({"name":"second","arguments":{"a":1,"b":2}}),
                tool,
                &tool_observed
            )
            .unwrap()
            .required_passed
        );
        vector!("tool-call-count", {
            let mut one = tool_observed.clone();
            one.tool_calls.pop();
            !evaluate_single(
                json!({"name":"second","arguments":{"a":1,"b":2}}),
                tool,
                &one,
            )
            .unwrap()
            .required_passed
        });
        vector!(
            "tool-call-name",
            !evaluate_single(
                json!({"name":"wrong","arguments":{"a":1,"b":2}}),
                tool,
                &tool_observed
            )
            .unwrap()
            .required_passed
        );
        vector!("tool-call-arguments", {
            let ordered_object = evaluate_single(
                json!({"name":"second","arguments":{"a":1,"b":2}}),
                tool,
                &tool_observed,
            )
            .unwrap()
            .required_passed;
            let mismatch = !evaluate_single(
                json!({"name":"second","arguments":{"a":2}}),
                tool,
                &tool_observed,
            )
            .unwrap()
            .required_passed;
            ordered_object && mismatch
        });

        let latency = "{ id: latency, kind: latency-ceiling, max_ms: 3000, required: true }";
        let mut measured = observed(None, None);
        measured.latency_ms = 3000;
        vector!(
            "latency-inclusive",
            evaluate_single(json!({}), latency, &measured)
                .unwrap()
                .required_passed
        );
        measured.latency_ms = 3001;
        vector!(
            "latency-over",
            !evaluate_single(json!({}), latency, &measured)
                .unwrap()
                .required_passed
        );
        let cost = "{ id: cost, kind: cost-ceiling, max_usd: 0.02, required: true }";
        measured.cost_usd = Some(0.02);
        vector!(
            "cost-inclusive",
            evaluate_single(json!({}), cost, &measured)
                .unwrap()
                .required_passed
        );
        measured.cost_usd = Some(0.020_001);
        vector!(
            "cost-over",
            !evaluate_single(json!({}), cost, &measured)
                .unwrap()
                .required_passed
        );
        measured.cost_usd = None;
        vector!("cost-unknown", {
            let result = evaluate_single(json!({}), cost, &measured).unwrap();
            result.outcomes[0].status == EvaluatorStatus::Error
                && result.outcomes[0].error_code.as_deref() == Some("cost-unknown")
        });
        vector!(
            "required-error-gates",
            !evaluate_single(json!({}), cost, &measured)
                .unwrap()
                .required_passed
        );
        let optional_cost = "{ id: cost, kind: cost-ceiling, max_usd: 0.02, required: false }";
        vector!("optional-error-disclosed", {
            let result = evaluate_single(json!({}), optional_cost, &measured).unwrap();
            result.required_passed && result.outcomes[0].status == EvaluatorStatus::Error
        });
        vector!("evaluator-source-order", {
            let loaded =
                load_quality_dataset(MANIFEST.as_bytes(), CASES.as_bytes(), EVALUATORS.as_bytes())
                    .unwrap();
            let response = ObservedCandidateResponse {
                text: Some("{\"status\":\"ok\"}".into()),
                structured: Some(json!({"status":"ok"})),
                tool_calls: vec![ObservedToolCall {
                    name: "lookup".into(),
                    arguments: json!({"id":"1"}),
                }],
                latency_ms: 3000,
                cost_usd: Some(0.02),
            };
            let result = evaluate_case(&loaded.cases[0], &loaded.evaluators, &response);
            result.required_passed
                && result
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.kind)
                    .collect::<Vec<_>>()
                    == [
                        EvaluatorKind::ExactMatch,
                        EvaluatorKind::NormalizedMatch,
                        EvaluatorKind::Regex,
                        EvaluatorKind::JsonSchema,
                        EvaluatorKind::Field,
                        EvaluatorKind::ToolCall,
                        EvaluatorKind::LatencyCeiling,
                        EvaluatorKind::CostCeiling,
                    ]
        });
        assert_eq!(executed, 40, "evaluator acceptance vector count");
    }

    #[test]
    fn quality_outcomes_are_content_free() {
        let forbidden = [
            "request",
            "response",
            "expected",
            "regex",
            "schema",
            "arguments",
            "rubric",
            "prompt",
            "prose",
        ];
        assert_eq!(forbidden.len(), 9);
        let kinds = [
            EvaluatorKind::ExactMatch,
            EvaluatorKind::NormalizedMatch,
            EvaluatorKind::Regex,
            EvaluatorKind::JsonSchema,
            EvaluatorKind::Field,
            EvaluatorKind::ToolCall,
            EvaluatorKind::LatencyCeiling,
            EvaluatorKind::CostCeiling,
        ];
        let statuses = [
            EvaluatorStatus::Pass,
            EvaluatorStatus::Fail,
            EvaluatorStatus::Error,
        ];
        let mut outcomes = Vec::new();
        for (index, kind) in kinds.into_iter().enumerate() {
            outcomes.push(EvaluatorOutcome {
                evaluator_id: format!("e{index}"),
                kind,
                status: statuses[index % statuses.len()],
                error_code: (index % statuses.len() != 0).then(|| "safe-code".to_owned()),
                required: index % 2 == 0,
                subjective: false,
                latency_ms: (kind == EvaluatorKind::LatencyCeiling).then_some(42),
                cost_usd: (kind == EvaluatorKind::CostCeiling).then_some(0.01),
            });
        }
        let evaluation = CaseEvaluation {
            required_passed: false,
            outcomes,
        };
        let encoded = serde_json::to_value(&evaluation).unwrap();
        for (index, outcome) in encoded["outcomes"].as_array().unwrap().iter().enumerate() {
            let object = outcome.as_object().unwrap();
            for key in forbidden {
                assert!(!object.contains_key(key), "outcome {index} leaked {key}");
            }
            assert!(object.keys().all(|key| matches!(
                key.as_str(),
                "evaluator_id"
                    | "kind"
                    | "status"
                    | "error_code"
                    | "required"
                    | "subjective"
                    | "latency_ms"
                    | "cost_usd"
            )));
        }
        let serialized = serde_json::to_string(&encoded).unwrap();
        for content in [
            "customer",
            "prompt text",
            "expected answer",
            "tool arguments",
        ] {
            assert!(
                !serialized.contains(content),
                "serialized outcome leaked {content}"
            );
        }
        let decoded: CaseEvaluation = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, evaluation);
        let mut injected = encoded;
        injected["outcomes"][0]["expected"] = json!("secret");
        assert!(serde_json::from_value::<CaseEvaluation>(injected).is_err());
    }

    #[test]
    fn all_promotion_verdicts_and_precedence_are_locked() {
        let base: Vec<_> = (1..=10)
            .map(|sequence| promotion_outcome(sequence, EvaluatorStatus::Pass))
            .collect();
        let base_manifest = promotion_manifest(&base);
        let eligible = assess_fixture(
            &base_manifest,
            &base,
            &[],
            Some(true),
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );

        let policy_failed = assess_fixture(
            &base_manifest,
            &base,
            &[],
            Some(true),
            true,
            false,
            promotion_criteria(),
            false,
            1_000,
        );
        let capacity_failed = assess_fixture(
            &base_manifest,
            &base,
            &[],
            Some(false),
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        let mut incomplete_manifest = base_manifest.clone();
        incomplete_manifest.clean_shutdown = false;
        let insufficient = assess_fixture(
            &incomplete_manifest,
            &base,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        let mut unknown_cost = base.clone();
        unknown_cost[0].candidate_cost_usd = None;
        let cost_unknown = assess_fixture(
            &promotion_manifest(&unknown_cost),
            &unknown_cost,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        let mut failed_quality = base.clone();
        for outcome in failed_quality.iter_mut().take(3) {
            outcome.evaluator_outcomes[0].status = EvaluatorStatus::Fail;
        }
        let quality_failed = assess_fixture(
            &promotion_manifest(&failed_quality),
            &failed_quality,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );

        let verdicts = [
            (
                "policy-failed",
                policy_failed.assessment.completion_verdict,
                PromotionVerdict::PolicyFailed,
            ),
            (
                "capacity-failed",
                capacity_failed.assessment.completion_verdict,
                PromotionVerdict::CapacityFailed,
            ),
            (
                "insufficient-evidence",
                insufficient.assessment.completion_verdict,
                PromotionVerdict::InsufficientEvidence,
            ),
            (
                "cost-unknown",
                cost_unknown.assessment.completion_verdict,
                PromotionVerdict::CostUnknown,
            ),
            (
                "quality-failed",
                quality_failed.assessment.completion_verdict,
                PromotionVerdict::QualityFailed,
            ),
            (
                "eligible",
                eligible.assessment.completion_verdict,
                PromotionVerdict::Eligible,
            ),
        ];
        for (name, actual, expected) in verdicts {
            assert_eq!(actual, expected, "verdict vector {name}");
        }

        let mut simultaneous_outcomes = failed_quality.clone();
        simultaneous_outcomes[0].candidate_cost_usd = None;
        let mut simultaneous_manifest = promotion_manifest(&simultaneous_outcomes);
        simultaneous_manifest.clean_shutdown = false;
        let simultaneous = assess_fixture(
            &simultaneous_manifest,
            &simultaneous_outcomes,
            &[4],
            Some(false),
            true,
            false,
            promotion_criteria(),
            false,
            1_000,
        );
        assert_eq!(
            simultaneous.assessment.completion_verdict,
            PromotionVerdict::PolicyFailed
        );
        assert_eq!(simultaneous.assessment.gates.policy, GateResult::Fail);
        assert_eq!(simultaneous.assessment.gates.capacity, GateResult::Fail);
        assert_eq!(
            simultaneous.assessment.gates.evidence,
            GateResult::Insufficient
        );
        assert_eq!(simultaneous.assessment.gates.cost, GateResult::Unknown);
        assert_eq!(simultaneous.assessment.gates.quality, GateResult::Fail);
        for blocker in [
            PromotionBlocker::PolicyInfeasible,
            PromotionBlocker::RegistryUnavailable,
            PromotionBlocker::IncompleteRun,
            PromotionBlocker::SequenceGaps,
            PromotionBlocker::CostUnknown,
            PromotionBlocker::PassRate,
        ] {
            assert!(
                simultaneous.assessment.blockers.contains(&blocker),
                "missing blocker {blocker:?}"
            );
        }

        assert_eq!(
            eligible.overlay_key,
            "sha256:c12c29c75c45dd3965df53483257b0767e988ddf61b5c6517bbfd78a420678f5"
        );
        let registry = promotion_registry(None, true);
        let before = serde_json::to_vec(&registry).unwrap();
        let policy = promotion_policy(true);
        let owned_costs = OwnedCostCatalog::default();
        let workload = PromotionWorkload {
            app: "support".into(),
            tags: vec!["prod".into(), "prod".into()],
        };
        let _ = assess_promotion(PromotionInput {
            manifest: &base_manifest,
            outcomes: &base,
            gaps: &[],
            policy: &policy,
            registry: &registry,
            registry_digest: &promotion_registry_digest(&registry),
            owned_costs: &owned_costs,
            workload: &workload,
            candidate_supply_id: "public/candidate",
            task_class: TaskClass::Mechanical,
            protocol: QualityProtocol::Responses,
            dataset_digest: PROMOTION_DATASET_DIGEST,
            evaluator_digest: PROMOTION_EVALUATOR_DIGEST,
            criteria: promotion_criteria(),
            judge_required: false,
            as_of_ms: 1_000,
        })
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&registry).unwrap(),
            before,
            "registry mutated"
        );
        assert!(
            before
                .windows(b"\"ratings\":{}".len())
                .any(|window| window == b"\"ratings\":{}"),
            "ratings-empty policy fixture changed"
        );
    }

    #[test]
    fn wilson_freshness_capacity_and_cost_vectors() {
        let mut executed = 0usize;
        macro_rules! vector {
            ($name:literal, $condition:expr) => {{
                executed += 1;
                assert!($condition, "statistics acceptance vector failed: {}", $name);
            }};
        }

        vector!("wilson-n-zero", wilson_lower_95(0, 0).is_none());
        vector!("wilson-fixed-z", {
            (wilson_lower_95(10, 10).unwrap() - 0.722_467_200_137_110_9).abs() < 1e-12
                && (wilson_lower_95(5, 10).unwrap() - 0.236_593_090_512_564).abs() < 1e-12
        });
        vector!("nearest-rank-p95", {
            nearest_rank_p95(&(1..=20).collect::<Vec<_>>()) == Some(19)
                && nearest_rank_p95(&[]).is_none()
        });

        let candidate_kinds = [
            CandidateErrorKind::Timeout,
            CandidateErrorKind::Transport,
            CandidateErrorKind::Disconnect,
            CandidateErrorKind::HttpStatus,
            CandidateErrorKind::ResponseTooLarge,
            CandidateErrorKind::InvalidResponse,
        ];
        let mut attempts = Vec::new();
        for (index, kind) in candidate_kinds.into_iter().enumerate() {
            let mut outcome = promotion_outcome(index as u64 + 1, EvaluatorStatus::Pass);
            outcome.status = QualityAttemptStatus::CandidateError;
            outcome.candidate_error = Some(kind);
            outcome.latency_ms = None;
            attempts.push(outcome);
        }
        for status in [
            QualityAttemptStatus::EvaluatorError,
            QualityAttemptStatus::JudgeError,
            QualityAttemptStatus::Cancelled,
            QualityAttemptStatus::InternalError,
        ] {
            let mut outcome = promotion_outcome(attempts.len() as u64 + 1, EvaluatorStatus::Pass);
            outcome.status = status;
            outcome.latency_ms = None;
            attempts.push(outcome);
        }
        attempts.push(promotion_outcome(11, EvaluatorStatus::Pass));
        attempts.push(promotion_outcome(12, EvaluatorStatus::Pass));
        let capacity = assess_fixture(
            &promotion_manifest(&attempts),
            &attempts,
            &[],
            Some(true),
            true,
            true,
            PromotionCriteria {
                max_candidate_error_rate: 0.55,
                ..promotion_criteria()
            },
            false,
            1_000,
        );
        vector!("candidate-capacity-numerator-denominator", {
            capacity.assessment.metrics.dispatched_attempts == 12
                && capacity.assessment.metrics.candidate_capacity_errors == 6
                && capacity.assessment.metrics.candidate_error_rate == Some(0.5)
                && capacity.assessment.completion_verdict == PromotionVerdict::InsufficientEvidence
        });

        let base: Vec<_> = (1..=10)
            .map(|sequence| promotion_outcome(sequence, EvaluatorStatus::Pass))
            .collect();
        let manifest = promotion_manifest(&base);
        vector!(
            "available-true-neutral",
            assess_fixture(
                &manifest,
                &base,
                &[],
                Some(true),
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::Eligible
        );
        vector!(
            "available-null-neutral",
            assess_fixture(
                &manifest,
                &base,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::Eligible
        );
        vector!(
            "available-false-capacity",
            assess_fixture(
                &manifest,
                &base,
                &[],
                Some(false),
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::CapacityFailed
        );

        let mut immature_criteria = promotion_criteria();
        immature_criteria.min_samples = 11;
        vector!(
            "immature-capacity",
            assess_fixture(
                &manifest,
                &base,
                &[],
                None,
                true,
                true,
                immature_criteria,
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::InsufficientEvidence
        );
        let mut no_latency = base.clone();
        for outcome in &mut no_latency {
            outcome.latency_ms = None;
        }
        let no_latency_assessment = assess_fixture(
            &promotion_manifest(&no_latency),
            &no_latency,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        vector!(
            "mature-empty-p95",
            no_latency_assessment.assessment.completion_verdict
                == PromotionVerdict::InsufficientEvidence
                && no_latency_assessment
                    .assessment
                    .blockers
                    .contains(&PromotionBlocker::EmptyLatencySet)
        );

        let mut one_sample_criteria = promotion_criteria();
        one_sample_criteria.min_samples = 1;
        one_sample_criteria.min_pass_rate = 1.0;
        one_sample_criteria.min_wilson_lower_95 = 0.0;
        let required_fail = vec![promotion_outcome(1, EvaluatorStatus::Fail)];
        let failed = assess_fixture(
            &promotion_manifest(&required_fail),
            &required_fail,
            &[],
            None,
            true,
            true,
            one_sample_criteria,
            false,
            1_000,
        );
        vector!(
            "required-fail-is-complete-sample",
            failed.assessment.metrics.quality_sample_count == 1
                && failed.assessment.metrics.quality_pass_count == 0
                && failed.assessment.completion_verdict == PromotionVerdict::QualityFailed
        );
        let required_error = vec![promotion_outcome(1, EvaluatorStatus::Error)];
        let errored = assess_fixture(
            &promotion_manifest(&required_error),
            &required_error,
            &[],
            None,
            true,
            true,
            one_sample_criteria,
            false,
            1_000,
        );
        vector!(
            "required-engine-error-is-incomplete",
            errored.assessment.metrics.quality_sample_count == 0
                && errored.assessment.completion_verdict == PromotionVerdict::InsufficientEvidence
                && errored
                    .assessment
                    .blockers
                    .contains(&PromotionBlocker::RequiredEvaluatorError)
        );
        let mut optional = base.clone();
        for outcome in &mut optional {
            outcome
                .evaluator_outcomes
                .push(crate::quality_run::QualityEvaluatorEvidence {
                    evaluator_id: "optional".into(),
                    kind: EvaluatorKind::Regex,
                    status: EvaluatorStatus::Error,
                    error_code: Some(crate::quality_run::QualityEvaluatorErrorCode::EvaluatorError),
                    required: false,
                    subjective: false,
                    latency_ms: None,
                });
        }
        let optional_assessment = assess_fixture(
            &promotion_manifest(&optional),
            &optional,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        vector!(
            "optional-errors-non-gating",
            optional_assessment.assessment.completion_verdict == PromotionVerdict::Eligible
                && optional_assessment
                    .assessment
                    .metrics
                    .optional_evaluator_errors
                    == 10
                && optional_assessment.assessment.metrics.quality_sample_count == 10
        );

        let judge_outcomes = |status| {
            let mut outcomes = base.clone();
            for outcome in &mut outcomes {
                outcome.judge = Some(crate::quality_run::JudgeOutcomeEvidence {
                    required: true,
                    subjective: true,
                    status,
                    score: Some(if status == EvaluatorStatus::Pass {
                        0.9
                    } else {
                        0.1
                    }),
                    threshold: 0.8,
                    error_code: (status == EvaluatorStatus::Error)
                        .then_some(crate::quality_run::JudgeErrorCode::InvalidResponse),
                    input_tokens: Some(2),
                    output_tokens: Some(1),
                    cost_usd: Some(0.001),
                });
            }
            outcomes
        };
        let judge_pass = judge_outcomes(EvaluatorStatus::Pass);
        vector!(
            "required-judge-pass",
            assess_fixture(
                &promotion_manifest(&judge_pass),
                &judge_pass,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                true,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::Eligible
        );
        let judge_fail = judge_outcomes(EvaluatorStatus::Fail);
        vector!(
            "required-judge-fail",
            assess_fixture(
                &promotion_manifest(&judge_fail),
                &judge_fail,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                true,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::QualityFailed
        );
        let judge_error = judge_outcomes(EvaluatorStatus::Error);
        vector!(
            "required-judge-error",
            assess_fixture(
                &promotion_manifest(&judge_error),
                &judge_error,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                true,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::InsufficientEvidence
        );
        vector!(
            "required-judge-missing",
            assess_fixture(
                &manifest,
                &base,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                true,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::InsufficientEvidence
        );

        let mut missing_usage = base.clone();
        missing_usage[0].output_tokens = None;
        vector!(
            "missing-usage-cost-unknown",
            assess_fixture(
                &promotion_manifest(&missing_usage),
                &missing_usage,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::CostUnknown
        );
        vector!(
            "missing-price-cost-unknown",
            assess_fixture(
                &manifest,
                &base,
                &[],
                None,
                false,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::CostUnknown
        );
        let mut tri_state_unknown = base.clone();
        tri_state_unknown[0]
            .cost_evaluators
            .push(crate::quality_run::CostEvaluatorEvidence {
                evaluator_id: "cost".into(),
                required: true,
                status: CostEvaluatorStatus::Unknown,
                observed_cost_usd: None,
            });
        let tri_state = assess_fixture(
            &promotion_manifest(&tri_state_unknown),
            &tri_state_unknown,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        vector!("cost-evaluator-tri-state-unknown", {
            tri_state.assessment.completion_verdict == PromotionVerdict::CostUnknown
                && serde_json::to_string(&tri_state_unknown[0])
                    .unwrap()
                    .contains("\"status\":\"unknown\"")
        });
        let base_metrics = assess_fixture(
            &manifest,
            &base,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        vector!("successful-latency-and-cost-metrics", {
            base_metrics.assessment.metrics.successful_latencies == 10
                && base_metrics.assessment.metrics.p95_latency_ms == Some(20)
                && (base_metrics.assessment.metrics.candidate_cost_usd.unwrap() - 0.1).abs() < 1e-12
        });
        let mut ceiling_fail = base.clone();
        ceiling_fail[0]
            .cost_evaluators
            .push(crate::quality_run::CostEvaluatorEvidence {
                evaluator_id: "cost".into(),
                required: true,
                status: CostEvaluatorStatus::Fail,
                observed_cost_usd: Some(0.01),
            });
        let ceiling = assess_fixture(
            &promotion_manifest(&ceiling_fail),
            &ceiling_fail,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        vector!(
            "known-cost-ceiling-failure",
            ceiling.assessment.completion_verdict == PromotionVerdict::QualityFailed
                && ceiling
                    .assessment
                    .blockers
                    .contains(&PromotionBlocker::CostCeilingExceeded)
        );

        let mut partial = manifest.clone();
        partial.clean_shutdown = false;
        vector!(
            "partial-run-insufficient",
            assess_fixture(
                &partial,
                &base,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::InsufficientEvidence
        );
        let mut cancelled = manifest.clone();
        cancelled.cancelled = true;
        cancelled.clean_shutdown = false;
        vector!(
            "cancelled-run-insufficient",
            assess_fixture(
                &cancelled,
                &base,
                &[],
                None,
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::InsufficientEvidence
        );
        vector!(
            "gapped-run-insufficient",
            assess_fixture(
                &manifest,
                &base,
                &[3],
                None,
                true,
                true,
                promotion_criteria(),
                false,
                1_000
            )
            .assessment
            .completion_verdict
                == PromotionVerdict::InsufficientEvidence
        );

        let expiry_cases = [
            (
                "eligible",
                assess_fixture(
                    &manifest,
                    &base,
                    &[],
                    None,
                    true,
                    true,
                    promotion_criteria(),
                    false,
                    1_001,
                ),
                PromotionVerdict::Eligible,
                PromotionVerdict::InsufficientEvidence,
            ),
            (
                "quality-failed",
                assess_fixture(
                    &promotion_manifest(&required_fail),
                    &required_fail,
                    &[],
                    None,
                    true,
                    true,
                    one_sample_criteria,
                    false,
                    1_001,
                ),
                PromotionVerdict::QualityFailed,
                PromotionVerdict::InsufficientEvidence,
            ),
            (
                "cost-unknown",
                assess_fixture(
                    &promotion_manifest(&missing_usage),
                    &missing_usage,
                    &[],
                    None,
                    true,
                    true,
                    promotion_criteria(),
                    false,
                    1_001,
                ),
                PromotionVerdict::CostUnknown,
                PromotionVerdict::InsufficientEvidence,
            ),
            (
                "policy-failed",
                assess_fixture(
                    &manifest,
                    &base,
                    &[],
                    None,
                    true,
                    false,
                    promotion_criteria(),
                    false,
                    1_001,
                ),
                PromotionVerdict::PolicyFailed,
                PromotionVerdict::PolicyFailed,
            ),
            (
                "capacity-failed",
                assess_fixture(
                    &manifest,
                    &base,
                    &[],
                    Some(false),
                    true,
                    true,
                    promotion_criteria(),
                    false,
                    1_001,
                ),
                PromotionVerdict::CapacityFailed,
                PromotionVerdict::CapacityFailed,
            ),
            (
                "insufficient",
                assess_fixture(
                    &partial,
                    &base,
                    &[],
                    None,
                    true,
                    true,
                    promotion_criteria(),
                    false,
                    1_001,
                ),
                PromotionVerdict::InsufficientEvidence,
                PromotionVerdict::InsufficientEvidence,
            ),
        ];
        vector!(
            "expiry-transformations",
            expiry_cases
                .iter()
                .all(|(name, overlay, completion, effective)| {
                    assert!(overlay.assessment.stale, "{name} not stale");
                    overlay.assessment.completion_verdict == *completion
                        && overlay.assessment.effective_verdict == *effective
                })
        );
        assert_eq!(executed, 25, "statistics vector count");
    }

    #[test]
    fn undispatched_and_non_normalized_outcomes_never_inflate_promotion() {
        let mut outcomes: Vec<_> = (1..=3)
            .map(|sequence| promotion_outcome(sequence, EvaluatorStatus::Pass))
            .collect();
        outcomes[0].dispatched = false;
        outcomes[0].candidate_cost_usd = Some(100.0);
        outcomes[0].latency_ms = Some(10_000);
        let manifest = promotion_manifest(&outcomes);
        let overlay = assess_fixture(
            &manifest,
            &outcomes,
            &[],
            Some(true),
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        assert_eq!(overlay.assessment.metrics.dispatched_attempts, 2);
        assert_eq!(overlay.assessment.metrics.quality_sample_count, 2);
        assert_eq!(overlay.assessment.metrics.quality_pass_count, 2);
        assert_eq!(overlay.assessment.metrics.successful_latencies, 2);
        assert_eq!(overlay.assessment.metrics.p95_latency_ms, Some(13));
        assert_eq!(overlay.assessment.metrics.candidate_cost_usd, Some(0.02));

        let mut internal = promotion_outcome(1, EvaluatorStatus::Pass);
        internal.status = QualityAttemptStatus::InternalError;
        internal.reason = Some(QualityReasonCode::WriterError);
        let internal_manifest = promotion_manifest(std::slice::from_ref(&internal));
        let internal_overlay = assess_fixture(
            &internal_manifest,
            &[internal],
            &[],
            Some(true),
            true,
            true,
            PromotionCriteria {
                min_samples: 1,
                ..promotion_criteria()
            },
            false,
            1_000,
        );
        assert_eq!(internal_overlay.assessment.metrics.dispatched_attempts, 1);
        assert_eq!(internal_overlay.assessment.metrics.quality_sample_count, 0);
        assert_eq!(internal_overlay.assessment.metrics.candidate_cost_usd, None);
    }

    #[test]
    fn required_judge_and_provenance_mismatches_are_insufficient() {
        let mut outcomes: Vec<_> = (1..=2)
            .map(|sequence| promotion_outcome(sequence, EvaluatorStatus::Pass))
            .collect();
        for outcome in &mut outcomes {
            outcome.judge = Some(JudgeOutcomeEvidence {
                required: false,
                subjective: true,
                status: EvaluatorStatus::Pass,
                score: Some(0.9),
                threshold: 0.5,
                error_code: None,
                input_tokens: Some(2),
                output_tokens: Some(1),
                cost_usd: Some(0.01),
            });
        }
        let manifest = promotion_manifest(&outcomes);
        let judge = assess_fixture(
            &manifest,
            &outcomes,
            &[],
            Some(true),
            true,
            true,
            promotion_criteria(),
            true,
            1_000,
        );
        assert_eq!(
            judge.assessment.completion_verdict,
            PromotionVerdict::InsufficientEvidence
        );
        assert!(judge
            .assessment
            .blockers
            .contains(&PromotionBlocker::RequiredJudgeError));

        for field in ["policy", "registry", "owned-cost"] {
            let mut changed = promotion_manifest(&outcomes);
            match field {
                "policy" => changed.provenance.policy_digest = format!("sha256:{}", "5".repeat(64)),
                "registry" => {
                    changed.provenance.registry_digest = format!("sha256:{}", "6".repeat(64))
                }
                "owned-cost" => {
                    changed.provenance.owned_cost_digest =
                        Some(format!("sha256:{}", "7".repeat(64)))
                }
                _ => unreachable!(),
            }
            let overlay = assess_fixture(
                &changed,
                &outcomes,
                &[],
                Some(true),
                true,
                true,
                promotion_criteria(),
                false,
                1_000,
            );
            assert_eq!(
                overlay.assessment.completion_verdict,
                PromotionVerdict::InsufficientEvidence,
                "{field} provenance mismatch"
            );
            assert!(overlay
                .assessment
                .blockers
                .contains(&PromotionBlocker::EvidenceMismatch));
        }
    }

    #[test]
    fn promotion_overlay_serialization_is_golden() {
        let outcomes: Vec<_> = (1..=2)
            .map(|sequence| promotion_outcome(sequence, EvaluatorStatus::Pass))
            .collect();
        let overlay = assess_fixture(
            &promotion_manifest(&outcomes),
            &outcomes,
            &[],
            None,
            true,
            true,
            promotion_criteria(),
            false,
            1_000,
        );
        let bytes = serde_json::to_vec(&overlay).unwrap();
        assert_eq!(
            format!("sha256:{:x}", Sha256::digest(bytes)),
            "sha256:72983047282c8da8aabedf31a8142b6247d4ea84095a1367d05254692e3720b6"
        );
    }
}
