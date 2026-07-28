use std::collections::{BTreeMap, BTreeSet, HashMap};

use bowline_core::attribution::AttributionRef;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::passive::{
    validate_event, CanonicalPassiveEvent, ParsedPassiveEvent, MAX_EVENTS, MAX_INPUT_BYTES,
    MAX_LINE_BYTES,
};

pub const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MAX_PROFILE_STRING_BYTES: usize = 256;

#[derive(Debug, Clone)]
pub struct TransformProfile {
    path: String,
    kind: String,
    source_contract: String,
    attribution_namespace: Option<String>,
    timestamp_unit: TimestampUnit,
    fields: BTreeMap<Target, String>,
    constants: BTreeMap<Target, Value>,
    normalized_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileSchema {
    version: u32,
    kind: String,
    source_contract: String,
    #[serde(default)]
    attribution_namespace: Option<String>,
    timestamp_unit: String,
    fields: BTreeMap<String, String>,
    #[serde(default)]
    constants: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Target {
    EventId,
    ObservedAtMs,
    Method,
    Route,
    Model,
    ActualSupplyValue,
    Status,
    Streamed,
    LatencyMs,
    InputTokens,
    OutputTokens,
    DimensionsApp,
    DimensionsTeam,
    DimensionsEnvironment,
    DimensionsCostCenter,
    DimensionsTaskClass,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TimestampUnit {
    Milliseconds,
    Seconds,
    Microseconds,
    Nanoseconds,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("{path}: {reason}")]
    Profile { path: String, reason: String },
    #[error("{source_path}:{line} (profile {profile_path}): {reason}")]
    Source {
        source_path: String,
        line: usize,
        profile_path: String,
        reason: String,
    },
    #[error("{source_path}: {reason}")]
    Input { source_path: String, reason: String },
}

impl TransformProfile {
    pub fn from_yaml(source: &str, path: &str) -> Result<Self, ProfileError> {
        if source.len() > MAX_PROFILE_BYTES {
            return Err(profile_error(path, "profile exceeds compiled size limit"));
        }
        let schema: ProfileSchema = serde_yaml::from_str(source)
            .map_err(|error| profile_error(path, format!("invalid profile schema: {error}")))?;
        if schema.version != 1 {
            return Err(profile_error(path, "profile version must equal 1"));
        }
        validate_profile_string(path, "kind", &schema.kind)?;
        validate_profile_string(path, "source_contract", &schema.source_contract)?;
        if let Some(namespace) = &schema.attribution_namespace {
            AttributionRef {
                namespace: namespace.clone(),
                value: "validation-placeholder".to_string(),
            }
            .validate()
            .map_err(|error| profile_error(path, error.to_string()))?;
        }
        let timestamp_unit = match schema.timestamp_unit.as_str() {
            "milliseconds" => TimestampUnit::Milliseconds,
            "seconds" => TimestampUnit::Seconds,
            "microseconds" => TimestampUnit::Microseconds,
            "nanoseconds" => TimestampUnit::Nanoseconds,
            _ => return Err(profile_error(path, "unsupported timestamp unit")),
        };
        let mut fields = BTreeMap::new();
        for (name, pointer) in schema.fields {
            let target = Target::parse(&name)
                .ok_or_else(|| profile_error(path, format!("unknown profile target {name}")))?;
            validate_pointer(path, target, &pointer)?;
            fields.insert(target, pointer);
        }
        let mut constants = BTreeMap::new();
        for (name, yaml_value) in schema.constants {
            let target = Target::parse(&name)
                .ok_or_else(|| profile_error(path, format!("unknown profile target {name}")))?;
            if fields.contains_key(&target) {
                return Err(profile_error(
                    path,
                    format!("target {name} is configured more than once"),
                ));
            }
            let value = serde_json::to_value(yaml_value)
                .map_err(|error| profile_error(path, format!("invalid constant: {error}")))?;
            validate_scalar(target, &value)
                .map_err(|reason| profile_error(path, format!("constant {name}: {reason}")))?;
            validate_constant(target, &value)
                .map_err(|reason| profile_error(path, format!("constant {name}: {reason}")))?;
            constants.insert(target, value);
        }
        for required in Target::required() {
            if !fields.contains_key(required) && !constants.contains_key(required) {
                return Err(profile_error(
                    path,
                    format!("missing required target {}", required.name()),
                ));
            }
        }
        if (fields.contains_key(&Target::ActualSupplyValue)
            || constants.contains_key(&Target::ActualSupplyValue))
            && schema.attribution_namespace.is_none()
        {
            return Err(profile_error(
                path,
                "actual_supply_value requires attribution_namespace",
            ));
        }
        if let Some(timestamp) = constants.get(&Target::ObservedAtMs).and_then(Value::as_u64) {
            timestamp_unit.to_milliseconds(timestamp).ok_or_else(|| {
                profile_error(path, "constant observed_at_ms conversion overflow")
            })?;
        }
        let normalized = serde_json::to_vec(&(
            schema.version,
            &schema.kind,
            &schema.source_contract,
            &schema.attribution_namespace,
            timestamp_unit,
            &fields,
            &constants,
        ))
        .map_err(|error| profile_error(path, format!("profile digest failed: {error}")))?;
        Ok(Self {
            path: path.to_string(),
            kind: schema.kind,
            source_contract: schema.source_contract,
            attribution_namespace: schema.attribution_namespace,
            timestamp_unit,
            fields,
            constants,
            normalized_digest: format!("sha256:{:x}", Sha256::digest(normalized)),
        })
    }

    pub fn normalized_digest(&self) -> &str {
        &self.normalized_digest
    }

    pub fn source_contract(&self) -> &str {
        &self.source_contract
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn validate_producer_contract(
        &self,
        formatter_source: &str,
        fixture_source: &str,
    ) -> Result<(), ProfileError> {
        let formatter: serde_yaml::Value =
            serde_yaml::from_str(formatter_source).map_err(|error| {
                profile_error(&self.path, format!("invalid producer config: {error}"))
            })?;
        let declared = formatter
            .get("typed_json_format")
            .and_then(serde_yaml::Value::as_mapping)
            .ok_or_else(|| profile_error(&self.path, "missing typed_json_format mapping"))?;
        let fixture: Value = fixture_source
            .lines()
            .next()
            .ok_or_else(|| profile_error(&self.path, "empty producer fixture"))
            .and_then(|line| {
                serde_json::from_str(line).map_err(|error| {
                    profile_error(&self.path, format!("invalid producer fixture: {error}"))
                })
            })?;
        let fixture = fixture
            .as_object()
            .ok_or_else(|| profile_error(&self.path, "producer fixture must be an object"))?;
        for (target, pointer) in &self.fields {
            let key = pointer
                .strip_prefix('/')
                .filter(|value| !value.contains('/'))
                .ok_or_else(|| {
                    profile_error(&self.path, "producer contract pointers must be top-level")
                })?;
            if !declared.contains_key(serde_yaml::Value::String(key.to_string())) {
                return Err(profile_error(
                    &self.path,
                    format!("producer config missing key for target {}", target.name()),
                ));
            }
            let value = fixture
                .get(key)
                .filter(|value| !value.is_null())
                .ok_or_else(|| {
                    profile_error(
                        &self.path,
                        format!("producer fixture missing key for target {}", target.name()),
                    )
                })?;
            validate_scalar(*target, value).map_err(|reason| {
                profile_error(
                    &self.path,
                    format!("producer fixture target {}: {reason}", target.name()),
                )
            })?;
        }
        Ok(())
    }
}

pub fn transform_profile_jsonl(
    profile: &TransformProfile,
    source: &str,
    source_path: &str,
) -> Result<Vec<ParsedPassiveEvent>, ProfileError> {
    if source.len() > MAX_INPUT_BYTES {
        return Err(ProfileError::Input {
            source_path: source_path.to_string(),
            reason: format!("input exceeds {MAX_INPUT_BYTES} bytes"),
        });
    }
    let mut parsed = Vec::new();
    let mut event_lines = HashMap::<String, usize>::new();
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if parsed.len() >= MAX_EVENTS {
            return Err(source_error(
                profile,
                source_path,
                line_number,
                format!("event count exceeds {MAX_EVENTS}"),
            ));
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(source_error(
                profile,
                source_path,
                line_number,
                format!("line exceeds {MAX_LINE_BYTES} bytes"),
            ));
        }
        let raw: Value = serde_json::from_str(line).map_err(|error| {
            source_error(
                profile,
                source_path,
                line_number,
                format!("invalid JSON: {error}"),
            )
        })?;
        let mut canonical = Map::new();
        canonical.insert("schema_version".to_string(), Value::from(1));
        canonical.insert("dimensions".to_string(), Value::Object(Map::new()));
        for (target, value) in &profile.constants {
            insert_target(
                profile,
                *target,
                value.clone(),
                &mut canonical,
                source_path,
                line_number,
            )?;
        }
        for (target, pointer) in &profile.fields {
            match raw.pointer(pointer) {
                Some(value) if !value.is_null() => insert_target(
                    profile,
                    *target,
                    value.clone(),
                    &mut canonical,
                    source_path,
                    line_number,
                )?,
                _ if target.required_per_event() => {
                    return Err(source_error(
                        profile,
                        source_path,
                        line_number,
                        format!("required target {} is absent or null", target.name()),
                    ));
                }
                _ => {}
            }
        }
        if let Some(value) = canonical.remove("actual_supply_value") {
            canonical.insert(
                "actual_supply_ref".to_string(),
                serde_json::json!({
                    "namespace": profile.attribution_namespace.as_deref().unwrap_or_default(),
                    "value": value,
                }),
            );
        }
        let event: CanonicalPassiveEvent = serde_json::from_value(Value::Object(canonical))
            .map_err(|error| {
                source_error(
                    profile,
                    source_path,
                    line_number,
                    format!("canonical target type error: {error}"),
                )
            })?;
        validate_event(&event)
            .map_err(|reason| source_error(profile, source_path, line_number, reason))?;
        if let Some(first_line) = event_lines.insert(event.event_id.clone(), line_number) {
            return Err(source_error(
                profile,
                source_path,
                line_number,
                format!(
                    "duplicate event_id first seen at line {first_line}, duplicated at line {line_number}"
                ),
            ));
        }
        parsed.push(ParsedPassiveEvent {
            source_line: line_number,
            event,
        });
    }
    Ok(parsed)
}

fn insert_target(
    profile: &TransformProfile,
    target: Target,
    mut value: Value,
    canonical: &mut Map<String, Value>,
    source_path: &str,
    line: usize,
) -> Result<(), ProfileError> {
    validate_scalar(target, &value)
        .map_err(|reason| source_error(profile, source_path, line, reason))?;
    if target == Target::ObservedAtMs {
        let timestamp = value.as_u64().expect("validated timestamp");
        value = Value::from(
            profile
                .timestamp_unit
                .to_milliseconds(timestamp)
                .ok_or_else(|| {
                    source_error(profile, source_path, line, "timestamp conversion overflow")
                })?,
        );
    }
    if let Some(dimension) = target.dimension_name() {
        canonical
            .get_mut("dimensions")
            .and_then(Value::as_object_mut)
            .expect("dimensions object is initialized")
            .insert(dimension.to_string(), value);
    } else {
        canonical.insert(target.name().to_string(), value);
    }
    Ok(())
}

fn validate_scalar(target: Target, value: &Value) -> Result<(), String> {
    let kind = match target {
        Target::EventId
        | Target::Method
        | Target::Route
        | Target::Model
        | Target::ActualSupplyValue
        | Target::DimensionsApp
        | Target::DimensionsTeam
        | Target::DimensionsEnvironment
        | Target::DimensionsCostCenter
        | Target::DimensionsTaskClass => "string",
        Target::ObservedAtMs
        | Target::Status
        | Target::LatencyMs
        | Target::InputTokens
        | Target::OutputTokens => "integer",
        Target::Streamed => "boolean",
    };
    let valid = match kind {
        "string" => value.is_string(),
        "integer" => value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        _ => false,
    };
    if !valid {
        let article = if kind == "integer" { "an" } else { "a" };
        return Err(format!(
            "target {} must resolve to {article} {kind}",
            target.name()
        ));
    }
    Ok(())
}

fn validate_constant(target: Target, value: &Value) -> Result<(), String> {
    let string = value.as_str();
    match target {
        Target::EventId
            if string.is_some_and(|value| value.trim().is_empty() || value.len() > 256) =>
        {
            Err("must contain 1..=256 bytes".to_string())
        }
        Target::Method if string != Some("POST") => Err("must equal POST".to_string()),
        Target::Route
            if string.is_some_and(|value| {
                value.is_empty()
                    || value.len() > 1_024
                    || crate::protocol::classify_inference_protocol("POST", value).is_none()
            }) =>
        {
            Err("must be an exact catalogued POST path".to_string())
        }
        Target::Status if !matches!(value.as_u64(), Some(100..=599)) => {
            Err("must be within 100..=599".to_string())
        }
        Target::Model
        | Target::DimensionsApp
        | Target::DimensionsTeam
        | Target::DimensionsEnvironment
        | Target::DimensionsCostCenter
            if string.is_some_and(|value| value.len() > 256) =>
        {
            Err("must contain at most 256 bytes".to_string())
        }
        Target::ActualSupplyValue
            if string.is_some_and(|value| value.trim().is_empty() || value.len() > 256) =>
        {
            Err("must contain 1..=256 bytes".to_string())
        }
        Target::DimensionsTaskClass
            if !matches!(
                string,
                Some(
                    "mechanical"
                        | "heavy-lifting"
                        | "taste-sensitive"
                        | "judgment"
                        | "unclassified"
                )
            ) =>
        {
            Err("must be a supported task class".to_string())
        }
        _ => Ok(()),
    }
}

fn validate_pointer(path: &str, target: Target, pointer: &str) -> Result<(), ProfileError> {
    if !pointer.starts_with('/') || pointer.len() > 1_024 {
        return Err(profile_error(
            path,
            "source pointer must be a bounded JSON pointer",
        ));
    }
    let forbidden = BTreeSet::from([
        "prompt",
        "prompts",
        "messages",
        "message",
        "content",
        "contents",
        "toolarguments",
        "toolargs",
        "requestbody",
        "responsebody",
        "headers",
        "header",
        "authorization",
        "auth",
        "token",
        "tokens",
        "apikey",
        "secret",
        "secrets",
        "cookie",
        "cookies",
        "password",
        "passwords",
        "rawurl",
        "rawurls",
        "credential",
        "credentials",
    ]);
    for encoded in pointer.split('/').skip(1) {
        let bytes = encoded.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'~' && !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                return Err(profile_error(path, "invalid JSON pointer escape"));
            }
        }
        let decoded = encoded.replace("~1", "/").replace("~0", "~");
        let normalized = decoded
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        let usage_scalar = match target {
            Target::InputTokens => matches!(normalized.as_str(), "prompttokens" | "inputtokens"),
            Target::OutputTokens => {
                matches!(normalized.as_str(), "completiontokens" | "outputtokens")
            }
            _ => false,
        };
        if !usage_scalar && forbidden.iter().any(|word| normalized.contains(word)) {
            return Err(profile_error(path, "forbidden source pointer segment"));
        }
    }
    Ok(())
}

fn validate_profile_string(path: &str, name: &str, value: &str) -> Result<(), ProfileError> {
    if value.trim().is_empty() || value.len() > MAX_PROFILE_STRING_BYTES {
        Err(profile_error(
            path,
            format!("{name} must contain 1..={MAX_PROFILE_STRING_BYTES} bytes"),
        ))
    } else {
        Ok(())
    }
}

fn profile_error(path: &str, reason: impl Into<String>) -> ProfileError {
    ProfileError::Profile {
        path: path.to_string(),
        reason: reason.into(),
    }
}

fn source_error(
    profile: &TransformProfile,
    source_path: &str,
    line: usize,
    reason: impl Into<String>,
) -> ProfileError {
    ProfileError::Source {
        source_path: source_path.to_string(),
        line,
        profile_path: profile.path.clone(),
        reason: reason.into(),
    }
}

impl Target {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "event_id" => Self::EventId,
            "observed_at_ms" => Self::ObservedAtMs,
            "method" => Self::Method,
            "route" => Self::Route,
            "model" => Self::Model,
            "actual_supply_value" => Self::ActualSupplyValue,
            "status" => Self::Status,
            "streamed" => Self::Streamed,
            "latency_ms" => Self::LatencyMs,
            "input_tokens" => Self::InputTokens,
            "output_tokens" => Self::OutputTokens,
            "dimensions.app" => Self::DimensionsApp,
            "dimensions.team" => Self::DimensionsTeam,
            "dimensions.environment" => Self::DimensionsEnvironment,
            "dimensions.cost_center" => Self::DimensionsCostCenter,
            "dimensions.task_class" => Self::DimensionsTaskClass,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::EventId => "event_id",
            Self::ObservedAtMs => "observed_at_ms",
            Self::Method => "method",
            Self::Route => "route",
            Self::Model => "model",
            Self::ActualSupplyValue => "actual_supply_value",
            Self::Status => "status",
            Self::Streamed => "streamed",
            Self::LatencyMs => "latency_ms",
            Self::InputTokens => "input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::DimensionsApp => "dimensions.app",
            Self::DimensionsTeam => "dimensions.team",
            Self::DimensionsEnvironment => "dimensions.environment",
            Self::DimensionsCostCenter => "dimensions.cost_center",
            Self::DimensionsTaskClass => "dimensions.task_class",
        }
    }

    fn dimension_name(self) -> Option<&'static str> {
        match self {
            Self::DimensionsApp => Some("app"),
            Self::DimensionsTeam => Some("team"),
            Self::DimensionsEnvironment => Some("environment"),
            Self::DimensionsCostCenter => Some("cost_center"),
            Self::DimensionsTaskClass => Some("task_class"),
            _ => None,
        }
    }

    fn required() -> &'static [Self] {
        &[
            Self::EventId,
            Self::ObservedAtMs,
            Self::Method,
            Self::Route,
            Self::Status,
            Self::Streamed,
            Self::LatencyMs,
        ]
    }

    fn required_per_event(self) -> bool {
        Self::required().contains(&self)
    }
}

impl TimestampUnit {
    fn to_milliseconds(self, value: u64) -> Option<u64> {
        match self {
            Self::Milliseconds => Some(value),
            Self::Seconds => value.checked_mul(1_000),
            Self::Microseconds => Some(value / 1_000),
            Self::Nanoseconds => Some(value / 1_000_000),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use bowline_core::{
        attribution::{AttributionResolver, AttributionRule},
        config::OwnedCostCatalog,
        decision::QualityFloors,
        policy::PolicyBundle,
        supply::Registry,
        traffic::CoverageStatus,
    };

    use crate::passive::{normalize_passive_event, PassiveNormalizationContext};

    use super::{transform_profile_jsonl, TransformProfile};

    #[test]
    fn shipped_profiles_normalize_to_the_same_canonical_facts() {
        let litellm = shipped("litellm", "profile.yaml");
        let envoy = shipped("envoy", "profile.yaml");
        let litellm_source = shipped("litellm", "fixture.jsonl");
        let envoy_source = shipped("envoy", "fixture.jsonl");

        let litellm_profile =
            TransformProfile::from_yaml(&litellm, "litellm/profile.yaml").expect("LiteLLM profile");
        let envoy_profile =
            TransformProfile::from_yaml(&envoy, "envoy/profile.yaml").expect("Envoy profile");
        let left =
            transform_profile_jsonl(&litellm_profile, &litellm_source, "litellm/fixture.jsonl")
                .expect("LiteLLM transforms");
        let right = transform_profile_jsonl(&envoy_profile, &envoy_source, "envoy/fixture.jsonl")
            .expect("Envoy transforms");

        assert_eq!(left.len(), 1);
        assert_eq!(right.len(), 1);
        let left = &left[0].event;
        let right = &right[0].event;
        assert_eq!(left.event_id, right.event_id);
        assert_eq!(left.observed_at_ms, right.observed_at_ms);
        assert_eq!(left.method, right.method);
        assert_eq!(left.route, right.route);
        assert_eq!(left.model, right.model);
        assert_eq!(left.actual_supply_ref, right.actual_supply_ref);
        assert_eq!(left.status, right.status);
        assert_eq!(left.streamed, right.streamed);
        assert_eq!(left.latency_ms, right.latency_ms);
        assert_eq!(left.input_tokens, right.input_tokens);
        assert_eq!(left.output_tokens, right.output_tokens);
        assert_eq!(left.dimensions.app, right.dimensions.app);
    }

    #[test]
    fn strict_profiles_and_scalar_extraction_reject_unsafe_shapes() {
        let base = profile();
        for (name, source, reason) in [
            (
                "missing required target",
                base.replace("  latency_ms: /latency_ms\n", ""),
                "missing required target latency_ms",
            ),
            (
                "unknown target",
                base.replace("  model: /model\n", "  arbitrary: /model\n"),
                "unknown profile target arbitrary",
            ),
            (
                "duplicate target",
                base.replace("constants:\n", "constants:\n  model: duplicate\n"),
                "target model is configured more than once",
            ),
            (
                "unsupported timestamp unit",
                base.replace("timestamp_unit: milliseconds", "timestamp_unit: minutes"),
                "unsupported timestamp unit",
            ),
            (
                "forbidden headers pointer",
                base.replace("  model: /model", "  model: /headers/authorization"),
                "forbidden source pointer segment",
            ),
            (
                "forbidden messages pointer",
                base.replace("  model: /model", "  model: /messages/0/content"),
                "forbidden source pointer segment",
            ),
            (
                "normalized forbidden pointer",
                base.replace("  model: /model", "  model: /API_Key"),
                "forbidden source pointer segment",
            ),
            (
                "plural forbidden pointer",
                base.replace("  model: /model", "  model: /tokens"),
                "forbidden source pointer segment",
            ),
            (
                "malformed pointer escape",
                base.replace("  model: /model", "  model: /api~2key"),
                "invalid JSON pointer escape",
            ),
            (
                "constant attribution without namespace",
                base.replace("attribution_namespace: deployment\n", "")
                    .replace("  actual_supply_value: /deployment\n", "")
                    .replace("constants:\n", "constants:\n  actual_supply_value: east\n"),
                "actual_supply_value requires attribution_namespace",
            ),
        ] {
            let error = TransformProfile::from_yaml(&source, "unsafe-profile.yaml")
                .expect_err(name)
                .to_string();
            assert!(error.contains("unsafe-profile.yaml"), "{name}: {error}");
            assert!(error.contains(reason), "{name}: {error}");
            assert!(!error.contains("authorization"), "{name}: {error}");
            assert!(!error.contains("messages"), "{name}: {error}");
        }

        let profile = TransformProfile::from_yaml(&base, "profile.yaml").expect("profile");
        for (name, source, reason) in [
            (
                "wrong scalar type",
                raw_event().replace("\"status_code\":200", "\"status_code\":{}"),
                "target status must resolve to an integer",
            ),
            (
                "required source value absent",
                raw_event().replace(",\"latency_ms\":25", ""),
                "required target latency_ms is absent or null",
            ),
            (
                "arbitrary object copy",
                raw_event().replace("\"model\":\"shared-model\"", "\"model\":{}"),
                "target model must resolve to a string",
            ),
            (
                "oversized scalar",
                raw_event().replace("shared-model", &"x".repeat(257)),
                "model must contain at most 256 bytes",
            ),
        ] {
            let input = format!("{}\n{source}", raw_event().replace("req-1", "req-first"));
            let error = transform_profile_jsonl(&profile, &input, "source.jsonl")
                .expect_err(name)
                .to_string();
            assert!(
                error.starts_with("source.jsonl:2 (profile profile.yaml):"),
                "{name}: {error}"
            );
            assert!(error.contains(reason), "{name}: {error}");
            assert!(!error.contains("shared-model"), "{name}: {error}");
        }
    }

    #[test]
    fn absent_optional_profile_values_are_semantic_coverage_gaps() {
        let profile = TransformProfile::from_yaml(&profile(), "profile.yaml").expect("profile");
        for (name, source, reason) in [
            (
                "model",
                raw_event().replace("\"model\":\"shared-model\",", ""),
                "missing-model",
            ),
            (
                "attribution",
                raw_event().replace("\"deployment\":\"east\",", ""),
                "missing-attribution",
            ),
            (
                "usage",
                raw_event().replace("\"prompt_tokens\":10", "\"prompt_tokens\":null"),
                "missing-required-usage",
            ),
            (
                "app",
                raw_event().replace("\"app\":\"support\"", "\"app\":null"),
                "missing-app",
            ),
        ] {
            let parsed = transform_profile_jsonl(&profile, &source, "source.jsonl")
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let record = normalize_passive_event(&parsed[0], &context())
                .expect("semantic normalization")
                .record;
            assert_eq!(
                record.coverage_status,
                CoverageStatus::IncompleteObservation,
                "{name}"
            );
            assert_eq!(record.coverage_reason.as_deref(), Some(reason), "{name}");
            assert!(record.decision.shadow.is_none(), "{name}");
            assert_eq!(record.actual.est_cost_usd, None, "{name}");
        }
    }

    #[test]
    fn envoy_formatter_profile_and_fixture_are_in_parity() {
        let formatter = shipped("envoy", "typed-json-access-log.yaml");
        let profile_source = shipped("envoy", "profile.yaml");
        let fixture = shipped("envoy", "fixture.jsonl");
        let profile = TransformProfile::from_yaml(&profile_source, "envoy/profile.yaml")
            .expect("Envoy profile");
        profile
            .validate_producer_contract(&formatter, &fixture)
            .expect("formatter, profile, and fixture parity");
        transform_profile_jsonl(&profile, &fixture, "envoy/fixture.jsonl")
            .expect("fixture transforms");
    }

    #[test]
    fn profile_and_source_contract_digest_is_content_addressed() {
        let first = TransformProfile::from_yaml(&profile(), "profile.yaml").expect("profile");
        let changed = TransformProfile::from_yaml(
            &profile().replace("source_contract: test-v1", "source_contract: test-v2"),
            "profile.yaml",
        )
        .expect("changed profile");
        assert_ne!(first.normalized_digest(), changed.normalized_digest());
        assert_eq!(first.source_contract(), "test-v1");
    }

    #[test]
    fn supported_timestamp_units_normalize_to_milliseconds() {
        for (unit, input, expected) in [
            ("milliseconds", 1_783_785_600_123_u64, 1_783_785_600_123_u64),
            ("seconds", 1_783_785_600_u64, 1_783_785_600_000_u64),
            (
                "microseconds",
                1_783_785_600_123_000_u64,
                1_783_785_600_123_u64,
            ),
            (
                "nanoseconds",
                1_783_785_600_123_000_000_u64,
                1_783_785_600_123_u64,
            ),
        ] {
            let profile = TransformProfile::from_yaml(
                &profile().replace(
                    "timestamp_unit: milliseconds",
                    &format!("timestamp_unit: {unit}"),
                ),
                "profile.yaml",
            )
            .expect("supported timestamp unit");
            let source = raw_event().replace("1783785600123", &input.to_string());
            let parsed = transform_profile_jsonl(&profile, &source, "source.jsonl")
                .expect("timestamp transforms");
            assert_eq!(parsed[0].event.observed_at_ms, expected, "{unit}");
        }
    }

    #[test]
    fn compound_sensitive_pointer_segments_are_rejected_without_reflection() {
        for pointer in [
            "/auth_token",
            "/clientSecret",
            "/authorization.value",
            "/request-body-text",
            "/responseBody",
            "/api_key_value",
            "/Client.SECRET.Value",
        ] {
            let source = profile().replace("  model: /model", &format!("  model: {pointer}"));
            let error = TransformProfile::from_yaml(&source, "profile.yaml")
                .expect_err("compound sensitive pointer")
                .to_string();
            assert!(
                error.contains("forbidden source pointer segment"),
                "{error}"
            );
            assert!(!error.contains(pointer), "{error}");
        }
        TransformProfile::from_yaml(
            &profile().replace("  model: /model", "  model: /model_identifier"),
            "profile.yaml",
        )
        .expect("innocuous compound pointer remains supported");
    }

    #[test]
    fn envoy_parity_rejects_missing_keys_non_objects_and_wrong_types() {
        let formatter = shipped("envoy", "typed-json-access-log.yaml");
        let profile_source = shipped("envoy", "profile.yaml");
        let fixture = shipped("envoy", "fixture.jsonl");
        let profile = TransformProfile::from_yaml(&profile_source, "envoy/profile.yaml").unwrap();
        for (name, formatter_source, fixture_source) in [
            (
                "missing formatter",
                formatter.replace("  model: \"%DYNAMIC_METADATA(bowline:model)%\"\n", ""),
                fixture.clone(),
            ),
            (
                "missing fixture",
                formatter.clone(),
                fixture.replace("\"model\":\"shared-model\",", ""),
            ),
            ("non-object fixture", formatter.clone(), "[]\n".to_string()),
            (
                "wrong scalar",
                formatter.clone(),
                fixture.replace("\"status\":200", "\"status\":\"200\""),
            ),
        ] {
            let error = profile
                .validate_producer_contract(&formatter_source, &fixture_source)
                .expect_err(name)
                .to_string();
            assert!(error.contains("envoy/profile.yaml"), "{name}: {error}");
        }
    }

    #[test]
    fn invalid_constants_fail_when_the_profile_loads() {
        for (name, source) in [
            (
                "empty event",
                profile()
                    .replace("  event_id: /request_id\n", "")
                    .replace("constants:\n", "constants:\n  event_id: ''\n"),
            ),
            (
                "oversized model",
                profile().replace("  model: /model\n", "").replace(
                    "constants:\n",
                    &format!("constants:\n  model: {}\n", "x".repeat(257)),
                ),
            ),
            (
                "invalid task class",
                profile().replace(
                    "constants:\n",
                    "constants:\n  dimensions.task_class: impossible\n",
                ),
            ),
            (
                "invalid method",
                profile().replace("  method: POST", "  method: GET"),
            ),
        ] {
            TransformProfile::from_yaml(&source, "profile.yaml").expect_err(name);
        }
    }

    #[test]
    fn usage_pointer_names_are_allowed_only_for_matching_usage_targets() {
        for target in ["model", "event_id"] {
            for pointer in [
                "/prompt_tokens",
                "/completion_tokens",
                "/input_tokens",
                "/output_tokens",
            ] {
                let source = profile().replace(
                    &format!(
                        "  {target}: /{}",
                        if target == "model" {
                            "model"
                        } else {
                            "request_id"
                        }
                    ),
                    &format!("  {target}: {pointer}"),
                );
                let error = TransformProfile::from_yaml(&source, "profile.yaml")
                    .expect_err("usage pointer laundering")
                    .to_string();
                assert!(error.contains("forbidden source pointer segment"));
                assert!(!error.contains(pointer));
            }
        }
        for (target, allowed) in [
            ("input_tokens", ["/prompt_tokens", "/input_tokens"]),
            ("output_tokens", ["/completion_tokens", "/output_tokens"]),
        ] {
            for pointer in allowed {
                let original = if target == "input_tokens" {
                    "/usage/prompt_tokens"
                } else {
                    "/usage/completion_tokens"
                };
                TransformProfile::from_yaml(
                    &profile().replace(
                        &format!("  {target}: {original}"),
                        &format!("  {target}: {pointer}"),
                    ),
                    "profile.yaml",
                )
                .expect("matching usage target");
            }
        }
    }

    #[test]
    fn unusable_constants_and_timestamp_overflow_fail_at_profile_load() {
        let cases = [
            profile()
                .replace("  event_id: /request_id\n", "")
                .replace("constants:\n", "constants:\n  event_id: '   '\n"),
            profile()
                .replace("  status: /status_code\n", "")
                .replace("constants:\n", "constants:\n  status: 99\n"),
            profile()
                .replace("  status: /status_code\n", "")
                .replace("constants:\n", "constants:\n  status: 600\n"),
            constant_route("/not-catalogued"),
            constant_route("https://user:pass@example.invalid/v1/responses"),
            constant_route("/v1/responses?token=x"),
            profile()
                .replace("  actual_supply_value: /deployment\n", "")
                .replace("constants:\n", "constants:\n  actual_supply_value: ''\n"),
            profile().replace(
                "attribution_namespace: deployment",
                "attribution_namespace: '   '",
            ),
            profile()
                .replace("timestamp_unit: milliseconds", "timestamp_unit: seconds")
                .replace("  observed_at_ms: /started_at_ms\n", "")
                .replace(
                    "constants:\n",
                    "constants:\n  observed_at_ms: 18446744073709551615\n",
                ),
            profile()
                .replace(
                    "timestamp_unit: milliseconds",
                    "timestamp_unit: microseconds",
                )
                .replace("  observed_at_ms: /started_at_ms\n", "")
                .replace(
                    "constants:\n",
                    "constants:\n  observed_at_ms: 18446744073709551616\n",
                ),
            profile()
                .replace(
                    "timestamp_unit: milliseconds",
                    "timestamp_unit: nanoseconds",
                )
                .replace("  observed_at_ms: /started_at_ms\n", "")
                .replace(
                    "constants:\n",
                    "constants:\n  observed_at_ms: 18446744073709551616\n",
                ),
        ];
        for source in cases {
            TransformProfile::from_yaml(&source, "profile.yaml").expect_err("unusable constant");
        }
    }

    fn constant_route(route: &str) -> String {
        profile()
            .replace("  route: /route\n", "")
            .replace("constants:\n", &format!("constants:\n  route: '{route}'\n"))
    }

    fn profile() -> String {
        r#"version: 1
kind: test-jsonl-v1
source_contract: test-v1
attribution_namespace: deployment
timestamp_unit: milliseconds
fields:
  event_id: /request_id
  observed_at_ms: /started_at_ms
  route: /route
  model: /model
  actual_supply_value: /deployment
  status: /status_code
  latency_ms: /latency_ms
  input_tokens: /usage/prompt_tokens
  output_tokens: /usage/completion_tokens
  dimensions.app: /metadata/app
constants:
  method: POST
  streamed: false
"#
        .to_string()
    }

    fn raw_event() -> String {
        r#"{"request_id":"req-1","started_at_ms":1783785600123,"route":"/v1/responses","model":"shared-model","deployment":"east","status_code":200,"latency_ms":25,"usage":{"prompt_tokens":10,"completion_tokens":5},"metadata":{"app":"support"}}"#.to_string()
    }

    fn shipped(integration: &str, name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../integrations")
            .join(integration)
            .join(name);
        fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
    }

    fn context() -> PassiveNormalizationContext {
        let registry = Registry::from_json(r#"{"feed_version":"test","entries":[
          {"id":"public/east","model":"shared-model","location":"east","attributes":{"class":"public-api","jurisdiction":"us","retention":"days30","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0},"ratings":{"mechanical":0.9}}
        ]}"#).expect("registry");
        let policy = PolicyBundle::from_yaml(
            r#"version: 1
rules:
  - name: default
    default: true
    require:
      supply_class: [public-api]
"#,
        )
        .expect("policy");
        let resolver = AttributionResolver::new(
            vec![AttributionRule {
                namespace: "deployment".into(),
                value: "east".into(),
                supply_id: "public/east".into(),
            }],
            None,
            &registry,
        )
        .expect("resolver");
        PassiveNormalizationContext {
            policy,
            registry,
            resolver,
            owned_costs: OwnedCostCatalog::default(),
            floors: QualityFloors::default(),
        }
    }
}
