use std::{
    collections::{BTreeSet, HashMap},
    fmt,
};

use bowline_core::{
    attribution::{
        resolve_actual_supply, AttributionInput, AttributionRef, AttributionResolver,
        AttributionResult, AttributionSource, AttributionStatus,
    },
    config::OwnedCostCatalog,
    decision::{decide, QualityFloors},
    ledger::{DecisionRecord, UsageSource},
    policy::{PolicyBundle, WorkloadIdentity},
    supply::{Registry, TaskClass},
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{
    observation::{
        actual_cost, apply_attribution_coverage, build_decision_record, ActualObservation,
        RecordEnvelope,
    },
    protocol::classify_inference_protocol,
};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 16 * 1024;
pub const MAX_EVENTS: usize = 100_000;
const MAX_ID_BYTES: usize = 256;
const MAX_DIMENSION_BYTES: usize = 256;
const MAX_ROUTE_BYTES: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPassiveEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub observed_at_ms: u64,
    pub method: String,
    pub route: String,
    pub model: Option<String>,
    pub actual_supply_ref: Option<AttributionRef>,
    pub status: u16,
    pub streamed: bool,
    pub latency_ms: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub dimensions: PassiveDimensions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveDimensions {
    pub app: Option<String>,
    pub team: Option<String>,
    pub environment: Option<String>,
    pub cost_center: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_task_class")]
    pub task_class: Option<TaskClass>,
}

fn deserialize_optional_task_class<'de, D>(deserializer: D) -> Result<Option<TaskClass>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionalTaskClassVisitor;

    impl<'de> Visitor<'de> for OptionalTaskClassVisitor {
        type Value = Option<TaskClass>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded task-class string or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(TaskClassVisitor).map(Some)
        }
    }

    struct TaskClassVisitor;

    impl Visitor<'_> for TaskClassVisitor {
        type Value = TaskClass;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a supported task-class string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_DIMENSION_BYTES {
                return Err(E::custom(
                    "dimensions.task_class must contain at most 256 bytes",
                ));
            }
            match value {
                "mechanical" => Ok(TaskClass::Mechanical),
                "heavy-lifting" => Ok(TaskClass::HeavyLifting),
                "taste-sensitive" => Ok(TaskClass::TasteSensitive),
                "judgment" => Ok(TaskClass::Judgment),
                "unclassified" => Ok(TaskClass::Unclassified),
                _ => Err(E::custom("invalid dimensions.task_class value")),
            }
        }
    }

    deserializer.deserialize_option(OptionalTaskClassVisitor)
}

#[derive(Debug, Clone)]
pub struct ParsedPassiveEvent {
    pub source_line: usize,
    pub event: CanonicalPassiveEvent,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionRecordDraft {
    pub source_line: usize,
    pub record: DecisionRecord,
}

pub struct PassiveNormalizationContext {
    pub policy: PolicyBundle,
    pub registry: Registry,
    pub resolver: AttributionResolver,
    pub owned_costs: OwnedCostCatalog,
    pub floors: QualityFloors,
}

#[derive(Debug, Error)]
pub enum PassiveError {
    #[error("{path}:{line}: {reason}")]
    Line {
        path: String,
        line: usize,
        reason: String,
    },
    #[error("{path}: {reason}")]
    Input { path: String, reason: String },
}

pub fn parse_canonical_jsonl(source: &str) -> Result<Vec<ParsedPassiveEvent>, PassiveError> {
    parse_canonical_jsonl_named(source, "<memory>")
}

pub fn parse_canonical_jsonl_named(
    source: &str,
    path: &str,
) -> Result<Vec<ParsedPassiveEvent>, PassiveError> {
    if source.len() > MAX_INPUT_BYTES {
        return Err(PassiveError::Input {
            path: path.to_string(),
            reason: format!("input exceeds {MAX_INPUT_BYTES} bytes"),
        });
    }
    let mut parsed = Vec::new();
    let mut event_lines = HashMap::<String, usize>::new();
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if parsed.len() >= MAX_EVENTS {
            return line_error(
                path,
                line_number,
                format!("event count exceeds {MAX_EVENTS}"),
            );
        }
        if line.len() > MAX_LINE_BYTES {
            return line_error(
                path,
                line_number,
                format!("line exceeds {MAX_LINE_BYTES} bytes"),
            );
        }
        let event: CanonicalPassiveEvent =
            serde_json::from_str(line).map_err(|error| PassiveError::Line {
                path: path.to_string(),
                line: line_number,
                reason: error.to_string(),
            })?;
        validate_event(&event).map_err(|reason| PassiveError::Line {
            path: path.to_string(),
            line: line_number,
            reason,
        })?;
        if let Some(first_line) = event_lines.insert(event.event_id.clone(), line_number) {
            return line_error(
                path,
                line_number,
                format!(
                    "duplicate event_id first seen at line {first_line}, duplicated at line {line_number}"
                ),
            );
        }
        parsed.push(ParsedPassiveEvent {
            source_line: line_number,
            event,
        });
    }
    Ok(parsed)
}

pub(crate) fn validate_event(event: &CanonicalPassiveEvent) -> Result<(), String> {
    if event.schema_version != 1 {
        return Err("schema_version must equal 1".to_string());
    }
    validate_required("event_id", &event.event_id, MAX_ID_BYTES)?;
    validate_required("method", &event.method, 16)?;
    validate_required("route", &event.route, MAX_ROUTE_BYTES)?;
    if event.route.contains("://")
        || event.route.starts_with("//")
        || event.route.contains('?')
        || event.route.contains('#')
    {
        return Err(
            "route must be an exact path without URL authority, query, or fragment".to_string(),
        );
    }
    if !(100..=599).contains(&event.status) {
        return Err("status must be within 100..=599".to_string());
    }
    if classify_inference_protocol(&event.method, &event.route).is_none() {
        return Err("method/path is absent from the inference catalog".to_string());
    }
    if let Some(model) = &event.model {
        validate_optional("model", model, MAX_ID_BYTES)?;
    }
    if let Some(reference) = &event.actual_supply_ref {
        reference.validate().map_err(|error| error.to_string())?;
    }
    for (name, value) in [
        ("dimensions.app", event.dimensions.app.as_deref()),
        ("dimensions.team", event.dimensions.team.as_deref()),
        (
            "dimensions.environment",
            event.dimensions.environment.as_deref(),
        ),
        (
            "dimensions.cost_center",
            event.dimensions.cost_center.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_optional(name, value, MAX_DIMENSION_BYTES)?;
        }
    }
    Ok(())
}

fn validate_required(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max {
        Err(format!("{name} must contain 1..={max} bytes"))
    } else {
        Ok(())
    }
}

fn validate_optional(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        Err(format!("{name} must contain at most {max} bytes"))
    } else {
        Ok(())
    }
}

fn line_error<T>(path: &str, line: usize, reason: String) -> Result<T, PassiveError> {
    Err(PassiveError::Line {
        path: path.to_string(),
        line,
        reason,
    })
}

pub fn normalize_passive_event(
    parsed: &ParsedPassiveEvent,
    context: &PassiveNormalizationContext,
) -> Result<DecisionRecordDraft, PassiveError> {
    let event = &parsed.event;
    let protocol = classify_inference_protocol(&event.method, &event.route).ok_or_else(|| {
        PassiveError::Line {
            path: "<normalized>".to_string(),
            line: parsed.source_line,
            reason: "method/path is absent from the inference catalog".to_string(),
        }
    })?;
    let app = event
        .dimensions
        .app
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let mut tags = dimension_tags(&event.dimensions);
    let mut identity = WorkloadIdentity {
        api_key_digest: None,
        route: event.route.clone(),
        app,
        tags: tags.clone(),
    };
    tags.extend(context.policy.resolve_tags(&identity));
    tags.sort();
    tags.dedup();
    identity.tags = tags;

    let model = event
        .model
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let input_tokens = event.input_tokens;
    let output_tokens = match protocol {
        ProtocolKind::Embeddings => event.output_tokens.or(Some(0)),
        _ => event.output_tokens,
    };
    let mut decision = decide(
        &context.policy,
        &context.registry,
        &context.floors,
        &identity,
        event.dimensions.task_class,
        input_tokens.unwrap_or(0),
        output_tokens.unwrap_or(0),
        &context.owned_costs,
    );
    let attribution_input = event
        .actual_supply_ref
        .clone()
        .map(AttributionInput::Single)
        .unwrap_or(AttributionInput::Absent);
    let mut attribution = if protocol.is_supported() {
        resolve_actual_supply(
            &context.resolver,
            &context.registry,
            attribution_input,
            model.as_deref(),
            AttributionSource::PassiveEvent,
        )
    } else {
        AttributionResult {
            status: AttributionStatus::Missing,
            source: AttributionSource::PassiveEvent,
            reference: None,
            supply_id: None,
            reason: Some("attribution-not-attempted-for-unsupported-observation".to_string()),
        }
    };

    let (coverage_status, coverage_reason) = if !protocol.is_supported() {
        (
            CoverageStatus::UnsupportedProtocol,
            Some("unsupported-protocol".to_string()),
        )
    } else if identity.app.is_none() {
        (
            CoverageStatus::IncompleteObservation,
            Some("missing-app".to_string()),
        )
    } else if model.is_none() {
        (
            CoverageStatus::IncompleteObservation,
            Some("missing-model".to_string()),
        )
    } else if let Some(reason) = missing_usage_reason(protocol, input_tokens, event.output_tokens) {
        (CoverageStatus::IncompleteObservation, Some(reason))
    } else {
        (CoverageStatus::Supported, None)
    };
    let (coverage_status, coverage_reason) =
        apply_attribution_coverage(coverage_status, coverage_reason, &attribution, true);
    let supported = coverage_status == CoverageStatus::Supported;
    if !supported {
        decision.shadow = None;
        attribution.supply_id = None;
    }
    let est_cost_usd = supported
        .then(|| {
            actual_cost(
                &context.registry,
                attribution.supply_id.as_deref(),
                model.as_deref(),
                input_tokens,
                output_tokens,
                &context.owned_costs,
            )
        })
        .flatten();
    let usage_source = if input_tokens.is_none() && event.output_tokens.is_none() {
        UsageSource::Missing
    } else {
        UsageSource::Observed
    };
    let record = build_decision_record(
        RecordEnvelope {
            id: event.event_id.clone(),
            ts_ms: event.observed_at_ms,
            run_id: None,
            sequence: None,
            accounting_truncated: false,
            protocol,
            observation_source: ObservationSource::Passive,
            coverage_status,
            coverage_reason,
            identity,
            decision,
        },
        ActualObservation {
            upstream: "passive".to_string(),
            model,
            status: event.status,
            streamed: event.streamed,
            latency_ms: event.latency_ms,
            input_tokens,
            output_tokens,
            usage_source,
            est_cost_usd,
            attribution,
        },
    );
    Ok(DecisionRecordDraft {
        source_line: parsed.source_line,
        record,
    })
}

fn missing_usage_reason(
    protocol: ProtocolKind,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
) -> Option<String> {
    let missing = match protocol {
        ProtocolKind::ChatCompletions | ProtocolKind::Responses => {
            input_tokens.is_none() || output_tokens.is_none()
        }
        ProtocolKind::Embeddings => input_tokens.is_none(),
        ProtocolKind::Unsupported => false,
    };
    missing.then(|| "missing-required-usage".to_string())
}

fn dimension_tags(dimensions: &PassiveDimensions) -> Vec<String> {
    [
        ("team", dimensions.team.as_deref()),
        ("environment", dimensions.environment.as_deref()),
        ("cost-center", dimensions.cost_center.as_deref()),
    ]
    .into_iter()
    .filter_map(|(namespace, value)| {
        value
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("{namespace}:{value}"))
    })
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use bowline_core::{
        attribution::{AttributionResolver, AttributionRule, AttributionStatus},
        config::OwnedCostCatalog,
        decision::QualityFloors,
        ledger::{RecoveryOutcome, UsageSource},
        policy::PolicyBundle,
        report::compute_report,
        supply::Registry,
        traffic::{CoverageStatus, ObservationSource, ProtocolKind},
    };
    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn strict_canonical_schema_rejects_structural_errors_with_lines() {
        let valid = include_str!("../tests/fixtures/passive/canonical-v1.jsonl");
        let parsed = parse_canonical_jsonl(valid).expect("fixture parses");
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].source_line, 1);
        assert_eq!(parsed[0].event.event_id, "chat-1");

        for (name, source, reason) in [
            ("malformed", "{".to_string(), "fixture.jsonl:1:"),
            ("unknown", event_with("\"prompt\":\"secret\","), "unknown field"),
            ("version", event().replace("\"schema_version\":1", "\"schema_version\":2"), "schema_version"),
            ("empty id", event().replace("\"event_id\":\"evt-1\"", "\"event_id\":\"\""), "event_id"),
            ("status", event().replace("\"status\":200", "\"status\":99"), "status"),
            (
                "dimensions",
                event().replace(
                    ",\"dimensions\":{\"app\":\"support\",\"team\":\"customer-ops\",\"environment\":\"prod\",\"cost_center\":\"cc-14\",\"task_class\":\"mechanical\"}",
                    "",
                ),
                "dimensions",
            ),
            ("route", event().replace("/v1/chat/completions", "/not-inference"), "method/path"),
        ] {
            let error = parse_canonical_jsonl_named(&source, "fixture.jsonl").expect_err(name);
            assert!(error.to_string().contains(reason), "{name}: {error}");
        }

        for forbidden in [
            "prompt",
            "messages",
            "input",
            "output",
            "headers",
            "authorization",
            "url",
            "cost",
            "supply_id",
            "placement",
            "decision",
            "coverage",
            "protocol",
        ] {
            assert!(parse_canonical_jsonl_named(
                &event_with(&format!("\"{forbidden}\":\"forbidden\",")),
                "fixture.jsonl"
            )
            .is_err());
        }
        assert!(
            parse_canonical_jsonl_named(&"x".repeat(MAX_INPUT_BYTES + 1), "fixture.jsonl").is_err()
        );
        let duplicate = format!("{}\n{}", event(), event());
        let error = parse_canonical_jsonl_named(&duplicate, "fixture.jsonl")
            .expect_err("duplicate event ID");
        assert!(error.to_string().contains(
            "fixture.jsonl:2: duplicate event_id first seen at line 1, duplicated at line 2"
        ));
    }

    #[test]
    fn strict_field_bounds_types_and_urls_have_safe_line_errors() {
        let cases = [
            (
                "event id bound",
                event_with_json(&["event_id"], json!("x".repeat(MAX_ID_BYTES + 1))),
                "event_id must contain 1..=256 bytes",
            ),
            (
                "method bound",
                event_with_json(&["method"], json!("x".repeat(17))),
                "method must contain 1..=16 bytes",
            ),
            (
                "route bound",
                event_with_json(
                    &["route"],
                    json!(format!("/{}", "x".repeat(MAX_ROUTE_BYTES))),
                ),
                "route must contain 1..=1024 bytes",
            ),
            (
                "model bound",
                event_with_json(&["model"], json!("x".repeat(MAX_ID_BYTES + 1))),
                "model must contain at most 256 bytes",
            ),
            (
                "attribution namespace bound",
                event_with_json(&["actual_supply_ref", "namespace"], json!("x".repeat(257))),
                "invalid attribution namespace: exceeds 256 bytes",
            ),
            (
                "attribution value bound",
                event_with_json(&["actual_supply_ref", "value"], json!("x".repeat(257))),
                "invalid attribution value: exceeds 256 bytes",
            ),
            (
                "app bound",
                event_with_json(&["dimensions", "app"], json!("x".repeat(257))),
                "dimensions.app must contain at most 256 bytes",
            ),
            (
                "team bound",
                event_with_json(&["dimensions", "team"], json!("x".repeat(257))),
                "dimensions.team must contain at most 256 bytes",
            ),
            (
                "environment bound",
                event_with_json(&["dimensions", "environment"], json!("x".repeat(257))),
                "dimensions.environment must contain at most 256 bytes",
            ),
            (
                "cost center bound",
                event_with_json(&["dimensions", "cost_center"], json!("x".repeat(257))),
                "dimensions.cost_center must contain at most 256 bytes",
            ),
            (
                "task class bound",
                event_with_json(
                    &["dimensions", "task_class"],
                    json!(format!("SENSITIVE_SENTINEL{}", "x".repeat(257))),
                ),
                "dimensions.task_class must contain at most 256 bytes",
            ),
            (
                "line bound",
                event_with_json(
                    &["event_id"],
                    json!(format!("SENSITIVE_SENTINEL{}", "x".repeat(MAX_LINE_BYTES))),
                ),
                "line exceeds 16384 bytes",
            ),
            (
                "invalid timestamp type",
                event_with_json(&["observed_at_ms"], json!(false)),
                "invalid type",
            ),
            (
                "invalid streamed type",
                event_with_json(&["streamed"], json!(7)),
                "invalid type",
            ),
            (
                "invalid dimensions type",
                event_with_json(&["dimensions"], json!(7)),
                "invalid type",
            ),
            (
                "invalid task class type",
                event_with_json(&["dimensions", "task_class"], json!(7)),
                "invalid type",
            ),
            (
                "status above range",
                event_with_json(&["status"], json!(600)),
                "status must be within 100..=599",
            ),
            (
                "absolute URL",
                event_with_json(
                    &["route"],
                    json!("https://example.invalid/v1/chat/completions"),
                ),
                "route must be an exact path without URL authority, query, or fragment",
            ),
            (
                "query URL",
                event_with_json(
                    &["route"],
                    json!("/v1/chat/completions?token=SENSITIVE_SENTINEL"),
                ),
                "route must be an exact path without URL authority, query, or fragment",
            ),
            (
                "credential URL",
                event_with_json(
                    &["route"],
                    json!("//user:SENSITIVE_SENTINEL@example.invalid/v1/chat/completions"),
                ),
                "route must be an exact path without URL authority, query, or fragment",
            ),
        ];

        for (name, invalid, reason) in cases {
            assert_safe_line_error(name, &invalid, reason);
        }

        let mut events = String::new();
        for index in 0..=MAX_EVENTS {
            if index > 0 {
                events.push('\n');
            }
            events.push_str(&minimal_event(index));
        }
        assert!(
            events.len() <= MAX_INPUT_BYTES,
            "event-count fixture must fit input bound"
        );
        let error = parse_canonical_jsonl_named(&events, "fixture.jsonl")
            .expect_err("compiled event maximum");
        assert_eq!(
            error.to_string(),
            format!(
                "fixture.jsonl:{}: event count exceeds {MAX_EVENTS}",
                MAX_EVENTS + 1
            )
        );
    }

    #[test]
    fn normalization_recomputes_identity_policy_attribution_and_cost() {
        let context = context();
        let parsed = parse_canonical_jsonl(&event()).expect("event parses");
        let draft = normalize_passive_event(&parsed[0], &context).expect("normalizes");
        assert_eq!(draft.source_line, 1);
        assert_eq!(draft.record.id, "evt-1");
        assert_eq!(draft.record.ts_ms, 1_783_785_600_123);
        assert_eq!(draft.record.run_id, None);
        assert_eq!(draft.record.sequence, None);
        assert_eq!(draft.record.observation_source, ObservationSource::Passive);
        assert_eq!(draft.record.protocol, ProtocolKind::ChatCompletions);
        assert_eq!(draft.record.identity.api_key_digest, None);
        assert_eq!(draft.record.identity.app.as_deref(), Some("support"));
        assert!(draft
            .record
            .identity
            .tags
            .contains(&"team:customer-ops".to_string()));
        assert!(draft
            .record
            .identity
            .tags
            .contains(&"environment:prod".to_string()));
        assert!(draft
            .record
            .identity
            .tags
            .contains(&"cost-center:cc-14".to_string()));
        assert_eq!(
            draft.record.actual.supply_id.as_deref(),
            Some("public/east")
        );
        assert_eq!(
            draft.record.actual.attribution_status,
            AttributionStatus::Attributed
        );
        assert!(draft.record.actual.est_cost_usd.is_some());
        assert!(draft.record.decision.shadow.is_some());
        let dimensions =
            bowline_core::report::ReportDimensions::from_resolved_identity(&draft.record.identity);
        assert_eq!(dimensions.app, "support");
        assert_eq!(dimensions.team, "customer-ops");
        assert_eq!(dimensions.environment, "prod");
        assert_eq!(dimensions.cost_center, "cc-14");
        assert!(dimensions.complete);
    }

    #[test]
    fn incomplete_passive_evidence_is_coverage_only_without_legacy_fallback() {
        let context = context();
        for (source, reason) in [
            (
                event().replace("\"app\":\"support\"", "\"app\":\"\""),
                "missing-app",
            ),
            (
                event().replace(",\"model\":\"shared-model\"", ""),
                "missing-model",
            ),
            (
                event().replace(
                    ",\"actual_supply_ref\":{\"namespace\":\"deployment\",\"value\":\"east\"}",
                    "",
                ),
                "missing-attribution",
            ),
            (
                event().replace("\"value\":\"east\"", "\"value\":\"unknown\""),
                "unknown-attribution-reference",
            ),
            (
                event().replace("\"model\":\"shared-model\"", "\"model\":\"mismatch\""),
                "attribution-model-mismatch",
            ),
            (
                event().replace(",\"output_tokens\":5", ""),
                "missing-required-usage",
            ),
        ] {
            let parsed = parse_canonical_jsonl(&source).expect("structurally valid");
            let record = normalize_passive_event(&parsed[0], &context)
                .expect("normalizes")
                .record;
            assert_eq!(
                record.coverage_status,
                CoverageStatus::IncompleteObservation,
                "{reason}"
            );
            assert_eq!(record.coverage_reason.as_deref(), Some(reason));
            assert!(record.decision.shadow.is_none());
            assert_eq!(record.actual.supply_id, None);
            assert_eq!(record.actual.est_cost_usd, None);
        }
    }

    #[test]
    fn protocol_usage_matrix_preserves_coverage_and_economic_exclusion() {
        let context = context();
        let cases = [
            (
                "responses complete",
                "/v1/responses",
                Some(10),
                Some(5),
                CoverageStatus::Supported,
                None,
                UsageSource::Observed,
            ),
            (
                "responses missing input",
                "/v1/responses",
                None,
                Some(5),
                CoverageStatus::IncompleteObservation,
                Some("missing-required-usage"),
                UsageSource::Observed,
            ),
            (
                "responses missing output",
                "/v1/responses",
                Some(10),
                None,
                CoverageStatus::IncompleteObservation,
                Some("missing-required-usage"),
                UsageSource::Observed,
            ),
            (
                "embeddings missing input",
                "/v1/embeddings",
                None,
                Some(5),
                CoverageStatus::IncompleteObservation,
                Some("missing-required-usage"),
                UsageSource::Observed,
            ),
            (
                "embeddings absent output",
                "/v1/embeddings",
                Some(10),
                None,
                CoverageStatus::Supported,
                None,
                UsageSource::Observed,
            ),
            (
                "unsupported with tokens",
                "/v1/completions",
                Some(10),
                Some(5),
                CoverageStatus::UnsupportedProtocol,
                Some("unsupported-protocol"),
                UsageSource::Observed,
            ),
            (
                "unsupported without tokens",
                "/v1/completions",
                None,
                None,
                CoverageStatus::UnsupportedProtocol,
                Some("unsupported-protocol"),
                UsageSource::Missing,
            ),
        ];
        let mut excluded = Vec::new();

        for (name, route, input, output, status, reason, usage_source) in cases {
            let record = normalize_usage_case(route, input, output, &context);
            assert_eq!(record.coverage_status, status, "{name}");
            assert_eq!(record.coverage_reason.as_deref(), reason, "{name}");
            assert_eq!(record.actual.usage_source, usage_source, "{name}");
            if route == "/v1/embeddings" && input.is_some() && output.is_none() {
                assert_eq!(record.actual.output_tokens, Some(0), "{name}");
            }
            if status == CoverageStatus::Supported {
                assert!(record.decision.shadow.is_some(), "{name}");
                assert_eq!(
                    record.actual.supply_id.as_deref(),
                    Some("public/east"),
                    "{name}"
                );
                assert!(record.actual.est_cost_usd.is_some(), "{name}");
            } else {
                assert!(record.decision.shadow.is_none(), "{name}");
                assert_eq!(record.actual.supply_id, None, "{name}");
                assert_eq!(record.actual.est_cost_usd, None, "{name}");
                excluded.push(record);
            }
        }

        let report = compute_report(
            &excluded,
            &RecoveryOutcome::Clean {
                records: excluded.len() as u64,
            },
            &context.registry,
            &context.owned_costs,
            &context.floors,
            None,
        )
        .expect("excluded passive report");
        assert_eq!(report.protocol_coverage.supported_records, 0);
        assert_eq!(
            report.protocol_coverage.unsupported_records,
            excluded.len() as u64
        );
        assert_eq!(report.counterfactual.actual_cost_usd.value, None);
        assert_eq!(report.counterfactual.shadow_cost_usd.value, None);
        assert_eq!(report.unmapped_records, 0);
        assert_eq!(report.unpriced_records, 0);
        assert!(report.tier_arbitrage.is_empty());
    }

    #[test]
    fn absent_token_evidence_is_missing_independent_of_coverage() {
        let context = context();
        let record = normalize_usage_case("/v1/completions", None, None, &context);
        assert_eq!(record.coverage_status, CoverageStatus::UnsupportedProtocol);
        assert_eq!(record.actual.usage_source, UsageSource::Missing);
    }

    #[test]
    fn normalized_drafts_preserve_line_order_and_serialize_without_forbidden_content() {
        let context = context();
        let second = event()
            .replace("evt-1", "evt-2")
            .replace("1783785600123", "1");
        let parsed = parse_canonical_jsonl(&format!("{}\n{}", event(), second)).expect("parse");
        let drafts = parsed
            .iter()
            .map(|event| normalize_passive_event(event, &context).expect("normalize"))
            .collect::<Vec<_>>();
        assert_eq!(
            drafts
                .iter()
                .map(|draft| draft.source_line)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            drafts
                .iter()
                .map(|draft| draft.record.ts_ms)
                .collect::<Vec<_>>(),
            vec![1_783_785_600_123, 1]
        );
        let serialized = serde_json::to_string(&drafts)
            .expect("serializes")
            .to_ascii_lowercase();
        for forbidden in ["prompt", "messages", "authorization", "password", "raw_url"] {
            assert!(!serialized.contains(forbidden));
        }
    }

    fn event() -> String {
        r#"{"schema_version":1,"event_id":"evt-1","observed_at_ms":1783785600123,"method":"POST","route":"/v1/chat/completions","model":"shared-model","actual_supply_ref":{"namespace":"deployment","value":"east"},"status":200,"streamed":false,"latency_ms":25,"input_tokens":10,"output_tokens":5,"dimensions":{"app":"support","team":"customer-ops","environment":"prod","cost_center":"cc-14","task_class":"mechanical"}}"#.to_string()
    }

    fn event_with(prefix: &str) -> String {
        event().replacen('{', &format!("{{{prefix}"), 1)
    }

    fn event_with_json(path: &[&str], value: Value) -> String {
        let mut event: Value = serde_json::from_str(&event()).expect("event JSON");
        let mut target = &mut event;
        for segment in &path[..path.len() - 1] {
            target = target.get_mut(*segment).expect("test path exists");
        }
        target[path[path.len() - 1]] = value;
        serde_json::to_string(&event).expect("event serializes")
    }

    fn assert_safe_line_error(name: &str, invalid: &str, reason: &str) {
        let source = format!(
            "{}\n{invalid}",
            event_with_json(&["event_id"], json!("first"))
        );
        let error = parse_canonical_jsonl_named(&source, "fixture.jsonl").expect_err(name);
        let message = error.to_string();
        assert!(
            message.starts_with("fixture.jsonl:2: "),
            "{name}: {message}"
        );
        assert!(message.contains(reason), "{name}: {message}");
        assert!(!message.contains("SENSITIVE_SENTINEL"), "{name}: {message}");
    }

    fn minimal_event(index: usize) -> String {
        format!(
            r#"{{"schema_version":1,"event_id":"e{index}","observed_at_ms":0,"method":"POST","route":"/v1/completions","status":200,"streamed":false,"latency_ms":0,"dimensions":{{}}}}"#
        )
    }

    fn normalize_usage_case(
        route: &str,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        context: &PassiveNormalizationContext,
    ) -> DecisionRecord {
        let mut value: Value = serde_json::from_str(&event()).expect("event JSON");
        value["route"] = json!(route);
        match input_tokens {
            Some(tokens) => value["input_tokens"] = json!(tokens),
            None => {
                value
                    .as_object_mut()
                    .expect("event object")
                    .remove("input_tokens");
            }
        }
        match output_tokens {
            Some(tokens) => value["output_tokens"] = json!(tokens),
            None => {
                value
                    .as_object_mut()
                    .expect("event object")
                    .remove("output_tokens");
            }
        }
        let source = serde_json::to_string(&value).expect("event serializes");
        let parsed = parse_canonical_jsonl(&source).expect("usage case parses");
        normalize_passive_event(&parsed[0], context)
            .expect("usage case normalizes")
            .record
    }

    fn context() -> PassiveNormalizationContext {
        let registry = Registry::from_json(r#"{"feed_version":"test","entries":[
          {"id":"public/east","model":"shared-model","location":"east","attributes":{"class":"public-api","jurisdiction":"us","retention":"days30","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0},"ratings":{"mechanical":0.9}},
          {"id":"public/legacy","model":"shared-model","location":"legacy","attributes":{"class":"public-api","jurisdiction":"us","retention":"days30","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":9.0,"output_per_mtok_usd":9.0},"ratings":{"mechanical":0.9}}
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
            Some("public/legacy".into()),
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
