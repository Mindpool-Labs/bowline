use bowline_core::ledger::UsageSource;
use bowline_core::traffic::ProtocolKind;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFacts {
    pub model: Option<String>,
    pub stream: bool,
    pub est_input_tokens: u64,
    pub shape_supported: bool,
    pub unsupported_reason: Option<String>,
}

pub fn parse_request(protocol: ProtocolKind, body: &[u8]) -> RequestFacts {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return request_facts(None, false, 0, false, Some("malformed-json"));
    };

    let model = request_model_field(&value);
    let stream = value
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if protocol == ProtocolKind::Unsupported {
        return request_facts(model, stream, 0, false, None);
    }

    if model.is_none() {
        return request_facts(model, stream, 0, false, Some("missing-model"));
    }

    match protocol {
        ProtocolKind::ChatCompletions => {
            let Some(messages) = value.get("messages").and_then(Value::as_array) else {
                return request_facts(model, stream, 0, false, Some("missing-messages"));
            };
            let chars = messages
                .iter()
                .map(|message| message_content_chars(message.get("content")))
                .sum::<usize>();
            request_facts(model, stream, (chars / 4) as u64, true, None)
        }
        ProtocolKind::Responses => {
            let Some(input) = value.get("input") else {
                return request_facts(model, stream, 0, false, Some("missing-input"));
            };
            let Some(chars) = responses_input_chars(input) else {
                return request_facts(model, stream, 0, false, Some("unsupported-input-shape"));
            };
            request_facts(model, stream, (chars / 4) as u64, true, None)
        }
        ProtocolKind::Embeddings => {
            let Some(input) = value.get("input") else {
                return request_facts(model, stream, 0, false, Some("missing-input"));
            };
            let Some(tokens) = embeddings_input_tokens(input) else {
                return request_facts(model, stream, 0, false, Some("unsupported-input-shape"));
            };
            request_facts(model, stream, tokens, true, None)
        }
        ProtocolKind::Unsupported => unreachable!(),
    }
}

fn request_facts(
    model: Option<String>,
    stream: bool,
    est_input_tokens: u64,
    shape_supported: bool,
    unsupported_reason: Option<&str>,
) -> RequestFacts {
    RequestFacts {
        model,
        stream,
        est_input_tokens,
        shape_supported,
        unsupported_reason: unsupported_reason.map(str::to_string),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFacts {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub source: UsageSource,
}

pub fn parse_response_usage(protocol: ProtocolKind, body: &[u8]) -> UsageFacts {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| usage_from_value(usage_container(protocol, &value)?))
        .unwrap_or_else(missing_usage)
}

pub fn parse_sse_usage(protocol: ProtocolKind, collected: &[u8]) -> UsageFacts {
    for value in sse_data_values(collected) {
        if let Some(usage) = usage_container(protocol, &value).and_then(usage_from_value) {
            return usage;
        }
    }

    missing_usage()
}

pub fn parse_sse_model(protocol: ProtocolKind, collected: &[u8]) -> Option<String> {
    if protocol == ProtocolKind::Unsupported {
        return None;
    }
    sse_data_values(collected).find_map(|value| response_model_field(protocol, &value))
}

pub fn parse_response_model(protocol: ProtocolKind, body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| response_model_field(protocol, &value))
}

fn sse_data_values(collected: &[u8]) -> impl Iterator<Item = Value> + '_ {
    String::from_utf8_lossy(collected)
        .lines()
        .filter_map(|line| {
            let data = line.trim_start().strip_prefix("data:")?.trim();
            if data.is_empty() || data == "[DONE]" {
                return None;
            }

            serde_json::from_str::<Value>(data).ok()
        })
        .collect::<Vec<_>>()
        .into_iter()
}

fn message_content_chars(content: Option<&Value>) -> usize {
    match content {
        Some(Value::String(text)) => text.chars().count(),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|part| {
                part.as_str()
                    .map(str::chars)
                    .map(Iterator::count)
                    .or_else(|| {
                        part.get("text")
                            .and_then(Value::as_str)
                            .map(|text| text.chars().count())
                    })
                    .unwrap_or(0)
            })
            .sum(),
        _ => 0,
    }
}

fn responses_input_chars(input: &Value) -> Option<usize> {
    match input {
        Value::String(text) => Some(text.chars().count()),
        Value::Array(items) => items.iter().try_fold(0_usize, |total, item| {
            responses_input_item_chars(item).map(|chars| total + chars)
        }),
        _ => None,
    }
}

fn responses_input_item_chars(item: &Value) -> Option<usize> {
    let Value::Object(object) = item else {
        return item.as_str().map(|text| text.chars().count());
    };

    match object.get("type").and_then(Value::as_str) {
        Some("input_text" | "output_text" | "text") => object
            .get("text")
            .and_then(Value::as_str)
            .map(|text| text.chars().count()),
        Some("message") => object.get("content").and_then(text_content_chars),
        Some("tool_result") => object
            .get("content")
            .or_else(|| object.get("output"))
            .and_then(text_content_chars),
        Some("function_call_output") => object.get("output").and_then(text_content_chars),
        None if object.get("role").and_then(Value::as_str).is_some() => {
            object.get("content").and_then(text_content_chars)
        }
        _ => None,
    }
}

fn text_content_chars(content: &Value) -> Option<usize> {
    match content {
        Value::String(text) => Some(text.chars().count()),
        Value::Array(parts) => parts.iter().try_fold(0_usize, |total, part| {
            text_content_part_chars(part).map(|chars| total + chars)
        }),
        _ => None,
    }
}

fn text_content_part_chars(part: &Value) -> Option<usize> {
    match part {
        Value::String(text) => Some(text.chars().count()),
        Value::Object(object)
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("input_text" | "output_text" | "text")
            ) =>
        {
            object
                .get("text")
                .and_then(Value::as_str)
                .map(|text| text.chars().count())
        }
        _ => None,
    }
}

fn embeddings_input_tokens(input: &Value) -> Option<u64> {
    match input {
        Value::String(text) => Some((text.chars().count() / 4) as u64),
        Value::Array(items) if items.iter().all(Value::is_string) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|text| text.chars().count())
                .sum::<usize>() as u64
                / 4,
        ),
        Value::Array(items) if items.iter().all(Value::is_u64) => Some(items.len() as u64),
        Value::Array(items)
            if items.iter().all(|item| {
                item.as_array()
                    .is_some_and(|tokens| tokens.iter().all(Value::is_u64))
            }) =>
        {
            Some(
                items
                    .iter()
                    .filter_map(Value::as_array)
                    .map(Vec::len)
                    .sum::<usize>() as u64,
            )
        }
        _ => None,
    }
}

fn usage_container(protocol: ProtocolKind, value: &Value) -> Option<&Value> {
    match protocol {
        ProtocolKind::Responses => value
            .get("response")
            .and_then(|response| response.get("usage"))
            .or_else(|| value.get("usage")),
        ProtocolKind::ChatCompletions | ProtocolKind::Embeddings => value.get("usage"),
        ProtocolKind::Unsupported => None,
    }
}

fn request_model_field(value: &Value) -> Option<String> {
    value
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn response_model_field(protocol: ProtocolKind, value: &Value) -> Option<String> {
    match protocol {
        ProtocolKind::Responses => value
            .get("response")
            .and_then(|response| response.get("model"))
            .or_else(|| value.get("model")),
        _ => value.get("model"),
    }
    .and_then(Value::as_str)
    .map(str::to_string)
}

fn usage_from_value(usage: &Value) -> Option<UsageFacts> {
    usage.as_object()?;
    let input_tokens =
        token_field(usage, "prompt_tokens").or_else(|| token_field(usage, "input_tokens"));
    let output_tokens =
        token_field(usage, "completion_tokens").or_else(|| token_field(usage, "output_tokens"));

    if input_tokens.is_none() && output_tokens.is_none() {
        return None;
    }

    Some(UsageFacts {
        input_tokens,
        output_tokens,
        source: UsageSource::Observed,
    })
}

fn token_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn missing_usage() -> UsageFacts {
    UsageFacts {
        input_tokens: None,
        output_tokens: None,
        source: UsageSource::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowline_core::traffic::ProtocolKind;

    #[test]
    fn request_estimates_message_content_chars() {
        let facts = parse_request(
            ProtocolKind::ChatCompletions,
            br#"{"model":"echo","stream":true,"messages":[{"content":"12345678"},{"content":[{"type":"text","text":"1234"}]}]}"#,
        );

        assert_eq!(facts.model.as_deref(), Some("echo"));
        assert!(facts.stream);
        assert_eq!(facts.est_input_tokens, 3);
    }

    #[test]
    fn response_usage_parses_openai_shape() {
        let usage = parse_response_usage(
            ProtocolKind::ChatCompletions,
            br#"{"usage":{"prompt_tokens":7,"completion_tokens":5}}"#,
        );

        assert_eq!(usage.input_tokens, Some(7));
        assert_eq!(usage.output_tokens, Some(5));
        assert_eq!(usage.source, UsageSource::Observed);
    }

    #[test]
    fn sse_usage_scans_data_events() {
        let usage = parse_sse_usage(
            ProtocolKind::ChatCompletions,
            b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":5}}\n\ndata: [DONE]\n\n",
        );

        assert_eq!(usage.input_tokens, Some(7));
        assert_eq!(usage.output_tokens, Some(5));
        assert_eq!(usage.source, UsageSource::Observed);
    }

    #[test]
    fn sse_usage_skips_null_and_uses_later_usage() {
        let usage = parse_sse_usage(
            ProtocolKind::ChatCompletions,
            b"data: {\"usage\":null}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: {\"usage\":{\"input_tokens\":11,\"output_tokens\":13}}\n\n",
        );

        assert_eq!(usage.input_tokens, Some(11));
        assert_eq!(usage.output_tokens, Some(13));
        assert_eq!(usage.source, UsageSource::Observed);
    }

    #[test]
    fn sse_empty_usage_is_missing() {
        let usage = parse_sse_usage(
            ProtocolKind::ChatCompletions,
            b"data: {\"usage\":{}}\n\ndata: [DONE]\n\n",
        );

        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, None);
        assert_eq!(usage.source, UsageSource::Missing);
    }

    #[test]
    fn non_streaming_null_usage_is_missing() {
        let usage = parse_response_usage(
            ProtocolKind::ChatCompletions,
            br#"{"model":"echo","usage":null}"#,
        );

        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, None);
        assert_eq!(usage.source, UsageSource::Missing);
    }

    #[test]
    fn sse_model_uses_first_data_chunk_with_model() {
        let model = parse_sse_model(
            ProtocolKind::ChatCompletions,
            b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: {\"model\":\"upstream-stream-model\"}\n\ndata: {\"model\":\"later\"}\n\n",
        );

        assert_eq!(model.as_deref(), Some("upstream-stream-model"));
    }

    #[test]
    fn responses_request_extracts_model_stream_and_input_text() {
        let facts = parse_request(
            ProtocolKind::Responses,
            br#"{"model":"gpt-response","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"12345678"}]}]}"#,
        );
        assert_eq!(facts.model.as_deref(), Some("gpt-response"));
        assert!(facts.stream);
        assert_eq!(facts.est_input_tokens, 2);
    }

    #[test]
    fn responses_request_requires_top_level_model() {
        let facts = parse_request(
            ProtocolKind::Responses,
            br#"{"response":{"model":"nested-response-model"},"input":"hello"}"#,
        );

        assert_eq!(facts.model, None);
        assert!(!facts.shape_supported);
        assert_eq!(facts.unsupported_reason.as_deref(), Some("missing-model"));
    }

    #[test]
    fn responses_request_rejects_boolean_and_custom_array_items() {
        for input in [
            r#"[true]"#,
            r#"[{"type":"custom","content":"must not count"}]"#,
        ] {
            let body = format!(r#"{{"model":"responses","input":{input}}}"#);
            let facts = parse_request(ProtocolKind::Responses, body.as_bytes());

            assert!(
                !facts.shape_supported,
                "input unexpectedly supported: {input}"
            );
            assert_eq!(
                facts.unsupported_reason.as_deref(),
                Some("unsupported-input-shape")
            );
            assert_eq!(facts.est_input_tokens, 0);
        }
    }

    #[test]
    fn responses_request_counts_explicit_supported_input_envelopes() {
        let facts = parse_request(
            ProtocolKind::Responses,
            br#"{"model":"responses","input":[{"type":"input_text","text":"1234"},{"type":"message","role":"user","content":[{"type":"input_text","text":"12345678"}]},{"type":"tool_result","content":"1234"},{"type":"function_call_output","call_id":"call-1","output":"12345678"}]}"#,
        );

        assert!(facts.shape_supported);
        assert_eq!(facts.est_input_tokens, 6);
    }

    #[test]
    fn responses_sse_reads_nested_completed_response_usage_and_model() {
        let body = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"response-model\",\"usage\":{\"input_tokens\":11,\"output_tokens\":13}}}\n\n";
        let usage = parse_sse_usage(ProtocolKind::Responses, body);
        assert_eq!(usage.input_tokens, Some(11));
        assert_eq!(usage.output_tokens, Some(13));
        assert_eq!(
            parse_sse_model(ProtocolKind::Responses, body).as_deref(),
            Some("response-model")
        );
    }

    #[test]
    fn embeddings_request_counts_text_and_token_id_inputs() {
        let text = parse_request(
            ProtocolKind::Embeddings,
            br#"{"model":"embed","input":["12345678","1234"]}"#,
        );
        let token_ids = parse_request(
            ProtocolKind::Embeddings,
            br#"{"model":"embed","input":[101,102,103,104]}"#,
        );
        assert_eq!(text.est_input_tokens, 3);
        assert_eq!(token_ids.est_input_tokens, 4);
    }

    #[test]
    fn embeddings_response_reads_prompt_usage_without_output_tokens() {
        let usage = parse_response_usage(
            ProtocolKind::Embeddings,
            br#"{"model":"embed","usage":{"prompt_tokens":17,"total_tokens":17}}"#,
        );
        assert_eq!(usage.input_tokens, Some(17));
        assert_eq!(usage.output_tokens, None);
        assert_eq!(usage.source, UsageSource::Observed);
    }

    #[test]
    fn supported_routes_disclose_malformed_and_unsupported_shapes() {
        let malformed = parse_request(ProtocolKind::ChatCompletions, b"not-json");
        assert!(!malformed.shape_supported);
        assert_eq!(
            malformed.unsupported_reason.as_deref(),
            Some("malformed-json")
        );

        let missing_messages = parse_request(
            ProtocolKind::ChatCompletions,
            br#"{"model":"chat","input":"wrong-surface"}"#,
        );
        assert!(!missing_messages.shape_supported);
        assert_eq!(
            missing_messages.unsupported_reason.as_deref(),
            Some("missing-messages")
        );

        let unknown_response_input = parse_request(
            ProtocolKind::Responses,
            br#"{"model":"responses","input":{"custom":true}}"#,
        );
        assert!(!unknown_response_input.shape_supported);
        assert_eq!(
            unknown_response_input.unsupported_reason.as_deref(),
            Some("unsupported-input-shape")
        );
    }

    #[test]
    fn chat_and_responses_tool_shapes_remain_supported() {
        let chat = parse_request(
            ProtocolKind::ChatCompletions,
            br#"{"model":"chat","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}"#,
        );
        let responses = parse_request(
            ProtocolKind::Responses,
            br#"{"model":"responses","input":"lookup","tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}"#,
        );
        assert!(chat.shape_supported);
        assert!(responses.shape_supported);
    }

    #[test]
    fn response_model_is_protocol_aware() {
        assert_eq!(
            parse_response_model(
                ProtocolKind::Responses,
                br#"{"response":{"model":"response-model"}}"#,
            )
            .as_deref(),
            Some("response-model")
        );
        assert_eq!(
            parse_response_model(ProtocolKind::ChatCompletions, br#"{"model":"chat-model"}"#,)
                .as_deref(),
            Some("chat-model")
        );
    }
}
