use std::{fs, sync::Arc};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{OriginalUri, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use bowline_core::{
    attribution::AttributionStatus,
    config::{load_owned_cost_catalog, Config, OwnedCostCatalog, RuntimeConfig},
    ledger::{Ledger, SegmentedLedger, UsageSource},
    report::compute_run_report,
    run::RunStore,
    supply::{Registry, TaskClass},
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};
use bowline_gateway::{
    identity::{declared_task_class, extract_identity},
    serve_with_shutdown,
    writer::{spawn_managed_writer, spawn_writer, ManagedWriter, ManagedWriterOptions},
    GatewayDeps, GatewayState,
};

#[tokio::test]
async fn enforcement_requires_active_provenance_from_injected_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let ledger_dir = temp.path().join("ledger");
    fs::create_dir(&ledger_dir).unwrap();
    let policy = shadow_policy();
    let registry = shadow_registry();
    let owned_costs = shadow_owned_costs(&registry);
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: temp.path().join("writer"),
        policy_digest: policy.digest().to_string(),
        registry_digest: "sha256:injected-observe-only".into(),
        attribution_digest: None,
        owned_cost_digest: Some(owned_costs.normalized_digest().to_string()),
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: 64 * 1024,
        max_segments: 8,
        queue_capacity: 16,
    })
    .unwrap();
    let deps = GatewayDeps::managed(
        policy,
        registry,
        Default::default(),
        owned_costs,
        writer.clone(),
    );
    let config = Config {
        listen: "127.0.0.1:0".into(),
        upstream: "http://127.0.0.1:9".into(),
        actual_supply_id: "public/echo-model".into(),
        policy_bundle: "unused-policy.yaml".into(),
        registry_feed: "unused-registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir,
        tco: None,
        attribution: None,
        floors: None,
        enforcement: Some(temp.path().join("must-not-be-read.yaml")),
        authority_signing: None,
        promotion_approval: None,
        state_backend: None,
        trusted_proxy_cidrs: Vec::new(),
        runtime: RuntimeConfig::default(),
    };

    let error = serve_with_shutdown(config, deps, async {})
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("requires active provenance"),
        "error: {error:#}"
    );
    writer
        .shutdown(std::time::Duration::from_secs(1))
        .await
        .unwrap();
}
use futures_util::{stream, StreamExt, TryStreamExt};
use std::time::Duration;
use tokio::{net::TcpListener, sync::Mutex};

const SSE_EVENT_ONE: &[u8] = b"data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\n";
const SSE_EVENT_USAGE: &[u8] =
    b"data: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":5}}\n\n";
const SSE_EVENT_EMPTY_USAGE: &[u8] = b"data: {\"usage\":{}}\n\n";
const SSE_EVENT_UPSTREAM_MODEL: &[u8] = b"data: {\"model\":\"upstream-stream-model\",\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\n";
const SSE_EVENT_DONE: &[u8] = b"data: [DONE]\n\n";
const GZIP_LABELED_BYTES: &[u8] = b"\x1f\x8bnot-actually-decompressed-by-bowline";
const CHAT_RESPONSE: &[u8] = br#"{"model":"echo-model","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":5}}"#;
const CHAT_RESPONSE_NULL_USAGE: &[u8] =
    br#"{"model":"echo-model","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":null}"#;
const RESPONSES_RESPONSE: &[u8] =
    br#"{"model":"response-upstream","usage":{"input_tokens":11,"output_tokens":13},"output":[]}"#;
const EMBEDDINGS_RESPONSE: &[u8] =
    br#"{"model":"embedding-upstream","usage":{"prompt_tokens":17,"total_tokens":17},"data":[]}"#;
const AUDIO_RESPONSE: &[u8] = br#"{"text":"unchanged"}"#;
const UNPRICED_RESPONSE: &[u8] =
    br#"{"model":"unpriced-model","usage":{"input_tokens":3,"output_tokens":4},"output":[]}"#;
const RESPONSES_SSE_START: &[u8] =
    b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n";
const RESPONSES_SSE_COMPLETED: &[u8] = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"response-upstream\",\"usage\":{\"input_tokens\":11,\"output_tokens\":13},\"output\":[{\"type\":\"function_call\",\"name\":\"lookup\",\"arguments\":\"{}\"}]}}\n\n";
const CHAT_TOOL_RESPONSE: &[u8] = br#"{"model":"echo-model","choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}}],"usage":{"prompt_tokens":7,"completion_tokens":5}}"#;

#[tokio::test]
async fn two_response_references_attribute_two_supplies() {
    let ledger = tempfile::tempdir().expect("ledger");
    let upstream = spawn_dynamic_attribution_upstream().await;
    let (gateway, writer) = spawn_dynamic_attribution_gateway(upstream, ledger.path()).await;
    let client = reqwest::Client::new();

    for (index, reference) in ["east", "west"].into_iter().enumerate() {
        let response = client
            .post(format!("{gateway}/v1/chat/completions?ref={reference}"))
            .body(r#"{"model":"echo-model","messages":[]}"#)
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-upstream-supply-ref"], reference);
        assert_eq!(
            response.bytes().await.expect("body").as_ref(),
            CHAT_RESPONSE
        );
        wait_for_managed_records(&writer, index as u64 + 1).await;
    }
    let run_id = writer.health().snapshot().run_id;
    writer
        .shutdown(Duration::from_secs(1))
        .await
        .expect("shutdown");
    let (records, _) = SegmentedLedger::read_run(ledger.path(), &run_id).expect("records");
    assert_eq!(records.len(), 2);
    for (record, expected_supply) in records.iter().zip(["public/east", "public/west"]) {
        assert_eq!(record.actual.supply_id.as_deref(), Some(expected_supply));
        assert_eq!(
            record.actual.attribution_status,
            AttributionStatus::Attributed
        );
        assert_eq!(record.coverage_status, CoverageStatus::Supported);
    }
}

#[tokio::test]
async fn repeated_attribution_header_is_coverage_only() {
    let ledger = tempfile::tempdir().expect("ledger");
    let upstream = spawn_dynamic_attribution_upstream().await;
    let (gateway, writer) = spawn_dynamic_attribution_gateway(upstream, ledger.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions?ref=east&ref=west"))
        .body(r#"{"model":"echo-model","messages":[]}"#)
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        CHAT_RESPONSE
    );
    wait_for_managed_records(&writer, 1).await;
    let snapshot = writer.health().snapshot();
    writer
        .shutdown(Duration::from_secs(1))
        .await
        .expect("shutdown");
    let (records, _) = SegmentedLedger::read_run(ledger.path(), &snapshot.run_id).expect("records");
    let record = &records[0];
    assert_eq!(
        record.actual.attribution_status,
        AttributionStatus::Ambiguous
    );
    assert_eq!(
        record.coverage_status,
        CoverageStatus::IncompleteObservation
    );
    assert!(record.decision.shadow.is_none());
    assert_eq!(record.actual.supply_id, None);
    assert_eq!(record.actual.est_cost_usd, None);
    assert_eq!(snapshot.unmapped, 0);
    assert_eq!(snapshot.unpriceable, 0);
}

#[tokio::test]
async fn streaming_dynamic_attribution_preserves_bytes() {
    let ledger = tempfile::tempdir().expect("ledger");
    let upstream = spawn_dynamic_attribution_upstream().await;
    let (gateway, writer) = spawn_dynamic_attribution_gateway(upstream, ledger.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions?ref=east"))
        .body(r#"{"model":"echo-model","stream":true,"messages":[]}"#)
        .send()
        .await
        .expect("response");
    assert_eq!(response.headers()["x-upstream-supply-ref"], "east");
    let chunks = response
        .bytes_stream()
        .try_collect::<Vec<_>>()
        .await
        .expect("stream");
    assert!(chunks.len() > 1);
    assert_eq!(chunks.concat(), expected_sse_body());
    wait_for_managed_records(&writer, 1).await;
    let run_id = writer.health().snapshot().run_id;
    writer
        .shutdown(Duration::from_secs(1))
        .await
        .expect("shutdown");
    let (records, _) = SegmentedLedger::read_run(ledger.path(), &run_id).expect("records");
    assert_eq!(records[0].actual.supply_id.as_deref(), Some("public/east"));
}

#[tokio::test]
async fn unknown_and_model_mismatch_do_not_fallback_but_malformed_header_uses_legacy() {
    let ledger = tempfile::tempdir().expect("ledger");
    let upstream = spawn_dynamic_attribution_upstream().await;
    let (gateway, writer) = spawn_dynamic_attribution_gateway(upstream, ledger.path()).await;
    let client = reqwest::Client::new();
    // (query, expected attribution status, expected coverage, expects a shadow/cost estimate)
    let cases = [
        (
            "unknown",
            AttributionStatus::UnknownReference,
            CoverageStatus::IncompleteObservation,
            false,
        ),
        // A non-UTF8 attribution header collapses to AttributionInput::Absent (same as no header
        // at all), so it reaches the legacy static-attribution fallback instead of being treated
        // as a spurious unknown reference: the actual supply resolves, so the observation is
        // fully supported and gets a shadow decision and a cost estimate like any other resolved
        // request.
        (
            "malformed",
            AttributionStatus::StaticConfigured,
            CoverageStatus::Supported,
            true,
        ),
        (
            "east&model=mismatch",
            AttributionStatus::ModelMismatch,
            CoverageStatus::IncompleteObservation,
            false,
        ),
    ];
    for (index, (query, ..)) in cases.into_iter().enumerate() {
        client
            .post(format!("{gateway}/v1/chat/completions?ref={query}"))
            .body(r#"{"model":"echo-model","messages":[]}"#)
            .send()
            .await
            .expect("response")
            .bytes()
            .await
            .expect("body");
        wait_for_managed_records(&writer, index as u64 + 1).await;
    }
    let run_id = writer.health().snapshot().run_id;
    writer
        .shutdown(Duration::from_secs(1))
        .await
        .expect("shutdown");
    let (records, _) = SegmentedLedger::read_run(ledger.path(), &run_id).expect("records");
    for (record, (_, status, coverage, resolved)) in records.iter().zip(cases) {
        assert_eq!(record.actual.attribution_status, status);
        assert_eq!(record.coverage_status, coverage);
        assert_eq!(record.decision.shadow.is_some(), resolved);
        assert_eq!(record.actual.est_cost_usd.is_some(), resolved);
    }
}

#[tokio::test]
async fn missing_response_header_uses_legacy_and_unsupported_reason_wins() {
    let ledger = tempfile::tempdir().expect("ledger");
    let upstream = spawn_dynamic_attribution_upstream().await;
    let (gateway, writer) = spawn_dynamic_attribution_gateway(upstream, ledger.path()).await;
    let client = reqwest::Client::new();
    client
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-upstream-supply-ref", "east")
        .body(r#"{"model":"echo-model","messages":[]}"#)
        .send()
        .await
        .expect("response")
        .bytes()
        .await
        .expect("body");
    client
        .post(format!("{gateway}/v1/completions?ref=unknown"))
        .body(r#"{"model":"echo-model"}"#)
        .send()
        .await
        .expect("response")
        .bytes()
        .await
        .expect("body");
    client
        .post(format!("{gateway}/v1/chat/completions?ref=unknown"))
        .body(r#"{"model":"echo-model","messages":true}"#)
        .send()
        .await
        .expect("response")
        .bytes()
        .await
        .expect("body");
    wait_for_managed_records(&writer, 3).await;
    let run_id = writer.health().snapshot().run_id;
    writer
        .shutdown(Duration::from_secs(1))
        .await
        .expect("shutdown");
    let (records, _) = SegmentedLedger::read_run(ledger.path(), &run_id).expect("records");
    assert_eq!(
        records[0].actual.supply_id.as_deref(),
        Some("public/legacy")
    );
    assert_eq!(
        records[0].actual.attribution_status,
        AttributionStatus::StaticConfigured
    );
    assert_eq!(
        records[1].coverage_status,
        CoverageStatus::UnsupportedProtocol
    );
    assert_eq!(
        records[1].coverage_reason.as_deref(),
        Some("unsupported-protocol")
    );
    assert_eq!(
        records[1].actual.attribution_status,
        AttributionStatus::Missing
    );
    assert_eq!(records[2].coverage_status, CoverageStatus::UnsupportedShape);
    assert_ne!(
        records[2].coverage_reason.as_deref(),
        Some("unknown-attribution-reference")
    );
    assert_eq!(
        records[2].actual.attribution_status,
        AttributionStatus::Missing
    );
}

#[derive(Clone, Default)]
struct CaptureState {
    bodies: Arc<Mutex<Vec<Bytes>>>,
    headers: Arc<Mutex<Vec<HeaderMap>>>,
    uris: Arc<Mutex<Vec<String>>>,
}

#[tokio::test]
async fn body_and_unknown_fields_pass_through_byte_identical() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let gateway = spawn_gateway(upstream).await;
    let body = Bytes::from_static(
        br#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],"x_future_field":{"a":1}}"#,
    );

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("authorization", "Bearer secret-token")
        .body(body.clone())
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(capture.bodies.lock().await.as_slice(), &[body]);
}

#[tokio::test]
async fn streaming_sse_passes_through() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let gateway = spawn_gateway(upstream).await;
    let expected_body = expected_sse_body();

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .body(r#"{"stream":true}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );

    let chunks = response
        .bytes_stream()
        .try_collect::<Vec<_>>()
        .await
        .expect("stream body readable");
    assert!(
        chunks.len() > 1,
        "gateway buffered SSE into {} chunk(s): {chunks:?}",
        chunks.len()
    );

    let body = chunks.concat();
    assert_eq!(body, expected_body);
    assert!(
        body.ends_with(SSE_EVENT_DONE),
        "SSE stream did not end with [DONE]: {body:?}"
    );
}

#[tokio::test]
async fn gzip_labeled_response_bytes_pass_through_unmodified() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let gateway = spawn_gateway(upstream).await;

    let response = reqwest::Client::new()
        .get(format!("{gateway}/encoded"))
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );

    let body = response.bytes().await.expect("encoded body readable");
    assert_eq!(body.as_ref(), GZIP_LABELED_BYTES);
}

#[tokio::test]
async fn request_body_over_10_mib_returns_413() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let gateway = spawn_gateway(upstream).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .body(vec![b'a'; 10 * 1024 * 1024 + 1])
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        capture.bodies.lock().await.is_empty(),
        "oversized request reached upstream"
    );
}

#[tokio::test]
async fn upstream_unreachable_returns_502() {
    let upstream = unused_localhost_url().await;
    let gateway = spawn_gateway(upstream).await;

    let response = reqwest::Client::new()
        .get(format!("{gateway}/v1/models"))
        .send()
        .await
        .expect("gateway response received");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn health_paths_are_local_and_never_reach_upstream() {
    let gateway = spawn_gateway("http://127.0.0.1:1".to_string()).await;
    let client = reqwest::Client::new();

    let live = client
        .get(format!("{gateway}/health/live"))
        .send()
        .await
        .expect("liveness response");
    let ready = client
        .get(format!("{gateway}/health/ready"))
        .send()
        .await
        .expect("readiness response");
    let status = client
        .get(format!("{gateway}/health/status"))
        .send()
        .await
        .expect("status response");

    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(
        live.bytes().await.expect("liveness bytes").as_ref(),
        br#"{"live":true,"mode":"shadow"}"#
    );
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(status.status(), StatusCode::OK);
    let body: serde_json::Value = status.json().await.expect("status JSON");
    assert_eq!(body["ready"], false);
    assert_eq!(body["mode"], "shadow");
}

#[tokio::test]
async fn managed_readiness_is_healthy_and_untrusted_identity_headers_are_ignored() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let tempdir = tempfile::tempdir().expect("temporary ledger directory");
    let (gateway, writer) = spawn_managed_gateway(
        upstream,
        tempdir.path(),
        vec!["10.0.0.0/8".parse().expect("trusted CIDR")],
        RuntimeConfig::default(),
    )
    .await;
    let client = reqwest::Client::new();

    let ready = client
        .get(format!("{gateway}/health/ready"))
        .send()
        .await
        .expect("readiness response");
    assert_eq!(ready.status(), StatusCode::OK);

    let response = client
        .post(format!("{gateway}/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-bowline-app", "support-bot")
        .header("x-bowline-task-class", "judgment")
        .body(r#"{"model":"echo-model","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .expect("chat response");
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await.expect("response body consumed");

    wait_for_managed_records(&writer, 1).await;
    writer
        .shutdown(Duration::from_secs(2))
        .await
        .expect("managed writer drains");
    let snapshot = writer.health().snapshot();
    assert_eq!(snapshot.untrusted_identity_headers, 1);
    let (records, _) = SegmentedLedger::read_run(tempdir.path(), &snapshot.run_id)
        .expect("managed records readable");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].identity.app, None);
    assert_eq!(records[0].decision.task_class, TaskClass::Unclassified);
    assert!(capture.headers.lock().await[0]
        .get("x-bowline-app")
        .is_none());
    assert!(capture.headers.lock().await[0]
        .get("x-bowline-task-class")
        .is_none());
}

#[tokio::test]
async fn response_header_timeout_returns_504() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let runtime = RuntimeConfig {
        response_header_timeout_ms: 20,
        ..RuntimeConfig::default()
    };
    let gateway = spawn_gateway_with_runtime(upstream, runtime).await;

    let response = reqwest::Client::new()
        .get(format!("{gateway}/slow-headers"))
        .send()
        .await
        .expect("gateway returns timeout response");

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn large_response_is_byte_identical_and_accounting_truncated() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("temporary ledger directory");
    let runtime = RuntimeConfig {
        accounting_limit_bytes: 32,
        ..RuntimeConfig::default()
    };
    let (gateway, writer) = spawn_managed_gateway(
        upstream,
        tempdir.path(),
        vec!["127.0.0.1/32".parse().expect("trusted CIDR")],
        runtime,
    )
    .await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"model":"echo-model","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .expect("chat response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("response bytes"),
        CHAT_RESPONSE
    );

    wait_for_managed_records(&writer, 1).await;
    writer
        .shutdown(Duration::from_secs(2))
        .await
        .expect("managed writer drains");
    let snapshot = writer.health().snapshot();
    assert_eq!(snapshot.truncated, 1);
    let (records, _) = SegmentedLedger::read_run(tempdir.path(), &snapshot.run_id)
        .expect("managed records readable");
    assert!(records[0].accounting_truncated);
    assert_eq!(records[0].actual.output_tokens, None);
}

#[tokio::test]
async fn stream_idle_timeout_terminates_downstream_and_records_incomplete() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("temporary ledger directory");
    let runtime = RuntimeConfig {
        stream_idle_timeout_ms: 20,
        ..RuntimeConfig::default()
    };
    let (gateway, writer) = spawn_managed_gateway(
        upstream,
        tempdir.path(),
        vec!["127.0.0.1/32".parse().expect("trusted CIDR")],
        runtime,
    )
    .await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"model":"slow-stream-model","stream":true,"messages":[]}"#)
        .send()
        .await
        .expect("stream headers arrive");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.bytes().await.is_err(),
        "idle stream must terminate with an error"
    );

    wait_for_managed_records(&writer, 1).await;
    writer
        .shutdown(Duration::from_secs(2))
        .await
        .expect("managed writer drains");
    let snapshot = writer.health().snapshot();
    assert_eq!(snapshot.truncated, 1);
    let (records, _) = SegmentedLedger::read_run(tempdir.path(), &snapshot.run_id)
        .expect("managed records readable");
    assert!(records[0].accounting_truncated);
    assert_eq!(records[0].actual.status, 200);
}

#[tokio::test]
async fn hop_by_hop_request_headers_stripped_and_response_headers_are_sane() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let gateway = spawn_gateway(upstream).await;

    let response = reqwest::Client::new()
        .get(format!("{gateway}/v1/models"))
        .header(header::HOST, "client.example")
        .header(header::CONNECTION, "close")
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-echo-marker")
            .and_then(|value| value.to_str().ok()),
        Some("present")
    );
    assert!(
        !response.headers().contains_key(header::TRANSFER_ENCODING),
        "client saw hop-by-hop transfer-encoding header: {:?}",
        response.headers()
    );

    let headers = capture.headers.lock().await;
    let received = headers.first().expect("upstream received request");
    assert!(
        !received.contains_key(header::CONNECTION),
        "upstream received connection header: {received:?}"
    );
    assert!(
        received
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            != Some("client.example"),
        "upstream received client host header: {received:?}"
    );
}

#[tokio::test]
async fn non_chat_paths_forwarded() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let gateway = spawn_gateway(upstream).await;

    let response = reqwest::Client::new()
        .get(format!("{gateway}/v1/models?limit=2"))
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.expect("body readable"),
        r#"{"echo":true}"#
    );
    assert_eq!(
        capture.uris.lock().await.as_slice(),
        &["/v1/models?limit=2"]
    );
}

#[tokio::test]
async fn bowline_headers_stripped_upstream() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let gateway = spawn_gateway(upstream).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "foo")
        .header("x-bowline-task-class", "mechanical")
        .body(r#"{"messages":[]}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);

    let headers = capture.headers.lock().await;
    let received = headers.first().expect("upstream received request");
    assert!(
        received
            .keys()
            .all(|name| !name.as_str().starts_with("x-bowline-")),
        "upstream headers contained bowline headers: {received:?}"
    );
}

#[tokio::test]
async fn shadow_record_written_for_chat_completion() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(r#"{"model":"echo-model","messages":[{"role":"user","content":"hello from support bot"}]}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await.expect("body readable");

    let records = wait_for_records(tempdir.path(), 1).await;
    let record = records.first().expect("record written");

    assert_eq!(record.identity.app.as_deref(), Some("support-bot"));
    assert_eq!(record.identity.tags, vec!["customer-data"]);
    assert!(record.decision.policy_digest.starts_with("sha256:"));
    assert!(!record.decision.feasible_ids.is_empty());
    assert!(record
        .decision
        .feasible_ids
        .iter()
        .all(|id| id.starts_with("local/") || id.starts_with("vpc/")));
    assert_eq!(record.actual.input_tokens, Some(7));
    assert_eq!(record.actual.usage_source, UsageSource::Observed);
    assert_eq!(record.actual.model.as_deref(), Some("echo-model"));
    assert!(record.actual.est_cost_usd.is_some());
}

#[tokio::test]
async fn streaming_request_recorded() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(r#"{"model":"echo-model","stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await.expect("stream body readable");

    let records = wait_for_records(tempdir.path(), 1).await;
    let record = records.first().expect("record written");
    assert!(record.actual.streamed);
    assert_eq!(record.actual.input_tokens, Some(7));
    assert_eq!(record.actual.output_tokens, Some(5));
    assert_eq!(record.actual.usage_source, UsageSource::Observed);
}

#[tokio::test]
async fn streaming_empty_usage_falls_back_to_estimated_request_tokens() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(r#"{"model":"empty-usage-stream-model","stream":true,"messages":[{"role":"user","content":"12345678"}]}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await.expect("stream body readable");

    let records = wait_for_records(tempdir.path(), 1).await;
    let record = records.first().expect("record written");
    assert_eq!(record.actual.input_tokens, Some(2));
    assert_eq!(record.actual.output_tokens, None);
    assert_eq!(record.actual.usage_source, UsageSource::Estimated);
}

#[tokio::test]
async fn non_streaming_null_usage_falls_back_to_estimated_request_tokens() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(
            r#"{"model":"null-usage-model","messages":[{"role":"user","content":"123456789012"}]}"#,
        )
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await.expect("body readable");

    let records = wait_for_records(tempdir.path(), 1).await;
    let record = records.first().expect("record written");
    assert_eq!(record.actual.input_tokens, Some(3));
    assert_eq!(record.actual.output_tokens, None);
    assert_eq!(record.actual.usage_source, UsageSource::Estimated);
}

#[tokio::test]
async fn streaming_record_uses_upstream_model_from_sse_chunks() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(r#"{"model":"request-model","stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.bytes().await.expect("stream body readable");

    let records = wait_for_records(tempdir.path(), 1).await;
    let record = records.first().expect("record written");
    assert_eq!(
        record.actual.model.as_deref(),
        Some("upstream-stream-model")
    );
    assert_eq!(record.actual.est_cost_usd, None);
    assert_eq!(record.actual.supply_id, None);
    assert_eq!(
        record.actual.attribution_status,
        bowline_core::attribution::AttributionStatus::ModelMismatch
    );
}

#[tokio::test]
async fn responses_request_is_recorded() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/responses"))
        .body(r#"{"model":"response-upstream","input":"hello"}"#)
        .send()
        .await
        .expect("request succeeds");
    assert_eq!(response.bytes().await.expect("body"), RESPONSES_RESPONSE);
    let record = wait_for_records(tempdir.path(), 1).await.remove(0);
    assert_eq!(record.protocol, ProtocolKind::Responses);
    assert_eq!(record.coverage_status, CoverageStatus::Supported);
    assert_eq!(record.observation_source, ObservationSource::Inline);
    assert_eq!(record.actual.model.as_deref(), Some("response-upstream"));
    assert_eq!(record.actual.input_tokens, Some(11));
    assert_eq!(record.actual.output_tokens, Some(13));
}

#[tokio::test]
async fn embeddings_request_is_recorded() {
    let upstream = spawn_echo_upstream(CaptureState::default()).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/embeddings"))
        .body(r#"{"model":"embedding-upstream","input":"hello"}"#)
        .send()
        .await
        .expect("request succeeds");
    assert_eq!(response.bytes().await.expect("body"), EMBEDDINGS_RESPONSE);
    let record = wait_for_records(tempdir.path(), 1).await.remove(0);
    assert_eq!(record.protocol, ProtocolKind::Embeddings);
    assert_eq!(record.coverage_status, CoverageStatus::Supported);
    assert_eq!(record.actual.input_tokens, Some(17));
    assert_eq!(record.actual.output_tokens, None);
}

#[tokio::test]
async fn unsupported_inference_is_forwarded_and_recorded_as_coverage_gap() {
    let upstream = spawn_echo_upstream(CaptureState::default()).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/audio/transcriptions"))
        .body(b"audio".as_slice())
        .send()
        .await
        .expect("request succeeds");
    assert_eq!(response.bytes().await.expect("body"), AUDIO_RESPONSE);
    let record = wait_for_records(tempdir.path(), 1).await.remove(0);
    assert_eq!(record.protocol, ProtocolKind::Unsupported);
    assert_eq!(record.coverage_status, CoverageStatus::UnsupportedProtocol);
    assert_eq!(
        record.coverage_reason.as_deref(),
        Some("unsupported-protocol")
    );
    assert!(record.decision.shadow.is_none());
}

#[tokio::test]
async fn streaming_responses_with_tool_output_is_byte_faithful_and_recorded() {
    let upstream = spawn_echo_upstream(CaptureState::default()).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/responses"))
        .body(r#"{"model":"response-upstream","stream":true,"input":"hello","tools":[{"type":"function","name":"lookup"}]}"#)
        .send().await.expect("request succeeds");
    let chunks = response
        .bytes_stream()
        .try_collect::<Vec<_>>()
        .await
        .expect("stream");
    assert_eq!(
        chunks.concat(),
        [RESPONSES_SSE_START, RESPONSES_SSE_COMPLETED].concat()
    );
    let record = wait_for_records(tempdir.path(), 1).await.remove(0);
    assert_eq!(record.protocol, ProtocolKind::Responses);
    assert_eq!(record.coverage_status, CoverageStatus::Supported);
    assert_eq!(record.actual.model.as_deref(), Some("response-upstream"));
    assert_eq!(
        (record.actual.input_tokens, record.actual.output_tokens),
        (Some(11), Some(13))
    );

    let request = Bytes::from_static(br#"{"model":"echo-model","messages":[{"role":"user","content":"call it"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}"#);
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture.clone()).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-test-tool-response", "true")
        .body(request.clone())
        .send()
        .await
        .expect("chat");
    assert_eq!(response.bytes().await.expect("body"), CHAT_TOOL_RESPONSE);
    assert_eq!(capture.bodies.lock().await.as_slice(), &[request]);
    assert_eq!(
        wait_for_records(tempdir.path(), 1).await[0].coverage_status,
        CoverageStatus::Supported
    );
}

#[tokio::test]
async fn unsupported_request_shapes_are_recorded_without_placement() {
    for (path, body, reason, expected_response) in [
        ("/v1/chat/completions", "{", "malformed-json", CHAT_RESPONSE),
        (
            "/v1/responses",
            r#"{"model":"response-upstream","input":{"image":"x"}}"#,
            "unsupported-input-shape",
            RESPONSES_RESPONSE,
        ),
    ] {
        let upstream = spawn_echo_upstream(CaptureState::default()).await;
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
        let response = reqwest::Client::new()
            .post(format!("{gateway}{path}"))
            .body(body.to_string())
            .send()
            .await
            .expect("request");
        let upstream_body = response.bytes().await.expect("body");
        assert_eq!(upstream_body, expected_response);
        let record = wait_for_records(tempdir.path(), 1).await.remove(0);
        assert_eq!(record.coverage_status, CoverageStatus::UnsupportedShape);
        assert_eq!(record.coverage_reason.as_deref(), Some(reason));
        assert!(record.decision.shadow.is_none());
    }
}

#[tokio::test]
async fn responses_nested_model_is_coverage_only_without_economics() {
    let upstream = spawn_echo_upstream(CaptureState::default()).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/responses"))
        .body(r#"{"response":{"model":"response-upstream"},"input":"hello"}"#)
        .send()
        .await
        .expect("request");
    assert_eq!(response.bytes().await.expect("body"), RESPONSES_RESPONSE);

    let record = wait_for_records(tempdir.path(), 1).await.remove(0);
    assert_eq!(record.coverage_status, CoverageStatus::UnsupportedShape);
    assert_eq!(record.coverage_reason.as_deref(), Some("missing-model"));
    assert!(record.decision.shadow.is_none());
    assert_eq!(record.actual.est_cost_usd, None);
}

#[tokio::test]
async fn responses_unknown_array_items_are_coverage_only_without_economics() {
    for body in [
        r#"{"model":"response-upstream","input":[true]}"#,
        r#"{"model":"response-upstream","input":[{"type":"custom","content":"text"}]}"#,
    ] {
        let upstream = spawn_echo_upstream(CaptureState::default()).await;
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;
        let response = reqwest::Client::new()
            .post(format!("{gateway}/v1/responses"))
            .body(body)
            .send()
            .await
            .expect("request");
        assert_eq!(response.bytes().await.expect("body"), RESPONSES_RESPONSE);

        let record = wait_for_records(tempdir.path(), 1).await.remove(0);
        assert_eq!(record.coverage_status, CoverageStatus::UnsupportedShape);
        assert_eq!(
            record.coverage_reason.as_deref(),
            Some("unsupported-input-shape")
        );
        assert!(record.decision.shadow.is_none());
        assert_eq!(record.actual.est_cost_usd, None);
    }
}

#[tokio::test]
async fn coverage_only_records_do_not_increment_mapping_or_priceability_counters() {
    let registry = coverage_registry();
    let mut estimated_costs = Vec::new();
    let mut unmapped = 0;
    let mut unpriceable = 0;
    let mut report_unmapped = 0;
    let mut report_unpriceable = 0;
    let cases = [
        ("/v1/chat/completions", "{", "public/echo-model"),
        (
            "/v1/responses",
            r#"{"model":"unpriced-model","input":{"image":"x"}}"#,
            "public/unpriced-model",
        ),
        ("/v1/audio/transcriptions", "audio", "public/echo-model"),
    ];

    for (path, body, actual_supply_id) in cases {
        let tempdir = tempfile::tempdir().expect("tempdir created");
        let upstream = spawn_echo_upstream(CaptureState::default()).await;
        let (gateway, writer) = spawn_managed_gateway_with_registry(
            upstream,
            tempdir.path(),
            registry.clone(),
            actual_supply_id,
        )
        .await;
        let response = reqwest::Client::new()
            .post(format!("{gateway}{path}"))
            .body(body.to_string())
            .send()
            .await
            .expect("coverage request");
        let _ = response.bytes().await.expect("response consumed");
        wait_for_managed_records(&writer, 1).await;
        writer
            .shutdown(Duration::from_secs(2))
            .await
            .expect("managed writer drains");

        let snapshot = writer.health().snapshot();
        let (records, recoveries) =
            SegmentedLedger::read_run(tempdir.path(), &snapshot.run_id).expect("records readable");
        assert_eq!(records.len(), 1);
        assert_ne!(records[0].coverage_status, CoverageStatus::Supported);
        estimated_costs.push(records[0].actual.est_cost_usd);
        unmapped += snapshot.unmapped;
        unpriceable += snapshot.unpriceable;

        let manifest = RunStore::list_manifests(tempdir.path())
            .expect("manifest readable")
            .remove(0);
        let report = compute_run_report(
            &records,
            &recoveries,
            &manifest,
            &registry,
            &OwnedCostCatalog::default(),
            &Default::default(),
            None,
        )
        .expect("report computes");
        assert!(!report.protocol_coverage.complete);
        report_unmapped += report.data_integrity.unmapped;
        report_unpriceable += report.data_integrity.unpriceable;
    }

    assert_eq!(
        (
            estimated_costs,
            unmapped,
            unpriceable,
            report_unmapped,
            report_unpriceable,
        ),
        (vec![None, None, None], 0, 0, 0, 0)
    );
}

#[tokio::test]
async fn non_inference_get_paths_are_not_recorded() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let chat = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(r#"{"model":"echo-model","messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("chat request succeeds");
    let _ = chat.bytes().await.expect("chat body readable");
    let _ = wait_for_records(tempdir.path(), 1).await;

    let response = reqwest::Client::new()
        .get(format!("{gateway}/v1/models"))
        .send()
        .await
        .expect("models request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(700)).await;
    let (records, _) = Ledger::read_all(tempdir.path()).expect("ledger readable");
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn response_identical_with_shadow_enabled() {
    let capture = CaptureState::default();
    let upstream = spawn_echo_upstream(capture).await;
    let tempdir = tempfile::tempdir().expect("tempdir created");
    let gateway = spawn_gateway_with_shadow(upstream, tempdir.path()).await;

    let response = reqwest::Client::new()
        .post(format!("{gateway}/v1/chat/completions"))
        .header("x-bowline-app", "support-bot")
        .body(r#"{"model":"echo-model","messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.bytes().await.expect("body readable");
    assert_eq!(body.as_ref(), CHAT_RESPONSE);
}

#[test]
fn identity_extraction() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer secret-token".parse().unwrap());
    headers.insert("x-bowline-app", "checkout".parse().unwrap());

    let identity = extract_identity(&headers, "/v1/chat/completions");

    assert_eq!(
        identity.api_key_digest.as_deref(),
        Some("sha256:930bbdc51b6aed5c2a5678fd6e28dee7a05e8a4b643cfc0b4427c3efb86c0d94")
    );
    assert_eq!(identity.route, "/v1/chat/completions");
    assert_eq!(identity.app.as_deref(), Some("checkout"));
    assert!(identity.tags.is_empty());

    let no_auth = extract_identity(&HeaderMap::new(), "/v1/models");
    assert_eq!(no_auth.api_key_digest, None);
    assert_eq!(no_auth.route, "/v1/models");
}

#[test]
fn declared_task_class_uses_kebab_case_header() {
    let mut headers = HeaderMap::new();
    headers.insert("x-bowline-task-class", "heavy-lifting".parse().unwrap());

    assert_eq!(declared_task_class(&headers), Some(TaskClass::HeavyLifting));

    headers.insert("x-bowline-task-class", "not-a-class".parse().unwrap());
    assert_eq!(declared_task_class(&headers), None);
}

async fn spawn_gateway(upstream: String) -> String {
    spawn_gateway_with_runtime(upstream, RuntimeConfig::default()).await
}

async fn spawn_gateway_with_runtime(upstream: String, runtime: RuntimeConfig) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway listener binds");
    let addr = listener.local_addr().expect("gateway addr available");
    let config = Config {
        listen: addr.to_string(),
        upstream,
        actual_supply_id: "openai/gpt-5-mini".to_string(),
        policy_bundle: "policy.yaml".into(),
        registry_feed: "registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: "ledger".into(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        authority_signing: None,
        promotion_approval: None,
        state_backend: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
        runtime,
    };
    let app = GatewayState::from_config(&config, GatewayDeps::default())
        .expect("configured state")
        .router();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("gateway serves");
    });

    format!("http://{addr}")
}

async fn spawn_gateway_with_shadow(upstream: String, ledger_dir: &std::path::Path) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway listener binds");
    let addr = listener.local_addr().expect("gateway addr available");
    let (writer, recovery) = spawn_writer(ledger_dir.to_path_buf()).expect("ledger writer starts");
    assert!(matches!(
        recovery,
        bowline_core::ledger::RecoveryOutcome::Absent
            | bowline_core::ledger::RecoveryOutcome::Clean { .. }
            | bowline_core::ledger::RecoveryOutcome::TornTail { .. }
    ));
    let registry = shadow_registry();
    let owned_costs = shadow_owned_costs(&registry);
    let deps = GatewayDeps::recording(
        shadow_policy(),
        registry,
        Default::default(),
        owned_costs,
        writer,
    );
    let config = Config {
        listen: addr.to_string(),
        upstream,
        actual_supply_id: "public/echo-model".to_string(),
        policy_bundle: "unused-policy.yaml".into(),
        registry_feed: "unused-registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger_dir.to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        authority_signing: None,
        promotion_approval: None,
        state_backend: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
        runtime: RuntimeConfig::default(),
    };
    let app = GatewayState::from_config(&config, deps)
        .expect("gateway config")
        .router();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("gateway serves");
    });

    format!("http://{addr}")
}

async fn spawn_managed_gateway(
    upstream: String,
    ledger_dir: &std::path::Path,
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    runtime: RuntimeConfig,
) -> (String, ManagedWriter) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway listener binds");
    let addr = listener.local_addr().expect("gateway addr available");
    let policy = shadow_policy();
    let registry = shadow_registry();
    let owned_costs = shadow_owned_costs(&registry);
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: ledger_dir.to_path_buf(),
        policy_digest: policy.digest().to_string(),
        registry_digest: "sha256:test-registry".to_string(),
        attribution_digest: None,
        owned_cost_digest: None,
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: 64 * 1024,
        max_segments: 8,
        queue_capacity: 16,
    })
    .expect("managed writer starts");
    let deps = GatewayDeps::managed(
        policy,
        registry,
        Default::default(),
        owned_costs,
        writer.clone(),
    );
    let config = Config {
        listen: addr.to_string(),
        upstream,
        actual_supply_id: "public/echo-model".to_string(),
        policy_bundle: "policy.yaml".into(),
        registry_feed: "registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger_dir.to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        authority_signing: None,
        promotion_approval: None,
        state_backend: None,
        trusted_proxy_cidrs,
        runtime,
    };
    let app = GatewayState::from_config(&config, deps)
        .expect("configured state")
        .router();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("gateway serves");
    });

    (format!("http://{addr}"), writer)
}

async fn spawn_managed_gateway_with_registry(
    upstream: String,
    ledger_dir: &std::path::Path,
    registry: Registry,
    actual_supply_id: &str,
) -> (String, ManagedWriter) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway listener binds");
    let addr = listener.local_addr().expect("gateway addr available");
    let policy = shadow_policy();
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: ledger_dir.to_path_buf(),
        policy_digest: policy.digest().to_string(),
        registry_digest: "sha256:coverage-registry".to_string(),
        attribution_digest: None,
        owned_cost_digest: None,
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: 64 * 1024,
        max_segments: 8,
        queue_capacity: 16,
    })
    .expect("managed writer starts");
    let deps = GatewayDeps::managed(
        policy,
        registry,
        Default::default(),
        OwnedCostCatalog::default(),
        writer.clone(),
    );
    let config = Config {
        listen: addr.to_string(),
        upstream,
        actual_supply_id: actual_supply_id.to_string(),
        policy_bundle: "policy.yaml".into(),
        registry_feed: "registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger_dir.to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        authority_signing: None,
        promotion_approval: None,
        state_backend: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
        runtime: RuntimeConfig::default(),
    };
    let app = GatewayState::from_config(&config, deps)
        .expect("configured state")
        .router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("gateway serves");
    });
    (format!("http://{addr}"), writer)
}

async fn wait_for_managed_records(writer: &ManagedWriter, count: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if writer.health().snapshot().recorded >= count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {count} managed records"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn unused_localhost_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("closed-port listener binds");
    let addr = listener.local_addr().expect("closed-port addr available");
    drop(listener);

    format!("http://{addr}")
}

async fn spawn_echo_upstream(capture: CaptureState) -> String {
    let app = Router::new()
        .fallback(any(echo_handler))
        .with_state(capture);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream listener binds");
    let addr = listener.local_addr().expect("upstream addr available");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream serves");
    });

    format!("http://{addr}")
}

async fn spawn_dynamic_attribution_upstream() -> String {
    async fn handler(OriginalUri(uri): OriginalUri, body: Body) -> Response {
        let body = to_bytes(body, 1024 * 1024).await.expect("body");
        let references = uri
            .query()
            .into_iter()
            .flat_map(|query| query.split('&'))
            .filter_map(|pair| pair.strip_prefix("ref="))
            .collect::<Vec<_>>();
        let mismatch = uri
            .query()
            .is_some_and(|query| query.contains("model=mismatch"));
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header("x-fidelity-marker", "preserved");
        for reference in references {
            if reference == "malformed" {
                builder = builder.header(
                    "x-upstream-supply-ref",
                    axum::http::HeaderValue::from_bytes(b"\xff").expect("opaque header"),
                );
            } else {
                builder = builder.header("x-upstream-supply-ref", reference);
            }
        }
        if request_is_streaming(&body) {
            let chunks = [SSE_EVENT_ONE, SSE_EVENT_USAGE, SSE_EVENT_DONE]
                .into_iter()
                .map(Bytes::from_static);
            let stream = stream::iter(chunks).then(|chunk| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, std::convert::Infallible>(chunk)
            });
            return builder
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(stream))
                .expect("stream response");
        }
        let response = if mismatch {
            Bytes::from_static(br#"{"model":"mismatch-model","usage":{"prompt_tokens":7,"completion_tokens":5},"choices":[]}"#)
        } else {
            Bytes::from_static(CHAT_RESPONSE)
        };
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(response))
            .expect("response")
    }
    let app = Router::new().fallback(any(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{addr}")
}

async fn spawn_dynamic_attribution_gateway(
    upstream: String,
    ledger_dir: &std::path::Path,
) -> (String, ManagedWriter) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let registry = dynamic_attribution_registry();
    let policy = shadow_policy();
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: ledger_dir.to_path_buf(),
        policy_digest: policy.digest().to_string(),
        registry_digest: "sha256:dynamic-registry".to_string(),
        attribution_digest: None,
        owned_cost_digest: None,
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: 64 * 1024,
        max_segments: 8,
        queue_capacity: 16,
    })
    .expect("writer");
    let deps = GatewayDeps::managed(
        policy,
        registry,
        Default::default(),
        OwnedCostCatalog::default(),
        writer.clone(),
    );
    let source = format!(
        r#"listen: {addr}
upstream: {upstream}
actual_supply_id: public/legacy
policy_bundle: unused
registry_feed: unused
ledger_dir: {}
attribution:
  version: 1
  response_header: x-upstream-supply-ref
  namespace: deployment
  mappings:
    - {{value: east, supply_id: public/east}}
    - {{value: west, supply_id: public/west}}
"#,
        ledger_dir.display()
    );
    let config = Config::from_yaml(&source).expect("dynamic config parses");
    config.validate().expect("dynamic config validates");
    let app = GatewayState::from_config(&config, deps)
        .expect("gateway state")
        .router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    (format!("http://{addr}"), writer)
}

async fn echo_handler(
    State(capture): State<CaptureState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = to_bytes(body, 10 * 1024 * 1024)
        .await
        .expect("request body readable");

    capture.bodies.lock().await.push(body.clone());
    capture.headers.lock().await.push(headers);
    capture.uris.lock().await.push(uri.to_string());

    if uri.path() == "/slow-headers" {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if uri.path() == "/encoded" {
        return (
            StatusCode::OK,
            [
                (header::CONTENT_ENCODING.as_str(), "gzip"),
                (header::CONTENT_TYPE.as_str(), "application/octet-stream"),
            ],
            Bytes::from_static(GZIP_LABELED_BYTES),
        )
            .into_response();
    }

    if uri.path() == "/v1/chat/completions" {
        if request_is_streaming(&body) {
            let chunks = match request_model(&body).as_deref() {
                Some("empty-usage-stream-model") => {
                    vec![SSE_EVENT_ONE, SSE_EVENT_EMPTY_USAGE, SSE_EVENT_DONE]
                }
                Some("request-model") => {
                    vec![SSE_EVENT_UPSTREAM_MODEL, SSE_EVENT_USAGE, SSE_EVENT_DONE]
                }
                _ => vec![SSE_EVENT_ONE, SSE_EVENT_USAGE, SSE_EVENT_DONE],
            }
            .into_iter()
            .map(Bytes::from_static);
            let delay = if request_model(&body).as_deref() == Some("slow-stream-model") {
                Duration::from_millis(100)
            } else {
                Duration::from_millis(20)
            };
            let body_stream = stream::iter(chunks).then(move |chunk| async move {
                tokio::time::sleep(delay).await;
                Ok::<Bytes, std::convert::Infallible>(chunk)
            });

            return Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(body_stream))
                .expect("SSE response builds");
        }

        if request_model(&body).as_deref() == Some("null-usage-model") {
            return (
                StatusCode::OK,
                [("content-type", "application/json")],
                Bytes::from_static(CHAT_RESPONSE_NULL_USAGE),
            )
                .into_response();
        }

        if capture
            .headers
            .lock()
            .await
            .last()
            .is_some_and(|headers| headers.get("x-test-tool-response").is_some())
        {
            return (
                StatusCode::OK,
                [("content-type", "application/json")],
                Bytes::from_static(CHAT_TOOL_RESPONSE),
            )
                .into_response();
        }

        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            Bytes::from_static(CHAT_RESPONSE),
        )
            .into_response();
    }

    if uri.path() == "/v1/responses" {
        if request_is_streaming(&body) {
            let chunks = [RESPONSES_SSE_START, RESPONSES_SSE_COMPLETED]
                .into_iter()
                .map(Bytes::from_static);
            let body_stream = stream::iter(chunks).then(|chunk| async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok::<Bytes, std::convert::Infallible>(chunk)
            });
            return Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(body_stream))
                .expect("Responses SSE builds");
        }
        if request_model(&body).as_deref() == Some("unpriced-model") {
            return (
                StatusCode::OK,
                [("content-type", "application/json")],
                Bytes::from_static(UNPRICED_RESPONSE),
            )
                .into_response();
        }
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            Bytes::from_static(RESPONSES_RESPONSE),
        )
            .into_response();
    }

    if uri.path() == "/v1/embeddings" {
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            Bytes::from_static(EMBEDDINGS_RESPONSE),
        )
            .into_response();
    }

    if uri.path() == "/v1/audio/transcriptions" {
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            Bytes::from_static(AUDIO_RESPONSE),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [("x-echo-marker", "present")],
        r#"{"echo":true}"#,
    )
        .into_response()
}

fn request_is_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(|stream| stream.as_bool()))
        .unwrap_or(false)
}

fn request_model(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("model")
                .and_then(|model| model.as_str())
                .map(str::to_string)
        })
}

fn expected_sse_body() -> Vec<u8> {
    [SSE_EVENT_ONE, SSE_EVENT_USAGE, SSE_EVENT_DONE].concat()
}

async fn wait_for_records(
    dir: &std::path::Path,
    count: usize,
) -> Vec<bowline_core::ledger::DecisionRecord> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    loop {
        let (records, _) = Ledger::read_all(dir).expect("ledger readable");
        if records.len() >= count {
            return records;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {count} ledger records, saw {}",
            records.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn shadow_policy() -> bowline_core::policy::PolicyBundle {
    bowline_core::policy::PolicyBundle::from_yaml(
        r#"
version: 1
identities:
  - match: { app: support-bot }
    tags: [customer-data]
rules:
  - name: customer-data-stays-sovereign
    subject: { tags: [customer-data] }
    task_class: heavy-lifting
    require:
      supply_class: [owned, vpc-open-weights]
      cloud_act_exposure: false
      retention: [none]
  - name: default
    default: true
    require:
      supply_class: [owned, vpc-open-weights, public-api]
"#,
    )
    .expect("policy parses")
}

fn shadow_owned_costs(registry: &Registry) -> OwnedCostCatalog {
    load_owned_cost_catalog(
        Some(
            "monthly_amortization_usd: 600\nmonthly_power_usd: 200\nmonthly_ops_usd: 200\nmonthly_capacity_mtok: 1000\n",
        ),
        Some("local/echo-model"),
        registry,
    )
    .expect("shadow owned-cost catalog")
}

fn shadow_registry() -> bowline_core::supply::Registry {
    bowline_core::supply::Registry::from_json(
        r#"
{
  "feed_version": "test",
  "entries": [
    {
      "id": "local/echo-model",
      "model": "echo-model",
      "location": "local",
      "attributes": {
        "class": "owned",
        "jurisdiction": "local",
        "retention": "none",
        "training_use": false,
        "cloud_act_exposure": false
      },
      "price": null,
      "ratings": { "heavy-lifting": 0.9 }
    },
    {
      "id": "vpc/echo-model",
      "model": "echo-model",
      "location": "vpc",
      "attributes": {
        "class": "vpc-open-weights",
        "jurisdiction": "eu",
        "retention": "none",
        "training_use": false,
        "cloud_act_exposure": false
      },
      "price": {
        "input_per_mtok_usd": 0.1,
        "output_per_mtok_usd": 0.2
      },
      "ratings": { "heavy-lifting": 0.9 }
    },
    {
      "id": "public/echo-model",
      "model": "echo-model",
      "location": "public",
      "attributes": {
        "class": "public-api",
        "jurisdiction": "us",
        "retention": "days30",
        "training_use": false,
        "cloud_act_exposure": true
      },
      "price": {
        "input_per_mtok_usd": 1.0,
        "output_per_mtok_usd": 2.0
      },
      "ratings": { "heavy-lifting": 0.9 }
    },
    {
      "id": "vpc/upstream-stream-model",
      "model": "upstream-stream-model",
      "location": "vpc",
      "attributes": {
        "class": "vpc-open-weights",
        "jurisdiction": "eu",
        "retention": "none",
        "training_use": false,
        "cloud_act_exposure": false
      },
      "price": {
        "input_per_mtok_usd": 0.1,
        "output_per_mtok_usd": 0.2
      },
      "ratings": { "heavy-lifting": 0.9 }
    }
  ]
}
"#,
    )
    .expect("registry parses")
}

fn dynamic_attribution_registry() -> Registry {
    Registry::from_json(
        r#"{"feed_version":"dynamic-test","entries":[
          {"id":"public/east","model":"echo-model","location":"east","attributes":{"class":"public-api","jurisdiction":"us","retention":"days30","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0},"ratings":{"heavy-lifting":0.9,"unclassified":0.9}},
          {"id":"public/west","model":"echo-model","location":"west","attributes":{"class":"public-api","jurisdiction":"us","retention":"days30","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":3.0,"output_per_mtok_usd":4.0},"ratings":{"heavy-lifting":0.9,"unclassified":0.9}},
          {"id":"public/legacy","model":"echo-model","location":"legacy","attributes":{"class":"public-api","jurisdiction":"us","retention":"days30","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":5.0,"output_per_mtok_usd":6.0},"ratings":{"heavy-lifting":0.9,"unclassified":0.9}}
        ]}"#,
    )
    .expect("dynamic registry")
}

fn coverage_registry() -> Registry {
    Registry::from_json(
        r#"
{
  "feed_version": "coverage-test",
  "entries": [
    {
      "id": "public/echo-model",
      "model": "echo-model",
      "location": "public",
      "attributes": { "class": "public-api", "jurisdiction": "us", "retention": "days30", "training_use": false, "cloud_act_exposure": true },
      "price": { "input_per_mtok_usd": 1.0, "output_per_mtok_usd": 2.0 },
      "ratings": { "heavy-lifting": 0.9 }
    },
    {
      "id": "public/unpriced-model",
      "model": "unpriced-model",
      "location": "public",
      "attributes": { "class": "public-api", "jurisdiction": "us", "retention": "days30", "training_use": false, "cloud_act_exposure": true },
      "price": null,
      "ratings": { "heavy-lifting": 0.9 }
    }
  ]
}
"#,
    )
    .expect("coverage registry parses")
}
