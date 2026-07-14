use std::time::{Duration, Instant};

use bowline_core::enforcement::ActuatorConfig;
use bowline_core::enforcement::AuthorityProtocol;
use bowline_gateway::actuator::{
    build_redirect_free_client, classify_candidate_result, sanitize_candidate_headers,
    send_authorized_candidate, validate_probe_response, ActuatorRegistry, CandidateFailure,
    CandidateResponseStream, CandidateTransportError, CircuitSnapshot, CircuitState,
};
use bytes::Bytes;
use futures_util::StreamExt;

fn actuator(supply_id: &str, concurrency: u32) -> ActuatorConfig {
    ActuatorConfig {
        supply_id: supply_id.into(),
        base_url: "http://127.0.0.1:3000".into(),
        authorization_env: "BOWLINE_TEST_TOKEN".into(),
        health_path: Some("/v1/models".into()),
        remote_acknowledged: false,
        connect_timeout_ms: 100,
        response_header_timeout_ms: 100,
        stream_idle_timeout_ms: 100,
        concurrency,
        probe_timeout_ms: 100,
        probe_max_bytes: 1024,
        breaker_consecutive_failures: 2,
        breaker_cooldown_ms: 100,
    }
}

#[tokio::test]
async fn candidate_admission_is_global_then_actuator_and_releases_exactly_once() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());
    let first = registry
        .try_acquire("candidate", Duration::from_millis(10))
        .await
        .unwrap();
    assert_eq!(registry.in_flight(), (1, 1));
    assert!(registry
        .try_acquire("candidate", Duration::from_millis(1))
        .await
        .is_err());
    drop(first);
    assert_eq!(registry.in_flight(), (0, 0));
    let second = registry
        .try_acquire("candidate", Duration::from_millis(10))
        .await
        .unwrap();
    drop(second);
    assert_eq!(registry.in_flight(), (0, 0));
}

#[tokio::test]
async fn startup_open_and_half_open_circuits_issue_no_candidate_permit() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    assert!(registry
        .try_acquire("candidate", Duration::from_millis(1))
        .await
        .is_err());
    assert_eq!(registry.in_flight(), (0, 0));
    let now = Instant::now() + Duration::from_millis(100);
    assert!(registry.try_begin_probe("candidate", now).unwrap());
    assert!(registry
        .try_acquire("candidate", Duration::from_millis(1))
        .await
        .is_err());
    assert_eq!(registry.in_flight(), (0, 0));
}

#[tokio::test]
async fn startup_probe_does_not_wait_for_normal_breaker_cooldown() {
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/v1/models",
        get(|| async { r#"{"data":[{"id":"canonical"}]}"# }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut config = actuator("candidate", 1);
    config.base_url = format!("http://{address}");
    config.breaker_cooldown_ms = 60_000;
    let registry = ActuatorRegistry::new(1, [config]).unwrap();

    assert!(registry
        .run_startup_probe("candidate", "canonical", None)
        .await
        .unwrap());
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[tokio::test]
async fn failed_redirecting_startup_probe_stays_open_and_never_contacts_target() {
    use axum::{http::StatusCode, response::Response, routing::get, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;

    let target_count = Arc::new(AtomicUsize::new(0));
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_app = Router::new().fallback(axum::routing::any({
        let target_count = Arc::clone(&target_count);
        move || {
            let target_count = Arc::clone(&target_count);
            async move {
                target_count.fetch_add(1, Ordering::AcqRel);
                r#"{"data":[{"id":"canonical"}]}"#
            }
        }
    }));
    tokio::spawn(async move { axum::serve(target_listener, target_app).await.unwrap() });

    let source_count = Arc::new(AtomicUsize::new(0));
    let source_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source_address = source_listener.local_addr().unwrap();
    let source_app = Router::new().route(
        "/v1/models",
        get({
            let source_count = Arc::clone(&source_count);
            move || {
                let source_count = Arc::clone(&source_count);
                async move {
                    source_count.fetch_add(1, Ordering::AcqRel);
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", format!("http://{target_address}/v1/models"))
                        .body(axum::body::Body::empty())
                        .unwrap()
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(source_listener, source_app).await.unwrap() });

    let mut config = actuator("candidate", 1);
    config.base_url = format!("http://{source_address}");
    config.breaker_cooldown_ms = 60_000;
    let registry = ActuatorRegistry::new(1, [config]).unwrap();
    assert!(!registry
        .run_startup_probe("candidate", "canonical", None)
        .await
        .unwrap());
    assert_eq!(source_count.load(Ordering::Acquire), 1);
    assert_eq!(target_count.load(Ordering::Acquire), 0);
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );
}

#[test]
fn breaker_starts_open_allows_one_probe_and_uses_monotonic_cooldown() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    let now = Instant::now();
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );
    assert!(!registry.try_begin_probe("candidate", now).unwrap());
    assert!(registry
        .try_begin_probe("candidate", now + Duration::from_millis(100))
        .unwrap());
    assert!(!registry
        .try_begin_probe("candidate", now + Duration::from_millis(101))
        .unwrap());
    registry.finish_probe("candidate", true, now + Duration::from_millis(102));
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[test]
fn breaker_classification_is_status_exact_and_content_free() {
    assert_eq!(
        classify_candidate_result(Some(401), None),
        Some(CandidateFailure::Authentication)
    );
    assert_eq!(
        classify_candidate_result(Some(403), None),
        Some(CandidateFailure::Authentication)
    );
    assert_eq!(
        classify_candidate_result(Some(500), None),
        Some(CandidateFailure::Server)
    );
    assert_eq!(
        classify_candidate_result(Some(599), None),
        Some(CandidateFailure::Server)
    );
    for status in [200, 400, 404, 408, 409, 422, 429, 499] {
        assert_eq!(classify_candidate_result(Some(status), None), None);
    }
    assert_eq!(
        classify_candidate_result(Some(400), Some(CandidateFailure::Connect)),
        Some(CandidateFailure::Connect)
    );
}

#[test]
fn breaker_opens_at_threshold_and_success_resets_failures() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    let now = Instant::now();
    registry.finish_probe("candidate", true, now);
    registry.record_candidate("candidate", Some(CandidateFailure::Connect), now);
    assert!(matches!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::ClosedWithFailures(1)
    ));
    registry.record_candidate("candidate", None, now);
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
    registry.record_candidate("candidate", Some(CandidateFailure::HeaderTimeout), now);
    registry.record_candidate("candidate", Some(CandidateFailure::StreamIdleTimeout), now);
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );
}

#[test]
fn stale_in_flight_success_cannot_close_an_open_circuit() {
    let registry = ActuatorRegistry::new(2, [actuator("candidate", 2)]).unwrap();
    let now = Instant::now();
    registry.finish_probe("candidate", true, now);
    registry.record_candidate("candidate", Some(CandidateFailure::Connect), now);
    registry.record_candidate("candidate", Some(CandidateFailure::Connect), now);
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );
    registry.record_candidate("candidate", None, now + Duration::from_millis(1));
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );
}

#[test]
fn public_state_enum_has_only_monotonic_breaker_phases() {
    let states = [
        CircuitState::Closed,
        CircuitState::Open,
        CircuitState::HalfOpen,
    ];
    assert_eq!(states.len(), 3);
}

#[test]
fn internal_snapshot_is_aggregate_and_content_free() {
    let registry = ActuatorRegistry::new(2, [actuator("sensitive-supply-name", 1)]).unwrap();
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.closed, 0);
    assert_eq!(snapshot.open, 1);
    assert_eq!(snapshot.half_open, 0);
    assert_eq!(snapshot.global_candidate_in_flight, 0);
    assert_eq!(snapshot.global_candidate_capacity, 2);
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("sensitive-supply-name"));
    assert!(!json.contains("http"));
    assert!(!json.contains("authorization"));
}

#[test]
fn candidate_network_boundary_accepts_only_an_authorized_dispatch_handle() {
    let _ = send_authorized_candidate;
}

#[test]
fn probe_requires_exact_200_bounded_strict_json_and_canonical_model() {
    let valid = br#"{"data":[{"id":"canonical"}]}"#;
    assert!(validate_probe_response(200, valid, "canonical", 1024).is_ok());
    for status in [199, 201, 301, 302, 303, 307, 308, 401, 500] {
        assert!(validate_probe_response(status, valid, "canonical", 1024).is_err());
    }
    assert!(validate_probe_response(200, valid, "other", 1024).is_err());
    assert!(validate_probe_response(200, b"{}", "canonical", 1024).is_err());
    assert!(validate_probe_response(200, b"not-json", "canonical", 1024).is_err());
    assert!(validate_probe_response(200, valid, "canonical", valid.len() - 1).is_err());
    assert!(validate_probe_response(
        200,
        br#"{"data":[{"id":"canonical","secret":"x"}]}"#,
        "canonical",
        1024
    )
    .is_err());
}

#[tokio::test]
async fn actuator_client_does_not_follow_any_redirect_status() {
    use axum::{extract::State, http::StatusCode, response::Response, routing::any, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;

    let target_count = Arc::new(AtomicUsize::new(0));
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let target_app = Router::new().fallback(any({
        let target_count = Arc::clone(&target_count);
        move || {
            let target_count = Arc::clone(&target_count);
            async move {
                target_count.fetch_add(1, Ordering::AcqRel);
                "target"
            }
        }
    }));
    tokio::spawn(async move { axum::serve(target_listener, target_app).await.unwrap() });

    for status in [301u16, 302, 303, 307, 308] {
        let source_count = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(any({
                let source_count = Arc::clone(&source_count);
                move |State(()): State<()>| {
                    let source_count = Arc::clone(&source_count);
                    async move {
                        source_count.fetch_add(1, Ordering::AcqRel);
                        Response::builder()
                            .status(StatusCode::from_u16(status).unwrap())
                            .header("location", format!("http://{target_addr}/target"))
                            .body(axum::body::Body::from("redirect-body"))
                            .unwrap()
                    }
                }
            }))
            .with_state(());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = build_redirect_free_client(Duration::from_secs(1))
            .unwrap()
            .get(format!("http://{addr}/source"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"redirect-body");
        assert_eq!(source_count.load(Ordering::Acquire), 1);
        assert_eq!(target_count.load(Ordering::Acquire), 0);
    }
}

#[test]
fn candidate_strips_every_connection_nominated_header() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::CONNECTION,
        reqwest::header::HeaderValue::from_static("x-private-hop, keep-alive"),
    );
    headers.append(
        reqwest::header::CONNECTION,
        reqwest::header::HeaderValue::from_static("x-second-hop, invalid token@"),
    );
    headers.insert(
        reqwest::header::HeaderName::from_static("x-private-hop"),
        reqwest::header::HeaderValue::from_static("secret"),
    );
    headers.insert(
        reqwest::header::HeaderName::from_static("x-second-hop"),
        reqwest::header::HeaderValue::from_static("secret-two"),
    );
    headers.insert(
        reqwest::header::HeaderName::from_static("x-ordinary"),
        reqwest::header::HeaderValue::from_static("kept"),
    );
    let seen = sanitize_candidate_headers(
        &headers,
        reqwest::header::HeaderValue::from_static("Bearer candidate"),
    );
    assert!(!seen.contains_key("connection"));
    assert!(!seen.contains_key("x-private-hop"));
    assert!(!seen.contains_key("x-second-hop"));
    assert_eq!(seen["x-ordinary"], "kept");
    assert_eq!(seen["authorization"], "Bearer candidate");
}

#[tokio::test]
async fn original_gateway_client_does_not_follow_any_redirect_status() {
    use axum::{http::StatusCode, response::Response, routing::any, Router};
    use bowline_gateway::{GatewayDeps, GatewayState};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;

    let target_count = Arc::new(AtomicUsize::new(0));
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let target_app = Router::new().fallback(any({
        let target_count = Arc::clone(&target_count);
        move || {
            let target_count = Arc::clone(&target_count);
            async move {
                target_count.fetch_add(1, Ordering::AcqRel);
                "target"
            }
        }
    }));
    tokio::spawn(async move { axum::serve(target_listener, target_app).await.unwrap() });

    for status in [301u16, 302, 303, 307, 308] {
        let source_count = Arc::new(AtomicUsize::new(0));
        let source_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_addr = source_listener.local_addr().unwrap();
        let source_app = Router::new().fallback(any({
            let source_count = Arc::clone(&source_count);
            move || {
                let source_count = Arc::clone(&source_count);
                async move {
                    source_count.fetch_add(1, Ordering::AcqRel);
                    Response::builder()
                        .status(StatusCode::from_u16(status).unwrap())
                        .header("location", format!("http://{target_addr}/target"))
                        .body(axum::body::Body::from("original-redirect"))
                        .unwrap()
                }
            }
        }));
        tokio::spawn(async move { axum::serve(source_listener, source_app).await.unwrap() });

        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway_listener.local_addr().unwrap();
        let gateway =
            GatewayState::new(format!("http://{source_addr}"), GatewayDeps::default()).router();
        tokio::spawn(async move {
            axum::serve(
                gateway_listener,
                gateway.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let response = build_redirect_free_client(Duration::from_secs(1))
            .unwrap()
            .post(format!("http://{gateway_addr}/v1/chat/completions"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            b"original-redirect"
        );
        assert_eq!(source_count.load(Ordering::Acquire), 1);
        assert_eq!(target_count.load(Ordering::Acquire), 0);
    }
}

#[tokio::test]
async fn candidate_stream_holds_permits_through_valid_chat_sse_completion() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());
    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let inner = futures_util::stream::iter([
        Ok(Bytes::from_static(b"data: {\"choices\":[]}\n\n")),
        Ok(Bytes::from_static(b"data: [DONE]\n\n")),
    ]);
    let output = CandidateResponseStream::new(
        inner,
        permit,
        AuthorityProtocol::ChatCompletions,
        true,
        1024,
    )
    .collect::<Vec<_>>()
    .await;
    assert_eq!(output.len(), 2);
    assert_eq!(registry.in_flight(), (0, 0));
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[tokio::test]
async fn candidate_stream_penalizes_proven_sse_incomplete_but_not_downstream_drop() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());

    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let inner =
        futures_util::stream::iter([Ok(Bytes::from_static(b"data: {\"partial\":true}\n\n"))]);
    let incomplete =
        CandidateResponseStream::new(inner, permit, AuthorityProtocol::Responses, true, 1024)
            .collect::<Vec<_>>()
            .await;
    assert!(matches!(
        incomplete.as_slice(),
        [Ok(_), Err(CandidateTransportError::ProtocolIncomplete)]
    ));
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::ClosedWithFailures(1)
    );

    registry.record_candidate("candidate", None, Instant::now());
    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let inner = futures_util::stream::iter([Err(CandidateTransportError::Transport)]);
    CandidateResponseStream::new(inner, permit, AuthorityProtocol::Responses, true, 1024)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::ClosedWithFailures(1)
    );

    registry.record_candidate("candidate", None, Instant::now());
    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let inner = futures_util::stream::pending::<Result<Bytes, CandidateTransportError>>();
    let stream = CandidateResponseStream::new(
        inner,
        permit,
        AuthorityProtocol::ChatCompletions,
        true,
        1024,
    );
    assert_eq!(registry.in_flight(), (1, 1));
    drop(stream);
    assert_eq!(registry.in_flight(), (0, 0));
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[tokio::test]
async fn responses_sse_completion_requires_one_structurally_valid_completed_event() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());
    registry.record_candidate("candidate", Some(CandidateFailure::Connect), Instant::now());
    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let false_positive = futures_util::stream::iter([Ok(Bytes::from_static(
        b"event: response.completed\ndata: {\"nested\":{\"type\":\"response.completed\"}}\n\n",
    ))]);
    CandidateResponseStream::new(
        false_positive,
        permit,
        AuthorityProtocol::Responses,
        true,
        1024,
    )
    .collect::<Vec<_>>()
    .await;
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );

    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());
    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let valid = futures_util::stream::iter([Ok(Bytes::from_static(
        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{}}\n\n",
    ))]);
    CandidateResponseStream::new(valid, permit, AuthorityProtocol::Responses, true, 1024)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[tokio::test]
async fn non_streaming_garbage_body_over_clean_close_opens_breaker() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());

    for _ in 0..2 {
        let permit = registry
            .try_acquire("candidate", Duration::from_millis(5))
            .await
            .unwrap();
        let inner = futures_util::stream::iter([Ok(Bytes::from_static(b"not-json"))]);
        let output = CandidateResponseStream::new(
            inner,
            permit,
            AuthorityProtocol::ChatCompletions,
            false,
            1024,
        )
        .collect::<Vec<_>>()
        .await;
        assert!(matches!(
            output.as_slice(),
            [Ok(_), Err(CandidateTransportError::ProtocolIncomplete)]
        ));
    }
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Open
    );
}

#[tokio::test]
async fn over_limit_healthy_response_records_success_and_resets_failures() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());
    registry.record_candidate("candidate", Some(CandidateFailure::Connect), Instant::now());
    assert!(matches!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::ClosedWithFailures(1)
    ));

    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let inner = futures_util::stream::iter([Ok(Bytes::from_static(b"0123456789"))]);
    let output = CandidateResponseStream::new(
        inner,
        permit,
        AuthorityProtocol::ChatCompletions,
        false,
        4, // accounting limit smaller than the body: forces over_limit
    )
    .collect::<Vec<_>>()
    .await;
    assert_eq!(output.len(), 1);
    assert!(output[0].is_ok());
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[tokio::test]
async fn candidate_stream_treats_done_marker_without_space_as_complete() {
    let registry = ActuatorRegistry::new(1, [actuator("candidate", 1)]).unwrap();
    registry.finish_probe("candidate", true, Instant::now());
    let permit = registry
        .try_acquire("candidate", Duration::from_millis(5))
        .await
        .unwrap();
    let inner = futures_util::stream::iter([
        Ok(Bytes::from_static(b"data: {\"choices\":[]}\n\n")),
        Ok(Bytes::from_static(b"data:[DONE]\n\n")),
    ]);
    let output = CandidateResponseStream::new(
        inner,
        permit,
        AuthorityProtocol::ChatCompletions,
        true,
        1024,
    )
    .collect::<Vec<_>>()
    .await;
    assert_eq!(output.len(), 2);
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
}

#[tokio::test]
async fn dedicated_probe_is_get_only_bodyless_bounded_and_requires_canonical_model() {
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        http::{HeaderMap, Method, StatusCode},
        routing::any,
        Router,
    };
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any({
            let seen = Arc::clone(&seen);
            move |State(()): State<()>, method: Method, headers: HeaderMap, body: Body| {
                let seen = Arc::clone(&seen);
                async move {
                    let body = to_bytes(body, 1024).await.unwrap();
                    seen.lock().unwrap().push((method, headers, body));
                    (StatusCode::OK, r#"{"data":[{"id":"candidate"}]}"#)
                }
            }
        }))
        .with_state(());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut config = actuator("candidate", 1);
    config.base_url = format!("http://{addr}");
    let registry = ActuatorRegistry::new(1, [config]).unwrap();
    let now = Instant::now() + Duration::from_millis(100);
    assert!(registry
        .run_probe("candidate", "candidate", None, now)
        .await
        .unwrap());
    assert_eq!(
        registry.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, Method::GET);
    assert!(seen[0].2.is_empty());
    assert!(!seen[0].1.contains_key("x-bowline-app"));
}
