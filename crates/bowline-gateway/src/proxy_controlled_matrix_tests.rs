use super::*;

use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri},
    http::{HeaderMap, Request, StatusCode},
    response::Response,
    routing::{any, get},
    Router,
};
use bowline_core::{
    config::{Config, InlineAttributionConfig, InlineAttributionMapping, RuntimeConfig},
    enforcement::{
        validate_promotion_documents, validate_recommendation_documents, EconomicsPromotionSource,
        EvidenceState, PromotionOpportunityEvidence, QualityPromotionSource, RouteMode,
    },
    ledger::{AuthorityLedgerV2, AuthorityRecordV2, CompletionStateV2, Ledger},
    quality::PromotionVerdict,
    supply::TaskClass,
};
use futures_util::{stream, StreamExt};
use tokio::net::TcpListener;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateBehavior {
    Success,
    PartialInputUsage,
    PartialOutputUsage,
    PrematureSse,
    ValidSse,
    Status(u16),
    HeaderTimeout,
    IdleTimeout,
    StreamError,
    Connect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeBehavior {
    Success,
    Failure,
    Redirect,
    Skip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CircuitSetup {
    Closed,
    Open,
    HalfOpen,
    Saturated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceSetup {
    Verified,
    Missing,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityHeaderSetup {
    Canonical,
    DuplicateApp,
    AmbiguousApp,
    MalformedApp,
    ReservedApp,
    OverlongApp,
    DuplicateTask,
    AmbiguousTask,
    MalformedTask,
    ReservedTask,
    OverlongTask,
    UnsupportedTask,
}

#[derive(Clone, Copy, Debug)]
struct MatrixCase {
    name: &'static str,
    protocol: AuthorityProtocol,
    mode: RouteMode,
    rollout_ppm: u32,
    fallback: FallbackMode,
    model_authority: bowline_core::enforcement::ModelAuthority,
    kill: &'static [u8],
    final_kill: Option<&'static [u8]>,
    kill_queue_failure: bool,
    app: &'static str,
    selector_app: &'static str,
    expect_unresolved_app: bool,
    identity_headers: IdentityHeaderSetup,
    declared_task: Option<&'static str>,
    policy_task: TaskClass,
    route_task: TaskClass,
    grant_task: TaskClass,
    expected_task: TaskClass,
    body: &'static str,
    evidence: EvidenceSetup,
    circuit: CircuitSetup,
    candidate: CandidateBehavior,
    probe: ProbeBehavior,
    terminal_writer_failure: bool,
    post_rejection_closing: bool,
    expect_evidence_unavailable: bool,
    drop_downstream: bool,
    stop_original: bool,
    omit_actuator_target: bool,
    expected_status: u16,
    expected_original: usize,
    expected_candidate: usize,
    expected_probe: usize,
    expected_redirect_target: usize,
    expected_target: PlanTarget,
    expected_evidence: EvidenceState,
    expected_reason: Option<SelectionReason>,
    expected_completion: CompletionStateV2,
    expected_kill: KillReadResult,
    original_status: u16,
    original_attribution: Option<&'static str>,
    original_upstream_override: Option<&'static str>,
}

struct ShadowParityEvidence {
    record: bowline_core::ledger::DecisionRecord,
    response_headers: Vec<(String, String)>,
    response_body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct OriginalRequestEvidence {
    method: Method,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn stable_shadow_projection(record: &bowline_core::ledger::DecisionRecord) -> serde_json::Value {
    let mut value = serde_json::to_value(record).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("id");
    object.remove("ts_ms");
    object.remove("run_id");
    object
        .get_mut("actual")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("latency_ms");
    value
}

fn parity_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    ["content-type", "x-bowline-supply", "x-parity-response"]
        .into_iter()
        .filter_map(|name| {
            headers
                .get(name)
                .map(|value| (name.to_owned(), value.to_str().unwrap().to_owned()))
        })
        .collect()
}

const CHAT_BODY: &str = r#"{"model":"baseline-model","messages":[]}"#;
const RESPONSES_BODY: &str = r#"{"model":"baseline-model","input":"hello"}"#;
const EMBEDDINGS_BODY: &str = r#"{"model":"baseline-model","input":["hello"]}"#;
const OVERLONG_APP_HEADER: &str = concat!(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "a"
);
const OVERLONG_TASK_HEADER: &str = concat!(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "a"
);

#[tokio::test]
async fn production_proxy_handler_enforcement_matrix_is_single_dispatch_and_evidenced() {
    let mut cases = vec![
        recommend_case(
            "recommend-verified",
            EvidenceSetup::Verified,
            EvidenceState::Presented,
        ),
        embeddings_case("embeddings-observe", RouteMode::Observe),
        embeddings_case("embeddings-recommend", RouteMode::Recommend),
        recommend_kill_case("recommend-kill-bypass", b"bypass\n", KillReadResult::Bypass),
        recommend_kill_case(
            "recommend-kill-malformed",
            b"malformed\n",
            KillReadResult::Malformed,
        ),
        recommend_missing_kill_case(),
        recommend_unsafe_kill_case(),
        recommend_queue_kill_case(),
        recommend_case(
            "recommend-missing",
            EvidenceSetup::Missing,
            EvidenceState::Unverified,
        ),
        recommend_case(
            "recommend-stale",
            EvidenceSetup::Stale,
            EvidenceState::Unverified,
        ),
        candidate_case("canary-bucket-in", AuthorityProtocol::Responses),
        fallback_case("canary-bucket-out", SelectionVariant::CanaryOut),
        fallback_case("selector-miss", SelectionVariant::SelectorMiss),
        declared_task_mismatch_case(),
        fallback_case("stale-grant", SelectionVariant::StaleGrant),
        fallback_case("pinned-preserve", SelectionVariant::PinnedPreserve),
        fallback_case("rewrite-failure", SelectionVariant::RewriteFailure),
        fallback_case("kill-bypass", SelectionVariant::KillBypass),
        fail_closed_case("kill-fail-closed", b"bypass\n"),
        fail_closed_case("kill-malformed", b"malformed\n"),
        queue_failure_case(),
        fallback_case("configured-bypass", SelectionVariant::ConfiguredBypass),
        fallback_case("candidate-saturation", SelectionVariant::Saturated),
        fallback_case("circuit-open", SelectionVariant::CircuitOpen),
        fallback_case("circuit-half-open", SelectionVariant::CircuitHalfOpen),
        stopped_original_case("stopped-original-circuit-open", CircuitSetup::Open, false),
        stopped_original_case(
            "stopped-original-admission-saturated",
            CircuitSetup::Saturated,
            false,
        ),
        stopped_original_case(
            "stopped-original-actuator-unavailable",
            CircuitSetup::Closed,
            true,
        ),
        candidate_case("chat-candidate", AuthorityProtocol::ChatCompletions),
        candidate_case("responses-candidate", AuthorityProtocol::Responses),
        sse_case(
            "chat-premature-sse",
            AuthorityProtocol::ChatCompletions,
            CandidateBehavior::PrematureSse,
            CompletionStateV2::Failed,
        ),
        sse_case(
            "responses-premature-sse",
            AuthorityProtocol::Responses,
            CandidateBehavior::PrematureSse,
            CompletionStateV2::Failed,
        ),
        sse_case(
            "chat-valid-sse",
            AuthorityProtocol::ChatCompletions,
            CandidateBehavior::ValidSse,
            CompletionStateV2::Succeeded,
        ),
        sse_case(
            "responses-valid-sse",
            AuthorityProtocol::Responses,
            CandidateBehavior::ValidSse,
            CompletionStateV2::Succeeded,
        ),
        failure_case("candidate-401", CandidateBehavior::Status(401), 401),
        failure_case("candidate-403", CandidateBehavior::Status(403), 403),
        failure_case("candidate-5xx", CandidateBehavior::Status(503), 503),
        failure_case("candidate-connect", CandidateBehavior::Connect, 502),
        failure_case(
            "candidate-header-timeout",
            CandidateBehavior::HeaderTimeout,
            504,
        ),
        stream_failure_case("candidate-idle-timeout", CandidateBehavior::IdleTimeout),
        stream_failure_case("candidate-stream-error", CandidateBehavior::StreamError),
        terminal_failure_case(),
        startup_case("startup-probe-success", ProbeBehavior::Success, 1, 0, true),
        startup_case("startup-probe-failure", ProbeBehavior::Failure, 1, 0, false),
        startup_case(
            "startup-probe-redirect",
            ProbeBehavior::Redirect,
            1,
            0,
            false,
        ),
    ];
    // Redirect target expectations are explicit rather than inferred from status.
    cases.last_mut().unwrap().expected_redirect_target = 0;

    for case in cases {
        run_case(case).await;
    }
}

#[tokio::test]
async fn candidate_partial_observed_usage_is_durable_without_modeled_delta() {
    for (name, candidate) in [
        (
            "candidate-input-only-usage",
            CandidateBehavior::PartialInputUsage,
        ),
        (
            "candidate-output-only-usage",
            CandidateBehavior::PartialOutputUsage,
        ),
    ] {
        run_case(MatrixCase {
            candidate,
            ..candidate_case(name, AuthorityProtocol::Responses)
        })
        .await;
    }
}

#[tokio::test]
async fn invalid_or_ambiguous_authority_headers_use_configured_fallback_without_candidate_dispatch()
{
    let cases = [
        (
            "duplicate-app-bypass",
            IdentityHeaderSetup::DuplicateApp,
            false,
            true,
        ),
        (
            "ambiguous-app-fail-closed",
            IdentityHeaderSetup::AmbiguousApp,
            true,
            true,
        ),
        (
            "reserved-app-bypass",
            IdentityHeaderSetup::ReservedApp,
            false,
            true,
        ),
        (
            "overlong-app-fail-closed",
            IdentityHeaderSetup::OverlongApp,
            true,
            true,
        ),
        (
            "duplicate-task-bypass",
            IdentityHeaderSetup::DuplicateTask,
            false,
            false,
        ),
        (
            "ambiguous-task-fail-closed",
            IdentityHeaderSetup::AmbiguousTask,
            true,
            false,
        ),
        (
            "reserved-task-bypass",
            IdentityHeaderSetup::ReservedTask,
            false,
            false,
        ),
        (
            "overlong-task-fail-closed",
            IdentityHeaderSetup::OverlongTask,
            true,
            false,
        ),
        (
            "unsupported-task-bypass",
            IdentityHeaderSetup::UnsupportedTask,
            false,
            false,
        ),
    ];
    for (name, identity_headers, fail_closed, unresolved_app) in cases {
        let mut case = fallback_case(name, SelectionVariant::SelectorMiss);
        case.app = "support";
        case.identity_headers = identity_headers;
        case.expect_unresolved_app = unresolved_app;
        case.expected_reason = Some(SelectionReason::UntrustedIdentity);
        if fail_closed {
            case.fallback = FallbackMode::FailClosed;
            case.expected_status = 503;
            case.expected_original = 0;
            case.expected_target = PlanTarget::None;
            case.expected_completion = CompletionStateV2::Local;
        }
        run_case(case).await;
    }
}

#[tokio::test]
async fn recommend_invalid_authority_metadata_is_unverified_and_original_only() {
    let cases = [
        ("recommend-duplicate-app", IdentityHeaderSetup::DuplicateApp),
        ("recommend-ambiguous-app", IdentityHeaderSetup::AmbiguousApp),
        ("recommend-malformed-app", IdentityHeaderSetup::MalformedApp),
        ("recommend-reserved-app", IdentityHeaderSetup::ReservedApp),
        ("recommend-overlong-app", IdentityHeaderSetup::OverlongApp),
        (
            "recommend-duplicate-task",
            IdentityHeaderSetup::DuplicateTask,
        ),
        (
            "recommend-ambiguous-task",
            IdentityHeaderSetup::AmbiguousTask,
        ),
        (
            "recommend-malformed-task",
            IdentityHeaderSetup::MalformedTask,
        ),
        ("recommend-reserved-task", IdentityHeaderSetup::ReservedTask),
        ("recommend-overlong-task", IdentityHeaderSetup::OverlongTask),
        (
            "recommend-unsupported-task",
            IdentityHeaderSetup::UnsupportedTask,
        ),
    ];

    for (name, identity_headers) in cases {
        run_case(MatrixCase {
            mode: RouteMode::Recommend,
            identity_headers,
            expected_original: 1,
            expected_candidate: 0,
            expected_target: PlanTarget::Original,
            expected_evidence: EvidenceState::Unverified,
            expected_reason: Some(SelectionReason::RecommendationOnly),
            expect_unresolved_app: matches!(
                identity_headers,
                IdentityHeaderSetup::DuplicateApp
                    | IdentityHeaderSetup::AmbiguousApp
                    | IdentityHeaderSetup::MalformedApp
                    | IdentityHeaderSetup::ReservedApp
                    | IdentityHeaderSetup::OverlongApp
            ),
            ..base_case(name)
        })
        .await;
    }
}

fn declared_task_mismatch_case() -> MatrixCase {
    MatrixCase {
        name: "declared-task-mismatch",
        declared_task: Some("judgment"),
        expected_task: TaskClass::Judgment,
        expected_original: 1,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_evidence: EvidenceState::Unverified,
        ..base_case("declared-task-mismatch")
    }
}

fn embeddings_case(name: &'static str, mode: RouteMode) -> MatrixCase {
    MatrixCase {
        protocol: AuthorityProtocol::Embeddings,
        mode,
        body: EMBEDDINGS_BODY,
        expected_original: 1,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_evidence: if mode == RouteMode::Observe {
            EvidenceState::NotRequired
        } else {
            EvidenceState::Unverified
        },
        ..base_case(name)
    }
}

#[derive(Clone, Copy)]
enum SelectionVariant {
    CanaryOut,
    SelectorMiss,
    StaleGrant,
    PinnedPreserve,
    RewriteFailure,
    KillBypass,
    ConfiguredBypass,
    Saturated,
    CircuitOpen,
    CircuitHalfOpen,
}

fn base_case(name: &'static str) -> MatrixCase {
    MatrixCase {
        name,
        protocol: AuthorityProtocol::Responses,
        mode: RouteMode::Enforce,
        rollout_ppm: 0,
        fallback: FallbackMode::Bypass,
        model_authority: bowline_core::enforcement::ModelAuthority::RewriteToCanonical,
        kill: b"armed\n",
        final_kill: None,
        kill_queue_failure: false,
        app: "support",
        selector_app: "support",
        expect_unresolved_app: false,
        identity_headers: IdentityHeaderSetup::Canonical,
        declared_task: None,
        policy_task: TaskClass::HeavyLifting,
        route_task: TaskClass::HeavyLifting,
        grant_task: TaskClass::HeavyLifting,
        expected_task: TaskClass::HeavyLifting,
        body: RESPONSES_BODY,
        evidence: EvidenceSetup::Verified,
        circuit: CircuitSetup::Closed,
        candidate: CandidateBehavior::Success,
        probe: ProbeBehavior::Skip,
        terminal_writer_failure: false,
        post_rejection_closing: false,
        expect_evidence_unavailable: false,
        drop_downstream: false,
        stop_original: false,
        omit_actuator_target: false,
        expected_status: 200,
        expected_original: 0,
        expected_candidate: 1,
        expected_probe: 0,
        expected_redirect_target: 0,
        expected_target: PlanTarget::Candidate,
        expected_evidence: EvidenceState::Presented,
        expected_reason: None,
        expected_completion: CompletionStateV2::Succeeded,
        expected_kill: KillReadResult::Armed,
        original_status: 200,
        original_attribution: None,
        original_upstream_override: None,
    }
}

fn parity_config(upstream: &str, root: &std::path::Path) -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        upstream: upstream.into(),
        actual_supply_id: "baseline".into(),
        policy_bundle: root.join("policy.yaml"),
        registry_feed: root.join("registry.json"),
        local_endpoints: Vec::new(),
        ledger_dir: root.join("shadow"),
        tco: None,
        attribution: Some(InlineAttributionConfig {
            version: 1,
            response_header: "x-bowline-supply".into(),
            namespace: "test".into(),
            mappings: vec![InlineAttributionMapping {
                value: "origin".into(),
                supply_id: "baseline".into(),
            }],
        }),
        floors: None,
        enforcement: None,
        trusted_proxy_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
        runtime: RuntimeConfig::default(),
    }
}

fn parity_policy_source() -> String {
    format!(
        r#"
version: 1
identities:
  - match: {{ app: support }}
    tags: [production]
rules:
  - name: default
    default: true
    task_class: {}
    require: {{ supply_class: [public-api, owned] }}
"#,
        task_yaml(TaskClass::HeavyLifting),
    )
}

async fn legacy_shadow_parity_evidence(upstream: &str) -> ShadowParityEvidence {
    let root = tempfile::tempdir().unwrap();
    let (writer, _) = crate::writer::spawn_writer(root.path().join("shadow")).unwrap();
    let deps = GatewayDeps::recording(
        PolicyBundle::from_yaml(&parity_policy_source()).unwrap(),
        test_registry(),
        QualityFloors::default(),
        load_owned_cost_catalog(None, Some("baseline"), &test_registry()).unwrap(),
        writer,
    );
    let state = GatewayState::from_config(&parity_config(upstream, root.path()), deps).unwrap();
    let path = "/v1/responses";
    let mut headers = HeaderMap::new();
    headers.insert("x-bowline-app", "support".parse().unwrap());
    headers.insert("x-parity-request", "same".parse().unwrap());
    let response = proxy_handler(
        State(state),
        ConnectInfo("127.0.0.1:40000".parse().unwrap()),
        Method::POST,
        OriginalUri(path.parse().unwrap()),
        headers,
        Request::builder()
            .method("POST")
            .uri(path)
            .header("x-bowline-app", "support")
            .header("x-parity-request", "same")
            .body(Body::from(RESPONSES_BODY))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    let response_headers = parity_response_headers(response.headers());
    let response_body = axum::body::to_bytes(response.into_body(), MAX_REQUEST_BODY_BYTES)
        .await
        .unwrap()
        .to_vec();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let record = loop {
        let (records, _) = Ledger::read_all(&root.path().join("shadow")).unwrap();
        if let Some(record) = records.into_iter().next() {
            break record;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "legacy shadow timeout"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    ShadowParityEvidence {
        record,
        response_headers,
        response_body,
    }
}

#[tokio::test]
async fn original_shadow_parity_is_exact_for_controlled_original_paths() {
    let requests = Arc::new(Mutex::new(Vec::<OriginalRequestEvidence>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().fallback(any({
        let requests = Arc::clone(&requests);
        move |request: Request<Body>| {
            let requests = Arc::clone(&requests);
            async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES)
                    .await
                    .unwrap();
                let mut headers = parts
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (name.as_str().to_owned(), value.to_str().unwrap().to_owned())
                    })
                    .collect::<Vec<_>>();
                headers.sort();
                requests
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(OriginalRequestEvidence {
                        method: parts.method,
                        uri: parts.uri.to_string(),
                        headers,
                        body: body.to_vec(),
                    });
                Response::builder()
                    .status(StatusCode::IM_A_TEAPOT)
                    .header("content-type", "application/json")
                    .header("x-bowline-supply", "origin")
                    .header("x-parity-response", "same")
                    .body(Body::from(
                        r#"{"model":"baseline-model","usage":{"input_tokens":1,"output_tokens":1},"output":[]}"#,
                    ))
                    .unwrap()
            }
        }
    }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let upstream: &'static str = Box::leak(format!("http://{address}").into_boxed_str());
    let legacy = legacy_shadow_parity_evidence(upstream).await;
    let cases = [
        MatrixCase {
            mode: RouteMode::Observe,
            expected_status: 418,
            expected_original: 0,
            expected_candidate: 0,
            expected_target: PlanTarget::Original,
            expected_evidence: EvidenceState::NotRequired,
            original_status: 418,
            original_attribution: Some("origin"),
            original_upstream_override: Some(upstream),
            ..base_case("parity-observe")
        },
        MatrixCase {
            expected_status: 418,
            original_status: 418,
            original_attribution: Some("origin"),
            original_upstream_override: Some(upstream),
            expected_original: 0,
            ..recommend_case(
                "parity-recommend",
                EvidenceSetup::Verified,
                EvidenceState::Presented,
            )
        },
        MatrixCase {
            expected_status: 418,
            original_status: 418,
            original_attribution: Some("origin"),
            original_upstream_override: Some(upstream),
            expected_original: 0,
            ..fallback_case("parity-bypass", SelectionVariant::KillBypass)
        },
    ];
    for case in cases {
        let name = case.name;
        let (legacy_request, request_count) = {
            let requests = requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (requests[0].body.clone(), requests.len())
        };
        let controlled = run_case(case).await.expect("parity capture");
        let observed = requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            observed.len(),
            request_count + 1,
            "{name} one original request"
        );
        assert_eq!(
            observed.last().unwrap(),
            &observed[0],
            "{name} request parity"
        );
        assert_eq!(
            legacy_request,
            RESPONSES_BODY.as_bytes(),
            "{name} request body"
        );
        assert_eq!(
            controlled.response_body, legacy.response_body,
            "{name} bytes"
        );
        assert_eq!(
            controlled.response_headers, legacy.response_headers,
            "{name} forwarded response headers"
        );
        assert_eq!(
            stable_shadow_projection(&controlled.record),
            stable_shadow_projection(&legacy.record),
            "{name} complete stable shadow evidence"
        );
        assert_eq!(
            controlled.record.actual.status, legacy.record.actual.status,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.model, legacy.record.actual.model,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.input_tokens, legacy.record.actual.input_tokens,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.output_tokens, legacy.record.actual.output_tokens,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.usage_source, legacy.record.actual.usage_source,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.attribution_status, legacy.record.actual.attribution_status,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.attribution_source, legacy.record.actual.attribution_source,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.attribution_reference,
            legacy.record.actual.attribution_reference,
            "{name}"
        );
        assert_eq!(
            controlled.record.actual.attribution_reason, legacy.record.actual.attribution_reason,
            "{name}"
        );
        assert_eq!(
            controlled.record.coverage_status, legacy.record.coverage_status,
            "{name}"
        );
        assert_eq!(
            controlled.record.coverage_reason, legacy.record.coverage_reason,
            "{name}"
        );
        assert_eq!(
            controlled.record.accounting_truncated, legacy.record.accounting_truncated,
            "{name}"
        );
    }
    task.abort();
}

fn stopped_original_case(
    name: &'static str,
    circuit: CircuitSetup,
    omit_actuator_target: bool,
) -> MatrixCase {
    MatrixCase {
        circuit,
        omit_actuator_target,
        stop_original: true,
        expected_status: 502,
        expected_original: 0,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_evidence: EvidenceState::Unverified,
        expected_completion: CompletionStateV2::Failed,
        ..base_case(name)
    }
}

fn recommend_kill_case(
    name: &'static str,
    kill: &'static [u8],
    expected_kill: KillReadResult,
) -> MatrixCase {
    MatrixCase {
        kill,
        expected_kill,
        ..recommend_case(name, EvidenceSetup::Verified, EvidenceState::Presented)
    }
}

fn recommend_missing_kill_case() -> MatrixCase {
    MatrixCase {
        name: "recommend-kill-missing",
        expected_kill: KillReadResult::Missing,
        ..recommend_case(
            "recommend-kill-missing",
            EvidenceSetup::Verified,
            EvidenceState::Presented,
        )
    }
}

fn recommend_unsafe_kill_case() -> MatrixCase {
    MatrixCase {
        name: "recommend-kill-unsafe",
        expected_kill: KillReadResult::Unsafe,
        ..recommend_case(
            "recommend-kill-unsafe",
            EvidenceSetup::Verified,
            EvidenceState::Presented,
        )
    }
}

fn recommend_queue_kill_case() -> MatrixCase {
    MatrixCase {
        name: "recommend-kill-queue-unavailable",
        kill_queue_failure: true,
        expected_kill: KillReadResult::QueueUnavailable,
        ..recommend_case(
            "recommend-kill-queue-unavailable",
            EvidenceSetup::Verified,
            EvidenceState::Presented,
        )
    }
}

fn sse_case(
    name: &'static str,
    protocol: AuthorityProtocol,
    candidate: CandidateBehavior,
    expected_completion: CompletionStateV2,
) -> MatrixCase {
    MatrixCase {
        protocol,
        body: if protocol == AuthorityProtocol::ChatCompletions {
            r#"{"model":"baseline-model","messages":[],"stream":true}"#
        } else {
            r#"{"model":"baseline-model","input":"hello","stream":true}"#
        },
        candidate,
        expected_completion,
        ..base_case(name)
    }
}

fn candidate_case(name: &'static str, protocol: AuthorityProtocol) -> MatrixCase {
    MatrixCase {
        protocol,
        body: if protocol == AuthorityProtocol::ChatCompletions {
            CHAT_BODY
        } else {
            RESPONSES_BODY
        },
        mode: if name == "canary-bucket-in" {
            RouteMode::CanaryEnforce
        } else {
            RouteMode::Enforce
        },
        rollout_ppm: if name == "canary-bucket-in" {
            1_000_000
        } else {
            0
        },
        ..base_case(name)
    }
}

fn recommend_case(
    name: &'static str,
    evidence: EvidenceSetup,
    expected_evidence: EvidenceState,
) -> MatrixCase {
    MatrixCase {
        mode: RouteMode::Recommend,
        rollout_ppm: 0,
        evidence,
        expected_original: 1,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_evidence,
        ..base_case(name)
    }
}

fn fallback_case(name: &'static str, variant: SelectionVariant) -> MatrixCase {
    let mut case = MatrixCase {
        expected_original: 1,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_evidence: EvidenceState::Unverified,
        ..base_case(name)
    };
    match variant {
        SelectionVariant::CanaryOut => {
            case.mode = RouteMode::CanaryEnforce;
            case.rollout_ppm = 0;
        }
        SelectionVariant::SelectorMiss => case.app = "other",
        SelectionVariant::StaleGrant => case.evidence = EvidenceSetup::Stale,
        SelectionVariant::PinnedPreserve => {
            case.model_authority = bowline_core::enforcement::ModelAuthority::Preserve;
        }
        SelectionVariant::RewriteFailure => case.body = r#"{"input":"missing-model"}"#,
        SelectionVariant::KillBypass => {
            case.kill = b"bypass\n";
            case.expected_kill = KillReadResult::Bypass;
        }
        SelectionVariant::ConfiguredBypass => {
            case.mode = RouteMode::Recommend;
            case.expected_evidence = EvidenceState::Presented;
        }
        SelectionVariant::Saturated => case.circuit = CircuitSetup::Saturated,
        SelectionVariant::CircuitOpen => case.circuit = CircuitSetup::Open,
        SelectionVariant::CircuitHalfOpen => case.circuit = CircuitSetup::HalfOpen,
    }
    case
}

fn fail_closed_case(name: &'static str, kill: &'static [u8]) -> MatrixCase {
    MatrixCase {
        fallback: FallbackMode::FailClosed,
        kill,
        expected_status: 503,
        expected_original: 0,
        expected_candidate: 0,
        expected_target: PlanTarget::None,
        expected_evidence: EvidenceState::Unverified,
        expected_completion: CompletionStateV2::Local,
        expected_kill: if kill == b"bypass\n" {
            KillReadResult::Bypass
        } else {
            KillReadResult::Malformed
        },
        ..base_case(name)
    }
}

fn queue_failure_case() -> MatrixCase {
    MatrixCase {
        name: "kill-reader-queue-failure",
        kill_queue_failure: true,
        fallback: FallbackMode::FailClosed,
        expected_status: 503,
        expected_original: 0,
        expected_candidate: 0,
        expected_target: PlanTarget::None,
        expected_evidence: EvidenceState::Unverified,
        expected_completion: CompletionStateV2::Local,
        expected_kill: KillReadResult::QueueUnavailable,
        ..base_case("kill-reader-queue-failure")
    }
}

fn failure_case(
    name: &'static str,
    behavior: CandidateBehavior,
    expected_status: u16,
) -> MatrixCase {
    let mut case = MatrixCase {
        candidate: behavior,
        expected_status,
        expected_completion: CompletionStateV2::Failed,
        ..base_case(name)
    };
    if behavior == CandidateBehavior::Connect {
        case.expected_candidate = 0;
    }
    if matches!(behavior, CandidateBehavior::Status(401 | 403 | 500..=599)) {
        case.drop_downstream = true;
    }
    case
}

fn stream_failure_case(name: &'static str, behavior: CandidateBehavior) -> MatrixCase {
    MatrixCase {
        candidate: behavior,
        expected_status: if behavior == CandidateBehavior::StreamError {
            502
        } else {
            200
        },
        expected_completion: CompletionStateV2::Failed,
        ..base_case(name)
    }
}

fn terminal_failure_case() -> MatrixCase {
    MatrixCase {
        name: "terminal-writer-failure",
        terminal_writer_failure: true,
        ..base_case("terminal-writer-failure")
    }
}

fn startup_case(
    name: &'static str,
    probe: ProbeBehavior,
    expected_probe: usize,
    expected_redirect_target: usize,
    healthy: bool,
) -> MatrixCase {
    MatrixCase {
        probe,
        circuit: CircuitSetup::Open,
        expected_probe,
        expected_redirect_target,
        expected_original: usize::from(!healthy),
        expected_candidate: usize::from(healthy),
        expected_target: if healthy {
            PlanTarget::Candidate
        } else {
            PlanTarget::Original
        },
        expected_evidence: if healthy {
            EvidenceState::Presented
        } else {
            EvidenceState::Unverified
        },
        ..base_case(name)
    }
}

async fn run_case(case: MatrixCase) -> Option<ShadowParityEvidence> {
    let root = tempfile::tempdir().unwrap();
    let redirect_target_count = Arc::new(AtomicUsize::new(0));
    let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_address = redirect_listener.local_addr().unwrap();
    let redirect_app = Router::new().fallback(any({
        let count = Arc::clone(&redirect_target_count);
        move || {
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::AcqRel);
                r#"{"data":[{"id":"candidate-model"}]}"#
            }
        }
    }));
    let redirect_task =
        tokio::spawn(async move { axum::serve(redirect_listener, redirect_app).await.unwrap() });

    let candidate_count = Arc::new(AtomicUsize::new(0));
    let probe_count = Arc::new(AtomicUsize::new(0));
    let candidate_base = if case.candidate == CandidateBehavior::Connect {
        "http://127.0.0.1:1".to_owned()
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = candidate_router(
            case,
            Arc::clone(&candidate_count),
            Arc::clone(&probe_count),
            redirect_address,
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    };

    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_bodies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_app = Router::new().fallback(any({
        let count = Arc::clone(&upstream_count);
        let bodies = Arc::clone(&upstream_bodies);
        move |request: Request<Body>| {
            let count = Arc::clone(&count);
            let bodies = Arc::clone(&bodies);
            async move {
                count.fetch_add(1, Ordering::AcqRel);
                let body = axum::body::to_bytes(request.into_body(), MAX_REQUEST_BODY_BYTES)
                    .await
                    .unwrap();
                bodies
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(body.to_vec());
                let mut response = Response::builder().status(case.original_status);
                if let Some(value) = case.original_attribution {
                    response = response.header("x-bowline-supply", value);
                }
                response
                    .body(Body::from(
                        r#"{"model":"baseline-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                    ))
                    .unwrap()
            }
        }
    }));
    let upstream_task = if case.stop_original {
        drop(upstream_listener);
        None
    } else {
        Some(tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app).await.unwrap()
        }))
    };

    let kill_root = root.path().join("kill");
    fs::create_dir(&kill_root).unwrap();
    fs::set_permissions(&kill_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(kill_root.join("state"), case.kill).unwrap();
    fs::set_permissions(kill_root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();

    let evidence_now = now_ms();
    let expires_at_ms = if case.evidence == EvidenceSetup::Stale {
        evidence_now + 80
    } else {
        evidence_now + 60_000
    };
    let source = enforcement_source(case, &kill_root, &candidate_base, expires_at_ms);
    let raw = EnforcementConfigV1::from_yaml(&source)
        .unwrap_or_else(|error| panic!("{} config parse failed: {error}", case.name));
    let validated = raw
        .validate()
        .unwrap_or_else(|error| panic!("{} config validation failed: {error}", case.name));
    let validation = validated
        .route("route")
        .unwrap()
        .promotion
        .as_ref()
        .map(|_| promotion_validation(&validated, case.protocol, evidence_now, expires_at_ms));
    let grant =
        (case.mode.grants_authority() && case.evidence != EvidenceSetup::Missing).then(|| {
            crate::enforcement_loader::test_verified_promotion_grant_for_task(
                validation.clone().unwrap(),
                case.grant_task,
            )
        });
    let recommendation = (case.mode == RouteMode::Recommend
        && case.protocol != AuthorityProtocol::Embeddings
        && case.evidence != EvidenceSetup::Missing)
        .then(|| {
            crate::enforcement_loader::test_verified_recommendation_evidence(
                validation.clone().unwrap(),
            )
        });

    let authority_dir = root.path().join("authority");
    fs::create_dir(&authority_dir).unwrap();
    fs::set_permissions(&authority_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let options = AuthorityWriterOptions {
        directory: authority_dir,
        enforcement_digest: validated.normalized_digest().to_owned(),
        actuator_digests: vec![validated.actuator_digest("candidate").unwrap()],
        grant_digests: grant
            .iter()
            .map(|grant| grant.grant_digest().to_owned())
            .collect(),
        queue_capacity: 8,
        max_records_bytes: 1024 * 1024,
    };
    let writer = if case.terminal_writer_failure {
        crate::writer::spawn_transient_faulting_authority_writer(options, 2).unwrap()
    } else {
        spawn_managed_authority_writer(options).unwrap()
    };
    if let Some(final_kill) = case.final_kill {
        let path = kill_root.join("state");
        writer.install_post_candidate_flush_hook(move || {
            std::fs::write(path, final_kill).unwrap();
        });
    }
    if case.post_rejection_closing {
        writer.install_post_rejection_closing_hook();
    }
    let actuators = ActuatorRegistry::new(1, raw.actuators).unwrap();
    let raw_kill_reader =
        KillStateReader::open(&kill_root.canonicalize().unwrap(), "state").unwrap();
    if case.name == "recommend-kill-missing" {
        fs::remove_file(kill_root.join("state")).unwrap();
    } else if case.name == "recommend-kill-unsafe" {
        fs::set_permissions(kill_root.join("state"), fs::Permissions::from_mode(0o644)).unwrap();
    }
    let kill_reader = BoundedKillStateReader::new(raw_kill_reader, 8);
    let target = ActuatorTarget {
        client: build_redirect_free_client(Duration::from_millis(20)).unwrap(),
        base_url: candidate_base,
        authorization: reqwest::header::HeaderValue::from_static("Bearer candidate-secret"),
        canonical_model: "candidate-model".into(),
        response_header_timeout: Duration::from_millis(20),
        stream_idle_timeout: Duration::from_millis(20),
    };
    let runtime = Arc::new(EnforcementRuntime {
        route_ids: vec!["route".into()],
        validated,
        grants: grant
            .into_iter()
            .map(|grant| ("route".into(), grant))
            .collect(),
        recommendations: recommendation
            .into_iter()
            .map(|evidence| ("route".into(), evidence))
            .collect(),
        kill_reader,
        actuators,
        targets: if case.omit_actuator_target {
            BTreeMap::new()
        } else {
            BTreeMap::from([("candidate".into(), target)])
        },
        writer: writer.clone(),
        terminal_tracker: Arc::new(AuthorityTerminalTracker::default()),
        last_kill_state: Mutex::new(KillReadResult::Unreadable),
    });

    let mut held_permit = None;
    match case.probe {
        ProbeBehavior::Success | ProbeBehavior::Failure | ProbeBehavior::Redirect => {
            run_startup_authority_probes(&runtime).await;
        }
        ProbeBehavior::Skip => match case.circuit {
            CircuitSetup::Closed => {
                runtime
                    .actuators
                    .finish_probe("candidate", true, Instant::now());
            }
            CircuitSetup::Open => {}
            CircuitSetup::HalfOpen => {
                assert!(runtime
                    .actuators
                    .try_begin_probe("candidate", Instant::now() + Duration::from_millis(100),)
                    .unwrap());
            }
            CircuitSetup::Saturated => {
                runtime
                    .actuators
                    .finish_probe("candidate", true, Instant::now());
                held_permit = Some(
                    runtime
                        .actuators
                        .try_acquire("candidate", Duration::from_millis(5))
                        .await
                        .unwrap(),
                );
            }
        },
    }
    if case.kill_queue_failure {
        runtime.kill_reader.shutdown();
    }
    if case.evidence == EvidenceSetup::Stale {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let permit_acquisitions_before = runtime.actuators.candidate_acquisition_count();

    let policy = PolicyBundle::from_yaml(&format!(
        r#"
version: 1
identities:
  - match: {{ app: {} }}
    tags: [production]
rules:
  - name: default
    default: true
    task_class: {}
    require: {{ supply_class: [public-api, owned] }}
"#,
        case.selector_app,
        task_yaml(case.policy_task),
    ))
    .unwrap();
    let registry = test_registry();
    let owned = load_owned_cost_catalog(None, Some("baseline"), &registry).unwrap();
    let (legacy_writer, _) = crate::writer::spawn_writer(root.path().join("shadow")).unwrap();
    let mut deps = GatewayDeps::recording(
        policy,
        registry,
        QualityFloors::default(),
        owned,
        legacy_writer,
    );
    deps.enforcement = Some(Arc::clone(&runtime));
    let upstream_base = case
        .original_upstream_override
        .map(str::to_owned)
        .unwrap_or_else(|| format!("http://{upstream_address}"));
    let state = if case.original_attribution.is_some() {
        GatewayState::from_config(&parity_config(&upstream_base, root.path()), deps).unwrap()
    } else {
        GatewayState::new(upstream_base, deps)
    };
    let path = match case.protocol {
        AuthorityProtocol::ChatCompletions => "/v1/chat/completions",
        AuthorityProtocol::Responses => "/v1/responses",
        AuthorityProtocol::Embeddings => "/v1/embeddings",
    };
    let uri: Uri = path.parse().unwrap();
    let mut headers = HeaderMap::new();
    match case.identity_headers {
        IdentityHeaderSetup::Canonical => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            if let Some(task) = case.declared_task {
                headers.insert("x-bowline-task-class", task.parse().unwrap());
            }
        }
        IdentityHeaderSetup::DuplicateApp => {
            headers.append("x-bowline-app", case.app.parse().unwrap());
            headers.append("x-bowline-app", "other".parse().unwrap());
        }
        IdentityHeaderSetup::AmbiguousApp => {
            headers.insert("x-bowline-app", "support,other".parse().unwrap());
        }
        IdentityHeaderSetup::MalformedApp => {
            headers.insert(
                "x-bowline-app",
                axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
            );
        }
        IdentityHeaderSetup::ReservedApp => {
            headers.insert("x-bowline-app", "untrusted".parse().unwrap());
        }
        IdentityHeaderSetup::OverlongApp => {
            headers.insert("x-bowline-app", OVERLONG_APP_HEADER.parse().unwrap());
        }
        IdentityHeaderSetup::DuplicateTask => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            headers.append("x-bowline-task-class", "heavy-lifting".parse().unwrap());
            headers.append("x-bowline-task-class", "judgment".parse().unwrap());
        }
        IdentityHeaderSetup::AmbiguousTask => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            headers.insert(
                "x-bowline-task-class",
                "heavy-lifting,judgment".parse().unwrap(),
            );
        }
        IdentityHeaderSetup::MalformedTask => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            headers.insert(
                "x-bowline-task-class",
                axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
            );
        }
        IdentityHeaderSetup::ReservedTask => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            headers.insert("x-bowline-task-class", "untrusted".parse().unwrap());
        }
        IdentityHeaderSetup::OverlongTask => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            headers.insert(
                "x-bowline-task-class",
                OVERLONG_TASK_HEADER.parse().unwrap(),
            );
        }
        IdentityHeaderSetup::UnsupportedTask => {
            headers.insert("x-bowline-app", case.app.parse().unwrap());
            headers.insert("x-bowline-task-class", "not-a-class".parse().unwrap());
        }
    }
    if case.original_upstream_override.is_some() {
        headers.insert("x-parity-request", "same".parse().unwrap());
    }
    let mut request = Request::builder().method("POST").uri(path);
    for (name, value) in &headers {
        request = request.header(name, value);
    }
    let response = proxy_handler(
        State(state),
        ConnectInfo("127.0.0.1:40000".parse().unwrap()),
        Method::POST,
        OriginalUri(uri),
        headers.clone(),
        request.body(Body::from(case.body)).unwrap(),
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        case.expected_status,
        "{}",
        case.name
    );
    let response_headers = parity_response_headers(response.headers());
    let response_body = if case.drop_downstream {
        drop(response);
        None
    } else {
        axum::body::to_bytes(response.into_body(), MAX_REQUEST_BODY_BYTES)
            .await
            .ok()
    };
    if case.expect_evidence_unavailable {
        assert_eq!(
            response_body.as_deref(),
            Some(br#"{"error":{"code":"evidence-unavailable"}}"#.as_slice()),
            "{} stable fatal response",
            case.name
        );
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let expected_records = if case.post_rejection_closing {
        2
    } else if case.final_kill.is_some() {
        4
    } else {
        2
    };
    while writer.manifest_snapshot().accepted < expected_records {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} terminal timeout",
            case.name
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    runtime.terminal_tracker.wait_idle().await;
    assert_eq!(
        runtime.actuators.candidate_acquisition_count() - permit_acquisitions_before,
        usize::from(case.final_kill.is_some() || case.expected_target == PlanTarget::Candidate),
        "{} candidate permit acquisitions",
        case.name
    );
    drop(held_permit);
    assert_eq!(
        upstream_count.load(Ordering::Acquire),
        case.expected_original,
        "{} original",
        case.name
    );
    assert_eq!(
        candidate_count.load(Ordering::Acquire),
        case.expected_candidate,
        "{} candidate",
        case.name
    );
    assert_eq!(
        probe_count.load(Ordering::Acquire),
        case.expected_probe,
        "{} probe",
        case.name
    );
    assert_eq!(
        redirect_target_count.load(Ordering::Acquire),
        case.expected_redirect_target,
        "{} redirect target",
        case.name
    );
    assert!(
        upstream_count.load(Ordering::Acquire) <= 1,
        "{} original duplicate",
        case.name
    );
    if case.protocol == AuthorityProtocol::Embeddings {
        assert_eq!(
            upstream_bodies
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[case.body.as_bytes().to_vec()],
            "{} original request bytes",
            case.name
        );
    }
    assert!(
        candidate_count.load(Ordering::Acquire) <= 1,
        "{} candidate duplicate",
        case.name
    );
    assert!(
        upstream_count.load(Ordering::Acquire) + candidate_count.load(Ordering::Acquire) <= 1,
        "{} retried",
        case.name
    );

    runtime.kill_reader.shutdown();
    let shutdown = writer.shutdown(Duration::from_secs(2)).await;
    let manifest = writer.manifest_snapshot();
    if case.terminal_writer_failure || case.post_rejection_closing {
        let _ = shutdown;
        assert!(!manifest.clean_shutdown, "{} must be incomplete", case.name);
        if case.terminal_writer_failure {
            assert_eq!(manifest.dropped, 1, "{} dropped terminal", case.name);
        }
    } else {
        shutdown.unwrap();
        let run = AuthorityLedgerV2::read_validated_authority_run(writer.manifest_path())
            .unwrap_or_else(|error| panic!("{} authority read: {error}", case.name));
        assert_eq!(
            run.records().len(),
            expected_records as usize,
            "{} pair",
            case.name
        );
        if case.final_kill.is_some() {
            let AuthorityRecordV2::Decision {
                decision: candidate,
                ..
            } = &run.records()[0]
            else {
                panic!("{} first record is not candidate decision", case.name)
            };
            let AuthorityRecordV2::Outcome {
                outcome: rejected, ..
            } = &run.records()[1]
            else {
                panic!("{} second record is not candidate rejection", case.name)
            };
            let AuthorityRecordV2::Decision {
                decision: replacement,
                ..
            } = &run.records()[2]
            else {
                panic!("{} third record is not replacement decision", case.name)
            };
            let AuthorityRecordV2::Outcome {
                outcome: replacement_outcome,
                ..
            } = &run.records()[3]
            else {
                panic!("{} fourth record is not replacement outcome", case.name)
            };
            assert_eq!(candidate.target, PlanTarget::Candidate);
            assert_eq!(rejected.completion, CompletionStateV2::PreDispatchRejected);
            assert_eq!(rejected.actual_dispatch, 0);
            assert_eq!(replacement.target, case.expected_target);
            assert_eq!(
                replacement.replaces_decision_id.as_deref(),
                Some(candidate.decision_id.as_str())
            );
            assert_eq!(
                replacement_outcome.replaces_decision_id,
                replacement.replaces_decision_id
            );
            assert_eq!(replacement_outcome.completion, case.expected_completion);
            runtime.kill_reader.shutdown();
            if let Some(task) = upstream_task {
                task.abort();
            }
            redirect_task.abort();
            return None;
        }
        let AuthorityRecordV2::Decision { decision, .. } = &run.records()[0] else {
            panic!("{} first record is not decision", case.name)
        };
        let AuthorityRecordV2::Outcome { outcome, .. } = &run.records()[1] else {
            panic!("{} second record is not outcome", case.name)
        };
        assert_eq!(
            decision.target, case.expected_target,
            "{} target",
            case.name
        );
        assert_eq!(
            decision.evidence_state, case.expected_evidence,
            "{} evidence",
            case.name
        );
        if let Some(expected_reason) = case.expected_reason {
            assert_eq!(decision.reason, expected_reason, "{} reason", case.name);
        }
        assert_eq!(
            outcome.completion, case.expected_completion,
            "{} completion",
            case.name
        );
        assert_eq!(
            decision.selection_facts.kill_state, case.expected_kill,
            "{} decision kill fact",
            case.name
        );
        assert_eq!(
            outcome.selection_facts.kill_state, case.expected_kill,
            "{} outcome kill fact",
            case.name
        );
        assert_eq!(
            decision.task_class, case.expected_task,
            "{} decision task",
            case.name
        );
        assert_eq!(
            outcome.task_class, case.expected_task,
            "{} outcome task",
            case.name
        );
        if case.expect_unresolved_app {
            assert_eq!(decision.app, None, "{} decision app", case.name);
            assert_eq!(outcome.app, None, "{} outcome app", case.name);
            assert_eq!(
                decision.workload_identity_digest, None,
                "{} decision workload identity",
                case.name
            );
            assert_eq!(
                outcome.workload_identity_digest, None,
                "{} outcome workload identity",
                case.name
            );
        }
        if case.protocol == AuthorityProtocol::Embeddings {
            assert_eq!(decision.protocol, AuthorityProtocol::Embeddings);
            assert_eq!(outcome.protocol, AuthorityProtocol::Embeddings);
            assert!(!decision.grants_candidate_authority());
            assert_eq!(decision.target, PlanTarget::Original);
            assert_eq!(outcome.target, PlanTarget::Original);
            assert_eq!(decision.intended_dispatch, 1);
            assert_eq!(outcome.actual_dispatch, 1);
            assert!(decision.grant.is_none());
            assert!(decision.actuator_identity_digest.is_none());
            assert!(decision.actuator_config_digest.is_none());
            assert!(outcome.grant_digest.is_none());
            assert!(outcome.actuator_identity_digest.is_none());
            assert!(outcome.actuator_config_digest.is_none());
        }
        match case.candidate {
            CandidateBehavior::PartialInputUsage => {
                assert_eq!(outcome.input_tokens, Some(3));
                assert_eq!(outcome.output_tokens, None);
                assert_eq!(
                    outcome.usage_source,
                    bowline_core::ledger::UsageSource::Observed
                );
                assert_eq!(outcome.observed_actual_cost_micros, None);
                assert_eq!(outcome.approved_counterfactual_cost_micros, None);
                assert_eq!(outcome.enforced_modeled_delta_micros, None);
            }
            CandidateBehavior::PartialOutputUsage => {
                assert_eq!(outcome.input_tokens, None);
                assert_eq!(outcome.output_tokens, Some(4));
                assert_eq!(
                    outcome.usage_source,
                    bowline_core::ledger::UsageSource::Observed
                );
                assert_eq!(outcome.observed_actual_cost_micros, None);
                assert_eq!(outcome.approved_counterfactual_cost_micros, None);
                assert_eq!(outcome.enforced_modeled_delta_micros, None);
            }
            _ => {}
        }
        if case.name == "configured-bypass" {
            assert_eq!(decision.reason, SelectionReason::RecommendationOnly);
        }
        if case.name == "circuit-open" {
            assert_eq!(decision.reason, SelectionReason::CircuitOpen);
        }
    }

    let parity = if case.original_attribution.is_some() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let record = loop {
            let (records, _) = Ledger::read_all(&root.path().join("shadow")).unwrap();
            if let Some(record) = records.into_iter().next() {
                break record;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "shadow flush timeout"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        Some(ShadowParityEvidence {
            record,
            response_headers,
            response_body: response_body.unwrap_or_default().to_vec(),
        })
    } else {
        None
    };
    if let Some(task) = upstream_task {
        task.abort();
    }
    redirect_task.abort();
    parity
}

#[tokio::test]
async fn final_reread_fallback_uses_route_configured_target_without_candidate_dispatch() {
    run_case(MatrixCase {
        name: "final-reread-fallback-bypass",
        final_kill: Some(b"bypass\n"),
        expected_status: 200,
        expected_original: 1,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_completion: CompletionStateV2::Succeeded,
        ..base_case("final-reread-fallback-bypass")
    })
    .await;
    run_case(MatrixCase {
        name: "final-reread-fallback-fail-closed",
        fallback: FallbackMode::FailClosed,
        final_kill: Some(b"malformed\n"),
        expected_status: 503,
        expected_original: 0,
        expected_candidate: 0,
        expected_target: PlanTarget::None,
        expected_completion: CompletionStateV2::Local,
        ..base_case("final-reread-fallback-fail-closed")
    })
    .await;
}

#[tokio::test]
async fn final_transition_fatal_is_stable_and_dispatches_neither_target_for_both_fallbacks() {
    for (name, fallback) in [
        ("final-transition-fatal-bypass", FallbackMode::Bypass),
        (
            "final-transition-fatal-fail-closed",
            FallbackMode::FailClosed,
        ),
    ] {
        run_case(MatrixCase {
            name,
            fallback,
            final_kill: Some(b"bypass\n"),
            post_rejection_closing: true,
            expect_evidence_unavailable: true,
            expected_status: 503,
            expected_original: 0,
            expected_candidate: 0,
            expected_target: PlanTarget::Candidate,
            expected_completion: CompletionStateV2::PreDispatchRejected,
            ..base_case(name)
        })
        .await;
    }
}

fn candidate_router(
    case: MatrixCase,
    candidate_count: Arc<AtomicUsize>,
    probe_count: Arc<AtomicUsize>,
    redirect_address: SocketAddr,
) -> Router {
    let probe = get(move || {
        let probe_count = Arc::clone(&probe_count);
        async move {
            probe_count.fetch_add(1, Ordering::AcqRel);
            match case.probe {
                ProbeBehavior::Failure => Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("{}"))
                    .unwrap(),
                ProbeBehavior::Redirect => Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", format!("http://{redirect_address}/v1/models"))
                    .body(Body::empty())
                    .unwrap(),
                _ => Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(r#"{"data":[{"id":"candidate-model"}]}"#))
                    .unwrap(),
            }
        }
    });
    Router::new()
        .route("/v1/models", probe)
        .fallback(any(move || {
            let count = Arc::clone(&candidate_count);
            async move {
                count.fetch_add(1, Ordering::AcqRel);
                match case.candidate {
                    CandidateBehavior::Success | CandidateBehavior::Connect => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(candidate_success_body(case.protocol)))
                        .unwrap(),
                    CandidateBehavior::PartialInputUsage => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(
                            r#"{"model":"candidate-model","usage":{"input_tokens":3},"output":[]}"#,
                        ))
                        .unwrap(),
                    CandidateBehavior::PartialOutputUsage => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(
                            r#"{"model":"candidate-model","usage":{"output_tokens":4},"output":[]}"#,
                        ))
                        .unwrap(),
                    CandidateBehavior::PrematureSse => Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .body(Body::from("data: {\"partial\":true}\n\n"))
                        .unwrap(),
                    CandidateBehavior::ValidSse => Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .body(Body::from(match case.protocol {
                            AuthorityProtocol::ChatCompletions => "data: [DONE]\n\n",
                            AuthorityProtocol::Responses => "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
                            AuthorityProtocol::Embeddings => unreachable!(),
                        }))
                        .unwrap(),
                    CandidateBehavior::Status(status) => Response::builder()
                        .status(StatusCode::from_u16(status).unwrap())
                        .body(Body::from("{}"))
                        .unwrap(),
                    CandidateBehavior::HeaderTimeout => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Response::builder()
                            .status(200)
                            .body(Body::from("{}"))
                            .unwrap()
                    }
                    CandidateBehavior::IdleTimeout => {
                        let stream = stream::once(async {
                            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"{"))
                        })
                        .chain(stream::pending());
                        Response::builder()
                            .status(200)
                            .body(Body::from_stream(stream))
                            .unwrap()
                    }
                    CandidateBehavior::StreamError => {
                        let stream = stream::iter([Err::<Bytes, std::io::Error>(
                            std::io::Error::other("synthetic stream failure"),
                        )]);
                        Response::builder()
                            .status(200)
                            .body(Body::from_stream(stream))
                            .unwrap()
                    }
                }
            }
        }))
}

fn candidate_success_body(protocol: AuthorityProtocol) -> &'static str {
    match protocol {
        AuthorityProtocol::ChatCompletions => {
            r#"{"model":"candidate-model","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":4}}"#
        }
        AuthorityProtocol::Responses => {
            r#"{"model":"candidate-model","usage":{"input_tokens":3,"output_tokens":4},"output":[]}"#
        }
        AuthorityProtocol::Embeddings => {
            r#"{"data":[{"embedding":[0.1]}],"model":"baseline-model","usage":{"prompt_tokens":1,"total_tokens":1}}"#
        }
    }
}

fn enforcement_source(
    case: MatrixCase,
    kill_root: &std::path::Path,
    candidate_base: &str,
    expires_at_ms: u64,
) -> String {
    let active = matrix_active_runtime_provenance();
    let (path, protocol) = match case.protocol {
        AuthorityProtocol::ChatCompletions => ("/v1/chat/completions", "chat-completions"),
        AuthorityProtocol::Responses => ("/v1/responses", "responses"),
        AuthorityProtocol::Embeddings => ("/v1/embeddings", "embeddings"),
    };
    let mode = match case.mode {
        RouteMode::Observe => "observe",
        RouteMode::Recommend => "recommend",
        RouteMode::CanaryEnforce => "canary-enforce",
        RouteMode::Enforce => "enforce",
    };
    let authority = if case.protocol == AuthorityProtocol::Embeddings {
        String::new()
    } else if case.mode.grants_authority() {
        format!(
            "    promoted_supply_id: candidate\n    actual_supply_id: baseline\n    task_class: {}\n    model_authority: {}\n    fallback: {}\n",
            task_yaml(case.route_task),
            match case.model_authority {
                bowline_core::enforcement::ModelAuthority::Preserve => "preserve",
                bowline_core::enforcement::ModelAuthority::RewriteToCanonical => "rewrite-to-canonical",
            },
            match case.fallback {
                FallbackMode::Bypass => "bypass",
                FallbackMode::FailClosed => "fail-closed",
            }
        )
    } else if case.mode == RouteMode::Recommend {
        format!(
            "    promoted_supply_id: candidate\n    actual_supply_id: baseline\n    task_class: {}\n    fallback: bypass\n",
            task_yaml(case.route_task)
        )
    } else {
        String::new()
    };
    let workload = if case.protocol == AuthorityProtocol::Embeddings {
        String::new()
    } else {
        format!(
            "    workload: {{app: {}, resolved_tags: [production]}}\n",
            case.selector_app
        )
    };
    let promotion =
        if case.protocol == AuthorityProtocol::Embeddings || case.mode == RouteMode::Observe {
            String::new()
        } else {
            format!(
                r#"    promotion:
      economics_bundle_path: economics
      economics_report_digest: sha256:{a}
      opportunity_digest: sha256:{b}
      quality_run_path: quality
      authorization_path: authorization/route.json
      quality_run_id: quality-1
      quality_report_digest: sha256:{c}
      policy_digest: {d}
      registry_digest: {e}
      owned_cost_digest: {f}
      max_economics_age_ms: 100000
      expires_at_ms: {expires_at_ms}
"#,
                a = "a".repeat(64),
                b = "b".repeat(64),
                c = "c".repeat(64),
                d = active.policy_digest(),
                e = active.registry_digest(),
                f = active.owned_cost_digest()
            )
        };
    format!(
        r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {{trust_root: {kill_root}, relative_path: state}}
actuators:
  - supply_id: candidate
    base_url: {candidate_base}
    authorization_env: TEST_CANDIDATE_TOKEN
    health_path: /v1/models
    connect_timeout_ms: 20
    response_header_timeout_ms: 20
    stream_idle_timeout_ms: 20
    concurrency: 1
    probe_timeout_ms: 50
    probe_max_bytes: 1024
    breaker_consecutive_failures: 1
    breaker_cooldown_ms: 100
routes:
  - route_id: route
    method: POST
    path: {path}
    protocol: {protocol}
{workload}
    mode: {mode}
    rollout_ppm: {rollout}
{authority}{promotion}
"#,
        kill_root = kill_root.display(),
        candidate_base = candidate_base,
        path = path,
        protocol = protocol,
        mode = mode,
        rollout = case.rollout_ppm,
        workload = workload,
        authority = authority,
        promotion = promotion,
    )
}

#[tokio::test]
async fn literal_untrusted_app_is_unresolved_through_production_handler() {
    run_case(MatrixCase {
        name: "literal-untrusted-reserved",
        app: "untrusted",
        selector_app: "untrusted",
        expect_unresolved_app: true,
        expected_original: 1,
        expected_candidate: 0,
        expected_target: PlanTarget::Original,
        expected_evidence: EvidenceState::Unverified,
        ..base_case("literal-untrusted-reserved")
    })
    .await;
}

#[test]
fn embeddings_candidate_is_closed_at_final_dispatch_boundary() {
    assert!(!candidate_protocol_may_dispatch(
        PlanTarget::Candidate,
        AuthorityProtocol::Embeddings
    ));
    assert!(candidate_protocol_may_dispatch(
        PlanTarget::Candidate,
        AuthorityProtocol::ChatCompletions
    ));
    assert!(candidate_protocol_may_dispatch(
        PlanTarget::Original,
        AuthorityProtocol::Embeddings
    ));
}

fn matrix_active_runtime_provenance() -> bowline_core::enforcement::ActiveRuntimeProvenance {
    let policy = bowline_core::policy::PolicyBundle::from_yaml(
        "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n",
    )
    .unwrap();
    bowline_core::enforcement::ActiveRuntimeProvenance::from_loaded(
        &policy,
        "controlled matrix registry source\n",
        &bowline_core::config::OwnedCostCatalog::default(),
    )
}

fn task_yaml(task: TaskClass) -> &'static str {
    match task {
        TaskClass::Mechanical => "mechanical",
        TaskClass::HeavyLifting => "heavy-lifting",
        TaskClass::TasteSensitive => "taste-sensitive",
        TaskClass::Judgment => "judgment",
        TaskClass::Unclassified => "unclassified",
    }
}

fn task_header(task: TaskClass) -> &'static str {
    task_yaml(task)
}

pub(crate) fn promotion_validation(
    validated: &ValidatedEnforcement,
    protocol: AuthorityProtocol,
    evidence_now: u64,
    expires_at_ms: u64,
) -> bowline_core::enforcement::ValidatedPromotionDocuments {
    let active = matrix_active_runtime_provenance();
    let digest = |ch: char| format!("sha256:{}", ch.to_string().repeat(64));
    let route = validated.route("route").unwrap();
    let workload = route_workload_digest(protocol, route.workload.as_ref().unwrap()).unwrap();
    let artifact_digests = [
        "dimensions.csv",
        "opportunities.csv",
        "reconciliation.csv",
        "report.html",
        "report.json",
        "report.md",
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            if name == "report.json" {
                digest('a')
            } else {
                digest('1')
            },
        )
    })
    .collect();
    let economics = EconomicsPromotionSource {
        schema_version: 1,
        as_of_ms: evidence_now,
        window_end_ms: evidence_now,
        complete: true,
        report_digest: digest('a'),
        bundle_digest: digest('1'),
        artifact_digests,
        selected_traffic_digest: digest('1'),
        selected_billing_digest: Some(digest('1')),
        selected_quality_digests: vec![digest('c')],
        opportunity: PromotionOpportunityEvidence {
            digest: digest('b'),
            workload_identity_digest: workload.clone(),
            task_class: route.task_class.unwrap_or(TaskClass::Unclassified),
            protocol,
            actual_supply_id: "baseline".into(),
            candidate_supply_id: "candidate".into(),
            eligible: true,
            policy_feasible: true,
            capacity_available: true,
            actual_cost_micros: Some(10),
            candidate_cost_micros: Some(5),
            actual_rate_micros: Some(bowline_core::economics::CostRateMicros {
                input_per_mtok_micros: 2_000_000,
                output_per_mtok_micros: 2_000_000,
            }),
            candidate_rate_micros: Some(bowline_core::economics::CostRateMicros {
                input_per_mtok_micros: 1_000_000,
                output_per_mtok_micros: 1_000_000,
            }),
        },
        policy_digest: active.policy_digest().into(),
        registry_digest: active.registry_digest().into(),
        owned_cost_digest: active.owned_cost_digest().into(),
    };
    let quality = QualityPromotionSource {
        schema_version: 2,
        run_id: "quality-1".into(),
        completed_at_ms: evidence_now,
        valid_until_ms: expires_at_ms,
        workload_identity_digest: workload,
        task_class: route.task_class.unwrap_or(TaskClass::Unclassified),
        protocol,
        candidate_supply_id: "candidate".into(),
        effective_verdict: PromotionVerdict::Eligible,
        manifest_digest: digest('1'),
        outcomes_digest: digest('1'),
        report_digest: digest('c'),
        manifest_valid: true,
        outcomes_valid: true,
        report_valid: true,
        policy_digest: active.policy_digest().into(),
        registry_digest: active.registry_digest().into(),
        owned_cost_digest: active.owned_cost_digest().into(),
    };
    let authorization = bowline_core::enforcement::seal_promotion_authorization(
        validated,
        "route",
        &economics,
        &quality,
        &active,
        evidence_now,
    )
    .unwrap();
    if route.mode == RouteMode::Recommend {
        validate_recommendation_documents(
            validated,
            "route",
            &economics,
            &quality,
            &authorization,
            &active,
            evidence_now,
        )
        .unwrap()
    } else {
        validate_promotion_documents(
            validated,
            "route",
            &economics,
            &quality,
            &authorization,
            &active,
            evidence_now,
        )
        .unwrap()
    }
}

pub(crate) fn modeled_delta_verified_grant_fixture(
) -> crate::enforcement_loader::VerifiedPromotionGrant {
    let case = base_case("modeled-delta-fixture");
    let evidence_now = now_ms();
    let source = enforcement_source(
        case,
        std::path::Path::new("/var/lib/bowline/test-kill"),
        "http://127.0.0.1:1",
        evidence_now + 60_000,
    );
    let validated = EnforcementConfigV1::from_yaml(&source)
        .unwrap()
        .validate()
        .unwrap();
    crate::enforcement_loader::test_verified_promotion_grant(promotion_validation(
        &validated,
        AuthorityProtocol::Responses,
        evidence_now,
        evidence_now + 60_000,
    ))
}

fn test_registry() -> Registry {
    Registry::from_json(
        r#"{
  "feed_version":"test",
  "entries":[
    {"id":"baseline","model":"baseline-model","location":"public","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0},"ratings":{"heavy-lifting":0.9}},
    {"id":"candidate","model":"candidate-model","location":"local","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{"heavy-lifting":0.9}}
  ]
}"#,
    )
    .unwrap()
}

fn request_context_policy() -> PolicyBundle {
    PolicyBundle::from_yaml(
        r#"
version: 1
identities:
  - match: { app: support }
    tags: [team:payments, env:prod, env:prod]
rules:
  - name: support
    subject: { app: support }
    task_class: heavy-lifting
  - name: default
    default: true
    task_class: unclassified
"#,
    )
    .unwrap()
}

#[tokio::test]
async fn runtime_task_matrix_binds_trusted_declaration_and_policy_fallback() {
    const TASKS: [TaskClass; 5] = [
        TaskClass::Mechanical,
        TaskClass::HeavyLifting,
        TaskClass::TasteSensitive,
        TaskClass::Judgment,
        TaskClass::Unclassified,
    ];

    let mut rows = 0;
    for runtime_task in TASKS {
        for route_task in TASKS {
            for grant_task in TASKS {
                let candidate = runtime_task == route_task && route_task == grant_task;
                run_case(MatrixCase {
                    name: "runtime-task-matrix",
                    declared_task: (runtime_task != TaskClass::Unclassified)
                        .then(|| task_header(runtime_task)),
                    policy_task: TaskClass::Unclassified,
                    route_task,
                    grant_task,
                    expected_task: runtime_task,
                    expected_original: usize::from(!candidate),
                    expected_candidate: usize::from(candidate),
                    expected_target: if candidate {
                        PlanTarget::Candidate
                    } else {
                        PlanTarget::Original
                    },
                    expected_evidence: if candidate {
                        EvidenceState::Presented
                    } else {
                        EvidenceState::Unverified
                    },
                    ..base_case("runtime-task-matrix")
                })
                .await;
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 125);
}

#[test]
fn unresolved_app_never_synthesizes_an_allowlistable_identity() {
    let policy = request_context_policy();
    let cases = [
        (HeaderMap::new(), true),
        (
            {
                let mut headers = HeaderMap::new();
                headers.insert(
                    "x-bowline-app",
                    axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
                );
                headers
            },
            true,
        ),
        (
            {
                let mut headers = HeaderMap::new();
                headers.insert("x-bowline-app", "support".parse().unwrap());
                headers
            },
            false,
        ),
    ];
    for (headers, trusted) in cases {
        let context = crate::identity::resolve_request_context(
            &policy,
            &headers,
            trusted,
            "/v1/chat/completions",
            AuthorityProtocol::ChatCompletions,
        );
        assert_eq!(context.app, None);
        assert_eq!(context.workload_identity_digest, None);
        assert!(!context.identity_trusted);
        assert!(context
            .identity
            .app
            .as_deref()
            .is_none_or(|app| app != "untrusted"));
    }
}

#[test]
fn trusted_authority_headers_reject_duplicate_ambiguous_malformed_reserved_and_overlong_values() {
    let policy = request_context_policy();
    let mut rows = Vec::new();

    let mut duplicate_app = HeaderMap::new();
    duplicate_app.append("x-bowline-app", "support".parse().unwrap());
    duplicate_app.append("x-bowline-app", "other".parse().unwrap());
    rows.push((duplicate_app, true));

    for value in ["support,other", "untrusted", OVERLONG_APP_HEADER] {
        let mut headers = HeaderMap::new();
        headers.insert("x-bowline-app", value.parse().unwrap());
        rows.push((headers, true));
    }

    let mut malformed_app = HeaderMap::new();
    malformed_app.insert(
        "x-bowline-app",
        axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    rows.push((malformed_app, true));

    let mut duplicate_task = HeaderMap::new();
    duplicate_task.insert("x-bowline-app", "support".parse().unwrap());
    duplicate_task.append("x-bowline-task-class", "heavy-lifting".parse().unwrap());
    duplicate_task.append("x-bowline-task-class", "judgment".parse().unwrap());
    rows.push((duplicate_task, false));

    for value in ["heavy-lifting,judgment", "not-a-class", "untrusted"] {
        let mut headers = HeaderMap::new();
        headers.insert("x-bowline-app", "support".parse().unwrap());
        headers.insert("x-bowline-task-class", value.parse().unwrap());
        rows.push((headers, false));
    }

    let mut malformed_task = HeaderMap::new();
    malformed_task.insert("x-bowline-app", "support".parse().unwrap());
    malformed_task.insert(
        "x-bowline-task-class",
        axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    rows.push((malformed_task, false));

    for (headers, app_invalid) in rows {
        let context = crate::identity::resolve_request_context(
            &policy,
            &headers,
            true,
            "/v1/chat/completions",
            AuthorityProtocol::ChatCompletions,
        );
        assert!(!context.authority_metadata_valid);
        if app_invalid {
            assert!(!context.identity_trusted);
            assert_eq!(context.app, None);
            assert_eq!(context.workload_identity_digest, None);
        } else {
            assert!(context.identity_trusted);
            assert_eq!(context.app.as_deref(), Some("support"));
            assert_eq!(context.task_class, TaskClass::HeavyLifting);
        }
    }
}

#[test]
fn literal_untrusted_is_unresolved_by_production_context_resolver() {
    let policy = PolicyBundle::from_yaml(
        r#"
version: 1
identities:
  - match: { app: untrusted }
    tags: [production]
rules:
  - name: configured-former-sentinel
    subject: { app: untrusted }
    task_class: judgment
  - name: default
    default: true
    task_class: unclassified
"#,
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-bowline-app", "untrusted".parse().unwrap());
    headers.insert("x-bowline-task-class", "judgment".parse().unwrap());

    let context = crate::identity::resolve_request_context(
        &policy,
        &headers,
        true,
        "/v1/chat/completions",
        AuthorityProtocol::ChatCompletions,
    );
    assert_eq!(context.app, None);
    assert_eq!(context.identity.app, None);
    assert_eq!(context.workload_identity_digest, None);
    assert!(!context.identity_trusted);
    assert!(context.resolved_tags.is_empty());
}

#[test]
fn embeddings_zero_authority_conversion_preserves_protocol_and_traffic_kind() {
    assert_eq!(
        authority_protocol(ProtocolKind::Embeddings),
        Some(AuthorityProtocol::Embeddings)
    );
    assert_eq!(
        protocol_to_traffic(AuthorityProtocol::Embeddings),
        ProtocolKind::Embeddings
    );

    let route = bowline_core::enforcement::EnforcementRoute {
        route_id: "embeddings-observe".into(),
        method: "POST".into(),
        path: "/v1/embeddings".into(),
        protocol: AuthorityProtocol::Embeddings,
        workload: None,
        mode: RouteMode::Observe,
        rollout_ppm: 0,
        promoted_supply_id: None,
        actual_supply_id: None,
        task_class: None,
        model_authority: None,
        fallback: None,
        promotion: None,
    };
    let observe = bowline_core::enforcement::SelectionInput {
        route,
        method: "POST".into(),
        path: "/v1/embeddings".into(),
        protocol: AuthorityProtocol::Embeddings,
        identity_trusted: false,
        authority_metadata_valid: true,
        shape_supported: true,
        task_class: TaskClass::Unclassified,
        app: None,
        resolved_tags: vec![],
        workload_identity_digest: None,
        request_body_digest: [0; 32],
        requested_supply_id: None,
        kill: KillReadResult::Unreadable,
        now_ms: 0,
        candidate_availability: CandidateAvailability::Unavailable,
        actuator_available: false,
    };
    let plan = bowline_core::enforcement::select_enforcement_plan_without_grant(&observe);
    assert_eq!(plan.target, PlanTarget::Original);
    assert_eq!(plan.reason, SelectionReason::ObserveOnly);
    assert!(plan.grant_digest.is_none());
}
