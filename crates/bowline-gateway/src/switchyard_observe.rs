//! Isolated, non-authoritative NeMo Relay 0.6.0 / Switchyard pilot wire contract.
//!
//! This module deliberately accepts only already-digested task metadata. Its result is telemetry,
//! never a Bowline plan, target, fallback, kill-state, or dispatch input.

use std::{
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bowline_core::{
    config::SwitchyardObserveConfig,
    routing::{RoutingSignal, RoutingTarget},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const ADAPTER_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SwitchyardObservationErrorClass {
    Timeout,
    AuthenticationFailed,
    MalformedResponse,
    Unavailable,
    ResponseOverflow,
    RedirectRejected,
    InvalidBackendId,
    QueueSaturated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwitchyardObserveHealth {
    pub adapter_version: u32,
    pub profile_version: u32,
    pub config_digest: String,
    pub queued: u64,
    pub observed: u64,
    pub dropped: u64,
    pub completed: u64,
    pub agreed: u64,
    pub native_capable: u64,
    pub native_efficient: u64,
    pub proposed_capable: u64,
    pub proposed_efficient: u64,
    pub timed_out: u64,
    pub invalid_backend_id: u64,
    pub malformed_response: u64,
    pub authentication_failed: u64,
    pub unavailable: u64,
    pub response_overflow: u64,
    pub redirect_rejected: u64,
    pub queue_saturated: u64,
    pub latency_ms_total: u64,
}

#[derive(Clone)]
pub struct SwitchyardObserveAdapter {
    sender: tokio::sync::mpsc::Sender<Observation>,
    health: Arc<Metrics>,
    profile_id_digest: Arc<str>,
    config_digest: Arc<str>,
    profile_version: u32,
}

struct Metrics {
    queued: AtomicU64,
    observed: AtomicU64,
    dropped: AtomicU64,
    completed: AtomicU64,
    agreed: AtomicU64,
    native_capable: AtomicU64,
    native_efficient: AtomicU64,
    proposed_capable: AtomicU64,
    proposed_efficient: AtomicU64,
    timed_out: AtomicU64,
    invalid_backend_id: AtomicU64,
    malformed_response: AtomicU64,
    authentication_failed: AtomicU64,
    unavailable: AtomicU64,
    response_overflow: AtomicU64,
    redirect_rejected: AtomicU64,
    queue_saturated: AtomicU64,
    latency_ms_total: AtomicU64,
}

impl Metrics {
    fn snapshot(&self, profile_version: u32, config_digest: &str) -> SwitchyardObserveHealth {
        SwitchyardObserveHealth {
            adapter_version: ADAPTER_VERSION,
            profile_version,
            config_digest: config_digest.into(),
            queued: self.queued.load(Ordering::Acquire),
            observed: self.observed.load(Ordering::Acquire),
            dropped: self.dropped.load(Ordering::Acquire),
            completed: self.completed.load(Ordering::Acquire),
            agreed: self.agreed.load(Ordering::Acquire),
            native_capable: self.native_capable.load(Ordering::Acquire),
            native_efficient: self.native_efficient.load(Ordering::Acquire),
            proposed_capable: self.proposed_capable.load(Ordering::Acquire),
            proposed_efficient: self.proposed_efficient.load(Ordering::Acquire),
            timed_out: self.timed_out.load(Ordering::Acquire),
            invalid_backend_id: self.invalid_backend_id.load(Ordering::Acquire),
            malformed_response: self.malformed_response.load(Ordering::Acquire),
            authentication_failed: self.authentication_failed.load(Ordering::Acquire),
            unavailable: self.unavailable.load(Ordering::Acquire),
            response_overflow: self.response_overflow.load(Ordering::Acquire),
            redirect_rejected: self.redirect_rejected.load(Ordering::Acquire),
            queue_saturated: self.queue_saturated.load(Ordering::Acquire),
            latency_ms_total: self.latency_ms_total.load(Ordering::Acquire),
        }
    }
}

#[derive(Serialize)]
struct Observation {
    schema_version: u32,
    task_ref: String,
    protocol: &'static str,
    step_id: u64,
    signals: Vec<RoutingSignal>,
    #[serde(skip)]
    native_target: RoutingTarget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    backend_id: String,
}

impl SwitchyardObserveAdapter {
    pub fn new(config: &SwitchyardObserveConfig) -> anyhow::Result<Self> {
        let authorization = env::var(&config.authorization_env).map_err(|_| {
            anyhow::anyhow!("switchyard authorization environment reference is unavailable")
        })?;
        if authorization.is_empty() {
            anyhow::bail!("switchyard authorization environment reference is empty");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            // The acknowledged endpoint is the entire transport boundary.  Following a redirect
            // could move an observation to a host which was neither validated nor acknowledged.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let (sender, mut receiver) =
            tokio::sync::mpsc::channel::<Observation>(config.observation_queue_capacity);
        let health = Arc::new(Metrics {
            queued: AtomicU64::new(0),
            observed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            agreed: AtomicU64::new(0),
            native_capable: AtomicU64::new(0),
            native_efficient: AtomicU64::new(0),
            proposed_capable: AtomicU64::new(0),
            proposed_efficient: AtomicU64::new(0),
            timed_out: AtomicU64::new(0),
            invalid_backend_id: AtomicU64::new(0),
            malformed_response: AtomicU64::new(0),
            authentication_failed: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            response_overflow: AtomicU64::new(0),
            redirect_rejected: AtomicU64::new(0),
            queue_saturated: AtomicU64::new(0),
            latency_ms_total: AtomicU64::new(0),
        });
        let worker_health = Arc::clone(&health);
        let url = config.decision_api_url.clone();
        let capable = config.capable_backend_id.clone();
        let efficient = config.efficient_backend_id.clone();
        tokio::spawn(async move {
            while let Some(observation) = receiver.recv().await {
                worker_health.queued.fetch_sub(1, Ordering::AcqRel);
                let started = Instant::now();
                let outcome = match client
                    .post(&url)
                    .header(reqwest::header::AUTHORIZATION, &authorization)
                    .json(&observation)
                    .send()
                    .await
                {
                    Err(error) if error.is_timeout() => {
                        Err(SwitchyardObservationErrorClass::Timeout)
                    }
                    Err(_) => Err(SwitchyardObservationErrorClass::Unavailable),
                    Ok(response)
                        if response.status() == reqwest::StatusCode::UNAUTHORIZED
                            || response.status() == reqwest::StatusCode::FORBIDDEN =>
                    {
                        Err(SwitchyardObservationErrorClass::AuthenticationFailed)
                    }
                    Ok(response) if response.status().is_redirection() => {
                        Err(SwitchyardObservationErrorClass::RedirectRejected)
                    }
                    Ok(response) if !response.status().is_success() => {
                        Err(SwitchyardObservationErrorClass::Unavailable)
                    }
                    Ok(response) => match bounded_response(response).await {
                        Err(error) => Err(error),
                        Ok(bytes) => match serde_json::from_slice::<Proposal>(&bytes) {
                            Err(_) => Err(SwitchyardObservationErrorClass::MalformedResponse),
                            Ok(proposal) => {
                                match backend_target(&proposal.backend_id, &capable, &efficient) {
                                    None => Err(SwitchyardObservationErrorClass::InvalidBackendId),
                                    Some(proposed) => Ok(proposed),
                                }
                            }
                        },
                    },
                };
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                worker_health
                    .latency_ms_total
                    .fetch_add(latency_ms, Ordering::AcqRel);
                worker_health.completed.fetch_add(1, Ordering::AcqRel);
                match outcome {
                    Err(error) => record_error(&worker_health, error),
                    Ok(proposed) => {
                        match proposed {
                            RoutingTarget::Capable => worker_health
                                .proposed_capable
                                .fetch_add(1, Ordering::AcqRel),
                            RoutingTarget::Efficient => worker_health
                                .proposed_efficient
                                .fetch_add(1, Ordering::AcqRel),
                        };
                        if proposed == observation.native_target {
                            worker_health.agreed.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                }
            }
        });
        Ok(Self {
            sender,
            health,
            profile_id_digest: Arc::from(profile_id_digest(&config.profile_id)),
            config_digest: Arc::from(Self::config_digest(config)),
            profile_version: config.version,
        })
    }

    pub fn observe(
        &self,
        task_ref: String,
        protocol: &'static str,
        step_id: u64,
        signals: Vec<RoutingSignal>,
        native_target: RoutingTarget,
    ) {
        let observation = Observation {
            schema_version: 1,
            task_ref,
            protocol,
            step_id,
            signals,
            native_target,
        };
        self.health.observed.fetch_add(1, Ordering::AcqRel);
        match native_target {
            RoutingTarget::Capable => self.health.native_capable.fetch_add(1, Ordering::AcqRel),
            RoutingTarget::Efficient => self.health.native_efficient.fetch_add(1, Ordering::AcqRel),
        };
        match self.sender.try_reserve() {
            Ok(permit) => {
                // Increment before publishing the item. A receiver cannot observe the item until
                // `send`, so the worker cannot decrement this counter below zero.
                self.health.queued.fetch_add(1, Ordering::AcqRel);
                permit.send(observation);
            }
            Err(_) => {
                self.health.dropped.fetch_add(1, Ordering::AcqRel);
                // A saturated queue is a complete observation outcome. Its elapsed work is zero,
                // and there is no body to read or parse, but it still has a native target and a
                // stable error class in the aggregate health record.
                self.health.completed.fetch_add(1, Ordering::AcqRel);
                record_error(
                    &self.health,
                    SwitchyardObservationErrorClass::QueueSaturated,
                );
            }
        }
    }

    pub fn health(&self) -> SwitchyardObserveHealth {
        self.health
            .snapshot(self.profile_version, &self.config_digest)
    }

    pub fn matches_profile(&self, profile_id: &str) -> bool {
        self.profile_id_digest.as_ref() == profile_id_digest(profile_id)
    }

    pub fn config_digest(config: &SwitchyardObserveConfig) -> String {
        let bytes = serde_json::to_vec(config).expect("switchyard configuration serializes");
        format!(
            "sha256:{:x}",
            Sha256::digest(
                [
                    b"bowline.switchyard.observe.v1\0".as_slice(),
                    bytes.as_slice()
                ]
                .concat()
            )
        )
    }
}

fn record_error(metrics: &Metrics, error: SwitchyardObservationErrorClass) {
    match error {
        SwitchyardObservationErrorClass::Timeout => {
            metrics.timed_out.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::AuthenticationFailed => {
            metrics.authentication_failed.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::MalformedResponse => {
            metrics.malformed_response.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::Unavailable => {
            metrics.unavailable.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::ResponseOverflow => {
            metrics.response_overflow.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::RedirectRejected => {
            metrics.redirect_rejected.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::InvalidBackendId => {
            metrics.invalid_backend_id.fetch_add(1, Ordering::AcqRel);
        }
        SwitchyardObservationErrorClass::QueueSaturated => {
            metrics.queue_saturated.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn profile_id_digest(profile_id: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(
            [
                b"bowline.switchyard.profile.v1\0".as_slice(),
                profile_id.as_bytes()
            ]
            .concat()
        )
    )
}

async fn bounded_response(
    response: reqwest::Response,
) -> Result<Vec<u8>, SwitchyardObservationErrorClass> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(SwitchyardObservationErrorClass::ResponseOverflow);
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
        let chunk = chunk.map_err(|_| SwitchyardObservationErrorClass::MalformedResponse)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(SwitchyardObservationErrorClass::ResponseOverflow);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn backend_target(value: &str, capable: &str, efficient: &str) -> Option<RoutingTarget> {
    if value == capable {
        Some(RoutingTarget::Capable)
    } else if value == efficient {
        Some(RoutingTarget::Efficient)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        extract::State,
        http::{header, HeaderMap, StatusCode},
        response::Response,
        routing::post,
        Json, Router,
    };
    use bowline_core::routing::RoutingSignal;
    use std::convert::Infallible;

    fn config(url: String) -> SwitchyardObserveConfig {
        SwitchyardObserveConfig {
            version: 1,
            decision_api_url: url,
            profile_id: "stage-main".into(),
            authorization_env: "BOWLINE_SWITCHYARD_TEST_AUTH".into(),
            timeout_ms: 25,
            capable_backend_id: "capable-backend".into(),
            efficient_backend_id: "efficient-backend".into(),
            observation_queue_capacity: 1,
            remote_acknowledged: false,
        }
    }

    fn config_with_timeout(url: String, timeout_ms: u64) -> SwitchyardObserveConfig {
        let mut config = config(url);
        config.timeout_ms = timeout_ms;
        config
    }

    async fn wait_for(mut predicate: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !predicate() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "adapter did not complete"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/decision"), server)
    }

    fn observe(adapter: &SwitchyardObserveAdapter, native: RoutingTarget) {
        adapter.observe(
            "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
            "responses",
            7,
            vec![RoutingSignal::Write],
            native,
        );
    }

    fn assert_native_unchanged(native: RoutingTarget) {
        // The only native input is copied into a telemetry-only message; an adapter outcome has
        // no mutable plan, authority, or dispatch handle to change.
        assert_eq!(native, RoutingTarget::Capable);
    }

    #[tokio::test]
    async fn valid_agreement_is_content_free_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (payload_tx, mut payload_rx) = tokio::sync::mpsc::channel(1);
        let (url, server) = serve(
            Router::new()
                .route(
                    "/decision",
                    post(
                        |State(sender): State<tokio::sync::mpsc::Sender<serde_json::Value>>,
                         Json(value): Json<serde_json::Value>| async move {
                            sender.send(value).await.unwrap();
                            Json(serde_json::json!({"backend_id":"capable-backend"}))
                        },
                    ),
                )
                .with_state(payload_tx),
        )
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        let payload = tokio::time::timeout(Duration::from_secs(1), payload_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            payload
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "protocol",
                "schema_version",
                "signals",
                "step_id",
                "task_ref",
            ]
        );
        let serialized = payload.to_string();
        assert!(!serialized.contains("fixture-secret"));
        assert!(!serialized.contains("stage-main"));
        assert!(serialized
            .contains("sha256:0000000000000000000000000000000000000000000000000000000000000001"));
        for forbidden in [
            "fixture-secret",
            "stage-main",
            "adapter_version",
            "profile_version",
            "profile_id_digest",
            "config_digest",
            "native_target",
            "prompt",
            "body",
            "header",
            "source",
        ] {
            assert!(!serialized.contains(forbidden), "wire leaked {forbidden}");
        }
        wait_for(|| adapter.health().completed == 1).await;
        let health = adapter.health();
        assert_eq!(health.agreed, 1);
        assert_eq!(health.native_capable, 1);
        assert_eq!(health.proposed_capable, 1);
        assert_eq!(health.adapter_version, ADAPTER_VERSION);
        assert_eq!(health.profile_version, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn valid_disagreement_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async { Json(serde_json::json!({"backend_id":"efficient-backend"})) }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        let health = adapter.health();
        assert_eq!(health.proposed_efficient, 1);
        assert_eq!(health.agreed, 0);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn timeout_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(75)).await;
                Json(serde_json::json!({"backend_id":"capable-backend"}))
            }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().timed_out, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn malformed_response_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(
            Router::new().route("/decision", post(|| async { (StatusCode::OK, "not-json") })),
        )
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().malformed_response, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn authentication_failure_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|headers: HeaderMap| async move {
                if headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    == Some("Bearer expected-other-secret")
                {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().authentication_failed, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_service_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().unavailable, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn response_overflow_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let oversized = "x".repeat(MAX_RESPONSE_BYTES + 1);
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(move || {
                let oversized = oversized.clone();
                async move { (StatusCode::OK, oversized) }
            }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().response_overflow, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn redirect_is_rejected_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async { (StatusCode::FOUND, [(header::LOCATION, "/other")], "") }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().redirect_rejected, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn invalid_backend_id_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async { Json(serde_json::json!({"backend_id":"not-mapped"})) }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert_eq!(adapter.health().invalid_backend_id, 1);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn queue_saturation_is_classified_and_keeps_native_dispatch() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(75)).await;
                Json(serde_json::json!({"backend_id":"capable-backend"}))
            }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config(url)).unwrap();
        let native = RoutingTarget::Capable;
        for _ in 0..8 {
            observe(&adapter, native);
        }
        wait_for(|| adapter.health().queue_saturated > 0).await;
        wait_for(|| {
            let health = adapter.health();
            health.completed == health.observed
        })
        .await;
        let health = adapter.health();
        assert!(health.dropped > 0);
        assert!(health.queued <= 1);
        assert_eq!(health.completed, health.observed);
        assert_eq!(health.native_capable, 8);
        assert_native_unchanged(native);
        server.abort();
    }

    #[tokio::test]
    async fn latency_includes_the_delayed_response_body() {
        std::env::set_var("BOWLINE_SWITCHYARD_TEST_AUTH", "Bearer fixture-secret");
        let (url, server) = serve(Router::new().route(
            "/decision",
            post(|| async {
                let stream = futures_util::stream::once(async {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    Ok::<Bytes, Infallible>(Bytes::from_static(
                        br#"{"backend_id":"capable-backend"}"#,
                    ))
                });
                Response::new(Body::from_stream(stream))
            }),
        ))
        .await;
        let adapter = SwitchyardObserveAdapter::new(&config_with_timeout(url, 200)).unwrap();
        let native = RoutingTarget::Capable;
        observe(&adapter, native);
        wait_for(|| adapter.health().completed == 1).await;
        assert!(adapter.health().latency_ms_total >= 30);
        assert_native_unchanged(native);
        server.abort();
    }
}
