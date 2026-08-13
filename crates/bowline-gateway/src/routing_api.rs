//! Separate local API for advisory, content-free routing decisions.

use std::{collections::BTreeMap, env, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header::AUTHORIZATION, Response, StatusCode},
    routing::post,
    Router,
};
use bowline_core::{
    enforcement::ValidatedEnforcement,
    ledger::{RoutingDecisionSourceV3, RoutingUnavailableCauseV3},
    routing::{RoutingSignal, RoutingTarget},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::routing_state::{RoutingStateError, RoutingStateStore, MAX_REQUEST_BYTES};

#[derive(Clone)]
pub struct RoutingApiState {
    expected_authorization: Arc<str>,
    routes: Arc<BTreeMap<String, RouteBinding>>,
    store: Option<Arc<RoutingStateStore>>,
    startup_unavailable: Option<RoutingUnavailableCauseV3>,
}

/// The decision listener has its own lifecycle.  It is stopped before the serving runtime drops
/// its shared store, so a lost file lease cannot leave an advisory writer accepting requests.
pub struct RoutingApiServer {
    shutdown: tokio::sync::watch::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl RoutingApiServer {
    pub fn start(listener: tokio::net::TcpListener, router: Router) -> Self {
        let (shutdown, mut receiver) = tokio::sync::watch::channel(());
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = receiver.changed().await;
                })
                .await
                .map_err(anyhow::Error::from)
                .context("routing decision API failed")
        });
        Self { shutdown, task }
    }

    pub async fn shutdown(self, grace: Duration) -> anyhow::Result<()> {
        let _ = self.shutdown.send(());
        tokio::time::timeout(grace, self.task)
            .await
            .context("routing decision API drain exceeded shutdown grace")?
            .map_err(anyhow::Error::from)??;
        Ok(())
    }
}

#[derive(Clone)]
struct RouteBinding {
    profile_id: String,
    profile: bowline_core::routing::StageRoutingProfile,
    profile_digest: String,
    route_digest: String,
    capable_supply_id: String,
    efficient_supply_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    schema_version: u32,
    route_id: String,
    task_id: String,
    step_id: u64,
    signals: Vec<RoutingSignal>,
}

#[derive(Debug, Serialize)]
struct DecisionResponse {
    schema_version: u32,
    decision_id: String,
    route_id: String,
    profile_id: String,
    profile_digest: String,
    task_ref: String,
    step_id: u64,
    target: RoutingTarget,
    selected_supply_id: String,
    reason: bowline_core::routing::RoutingReason,
    state_digest: String,
    authority: &'static str,
}

impl RoutingApiState {
    pub fn from_validated(
        validated: &ValidatedEnforcement,
        authorization_env: &str,
        store: Option<Arc<RoutingStateStore>>,
        startup_unavailable: Option<RoutingUnavailableCauseV3>,
    ) -> anyhow::Result<Self> {
        let expected_authorization = env::var(authorization_env).map_err(|_| {
            anyhow::anyhow!("routing authorization environment reference is unavailable")
        })?;
        if expected_authorization.is_empty() {
            anyhow::bail!("routing authorization environment reference is empty");
        }
        let mut routes = BTreeMap::new();
        for route in validated.routes() {
            let Some(profile) = validated.routing_profile_for_route(&route.route_id) else {
                continue;
            };
            let capable_supply_id = route
                .actual_supply_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("routed route has no capable supply"))?;
            let efficient_supply_id = route
                .promoted_supply_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("routed route has no efficient supply"))?;
            routes.insert(
                route.route_id.clone(),
                RouteBinding {
                    profile_id: profile.profile_id.clone(),
                    profile: profile.clone(),
                    profile_digest: profile.digest(),
                    route_digest: validated
                        .route_digest(&route.route_id)
                        .ok_or_else(|| anyhow::anyhow!("routed route digest unavailable"))?,
                    capable_supply_id,
                    efficient_supply_id,
                },
            );
        }
        Ok(Self {
            expected_authorization: Arc::from(expected_authorization),
            routes: Arc::new(routes),
            store,
            startup_unavailable,
        })
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/v1/routing/decision", post(decision))
            .with_state(self)
    }
}

async fn decision(State(state): State<RoutingApiState>, request: Request) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"),
    };
    let mut authorization = parts.headers.get_all(AUTHORIZATION).iter();
    if !matches!(
        (authorization.next(), authorization.next()),
        (Some(value), None) if value.as_bytes() == state.expected_authorization.as_bytes()
    ) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let request: DecisionRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if request.schema_version != 1 {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if !valid_request_identifier(&request.route_id) || !valid_request_identifier(&request.task_id) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(route) = state.routes.get(&request.route_id) else {
        return error(StatusCode::NOT_FOUND, "unknown_route");
    };
    let Some(store) = state.store.as_ref() else {
        return routing_unavailable_error(
            state
                .startup_unavailable
                .unwrap_or(RoutingUnavailableCauseV3::StartupUnavailable),
        );
    };
    let decision = match store.decide_with_source(
        &request.task_id,
        request.step_id,
        &route.route_digest,
        &route.profile,
        request.signals,
        RoutingDecisionSourceV3::LocalDecisionApi,
    ) {
        Ok(decision) => decision,
        Err(RoutingStateError::StepConflict) => {
            return error(StatusCode::CONFLICT, "step_conflict")
        }
        Err(state_error) => match state_error {
            RoutingStateError::Invalid => return error(StatusCode::BAD_REQUEST, "invalid_request"),
            RoutingStateError::Io | RoutingStateError::Locked | RoutingStateError::UnsafePath => {
                return routing_unavailable_error(RoutingUnavailableCauseV3::StartupUnavailable)
            }
            state_error => {
                return routing_unavailable_error(
                    state_error
                        .unavailable_cause()
                        .expect("state error has an unavailable cause"),
                )
            }
        },
    };
    let selected_supply_id = match decision.target {
        RoutingTarget::Capable => route.capable_supply_id.clone(),
        RoutingTarget::Efficient => route.efficient_supply_id.clone(),
    };
    let decision_id = digest(&(
        &decision.decision_digest,
        &request.route_id,
        &route.profile_id,
    ));
    response(
        StatusCode::OK,
        &DecisionResponse {
            schema_version: 1,
            decision_id,
            route_id: request.route_id,
            profile_id: route.profile_id.clone(),
            profile_digest: route.profile_digest.clone(),
            task_ref: decision.task_ref,
            step_id: decision.step_id,
            target: decision.target,
            selected_supply_id,
            reason: decision.reason,
            state_digest: decision.state_digest,
            authority: "advisory-only",
        },
    )
}

/// The API intentionally keeps its established public status and body. The typed cause is kept
/// for the inference evidence path and for stable internal classification.
fn routing_unavailable_error(_cause: RoutingUnavailableCauseV3) -> Response<Body> {
    error(StatusCode::SERVICE_UNAVAILABLE, "routing_unavailable")
}

fn valid_request_identifier(value: &str) -> bool {
    bowline_core::identifier::is_routing_request_identifier(value)
}

fn digest<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("decision id is serializable");
    format!(
        "sha256:{:x}",
        Sha256::digest(
            [
                b"bowline.routing.api.decision.v1\0".as_slice(),
                bytes.as_slice()
            ]
            .concat()
        )
    )
}

fn error(status: StatusCode, code: &'static str) -> Response<Body> {
    response(status, &serde_json::json!({ "error": code }))
}
fn response<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("response builder accepts fixed values")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowline_core::routing::{RoutingTarget, StageProfileKind};

    fn test_state() -> (RoutingApiState, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let profile = bowline_core::routing::StageRoutingProfile {
            profile_id: "stage-main".into(),
            kind: StageProfileKind::Stage,
            recent_window: 4,
            error_threshold: 2,
            exploration_threshold: 2,
            progress_threshold: 1,
            default_target: RoutingTarget::Capable,
        };
        let state = RoutingApiState {
            expected_authorization: Arc::from("Bearer routing-test-secret"),
            routes: Arc::new(BTreeMap::from([(
                "route-main".into(),
                RouteBinding {
                    profile_id: profile.profile_id.clone(),
                    profile_digest: profile.digest(),
                    profile,
                    route_digest: "sha256:route".into(),
                    capable_supply_id: "capable".into(),
                    efficient_supply_id: "efficient".into(),
                },
            )])),
            store: Some(Arc::new(
                RoutingStateStore::open(directory.path(), Default::default()).unwrap(),
            )),
            startup_unavailable: None,
        };
        (state, directory)
    }

    async fn call(
        state: RoutingApiState,
        authorization: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/routing/decision");
        if let Some(authorization) = authorization {
            request = request.header(AUTHORIZATION, authorization);
        }
        let response = decision(State(state), request.body(Body::from(body)).unwrap()).await;
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn strict_contract_limits_bodies_and_never_discloses_authorization() {
        let payload = br#"{"schema_version":1,"route_id":"route-main","task_id":"task-1","step_id":1,"signals":["write"]}"#.to_vec();
        let (state, _directory) = test_state();
        let (status, body) = call(state, None, payload.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, r#"{"error":"unauthorized"}"#);

        let (state, _directory) = test_state();
        let (status, body) = call(
            state,
            Some("Bearer routing-test-secret"),
            br#"{"schema_version":1,"route_id":"route-main","task_id":"task-1","step_id":1,"signals":[],"timestamp":1}"#.to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"invalid_request"}"#);

        let (state, _directory) = test_state();
        let (status, body) = call(
            state,
            Some("Bearer routing-test-secret"),
            vec![b'x'; MAX_REQUEST_BYTES + 1],
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body, r#"{"error":"body_too_large"}"#);

        let (state, _directory) = test_state();
        let (status, body) = call(state, Some("Bearer routing-test-secret"), payload).await;
        assert_eq!(status, StatusCode::OK);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        for field in [
            "schema_version",
            "decision_id",
            "route_id",
            "profile_id",
            "profile_digest",
            "task_ref",
            "step_id",
            "target",
            "selected_supply_id",
            "reason",
            "state_digest",
            "authority",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
        assert_eq!(value["authority"], "advisory-only");
        assert!(!body.contains("routing-test-secret"));
        assert!(!body.contains("task-1"));
    }

    #[tokio::test]
    async fn invalid_route_and_replayed_conflict_have_stable_errors() {
        let (state, _directory) = test_state();
        let unknown = br#"{"schema_version":1,"route_id":"unknown","task_id":"task-1","step_id":1,"signals":[]}"#.to_vec();
        let (status, body) = call(state.clone(), Some("Bearer routing-test-secret"), unknown).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, r#"{"error":"unknown_route"}"#);
        let first = br#"{"schema_version":1,"route_id":"route-main","task_id":"task-1","step_id":1,"signals":[]}"#.to_vec();
        assert_eq!(
            call(state.clone(), Some("Bearer routing-test-secret"), first)
                .await
                .0,
            StatusCode::OK
        );
        let conflict = br#"{"schema_version":1,"route_id":"route-main","task_id":"task-1","step_id":1,"signals":["write"]}"#.to_vec();
        let (status, body) = call(state, Some("Bearer routing-test-secret"), conflict).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, r#"{"error":"step_conflict"}"#);
    }

    #[tokio::test]
    async fn rejects_instruction_like_or_unbounded_identifiers_before_lookup() {
        for (route_id, task_id) in [
            ("route main", "task-1".to_owned()),
            ("route-main", "ignore instructions".to_owned()),
            ("route-main", "x".repeat(129)),
            ("route-main", "task\n1".to_owned()),
        ] {
            let (state, _directory) = test_state();
            let payload = serde_json::json!({
                "schema_version": 1,
                "route_id": route_id,
                "task_id": task_id,
                "step_id": 1,
                "signals": []
            })
            .to_string()
            .into_bytes();
            let (status, body) = call(state, Some("Bearer routing-test-secret"), payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, r#"{"error":"invalid_request"}"#);
        }
    }

    #[tokio::test]
    async fn configured_but_unavailable_state_keeps_listener_up_with_stable_503() {
        let (mut state, _directory) = test_state();
        state.store = None;
        state.startup_unavailable = Some(RoutingUnavailableCauseV3::StartupUnavailable);
        let (status, body) = call(
            state,
            Some("Bearer routing-test-secret"),
            br#"{"schema_version":1,"route_id":"route-main","task_id":"task-1","step_id":1,"signals":[]}"#.to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, r#"{"error":"routing_unavailable"}"#);
    }

    #[tokio::test]
    async fn typed_unavailable_causes_keep_the_api_503_contract_stable() {
        for cause in [
            RoutingUnavailableCauseV3::CapacityExhausted,
            RoutingUnavailableCauseV3::StateCorrupt,
            RoutingUnavailableCauseV3::WriterFailure,
            RoutingUnavailableCauseV3::StartupUnavailable,
        ] {
            let response = routing_unavailable_error(cause);
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(&body[..], br#"{"error":"routing_unavailable"}"#);
        }
    }

    #[tokio::test]
    async fn listener_is_separate_and_stops_accepting_when_its_runtime_drains() {
        let (state, _directory) = test_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = RoutingApiServer::start(listener, state.router());
        let response = reqwest::Client::new()
            .post(format!("http://{address}/v1/routing/decision"))
            .header(AUTHORIZATION, "Bearer routing-test-secret")
            .body(r#"{"schema_version":1,"route_id":"route-main","task_id":"task-1","step_id":1,"signals":[]}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        server.shutdown(Duration::from_secs(1)).await.unwrap();
        assert!(reqwest::Client::new()
            .post(format!("http://{address}/v1/routing/decision"))
            .send()
            .await
            .is_err());
    }
}
