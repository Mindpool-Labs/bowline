//! Sole test in this binary: `ALL_PROXY` is read once, at `reqwest::Client::builder().build()`
//! time, inside `SwitchyardObserveAdapter::new`. Setting it here must not reach any other test's
//! client construction, so it lives in its own integration binary rather than in
//! `switchyard_observe.rs`'s `mod tests`.

use std::time::Duration;

use axum::{extract::State, routing::post, Json, Router};
use bowline_core::{
    config::SwitchyardObserveConfig, routing::RoutingSignal, routing::RoutingTarget,
};
use bowline_gateway::switchyard_observe::SwitchyardObserveAdapter;

fn config(url: String) -> SwitchyardObserveConfig {
    SwitchyardObserveConfig {
        version: 1,
        decision_api_url: url,
        profile_id: "stage-main".into(),
        authorization_env: "BOWLINE_SWITCHYARD_PROXY_BOUNDARY_TEST_AUTH".into(),
        timeout_ms: 200,
        capable_backend_id: "capable-backend".into(),
        efficient_backend_id: "efficient-backend".into(),
        observation_queue_capacity: 1,
        remote_acknowledged: false,
    }
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
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

/// Stands up a real decision stub, sends one observation to it, and reports whether the
/// adapter actually reached that stub with no transport error.
async fn send_one_observation_to_a_local_stub() -> anyhow::Result<()> {
    std::env::set_var(
        "BOWLINE_SWITCHYARD_PROXY_BOUNDARY_TEST_AUTH",
        "Bearer fixture-secret",
    );
    let (payload_tx, mut payload_rx) = tokio::sync::mpsc::channel(1);
    let (url, _server) = serve(
        Router::new()
            .route(
                "/decision",
                post(
                    |State(sender): State<tokio::sync::mpsc::Sender<serde_json::Value>>,
                     Json(value): Json<serde_json::Value>| async move {
                        sender.send(value).await.unwrap();
                        Json(serde_json::json!({"backend_id": "capable-backend"}))
                    },
                ),
            )
            .with_state(payload_tx),
    )
    .await;

    let adapter = SwitchyardObserveAdapter::new(&config(url))?;
    adapter.observe(
        "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
        "responses",
        7,
        vec![RoutingSignal::Write],
        RoutingTarget::Capable,
    );

    wait_for(|| adapter.health().completed >= 1).await;

    if tokio::time::timeout(Duration::from_millis(500), payload_rx.recv())
        .await
        .is_err()
    {
        anyhow::bail!("the observation never reached the configured decision endpoint");
    }

    let health = adapter.health();
    if health.proposed_capable != 1 {
        anyhow::bail!("the adapter did not record a completed proposal from the endpoint");
    }
    Ok(())
}

#[tokio::test]
async fn the_adapter_ignores_ambient_proxy_environment() {
    // A proxy that would swallow the observation if reqwest honored the environment.
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("decoy binds");
    let decoy_addr = decoy.local_addr().expect("decoy address");
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let decoy_hit = hit.clone();
    tokio::spawn(async move {
        if decoy.accept().await.is_ok() {
            decoy_hit.store(true, std::sync::atomic::Ordering::Release);
        }
    });

    // Sole test in this binary, so the variable reaches no other client build.
    std::env::set_var("ALL_PROXY", format!("http://{decoy_addr}"));
    let result = send_one_observation_to_a_local_stub().await;
    std::env::remove_var("ALL_PROXY");

    assert!(
        result.is_ok(),
        "the observation reaches the configured endpoint"
    );
    assert!(
        !hit.load(std::sync::atomic::Ordering::Acquire),
        "no observation may reach a host the operator never acknowledged"
    );
}
