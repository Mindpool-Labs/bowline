use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{routing::post, Router};
use bowline_core::{
    config::{Config, OwnedCostCatalog, RuntimeConfig, StateBackendConfig},
    policy::PolicyBundle,
    run::RunStore,
    supply::Registry,
};
use bowline_gateway::{
    serve_with_runtime_factory,
    writer::{spawn_managed_writer, ManagedWriterOptions},
    GatewayDeps,
};
use tokio::{net::TcpListener, sync::oneshot};

#[tokio::test]
async fn file_lease_serve_promotes_standby_after_active_shutdown() {
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    let lease_parent = root.path().join("lease");
    fs::create_dir(&lease_parent).unwrap();
    fs::set_permissions(&lease_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let lease_path = lease_parent.join("active.lock");
    let ledger_dir = root.path().join("ledger");
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        axum::serve(
            upstream_listener,
            Router::new().route(
                "/v1/chat/completions",
                post(|| async {
                    r#"{"model":"test-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#
                }),
            ),
        )
        .await
        .unwrap()
    });
    let first_address = unused_address();
    let second_address = unused_address();
    let first_config = file_config(first_address, upstream_address, &ledger_dir, &lease_path);
    let second_config = file_config(second_address, upstream_address, &ledger_dir, &lease_path);
    let first_activations = Arc::new(AtomicUsize::new(0));
    let second_activations = Arc::new(AtomicUsize::new(0));
    let first_factory = runtime_factory(&ledger_dir, Arc::clone(&first_activations));
    let second_factory = runtime_factory(&ledger_dir, Arc::clone(&second_activations));
    let (first_shutdown_tx, first_shutdown_rx) = oneshot::channel();
    let (second_shutdown_tx, second_shutdown_rx) = oneshot::channel();
    let first_task = tokio::spawn(async move {
        serve_with_runtime_factory(first_config, first_factory, async {
            let _ = first_shutdown_rx.await;
        })
        .await
    });
    let second_task = tokio::spawn(async move {
        serve_with_runtime_factory(second_config, second_factory, async {
            let _ = second_shutdown_rx.await;
        })
        .await
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    wait_live(&client, first_address).await;
    wait_live(&client, second_address).await;
    let (active, standby) = wait_for_roles(&client, first_address, second_address).await;

    assert_eq!(post_chat(&client, active).await, reqwest::StatusCode::OK);
    let standby_rejection = client
        .post(format!("http://{standby}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        standby_rejection.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        standby_rejection.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "standby-no-lease"
    );

    let (remaining_shutdown, active_task, standby_task) = if active == first_address {
        first_shutdown_tx.send(()).unwrap();
        (second_shutdown_tx, first_task, second_task)
    } else {
        second_shutdown_tx.send(()).unwrap();
        (first_shutdown_tx, second_task, first_task)
    };
    tokio::time::timeout(Duration::from_secs(2), active_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    wait_ready(&client, standby).await;
    assert_eq!(post_chat(&client, standby).await, reqwest::StatusCode::OK);
    remaining_shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), standby_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(first_activations.load(Ordering::Acquire), 1);
    assert_eq!(second_activations.load(Ordering::Acquire), 1);
    let manifests = RunStore::list_manifests(&ledger_dir).unwrap();
    assert_eq!(manifests.len(), 2);
    assert_ne!(manifests[0].run_id, manifests[1].run_id);
    assert!(manifests.iter().all(|manifest| manifest.clean_shutdown));

    upstream.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_lease_server_stays_live_while_initial_activation_is_in_progress() {
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    let lease_parent = root.path().join("lease");
    fs::create_dir(&lease_parent).unwrap();
    fs::set_permissions(&lease_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let lease_path = lease_parent.join("active.lock");
    let ledger_dir = root.path().join("ledger");
    let address = unused_address();
    let config = file_config(
        address,
        "127.0.0.1:9".parse().unwrap(),
        &ledger_dir,
        &lease_path,
    );
    let (activation_started_tx, activation_started_rx) = oneshot::channel();
    let (activation_release_tx, activation_release_rx) = std::sync::mpsc::channel();
    let activations = Arc::new(AtomicUsize::new(0));
    let mut inner_factory = runtime_factory(&ledger_dir, Arc::clone(&activations));
    let mut activation_started_tx = Some(activation_started_tx);
    let factory = move || {
        activation_started_tx.take().unwrap().send(()).unwrap();
        activation_release_rx.recv().unwrap();
        inner_factory()
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        serve_with_runtime_factory(config, factory, async {
            let _ = shutdown_rx.await;
        })
        .await
    });
    activation_started_rx.await.unwrap();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    wait_live(&client, address).await;
    let ready = client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        ready.json::<serde_json::Value>().await.unwrap()["reason"],
        "activation-in-progress"
    );
    let rejected = client
        .post(format!("http://{address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "activation-in-progress"
    );
    assert!(!ledger_dir.exists());

    activation_release_tx.send(()).unwrap();
    wait_ready(&client, address).await;
    assert_eq!(activations.load(Ordering::Acquire), 1);
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

fn unused_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn file_config(
    listen: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    ledger_dir: &std::path::Path,
    lease_path: &std::path::Path,
) -> Config {
    Config {
        listen: listen.to_string(),
        upstream: format!("http://{upstream}"),
        actual_supply_id: "public/test".into(),
        policy_bundle: "unused-policy.yaml".into(),
        registry_feed: "unused-registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger_dir.to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        state_backend: Some(StateBackendConfig::FileLease {
            version: 1,
            path: lease_path.to_path_buf(),
            poll_interval_ms: 25,
            takeover_timeout_ms: 1_000,
        }),
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
        runtime: RuntimeConfig::default(),
    }
}

fn runtime_factory(
    ledger_dir: &std::path::Path,
    activations: Arc<AtomicUsize>,
) -> impl FnMut() -> anyhow::Result<GatewayDeps> {
    let ledger_dir = ledger_dir.to_path_buf();
    move || {
        activations.fetch_add(1, Ordering::AcqRel);
        let policy = test_policy();
        let registry = test_registry();
        let writer = spawn_managed_writer(ManagedWriterOptions {
            directory: ledger_dir.clone(),
            policy_digest: policy.digest().to_string(),
            registry_digest: "sha256:test-registry".into(),
            attribution_digest: None,
            owned_cost_digest: Some(OwnedCostCatalog::default().normalized_digest().into()),
            passive_profile_digest: None,
            passive_input_digest: None,
            segment_bytes: 64 * 1024,
            max_segments: 8,
            queue_capacity: 16,
        })?;
        Ok(GatewayDeps::managed(
            policy,
            registry,
            Default::default(),
            OwnedCostCatalog::default(),
            writer,
        ))
    }
}

async fn wait_live(client: &reqwest::Client, address: std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if client
            .get(format!("http://{address}/health/live"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "{address} not live");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_roles(
    client: &reqwest::Client,
    first: std::net::SocketAddr,
    second: std::net::SocketAddr,
) -> (std::net::SocketAddr, std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let first_ready = is_ready(client, first).await;
        let second_ready = is_ready(client, second).await;
        match (first_ready, second_ready) {
            (true, false) => return (first, second),
            (false, true) => return (second, first),
            _ => {}
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "did not observe exactly one ready gateway"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_ready(client: &reqwest::Client, address: std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if is_ready(client, address).await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{address} did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn is_ready(client: &reqwest::Client, address: std::net::SocketAddr) -> bool {
    client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .is_ok_and(|response| response.status() == reqwest::StatusCode::OK)
}

async fn post_chat(client: &reqwest::Client, address: std::net::SocketAddr) -> reqwest::StatusCode {
    client
        .post(format!("http://{address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap()
        .status()
}

fn test_policy() -> PolicyBundle {
    PolicyBundle::from_yaml(
        r#"
version: 1
identities: []
rules:
  - name: default
    default: true
    require:
      supply_class: [public-api]
"#,
    )
    .unwrap()
}

fn test_registry() -> Registry {
    Registry::from_json(
        r#"{
  "feed_version": "test",
  "entries": [{
    "id": "public/test",
    "model": "test-model",
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
    "ratings": {"unclassified": 0.9}
  }]
}"#,
    )
    .unwrap()
}
