use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{body::Body, http::StatusCode};
use bowline_core::{
    config::{
        Config, InlineAttributionConfig, InlineAttributionMapping, OwnedCostCatalog, RuntimeConfig,
        StateBackendConfig,
    },
    policy::PolicyBundle,
    supply::Registry,
};
use bowline_gateway::{
    serving_lease::{FileServingLease, LocalServingLease, ServingLease},
    supervisor::GatewaySupervisor,
    writer::{spawn_managed_writer, ManagedWriter, ManagedWriterOptions},
    GatewayDeps,
};
use bytes::Bytes;
use tokio::{net::TcpListener, sync::Notify};

fn lease_tempdir() -> tempfile::TempDir {
    let system_temp = std::env::temp_dir().canonicalize().unwrap();
    tempfile::tempdir_in(system_temp).unwrap()
}

#[test]
fn local_serving_lease_is_always_active() {
    let mut lease = LocalServingLease;

    assert!(lease.try_acquire().unwrap());
    assert!(lease.may_admit());
    lease.release().unwrap();
    assert!(lease.may_admit());
}

#[tokio::test]
async fn standby_router_defers_runtime_until_local_activation() {
    let temp = tempfile::tempdir().unwrap();
    let ledger_dir = temp.path().join("ledger");
    let config = test_config(&ledger_dir);
    let mut supervisor = GatewaySupervisor::new(config.clone(), LocalServingLease).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = supervisor.router();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let client = reqwest::Client::new();

    let live = client
        .get(format!("http://{address}/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
    let ready = client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!ledger_dir.exists());

    let activations = Arc::new(AtomicUsize::new(0));
    let writer_slot = Arc::new(Mutex::new(None::<ManagedWriter>));
    let activation_count = Arc::clone(&activations);
    let activation_writer = Arc::clone(&writer_slot);
    let activation_ledger = ledger_dir.clone();
    let policy = test_policy();
    let registry = test_registry();
    let mut factory = move || {
        activation_count.fetch_add(1, Ordering::AcqRel);
        let writer = spawn_managed_writer(ManagedWriterOptions {
            directory: activation_ledger.clone(),
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
        *activation_writer.lock().unwrap() = Some(writer.clone());
        Ok(GatewayDeps::managed(
            policy.clone(),
            registry.clone(),
            Default::default(),
            OwnedCostCatalog::default(),
            writer,
        ))
    };
    let summary = supervisor.activate(&mut factory).await.unwrap();

    assert_eq!(activations.load(Ordering::Acquire), 1);
    assert_eq!(
        summary.run_id,
        Some(
            writer_slot
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .health()
                .snapshot()
                .run_id,
        )
    );
    let ready = client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);

    supervisor.deactivate(Duration::from_secs(1)).await.unwrap();
    assert!(
        writer_slot
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .health()
            .snapshot()
            .clean_shutdown
    );
    let ready = client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

    server.abort();
}

#[tokio::test]
async fn file_lease_allows_one_active_and_fresh_run_takeover() {
    let root = lease_tempdir();
    let lease_parent = root.path().join("lease");
    std::fs::create_dir(&lease_parent).unwrap();
    std::fs::set_permissions(&lease_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lease_path = lease_parent.join("active.lock");
    let ledger_dir = root.path().join("ledger");
    let first_config = file_lease_config(&ledger_dir, &lease_path);
    let second_config = file_lease_config(&ledger_dir, &lease_path);
    let mut first =
        GatewaySupervisor::new(first_config, FileServingLease::open(&lease_path).unwrap()).unwrap();
    let mut second =
        GatewaySupervisor::new(second_config, FileServingLease::open(&lease_path).unwrap())
            .unwrap();
    let (first_address, first_server) = spawn_router(first.router()).await;
    let (second_address, second_server) = spawn_router(second.router()).await;
    let first_writers = Arc::new(Mutex::new(Vec::<ManagedWriter>::new()));
    let second_writers = Arc::new(Mutex::new(Vec::<ManagedWriter>::new()));
    let mut first_factory = managed_factory(&ledger_dir, Arc::clone(&first_writers));
    let mut second_factory = managed_factory(&ledger_dir, Arc::clone(&second_writers));

    first
        .reconcile(&mut first_factory, Duration::from_secs(1))
        .await
        .unwrap();
    second
        .reconcile(&mut second_factory, Duration::from_secs(1))
        .await
        .unwrap();

    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("http://{first_address}/health/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let standby_ready = client
        .get(format!("http://{second_address}/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(standby_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        standby_ready.json::<serde_json::Value>().await.unwrap()["reason"],
        "standby-no-lease"
    );
    let standby_status = client
        .get(format!("http://{second_address}/health/status"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(standby_status["serving_state"], "standby");
    let rejected = client
        .post(format!("http://{second_address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "standby-no-lease"
    );
    assert!(second_writers.lock().unwrap().is_empty());

    let first_run = first_writers.lock().unwrap()[0].health().snapshot().run_id;
    first.deactivate(Duration::from_secs(1)).await.unwrap();
    first_writers.lock().unwrap().clear();
    second
        .reconcile(&mut second_factory, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(second_writers.lock().unwrap().len(), 1);
    let second_run = second_writers.lock().unwrap()[0].health().snapshot().run_id;
    assert_ne!(first_run, second_run);
    assert_eq!(
        client
            .get(format!("http://{second_address}/health/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    second.deactivate(Duration::from_secs(1)).await.unwrap();
    first_server.abort();
    second_server.abort();
}

#[tokio::test]
async fn activation_failure_releases_partial_writer_before_retry() {
    let root = lease_tempdir();
    let lease_parent = root.path().join("lease");
    std::fs::create_dir(&lease_parent).unwrap();
    std::fs::set_permissions(&lease_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lease_path = lease_parent.join("active.lock");
    let ledger_dir = root.path().join("ledger");
    let mut config = file_lease_config(&ledger_dir, &lease_path);
    config.attribution = Some(InlineAttributionConfig {
        version: 1,
        response_header: "x-upstream-supply".into(),
        namespace: "test".into(),
        mappings: vec![InlineAttributionMapping {
            value: "primary".into(),
            supply_id: "public/test".into(),
        }],
    });
    let mut supervisor =
        GatewaySupervisor::new(config, FileServingLease::open(&lease_path).unwrap()).unwrap();
    let (address, server) = spawn_router(supervisor.router()).await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempt_count = Arc::clone(&attempts);
    let factory_ledger = ledger_dir.clone();
    let mut factory = move || {
        let attempt = attempt_count.fetch_add(1, Ordering::AcqRel);
        let policy = test_policy();
        let registry = if attempt == 0 {
            Registry::from_json(
                r#"{
  "feed_version": "invalid-first",
  "entries": [{
    "id": "public/other",
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
        } else {
            test_registry()
        };
        let writer = spawn_managed_writer(ManagedWriterOptions {
            directory: factory_ledger.clone(),
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
    };

    assert!(supervisor
        .reconcile(&mut factory, Duration::from_secs(1))
        .await
        .is_err());
    let status = reqwest::get(format!("http://{address}/health/status"))
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(status["serving_state"], "standby");
    assert_eq!(status["last_activation_reason"], "activation-failed");

    supervisor
        .reconcile(&mut factory, Duration::from_secs(1))
        .await
        .unwrap();
    let status = reqwest::get(format!("http://{address}/health/status"))
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(status["serving_state"], "active");
    assert!(status.get("last_activation_reason").is_none());

    supervisor.deactivate(Duration::from_secs(1)).await.unwrap();
    assert_eq!(attempts.load(Ordering::Acquire), 2);
    let manifests = bowline_core::run::RunStore::list_manifests(&ledger_dir).unwrap();
    assert_eq!(manifests.len(), 2);
    assert_eq!(
        manifests
            .iter()
            .filter(|manifest| manifest.writer_healthy)
            .count(),
        1
    );
    assert!(manifests
        .iter()
        .any(|manifest| { manifest.writer_error.as_deref() == Some("activation-failed") }));
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activating_is_unready_and_rejects_inference_until_runtime_is_complete() {
    let root = lease_tempdir();
    let ledger_dir = root.path().join("ledger");
    let lease_path = root.path().join("unused.lock");
    let config = file_lease_config(&ledger_dir, &lease_path);
    let owner = Arc::new(AtomicUsize::new(0));
    let mut supervisor =
        GatewaySupervisor::new(config, TestServingLease::new(1, Arc::clone(&owner))).unwrap();
    let (address, server) = spawn_router(supervisor.router()).await;
    let (activation_started_tx, activation_started_rx) = tokio::sync::oneshot::channel();
    let (activation_release_tx, activation_release_rx) = std::sync::mpsc::channel();
    let mut inner_factory = managed_factory(&ledger_dir, Arc::new(Mutex::new(Vec::new())));
    let mut activation_started_tx = Some(activation_started_tx);
    let mut factory = move || {
        activation_started_tx.take().unwrap().send(()).unwrap();
        activation_release_rx.recv().unwrap();
        inner_factory()
    };
    let activation = tokio::spawn(async move {
        let result = supervisor
            .reconcile(&mut factory, Duration::from_secs(1))
            .await;
        (supervisor, result)
    });
    activation_started_rx.await.unwrap();

    let client = reqwest::Client::new();
    let ready = client
        .get(format!("http://{address}/health/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        ready.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "mode": "shadow",
            "ready": false,
            "reason": "activation-in-progress"
        })
    );
    let status = client
        .get(format!("http://{address}/health/status"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        status,
        serde_json::json!({
            "mode": "shadow",
            "ready": false,
            "reason": "durable recording is not configured",
            "serving_state": "activating"
        })
    );
    let rejected = client
        .post(format!("http://{address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({"error": {"code": "activation-in-progress"}})
    );
    assert!(!ledger_dir.exists());

    activation_release_tx.send(()).unwrap();
    let (mut supervisor, result) = activation.await.unwrap();
    result.unwrap();
    assert_eq!(
        client
            .get(format!("http://{address}/health/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    supervisor.deactivate(Duration::from_secs(1)).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn lease_loss_stops_new_admission_before_peer_activation() {
    let root = lease_tempdir();
    let ledger_dir = root.path().join("ledger");
    let lease_path = root.path().join("unused.lock");
    let (upstream_address, started, release, upstream) = spawn_streaming_upstream().await;
    let mut first_config = file_lease_config(&ledger_dir, &lease_path);
    first_config.upstream = format!("http://{upstream_address}");
    let mut second_config = file_lease_config(&ledger_dir, &lease_path);
    second_config.upstream = format!("http://{upstream_address}");
    let owner = Arc::new(AtomicUsize::new(0));
    let mut first =
        GatewaySupervisor::new(first_config, TestServingLease::new(1, Arc::clone(&owner))).unwrap();
    let mut second =
        GatewaySupervisor::new(second_config, TestServingLease::new(2, Arc::clone(&owner)))
            .unwrap();
    let (first_address, first_server) = spawn_router(first.router()).await;
    let (second_address, second_server) = spawn_router(second.router()).await;
    let mut first_factory = managed_factory(&ledger_dir, Arc::new(Mutex::new(Vec::new())));
    let mut second_factory = managed_factory(&ledger_dir, Arc::new(Mutex::new(Vec::new())));
    first
        .reconcile(&mut first_factory, Duration::from_secs(1))
        .await
        .unwrap();
    second
        .reconcile(&mut second_factory, Duration::from_secs(1))
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let accepted = client
        .post(format!("http://{first_address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    started.notified().await;

    owner.store(2, Ordering::Release);
    let mut drain = tokio::spawn(async move {
        let result = first
            .reconcile(&mut first_factory, Duration::from_secs(1))
            .await;
        (first, first_factory, result)
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut drain)
            .await
            .is_err(),
        "lease-loss drain completed before the accepted response stream"
    );
    wait_for_ready_reason(&client, first_address, "draining").await;
    let rejected = client
        .post(format!("http://{first_address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "draining"
    );
    assert_eq!(
        client
            .get(format!("http://{second_address}/health/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    release.notify_one();
    assert_eq!(accepted.status(), StatusCode::OK);
    let body = accepted.text().await.unwrap();
    assert_eq!(
        body,
        r#"{"model":"test-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#
    );
    let (mut first, _, drain_result) = drain.await.unwrap();
    drain_result.unwrap();
    second
        .reconcile(&mut second_factory, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        client
            .get(format!("http://{second_address}/health/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    first.deactivate(Duration::from_secs(1)).await.unwrap();
    second.deactivate(Duration::from_secs(1)).await.unwrap();
    first_server.abort();
    second_server.abort();
    upstream.abort();
}

#[tokio::test]
async fn drain_timeout_keeps_serving_lease_held_until_process_cleanup() {
    let root = lease_tempdir();
    let ledger_dir = root.path().join("ledger");
    let lease_path = root.path().join("unused.lock");
    let (upstream_address, started, release, upstream) = spawn_streaming_upstream().await;
    let mut config = file_lease_config(&ledger_dir, &lease_path);
    config.upstream = format!("http://{upstream_address}");
    let available = Arc::new(AtomicBool::new(true));
    let releases = Arc::new(AtomicUsize::new(0));
    let lease = LossTrackingLease::new(Arc::clone(&available), Arc::clone(&releases));
    let mut supervisor = GatewaySupervisor::new(config, lease).unwrap();
    let (address, server) = spawn_router(supervisor.router()).await;
    let writers = Arc::new(Mutex::new(Vec::new()));
    let mut factory = managed_factory(&ledger_dir, Arc::clone(&writers));
    supervisor
        .reconcile(&mut factory, Duration::from_secs(1))
        .await
        .unwrap();
    writers.lock().unwrap().clear();
    let client = reqwest::Client::new();
    let accepted = client
        .post(format!("http://{address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    started.notified().await;

    available.store(false, Ordering::Release);
    let error = supervisor
        .reconcile(&mut factory, Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("gateway request drain exceeded shutdown grace"),
        "unexpected drain error: {error:#}"
    );
    assert_eq!(releases.load(Ordering::Acquire), 0);
    wait_for_ready_reason(&client, address, "draining").await;
    let rejected = client
        .post(format!("http://{address}/v1/chat/completions"))
        .body(r#"{"model":"test-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "draining"
    );

    release.notify_one();
    let _ = accepted.text().await.unwrap();
    supervisor.deactivate(Duration::from_secs(1)).await.unwrap();
    assert_eq!(releases.load(Ordering::Acquire), 1);
    server.abort();
    upstream.abort();
}

async fn spawn_streaming_upstream() -> (
    std::net::SocketAddr,
    Arc<Notify>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream_started = Arc::clone(&started);
    let upstream_release = Arc::clone(&release);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().route(
                "/v1/chat/completions",
                axum::routing::post(move || {
                    let started = Arc::clone(&upstream_started);
                    let release = Arc::clone(&upstream_release);
                    async move {
                        started.notify_one();
                        let stream = futures_util::stream::unfold(0_u8, move |state| {
                            let release = Arc::clone(&release);
                            async move {
                                match state {
                                    0 => Some((
                                        Ok::<_, std::io::Error>(Bytes::from_static(b"{")),
                                        1,
                                    )),
                                    1 => {
                                        release.notified().await;
                                        Some((
                                            Ok(Bytes::from_static(
                                                br#""model":"test-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                                            )),
                                            2,
                                        ))
                                    }
                                    _ => None,
                                }
                            }
                        });
                        Body::from_stream(stream)
                    }
                }),
            ),
        )
        .await
        .unwrap()
    });
    (address, started, release, server)
}

async fn wait_for_ready_reason(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    expected: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(response) = client
            .get(format!("http://{address}/health/ready"))
            .send()
            .await
        {
            let value = response.json::<serde_json::Value>().await.unwrap();
            if value["reason"] == expected {
                return;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "did not observe ready reason {expected}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct LossTrackingLease {
    held: bool,
    available: Arc<AtomicBool>,
    releases: Arc<AtomicUsize>,
}

impl LossTrackingLease {
    fn new(available: Arc<AtomicBool>, releases: Arc<AtomicUsize>) -> Self {
        Self {
            held: false,
            available,
            releases,
        }
    }
}

impl ServingLease for LossTrackingLease {
    fn try_acquire(&mut self) -> anyhow::Result<bool> {
        if self.held {
            return Ok(true);
        }
        self.held = self.available.load(Ordering::Acquire);
        Ok(self.held)
    }

    fn may_admit(&self) -> bool {
        self.held && self.available.load(Ordering::Acquire)
    }

    fn release(&mut self) -> anyhow::Result<()> {
        if self.held {
            self.releases.fetch_add(1, Ordering::AcqRel);
            self.held = false;
        }
        Ok(())
    }
}

struct TestServingLease {
    id: usize,
    owner: Arc<AtomicUsize>,
}

impl TestServingLease {
    fn new(id: usize, owner: Arc<AtomicUsize>) -> Self {
        Self { id, owner }
    }
}

impl ServingLease for TestServingLease {
    fn try_acquire(&mut self) -> anyhow::Result<bool> {
        if self.owner.load(Ordering::Acquire) == self.id {
            return Ok(true);
        }
        Ok(self
            .owner
            .compare_exchange(0, self.id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    fn may_admit(&self) -> bool {
        self.owner.load(Ordering::Acquire) == self.id
    }

    fn release(&mut self) -> anyhow::Result<()> {
        let _ = self
            .owner
            .compare_exchange(self.id, 0, Ordering::AcqRel, Ordering::Acquire);
        Ok(())
    }
}

async fn spawn_router(router: axum::Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    (address, server)
}

fn managed_factory(
    ledger_dir: &std::path::Path,
    writers: Arc<Mutex<Vec<ManagedWriter>>>,
) -> impl FnMut() -> anyhow::Result<GatewayDeps> {
    let ledger_dir = ledger_dir.to_path_buf();
    move || {
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
        writers.lock().unwrap().push(writer.clone());
        Ok(GatewayDeps::managed(
            policy,
            registry,
            Default::default(),
            OwnedCostCatalog::default(),
            writer,
        ))
    }
}

fn test_config(ledger_dir: &std::path::Path) -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        upstream: "http://127.0.0.1:9".into(),
        actual_supply_id: "public/test".into(),
        policy_bundle: "unused-policy.yaml".into(),
        registry_feed: "unused-registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger_dir.to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        authority_signing: None,
        state_backend: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
        runtime: RuntimeConfig::default(),
    }
}

fn file_lease_config(ledger_dir: &std::path::Path, lease_path: &std::path::Path) -> Config {
    let mut config = test_config(ledger_dir);
    config.state_backend = Some(StateBackendConfig::FileLease {
        version: 1,
        path: lease_path.to_path_buf(),
        poll_interval_ms: 10,
        takeover_timeout_ms: 1_000,
    });
    config
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
