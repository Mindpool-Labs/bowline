use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::http::StatusCode;
use bowline_core::{
    config::{Config, OwnedCostCatalog, RuntimeConfig},
    policy::PolicyBundle,
    supply::Registry,
};
use bowline_gateway::{
    serving_lease::{LocalServingLease, ServingLease},
    supervisor::GatewaySupervisor,
    writer::{spawn_managed_writer, ManagedWriter, ManagedWriterOptions},
    GatewayDeps,
};
use tokio::net::TcpListener;

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
    let summary = supervisor
        .activate(move || {
            activation_count.fetch_add(1, Ordering::AcqRel);
            let writer = spawn_managed_writer(ManagedWriterOptions {
                directory: activation_ledger,
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
                policy,
                registry,
                Default::default(),
                OwnedCostCatalog::default(),
                writer,
            ))
        })
        .await
        .unwrap();

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
        state_backend: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
        runtime: RuntimeConfig::default(),
    }
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
