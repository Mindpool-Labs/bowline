use std::{collections::BTreeSet, time::Duration};

use axum::{routing::post, Json, Router};
use bowline_core::{
    config::{Config, OwnedCostCatalog, RuntimeConfig},
    ledger::SegmentedLedger,
    policy::PolicyBundle,
    run::RunStore,
    supply::Registry,
};
use bowline_gateway::{
    writer::{spawn_managed_writer, ManagedWriterOptions},
    GatewayDeps, GatewayState,
};
use futures_util::{stream, StreamExt};
use serde_json::json;
use tokio::{net::TcpListener, task::JoinHandle};

const REQUESTS: u64 = 5_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_thousand_requests_leave_reconcilable_durable_evidence() {
    let upstream = spawn_upstream().await;
    let ledger = tempfile::tempdir().expect("temporary ledger");
    let policy = PolicyBundle::from_yaml(include_str!("../../../policies/default.yaml"))
        .expect("default policy");
    let registry =
        Registry::from_json(include_str!("../../../registry/feed.json")).expect("seed registry");
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: ledger.path().to_path_buf(),
        policy_digest: policy.digest().to_string(),
        registry_digest: "sha256:load-test-registry".to_string(),
        attribution_digest: None,
        owned_cost_digest: None,
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: 4 * 1024 * 1024,
        max_segments: 8,
        queue_capacity: REQUESTS as usize,
    })
    .expect("managed writer");
    let run_id = writer.health().snapshot().run_id;
    let config = Config {
        listen: "127.0.0.1:0".to_string(),
        upstream: upstream.base_url.clone(),
        actual_supply_id: "openai/gpt-5-mini".to_string(),
        policy_bundle: "unused-policy.yaml".into(),
        registry_feed: "unused-registry.json".into(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger.path().to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        authority_signing: None,
        promotion_approval: None,
        state_backend: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
        runtime: RuntimeConfig {
            writer_queue_capacity: REQUESTS as usize,
            ledger_segment_bytes: 4 * 1024 * 1024,
            ledger_max_segments: 8,
            ..RuntimeConfig::default()
        },
    };
    let deps = GatewayDeps::managed(
        policy,
        registry,
        Default::default(),
        OwnedCostCatalog::default(),
        writer.clone(),
    );
    let gateway = spawn_gateway(&config, deps).await;
    let client = reqwest::Client::new();

    let results = stream::iter(0..REQUESTS)
        .map(|_| {
            let client = client.clone();
            let url = format!("{}/v1/chat/completions", gateway.base_url);
            async move {
                client
                    .post(url)
                    .json(&json!({
                        "model": "gpt-5-mini",
                        "messages": [{"role": "user", "content": "load"}]
                    }))
                    .send()
                    .await
                    .expect("gateway response")
                    .error_for_status()
                    .expect("successful gateway status")
                    .bytes()
                    .await
                    .expect("gateway body")
            }
        })
        .buffer_unordered(64)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(results.len(), REQUESTS as usize);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = writer.health().snapshot();
        if snapshot.recorded + snapshot.dropped == snapshot.accepted {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "writer failed to reconcile accepted work: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    gateway.handle.abort();
    writer
        .shutdown(Duration::from_secs(20))
        .await
        .expect("writer drains cleanly");

    let manifests = RunStore::list_manifests(ledger.path()).expect("run manifests");
    assert_eq!(manifests.len(), 1);
    let manifest = &manifests[0];
    assert_eq!(manifest.run_id, run_id);
    assert_eq!(manifest.accepted, REQUESTS);
    assert_eq!(manifest.accepted, manifest.recorded + manifest.dropped);
    assert!(manifest.clean_shutdown);
    assert!(manifest.writer_healthy, "manifest: {manifest:?}");

    let (records, recovery) =
        SegmentedLedger::read_run(ledger.path(), &run_id).expect("ledger read");
    assert!(
        recovery.iter().all(|outcome| !outcome.blocks_append()),
        "recovery: {recovery:?}"
    );
    assert_eq!(records.len() as u64, manifest.recorded);
    let sequences = records
        .iter()
        .map(|record| record.sequence.expect("managed record sequence"))
        .collect::<BTreeSet<_>>();
    assert_eq!(sequences.len(), records.len(), "sequences must be unique");
    assert!(
        sequences.iter().all(|sequence| *sequence <= REQUESTS),
        "sequences must stay within the accepted range"
    );
    assert_eq!(REQUESTS - sequences.len() as u64, manifest.dropped);
}

async fn spawn_upstream() -> TestServer {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            Json(json!({
                "model": "gpt-5-mini",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5}
            }))
        }),
    );
    spawn(app, false).await
}

async fn spawn_gateway(config: &Config, deps: GatewayDeps) -> TestServer {
    let app = GatewayState::from_config(config, deps)
        .expect("gateway state")
        .router();
    spawn(app, true).await
}

async fn spawn(app: Router, connect_info: bool) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("server bind");
    let address = listener.local_addr().expect("server address");
    let handle = if connect_info {
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("server runs");
        })
    } else {
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server runs");
        })
    };
    TestServer {
        base_url: format!("http://{address}"),
        handle,
    }
}

struct TestServer {
    base_url: String,
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
