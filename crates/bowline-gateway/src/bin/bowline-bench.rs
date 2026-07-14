use std::{
    convert::Infallible,
    env, fs,
    path::{Path, PathBuf},
    process,
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::OriginalUri,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use bowline_core::{
    config::{Config, OwnedCostCatalog, RuntimeConfig},
    decision::QualityFloors,
    policy::PolicyBundle,
    supply::Registry,
};
use bowline_gateway::{
    writer::{spawn_managed_writer, ManagedWriter, ManagedWriterOptions},
    GatewayDeps, GatewayState,
};
use futures_util::stream;
use tokio::{net::TcpListener, task::JoinHandle};

const REQUESTS: usize = 500;
const WARMUP_REQUESTS: usize = 25;
const BUDGET_P95_ADDED_MS: f64 = 5.0;
const CHAT_REQUEST: &str =
    r#"{"model":"gpt-5-mini","messages":[{"role":"user","content":"bench"}]}"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let allow_fail = parse_args()?;
    let bowline_root = bowline_root();
    let policy_path = bowline_root.join("policies/default.yaml");
    let registry_path = bowline_root.join("registry/feed.json");

    let echo = spawn_echo_upstream().await?;
    let client = reqwest::Client::new();

    run_warmup(&client, &echo.base_url).await?;
    let direct = measure(&client, &echo.base_url).await?;

    let ledger = tempfile::tempdir().context("failed to create temporary ledger directory")?;
    let gateway = spawn_gateway_with_shadow(
        echo.base_url.clone(),
        ledger.path(),
        &policy_path,
        &registry_path,
    )
    .await?;

    run_warmup(&client, &gateway.server.base_url).await?;
    let gateway_stats = measure(&client, &gateway.server.base_url).await?;

    let added_p50_ms = gateway_stats.p50_ms - direct.p50_ms;
    let added_p95_ms = gateway_stats.p95_ms - direct.p95_ms;
    let added_p99_ms = gateway_stats.p99_ms - direct.p99_ms;
    let passed = added_p95_ms < BUDGET_P95_ADDED_MS;
    gateway.server.handle.abort();
    gateway
        .writer
        .shutdown(Duration::from_secs(30))
        .await
        .context("failed to drain benchmark ledger writer")?;
    let evidence = gateway.writer.health().snapshot();

    println!("bowline latency bench");
    println!("requests {REQUESTS}");
    println!("warmup_requests {WARMUP_REQUESTS}");
    println!(
        "direct_echo p50={:.3}ms p95={:.3}ms p99={:.3}ms",
        direct.p50_ms, direct.p95_ms, direct.p99_ms
    );
    println!(
        "gateway_shadow p50={:.3}ms p95={:.3}ms p99={:.3}ms",
        gateway_stats.p50_ms, gateway_stats.p95_ms, gateway_stats.p99_ms
    );
    println!(
        "added_delta p50={:.3}ms p95={:.3}ms p99={:.3}ms",
        added_p50_ms, added_p95_ms, added_p99_ms
    );
    println!("run_id {}", evidence.run_id);
    println!(
        "evidence accepted={} recorded={} dropped={} truncated={}",
        evidence.accepted, evidence.recorded, evidence.dropped, evidence.truncated
    );
    println!(
        "budget added_p95<{BUDGET_P95_ADDED_MS:.3}ms {}",
        if passed { "PASS" } else { "FAIL" }
    );

    if !passed && !allow_fail {
        process::exit(1);
    }

    Ok(())
}

fn parse_args() -> anyhow::Result<bool> {
    let mut allow_fail = false;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--allow-fail" => allow_fail = true,
            "-h" | "--help" => {
                println!("Usage: bowline-bench [--allow-fail]");
                process::exit(0);
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }

    Ok(allow_fail)
}

fn bowline_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

async fn spawn_echo_upstream() -> anyhow::Result<Server> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind echo upstream")?;
    let addr = listener
        .local_addr()
        .context("failed to read echo upstream address")?;
    let app = Router::new().fallback(any(echo_handler));
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(error = %err, "echo upstream failed");
        }
    });

    Ok(Server {
        base_url: format!("http://{addr}"),
        handle,
    })
}

async fn spawn_gateway_with_shadow(
    upstream: String,
    ledger_dir: &Path,
    policy_path: &Path,
    registry_path: &Path,
) -> anyhow::Result<BenchmarkGateway> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind gateway")?;
    let addr = listener
        .local_addr()
        .context("failed to read gateway address")?;
    let (deps, writer) = load_recording_deps(ledger_dir, policy_path, registry_path)?;
    let config = Config {
        listen: addr.to_string(),
        upstream,
        actual_supply_id: "openai/gpt-5-mini".to_string(),
        policy_bundle: policy_path.to_path_buf(),
        registry_feed: registry_path.to_path_buf(),
        local_endpoints: Vec::new(),
        ledger_dir: ledger_dir.to_path_buf(),
        tco: None,
        attribution: None,
        floors: None,
        enforcement: None,
        trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
        runtime: RuntimeConfig::default(),
    };
    let app = GatewayState::from_config(&config, deps)?.router();
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = %err, "gateway failed");
        }
    });

    Ok(BenchmarkGateway {
        server: Server {
            base_url: format!("http://{addr}"),
            handle,
        },
        writer,
    })
}

fn load_recording_deps(
    ledger_dir: &Path,
    policy_path: &Path,
    registry_path: &Path,
) -> anyhow::Result<(GatewayDeps, ManagedWriter)> {
    let policy_source = fs::read_to_string(policy_path)
        .with_context(|| format!("failed to read policy bundle {}", policy_path.display()))?;
    let registry_source = fs::read_to_string(registry_path)
        .with_context(|| format!("failed to read registry feed {}", registry_path.display()))?;
    let policy =
        PolicyBundle::from_yaml(&policy_source).context("failed to parse policy bundle")?;
    let registry =
        Registry::from_json(&registry_source).context("failed to parse registry feed")?;
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: ledger_dir.to_path_buf(),
        policy_digest: policy.digest().to_string(),
        registry_digest: "sha256:benchmark-registry".to_string(),
        attribution_digest: None,
        owned_cost_digest: None,
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: RuntimeConfig::default().ledger_segment_bytes,
        max_segments: RuntimeConfig::default().ledger_max_segments,
        queue_capacity: RuntimeConfig::default().writer_queue_capacity,
    })
    .context("failed to start managed ledger writer")?;

    let deps = GatewayDeps::managed(
        policy,
        registry,
        QualityFloors::default(),
        OwnedCostCatalog::default(),
        writer.clone(),
    );
    Ok((deps, writer))
}

async fn run_warmup(client: &reqwest::Client, base_url: &str) -> anyhow::Result<()> {
    for _ in 0..WARMUP_REQUESTS {
        post_chat(client, base_url).await?;
    }

    Ok(())
}

async fn measure(client: &reqwest::Client, base_url: &str) -> anyhow::Result<Stats> {
    let mut samples = Vec::with_capacity(REQUESTS);

    for _ in 0..REQUESTS {
        let started = Instant::now();
        post_chat(client, base_url).await?;
        samples.push(started.elapsed());
    }

    Ok(Stats::from_samples(&mut samples))
}

async fn post_chat(client: &reqwest::Client, base_url: &str) -> anyhow::Result<()> {
    let response = client
        .post(format!("{base_url}/v1/chat/completions"))
        .header("authorization", "Bearer bench-secret")
        .header("content-type", "application/json")
        .header("x-bowline-app", "bench")
        .header("x-bowline-task-class", "mechanical")
        .body(CHAT_REQUEST)
        .send()
        .await
        .context("chat/completions request failed")?;
    let status = response.status();
    let _ = response
        .bytes()
        .await
        .context("chat/completions response body failed")?;

    if !status.is_success() {
        bail!("chat/completions returned status {status}");
    }

    Ok(())
}

#[derive(Debug)]
struct Stats {
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

impl Stats {
    fn from_samples(samples: &mut [Duration]) -> Self {
        samples.sort_unstable();

        Self {
            p50_ms: percentile_ms(samples, 50),
            p95_ms: percentile_ms(samples, 95),
            p99_ms: percentile_ms(samples, 99),
        }
    }
}

fn percentile_ms(samples: &[Duration], percentile: usize) -> f64 {
    assert!(!samples.is_empty(), "latency samples must not be empty");
    let rank = (percentile * samples.len()).div_ceil(100).max(1);
    let index = rank.saturating_sub(1).min(samples.len() - 1);

    samples[index].as_secs_f64() * 1_000.0
}

struct Server {
    base_url: String,
    handle: JoinHandle<()>,
}

struct BenchmarkGateway {
    server: Server,
    writer: ManagedWriter,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn echo_handler(OriginalUri(uri): OriginalUri, body: Body) -> Response<Body> {
    let body = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    if uri.path() == "/v1/chat/completions" {
        if request_is_streaming(&body) {
            return sse_response();
        }

        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":5}}"#,
        )
            .into_response();
    }

    (StatusCode::OK, r#"{"echo":true}"#).into_response()
}

fn request_is_streaming(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(|stream| stream.as_bool()))
        .unwrap_or(false)
}

fn sse_response() -> Response<Body> {
    let chunks = [
        Bytes::from_static(br#"data: {"choices":[{"delta":{"content":"one"}}]}"#),
        Bytes::from_static(b"\n\n"),
        Bytes::from_static(br#"data: {"choices":[{"delta":{"content":"two"}}]}"#),
        Bytes::from_static(b"\n\n"),
        Bytes::from_static(br#"data: {"usage":{"prompt_tokens":7,"completion_tokens":5}}"#),
        Bytes::from_static(b"\n\n"),
        Bytes::from_static(b"data: [DONE]\n\n"),
    ];
    let stream = stream::iter(chunks.map(Ok::<Bytes, Infallible>));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("static SSE response builds")
}
