#![cfg(unix)]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bowline_core::{
    billing_run::BillingRunStore,
    ledger::{Ledger, SegmentedLedger},
    run::RunStore,
};

#[test]
fn promotion_seal_cli_surface_dispatches_to_the_sealer() {
    let dir = tempdir("promotion-seal-surface");
    let missing = dir.join("missing.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .args([
            "promotion",
            "seal",
            "--config",
            missing.to_str().unwrap(),
            "--route",
            "support-chat",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to read config"), "stderr: {stderr}");
    assert!(
        !stderr.contains("unrecognized subcommand"),
        "stderr: {stderr}"
    );
}

#[test]
fn relative_config_keeps_promotion_evidence_relative_to_its_absolute_directory() {
    let dir = tempdir("relative-promotion-config");
    write_relative_controlled_fixture(&dir, "support-chat");

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .current_dir(&dir)
        .args([
            "promotion",
            "seal",
            "--config",
            "config/bowline.yaml",
            "--route",
            "support-chat",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enforcement evidence"), "stderr: {stderr}");
    assert!(
        !stderr.contains("evidence root must be absolute"),
        "stderr: {stderr}"
    );
}

#[test]
fn relative_config_keeps_managed_serve_evidence_relative_to_its_absolute_directory() {
    let dir = tempdir("relative-serve-config");
    write_relative_controlled_fixture(&dir, "support-chat");

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .current_dir(&dir)
        .args(["serve", "--config", "config/bowline.yaml"])
        .env("BOWLINE_TEST_TOKEN", "Bearer test")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enforcement evidence"), "stderr: {stderr}");
    assert!(
        !stderr.contains("evidence root must be absolute"),
        "stderr: {stderr}"
    );
}

#[test]
fn relative_config_keeps_preflight_evidence_relative_to_its_absolute_directory() {
    let dir = tempdir("relative-preflight-config");
    write_relative_controlled_fixture(&dir, "support-chat");

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .current_dir(&dir)
        .args(["preflight", "--config", "config/bowline.yaml", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("enforcement-evidence"), "stdout: {stdout}");
    assert!(
        !stdout.contains("evidence root must be absolute"),
        "stdout: {stdout}"
    );
}

#[test]
fn promotion_seal_failure_sanitizes_route_identifier() {
    let dir = tempdir("promotion-seal-failure-route-output");
    let route_id = "support\u{202e}evil\u{2028}next";
    write_relative_controlled_fixture(&dir, route_id);

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .current_dir(&dir)
        .args([
            "promotion",
            "seal",
            "--config",
            "config/bowline.yaml",
            "--route",
            route_id,
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let mut operator_output = output.stdout;
    operator_output.extend_from_slice(&output.stderr);
    assert_safe_route_failure_output(&operator_output, route_id);
}

#[test]
fn authority_startup_failure_sanitizes_route_identifier() {
    let dir = tempdir("authority-startup-failure-route-output");
    let route_id = "support\u{202e}evil\u{2028}next";
    write_relative_controlled_fixture(&dir, route_id);

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .current_dir(&dir)
        .args(["serve", "--config", "config/bowline.yaml"])
        .env("BOWLINE_TEST_TOKEN", "Bearer test")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_safe_route_failure_output(&output.stderr, route_id);
}

#[test]
fn recommendation_verification_warning_sanitizes_route_identifier() {
    let dir = tempdir("recommendation-warning-route-output");
    let route_id = "support\u{202e}evil\u{2028}next";
    write_relative_controlled_fixture_with_mode(&dir, route_id, "recommend");

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .current_dir(&dir)
        .args(["serve", "--config", "config/bowline.yaml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let mut operator_output = output.stdout;
    operator_output.extend_from_slice(&output.stderr);
    assert_safe_route_failure_output(&operator_output, route_id);
}

fn assert_safe_route_failure_output(bytes: &[u8], raw_route_id: &str) {
    let output = String::from_utf8_lossy(bytes);
    assert!(
        !output.contains(raw_route_id),
        "output leaked route: {output}"
    );
    assert!(
        !output.contains('\u{202e}'),
        "output retained bidi: {output}"
    );
    assert!(
        !output.contains('\u{2028}'),
        "output retained Unicode line separator: {output}"
    );
    assert!(
        output.contains("support\\u{202e}evil\\u{2028}next"),
        "output omitted deterministic route rendering: {output}"
    );
}

#[test]
fn preflight_rejects_active_provenance_mismatch() {
    let dir = tempdir("preflight-active-provenance");
    let config = write_config(&dir, "127.0.0.1:0", "127.0.0.1:9");
    let missing_policy = dir.join("missing-policy.yaml");
    let enforcement = dir.join("enforcement.yaml");
    fs::write(
        &enforcement,
        "version: 1\nglobal_candidate_in_flight: 1\nkill_switch: {trust_root: /missing, relative_path: state}\nactuators: []\nroutes: []\n",
    )
    .unwrap();
    let source = fs::read_to_string(&config).unwrap().replace(
        &format!(
            "policy_bundle: {}",
            bowline_root().join("policies/default.yaml").display()
        ),
        &format!("policy_bundle: {}", missing_policy.display()),
    );
    fs::write(
        &config,
        format!("{source}enforcement: {}\n", enforcement.display()),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .args(["preflight", "--config", config.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("active provenance is unavailable"),
        "{stdout}"
    );
}

#[test]
fn valid_configured_enforcement_with_corrupt_observation_exits_before_any_dispatch() {
    let dir = tempdir("enforcement-not-ignored");
    let (upstream, upstream_count) = spawn_counting_upstream();
    let (candidate, candidate_count) = spawn_counting_upstream();
    let listen = unused_address();
    let config = write_config(&dir, &listen, &upstream);
    let mut source = fs::read_to_string(&config).unwrap();
    let ledger = dir.join("ledger");
    fs::create_dir_all(&ledger).unwrap();
    let mut corrupt = b"BWL1\n".to_vec();
    corrupt.extend_from_slice(&2_u32.to_le_bytes());
    corrupt.extend_from_slice(&0_u32.to_le_bytes());
    corrupt.extend_from_slice(b"{}");
    fs::write(ledger.join("decisions.bwl"), corrupt).unwrap();
    let (_, recovery) = Ledger::open(&ledger).unwrap();
    assert!(
        recovery.blocks_append(),
        "fixture must be unrecoverable: {recovery:?}"
    );
    let kill = dir.join("kill");
    fs::create_dir(&kill).unwrap();
    fs::set_permissions(&kill, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(kill.join("state"), b"armed\n").unwrap();
    fs::set_permissions(kill.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    let kill = fs::canonicalize(kill).unwrap();
    let enforcement = dir.join("enforcement.yaml");
    fs::write(
        &enforcement,
        format!(
            r#"version: 1
global_candidate_in_flight: 1
kill_switch: {{trust_root: {}, relative_path: state}}
actuators:
  - supply_id: local/qwen3-32b
    base_url: http://{candidate}
    authorization_env: TEST_CANDIDATE_TOKEN
    health_path: /v1/models
    connect_timeout_ms: 100
    response_header_timeout_ms: 100
    stream_idle_timeout_ms: 100
    concurrency: 1
    probe_timeout_ms: 100
    probe_max_bytes: 1024
    breaker_consecutive_failures: 1
    breaker_cooldown_ms: 100
routes:
  - route_id: valid-candidate-route
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    workload: {{app: support, resolved_tags: [production]}}
    mode: recommend
    rollout_ppm: 0
    promoted_supply_id: local/qwen3-32b
    actual_supply_id: openai/gpt-5-mini
    task_class: heavy-lifting
    fallback: bypass
    promotion:
      economics_bundle_path: economics
      economics_report_digest: sha256:{a}
      opportunity_digest: sha256:{b}
      quality_run_path: quality
      quality_run_id: quality-1
      quality_report_digest: sha256:{c}
      policy_digest: sha256:{d}
      registry_digest: sha256:{e}
      owned_cost_digest: sha256:{f}
      max_economics_age_ms: 100000
      expires_at_ms: 2000000000000
"#,
            kill.display(),
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64),
            d = "d".repeat(64),
            e = "e".repeat(64),
            f = "f".repeat(64),
        ),
    )
    .unwrap();
    source.push_str(&format!("enforcement: {}\n", enforcement.display()));
    fs::write(&config, source).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bowline"))
        .args(["serve", "--config", config.to_str().unwrap()])
        .env("TEST_CANDIDATE_TOKEN", "process-test-secret")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configured enforcement requires"),
        "stderr: {stderr}"
    );
    assert_eq!(upstream_count.load(Ordering::Acquire), 0);
    assert_eq!(candidate_count.load(Ordering::Acquire), 0);
}

#[test]
fn sigterm_before_billing_complete_transition_is_nonzero_and_incomplete() {
    let dir = tempdir("billing-signal-before");
    let (config, billing) = billing_fixture(&dir);
    let barriers = dir.join("barriers");
    fs::create_dir(&barriers).unwrap();
    let mut child = spawn_billing_import(&config, &billing, &barriers, "before");
    wait_for_file(&barriers.join("before-complete"), &mut child);
    assert!(Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let runs = fs::read_dir(dir.join("ledger/billing-runs"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(runs.len(), 1);
    let run = fs::canonicalize(runs[0].path()).unwrap();
    let manifest = BillingRunStore::load_manifest(&run).unwrap();
    assert!(!manifest.clean_shutdown);
    assert!(run.join(".billing-incomplete").is_file());
    assert!(!run.join(".billing-complete").exists());
}

#[test]
fn sigint_after_billing_complete_transition_still_reports_success() {
    let dir = tempdir("billing-signal-after");
    let (config, billing) = billing_fixture(&dir);
    let barriers = dir.join("barriers");
    fs::create_dir(&barriers).unwrap();
    let mut child = spawn_billing_import(&config, &billing, &barriers, "after");
    wait_for_file(&barriers.join("after-complete"), &mut child);
    assert!(Command::new("/bin/kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    fs::write(barriers.join("continue"), b"continue\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["clean_shutdown"], true);
    assert_eq!(summary["reconciled"], true);
    let runs = fs::read_dir(dir.join("ledger/billing-runs"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(runs.len(), 1);
    let run = fs::canonicalize(runs[0].path()).unwrap();
    assert!(BillingRunStore::load_manifest(&run).unwrap().clean_shutdown);
    assert!(run.join(".billing-complete").is_file());
}

#[test]
fn sigterm_drains_accepted_request_and_marks_clean_shutdown() {
    let dir = tempdir("sigterm-drain");
    let upstream = spawn_one_request_upstream();
    let listen = unused_address();
    let config = write_config(&dir, &listen, &upstream);
    let mut child = spawn_bowline(&config);

    wait_until_ready(&listen, &mut child);
    let body = r#"{"model":"gpt-5-mini","messages":[{"role":"user","content":"hi"}]}"#;
    let response = http_request(
        &listen,
        &format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ),
    );
    assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");

    let status = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("SIGTERM sent");
    assert!(status.success());
    let exit = child.wait().expect("Bowline exits");
    assert!(exit.success(), "Bowline exit: {exit}");

    let manifests = RunStore::list_manifests(&dir.join("ledger")).expect("manifest list");
    assert_eq!(manifests.len(), 1);
    let manifest = &manifests[0];
    assert!(manifest.clean_shutdown);
    assert_eq!(
        (manifest.accepted, manifest.recorded, manifest.dropped),
        (1, 1, 0)
    );
    let (records, _) = SegmentedLedger::read_run(&dir.join("ledger"), &manifest.run_id)
        .expect("run records readable");
    assert_eq!(records.len(), 1);
}

#[test]
fn restart_after_unclean_shutdown_preserves_evidence_and_starts_new_run() {
    let dir = tempdir("unclean-restart");
    let upstream = spawn_one_request_upstream();
    let listen = unused_address();
    let config = write_config(&dir, &listen, &upstream);

    let mut first = spawn_bowline(&config);
    wait_until_ready(&listen, &mut first);
    let status = Command::new("/bin/kill")
        .args(["-KILL", &first.id().to_string()])
        .status()
        .expect("SIGKILL sent");
    assert!(status.success());
    assert!(!first.wait().expect("killed Bowline reaped").success());

    let mut second = spawn_bowline(&config);
    wait_until_ready(&listen, &mut second);
    let status = Command::new("/bin/kill")
        .args(["-TERM", &second.id().to_string()])
        .status()
        .expect("SIGTERM sent");
    assert!(status.success());
    assert!(second.wait().expect("restarted Bowline exits").success());

    let manifests = RunStore::list_manifests(&dir.join("ledger")).expect("manifest list");
    assert_eq!(manifests.len(), 2);
    assert_eq!(
        manifests
            .iter()
            .filter(|manifest| manifest.clean_shutdown)
            .count(),
        1
    );
    assert_eq!(
        manifests
            .iter()
            .filter(|manifest| !manifest.clean_shutdown)
            .count(),
        1
    );
    assert_ne!(manifests[0].run_id, manifests[1].run_id);
}

fn spawn_bowline(config: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_bowline"))
        .args(["serve", "--config", config.to_str().expect("utf8 config")])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Bowline process starts")
}

fn wait_until_ready(address: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_response = String::new();
    loop {
        if let Some(status) = child.try_wait().expect("child status") {
            let mut stderr = String::new();
            child
                .stderr
                .as_mut()
                .expect("stderr pipe")
                .read_to_string(&mut stderr)
                .expect("stderr readable");
            panic!("Bowline exited before ready ({status}): {stderr}");
        }
        if let Ok(response) = try_http_request(
            address,
            "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ) {
            if response.starts_with("HTTP/1.1 200") {
                return;
            }
            last_response = response;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let mut stderr = String::new();
            if let Some(pipe) = child.stderr.as_mut() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!(
                "timed out waiting for readiness; last response={last_response:?}; stderr={stderr}"
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn http_request(address: &str, request: &str) -> String {
    try_http_request(address, request).expect("HTTP request succeeds")
}

fn try_http_request(address: &str, request: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream
        .write_all(request.as_bytes())
        .map_err(std::io::Error::other)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn spawn_one_request_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("upstream accepts request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).expect("upstream request reads");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"{"model":"gpt-5-mini","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":7,"completion_tokens":5}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("upstream response writes");
    });
    address.to_string()
}

fn spawn_counting_upstream() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("counting upstream binds");
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().expect("counting upstream address");
    let count = Arc::new(AtomicUsize::new(0));
    let thread_count = Arc::clone(&count);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((_stream, _)) => {
                    thread_count.fetch_add(1, Ordering::AcqRel);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("counting upstream accept failed: {error}"),
            }
        }
    });
    (address.to_string(), count)
}

fn write_config(dir: &Path, listen: &str, upstream: &str) -> PathBuf {
    let root = bowline_root();
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            r#"listen: {listen}
upstream: http://{upstream}
actual_supply_id: openai/gpt-5-mini
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
trusted_proxy_cidrs:
  - 127.0.0.1/32
runtime:
  shutdown_grace_ms: 2000
"#,
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display(),
        ),
    )
    .expect("process config written");
    config
}

fn write_relative_controlled_fixture(dir: &Path, route_id: &str) {
    write_relative_controlled_fixture_with_mode(dir, route_id, "enforce");
}

fn write_relative_controlled_fixture_with_mode(dir: &Path, route_id: &str, mode: &str) {
    let config_dir = dir.join("config");
    fs::create_dir_all(&config_dir).unwrap();
    fs::copy(
        bowline_root().join("policies/default.yaml"),
        config_dir.join("policy.yaml"),
    )
    .unwrap();
    fs::copy(
        bowline_root().join("registry/feed.json"),
        config_dir.join("registry.json"),
    )
    .unwrap();
    let kill = fs::canonicalize(&config_dir).unwrap().join("kill");
    fs::create_dir(&kill).unwrap();
    fs::set_permissions(&kill, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(kill.join("state"), b"armed\n").unwrap();
    fs::set_permissions(kill.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        config_dir.join("enforcement.yaml"),
        format!(
            r#"version: 1
global_candidate_in_flight: 1
kill_switch: {{trust_root: {}, relative_path: state}}
actuators:
  - supply_id: local/qwen3-32b
    base_url: http://127.0.0.1:9
    authorization_env: BOWLINE_TEST_TOKEN
    health_path: /v1/models
    connect_timeout_ms: 10
    response_header_timeout_ms: 10
    stream_idle_timeout_ms: 10
    concurrency: 1
    breaker_consecutive_failures: 1
    breaker_cooldown_ms: 10
    probe_timeout_ms: 10
    probe_max_bytes: 1024
routes:
  - route_id: {route_id_yaml}
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    workload: {{app: support, resolved_tags: [production]}}
    mode: {mode}
    rollout_ppm: 0
    promoted_supply_id: local/qwen3-32b
    actual_supply_id: openai/gpt-5-mini
    task_class: heavy-lifting
{model_authority_line}    fallback: bypass
    promotion:
      economics_bundle_path: evidence/economics
      economics_report_digest: sha256:{a}
      opportunity_digest: sha256:{b}
      quality_run_path: evidence/quality
      authorization_path: evidence/authorization.json
      quality_run_id: quality-1
      quality_report_digest: sha256:{c}
      policy_digest: sha256:{d}
      registry_digest: sha256:{e}
      owned_cost_digest: sha256:{f}
      max_economics_age_ms: 1000
      expires_at_ms: 2000000000000
"#,
            kill.display(),
            route_id_yaml = serde_yaml::to_string(route_id).unwrap().trim_end(),
            model_authority_line = if mode == "enforce" {
                "    model_authority: rewrite-to-canonical\n"
            } else {
                ""
            },
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64),
            d = "d".repeat(64),
            e = "e".repeat(64),
            f = "f".repeat(64),
        ),
    )
    .unwrap();
    fs::write(
        config_dir.join("bowline.yaml"),
        "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: policy.yaml\nregistry_feed: registry.json\nledger_dir: ledger\nenforcement: enforcement.yaml\n",
    )
    .unwrap();
}

fn bowline_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives under workspace root")
        .to_path_buf()
}

fn billing_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    let root = bowline_root();
    let config = dir.join("billing-bowline.yaml");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display(),
        ),
    )
    .unwrap();
    let billing = dir.join("billing.jsonl");
    fs::write(&billing, r#"{"schema_version":1,"row_id":"synthetic-signal","period_start_ms":1,"period_end_ms":2,"supply_id":"openai/gpt-5-mini","currency":"USD","charge_basis":"inference-usage-net","charge_usd":"1.000000","request_count":1,"input_tokens":2,"output_tokens":3}
"#).unwrap();
    (config, billing)
}

fn spawn_billing_import(config: &Path, billing: &Path, barriers: &Path, phase: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_bowline"))
        .args([
            "billing",
            "import",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            billing.to_str().unwrap(),
            "--json",
        ])
        .env("BOWLINE_TEST_BILLING_BARRIER_DIR", barriers)
        .env("BOWLINE_TEST_BILLING_BARRIER_PHASE", phase)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for_file(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("billing import exited before barrier {path:?}: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("timed out waiting for billing barrier {path:?}");
}

fn unused_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral address binds");
    let address = listener.local_addr().expect("ephemeral address");
    drop(listener);
    address.to_string()
}

fn tempdir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moves forward")
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "bowline-process-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("tempdir created");
    dir
}
