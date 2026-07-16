use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use bowline_core::{
    attribution::{AttributionSource, AttributionStatus},
    config::{load_owned_cost_catalog, Config},
    decision::{Decision, Placement},
    enforcement::{AuthorityProtocol, EvidenceState, PlanTarget, RouteMode, SelectionReason},
    ledger::{
        ActualOutcome, AuthorityDecisionV2, AuthorityGrantBindingV2, AuthorityLedgerV2,
        AuthorityOutcomeV2, AuthorityRecordV2, AuthoritySelectionFactsV2, CircuitStateV2,
        CompletionStateV2, DecisionRecord, Ledger, SegmentedLedger, UsageSource,
    },
    policy::{PolicyBundle, WorkloadIdentity},
    report::compute_run_report,
    run::{AuthorityRunDigestsV2, AuthorityRunStoreV2, RunDigests, RunLimits, RunStore},
    supply::{Registry, TaskClass},
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};
use bowline_gateway::writer::{spawn_managed_writer, ManagedWriterOptions};
use sha2::{Digest, Sha256};

fn bowline() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bowline"))
}

fn bowline_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives under workspace root")
        .to_path_buf()
}

fn materialize_evidence_fixture(source: &Path, destination: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["bowline.yaml", "policy.yaml", "registry.json", "tco.yaml"] {
        let target = destination.join(name);
        fs::copy(source.join(name), &target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ledger = destination.join("ledger");
    fs::create_dir(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["run-fixture-run-000000.bwl", "run-fixture-run.json"] {
        let target = ledger.join(name);
        fs::copy(source.join("ledger").join(name), &target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn evidence_export_fixture_is_schema_valid_exact_and_fail_closed() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = bowline_root();
    let dir = fs::canonicalize(tempdir("evidence-export")).unwrap();
    let fixture = dir.join("fixture");
    materialize_evidence_fixture(
        &root.join("crates/bowline/tests/fixtures/evidence-v1"),
        &fixture,
    );
    let config = fixture.join("bowline.yaml");
    let out = dir.join("evidence.json");
    let export = bowline()
        .args([
            "export",
            "evidence",
            "--config",
            config.to_str().unwrap(),
            "--run-id",
            "fixture-run",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bundle: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("schemas/evidence-bundle-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    if let Err(errors) = validator.validate(&bundle) {
        panic!(
            "fixture export failed schema validation: {}",
            errors
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    let report = bowline()
        .args([
            "report",
            "--config",
            config.to_str().unwrap(),
            "--run-id",
            "fixture-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        report.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(bundle["aggregates"], report["report"]);
    assert_eq!(
        bundle["coverage"]["protocol_coverage"],
        report["report"]["protocol_coverage"]
    );
    assert_eq!(bundle["decisions"][0]["decision_ref"], "fixture-run:1");
    assert_eq!(bundle["decisions"][0].as_object().unwrap().len(), 13);
    let encoded = serde_json::to_string(&bundle).unwrap();
    for forbidden in [
        "SENTINEL-REQUEST-ID",
        "SENTINEL-ROUTE",
        "SENTINEL-APP",
        "SENTINEL-TAG",
        "SENTINEL-POLICY-TAG",
        "SENTINEL-API-KEY",
        "SENTINEL-UPSTREAM",
        "SENTINEL-MODEL",
        "SENTINEL-ATTRIBUTION",
        "SENTINEL-CONTENT",
        "SENTINEL-AUTHORIZATION",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "fixture export leaked {forbidden}"
        );
    }

    let symlink_target = dir.join("symlink-target");
    fs::write(&symlink_target, b"preserve-me").unwrap();
    let symlink_out = dir.join("symlink-out.json");
    symlink(&symlink_target, &symlink_out).unwrap();
    let symlink_export = bowline()
        .args([
            "export",
            "evidence",
            "--config",
            config.to_str().unwrap(),
            "--run-id",
            "fixture-run",
            "--out",
            symlink_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(symlink_export.status.success());
    assert_eq!(fs::read(&symlink_target).unwrap(), b"preserve-me");
    assert!(fs::symlink_metadata(&symlink_out)
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(
        fs::metadata(&symlink_out).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let unknown_out = dir.join("unknown.json");
    let unknown = bowline()
        .args([
            "export",
            "evidence",
            "--config",
            config.to_str().unwrap(),
            "--run-id",
            "missing-run",
            "--out",
            unknown_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(!unknown_out.exists());

    let tampered_fixture = dir.join("tampered-fixture");
    materialize_evidence_fixture(
        &root.join("crates/bowline/tests/fixtures/evidence-v1"),
        &tampered_fixture,
    );
    let tampered_segment = tampered_fixture
        .join("ledger")
        .join("run-fixture-run-000000.bwl");
    let mut tampered_bytes = fs::read(&tampered_segment).unwrap();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 1;
    fs::write(&tampered_segment, tampered_bytes).unwrap();
    fs::set_permissions(&tampered_segment, fs::Permissions::from_mode(0o600)).unwrap();
    let tampered_out = dir.join("tampered.json");
    let tampered = bowline()
        .args([
            "export",
            "evidence",
            "--config",
            tampered_fixture.join("bowline.yaml").to_str().unwrap(),
            "--run-id",
            "fixture-run",
            "--out",
            tampered_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!tampered.status.success());
    assert!(!tampered_out.exists());

    let changed_policy = dir.join("policy.yaml");
    let mut policy = fs::read_to_string(fixture.join("policy.yaml")).unwrap();
    policy.push_str("\n# digest mismatch\n");
    fs::write(&changed_policy, policy).unwrap();
    let mismatched_config = dir.join("mismatched.yaml");
    fs::write(
        &mismatched_config,
        format!(
            "listen: 127.0.0.1:8080\nupstream: https://example.invalid\n\
             actual_supply_id: supply/actual\npolicy_bundle: {}\nregistry_feed: {}\n\
             ledger_dir: {}\ntco: {}\ntrusted_proxy_cidrs: [127.0.0.1/32]\n",
            changed_policy.display(),
            fixture.join("registry.json").display(),
            fixture.join("ledger").display(),
            fixture.join("tco.yaml").display(),
        ),
    )
    .unwrap();
    let mismatch_out = dir.join("mismatch.json");
    let mismatch = bowline()
        .args([
            "export",
            "evidence",
            "--config",
            mismatched_config.to_str().unwrap(),
            "--run-id",
            "fixture-run",
            "--out",
            mismatch_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    assert!(
        String::from_utf8_lossy(&mismatch.stderr).contains("policy digest mismatch"),
        "stderr: {}",
        String::from_utf8_lossy(&mismatch.stderr)
    );
    assert!(!mismatch_out.exists());
}

#[test]
fn economics_validate_is_offline_no_write_and_report_refuses_unbound_sources() {
    let dir = fs::canonicalize(tempdir("economics-cli-no-write")).unwrap();
    let root = bowline_root();
    let ledger = dir.join("ledger");
    fs::create_dir(&ledger).unwrap();
    let config = dir.join("bowline.yaml");
    fs::write(&config, format!("listen: 127.0.0.1:0\nupstream: http://127.0.0.1:1\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n", root.join("policies/default.yaml").display(), root.join("registry/feed.json").display(), ledger.display())).unwrap();
    let analysis = dir.join("analysis.yaml");
    fs::write(&analysis, "schema_version: 1\nas_of_ms: 2000\ntraffic_run_id: missing-traffic\nmode: modeled-only\nbilling_run_id: null\nquality_run_ids: [missing-quality]\nwindow_start_ms: 1000\nwindow_end_ms: 2000\nrequire_request_count: true\nrequire_input_tokens: true\nrequire_output_tokens: true\nrequest_tolerance_ppm: 0\ninput_token_tolerance_ppm: 0\noutput_token_tolerance_ppm: 0\nminimum_record_coverage_ppm: 1000000\nminimum_qualified_charge_coverage_ppm: 1000000\nmaximum_charge_variance_ppm: 0\nminimum_duration_ms: 1000\nminimum_supported_records: 1\nannualize: false\nrepresentative_window_acknowledged: false\n").unwrap();
    let before = fs::read_dir(&ledger).unwrap().count();
    let validate = bowline()
        .args([
            "economics",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--analysis",
            analysis.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!validate.status.success());
    assert!(String::from_utf8_lossy(&validate.stderr).contains("unknown traffic run"));
    assert_eq!(fs::read_dir(&ledger).unwrap().count(), before);
    let output = dir.join("bundle");
    let report = bowline()
        .args([
            "economics",
            "report",
            "--config",
            config.to_str().unwrap(),
            "--analysis",
            analysis.to_str().unwrap(),
            "--out-dir",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!report.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&ledger).unwrap().count(), before);
}

#[test]
fn economics_complete_run_exits_zero_and_repeats_deterministically() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let dir = fs::canonicalize(tempdir("economics-complete")).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let (config, dataset, evaluators, canary) =
        canary_fixture(&dir, &format!("http://{address}/v1/"), 1);
    let registry_bytes = fs::read(dir.join("registry.json")).unwrap();
    let registry = Registry::from_json(std::str::from_utf8(&registry_bytes).unwrap()).unwrap();
    let policy_source = fs::read_to_string(dir.join("policy.yaml")).unwrap();
    let policy = PolicyBundle::from_yaml(&policy_source).unwrap();
    let owned = load_owned_cost_catalog(None, Some("public/candidate"), &registry).unwrap();
    let ledger = dir.join("ledger");
    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: ledger.clone(),
        policy_digest: policy.digest().to_owned(),
        registry_digest: format!("sha256:{:x}", Sha256::digest(&registry_bytes)),
        attribution_digest: None,
        owned_cost_digest: Some(owned.normalized_digest().to_owned()),
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: 64 * 1024,
        max_segments: 8,
        queue_capacity: 8,
    })
    .unwrap();
    let context = writer.accept_request().unwrap();
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    writer
        .try_record(DecisionRecord {
            id: "economics-record-1".into(),
            ts_ms,
            run_id: Some(context.run_id.clone()),
            sequence: Some(context.sequence),
            accounting_truncated: false,
            protocol: ProtocolKind::Responses,
            observation_source: ObservationSource::Inline,
            coverage_status: CoverageStatus::Supported,
            coverage_reason: None,
            identity: WorkloadIdentity {
                api_key_digest: None,
                route: "/v1/responses".into(),
                app: Some("support".into()),
                tags: vec!["test".into()],
            },
            decision: Decision {
                policy_digest: policy.digest().to_owned(),
                task_class: TaskClass::Mechanical,
                feasible_ids: vec!["public/candidate".into()],
                floor: 0.0,
                shadow: Some(Placement {
                    supply_id: "public/candidate".into(),
                    est_cost_usd: Some(0.0),
                }),
            },
            actual: ActualOutcome {
                upstream: "synthetic".into(),
                supply_id: Some("public/candidate".into()),
                model: Some("candidate-model".into()),
                status: 200,
                streamed: false,
                latency_ms: 10,
                input_tokens: Some(2),
                output_tokens: Some(1),
                usage_source: UsageSource::Observed,
                est_cost_usd: Some(0.000004),
                attribution_status: AttributionStatus::StaticConfigured,
                attribution_source: AttributionSource::LegacyConfigured,
                attribution_reference: None,
                attribution_reason: None,
            },
        })
        .unwrap();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(writer.shutdown(std::time::Duration::from_secs(2)))
        .unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).ok();
        let body = r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":2,"output_tokens":1}}"#;
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
    });
    let mut command_args = vec!["canary".into(), "run".into()];
    command_args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    command_args.push("--json".into());
    let canary_output = bowline()
        .args(command_args)
        .env(
            "BOWLINE_TEST_CANDIDATE_AUTHORIZATION",
            "Bearer synthetic-secret",
        )
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        canary_output.status.success(),
        "{}",
        String::from_utf8_lossy(&canary_output.stderr)
    );
    let quality: serde_json::Value = serde_json::from_slice(&canary_output.stdout).unwrap();
    let quality_run_id = quality["run_id"].as_str().unwrap();
    let quality_manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            ledger
                .join("quality-runs")
                .join(quality_run_id)
                .join("manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let as_of_ms = quality_manifest["completed_at_ms"].as_u64().unwrap();

    let billing = dir.join("billing.jsonl");
    fs::write(&billing, format!("{{\"schema_version\":1,\"row_id\":\"synthetic-row\",\"period_start_ms\":{},\"period_end_ms\":{},\"supply_id\":\"public/candidate\",\"currency\":\"USD\",\"charge_basis\":\"inference-usage-net\",\"charge_usd\":\"0.000004\",\"request_count\":1,\"input_tokens\":2,\"output_tokens\":1}}\n", ts_ms - 1, ts_ms + 1)).unwrap();
    let billing_output = bowline()
        .args([
            "billing",
            "import",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            billing.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        billing_output.status.success(),
        "{}",
        String::from_utf8_lossy(&billing_output.stderr)
    );
    let billing_summary: serde_json::Value =
        serde_json::from_slice(&billing_output.stdout).unwrap();
    let billing_run_id = billing_summary["run_id"].as_str().unwrap();
    let analysis = dir.join("analysis.yaml");
    fs::write(&analysis, format!("schema_version: 1\nas_of_ms: {as_of_ms}\ntraffic_run_id: {}\nmode: billing-reconciled\nbilling_run_id: {billing_run_id}\nquality_run_ids: [{quality_run_id}]\nwindow_start_ms: {}\nwindow_end_ms: {}\nrequire_request_count: true\nrequire_input_tokens: true\nrequire_output_tokens: true\nrequest_tolerance_ppm: 0\ninput_token_tolerance_ppm: 0\noutput_token_tolerance_ppm: 0\nminimum_record_coverage_ppm: 1000000\nminimum_qualified_charge_coverage_ppm: 1000000\nmaximum_charge_variance_ppm: 0\nminimum_duration_ms: 2\nminimum_supported_records: 1\nannualize: true\nrepresentative_window_acknowledged: true\n", context.run_id, ts_ms - 1, ts_ms + 1)).unwrap();
    let validate = bowline()
        .args([
            "economics",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--analysis",
            analysis.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    for name in ["bundle-a", "bundle-b"] {
        let out = dir.join(name);
        let result = bowline()
            .args([
                "economics",
                "report",
                "--config",
                config.to_str().unwrap(),
                "--analysis",
                analysis.to_str().unwrap(),
                "--out-dir",
                out.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read_dir(&out).unwrap().count(), 7);
    }
    for artifact in [
        "report.json",
        "report.md",
        "report.html",
        "dimensions.csv",
        "opportunities.csv",
        "reconciliation.csv",
        "manifest.json",
    ] {
        assert_eq!(
            fs::read(dir.join("bundle-a").join(artifact)).unwrap(),
            fs::read(dir.join("bundle-b").join(artifact)).unwrap(),
            "{artifact}"
        );
    }

    let mismatch_billing = dir.join("billing-mismatch.jsonl");
    fs::write(
        &mismatch_billing,
        fs::read_to_string(&billing)
            .unwrap()
            .replace("\"request_count\":1", "\"request_count\":2")
            .replace("synthetic-row", "synthetic-row-mismatch"),
    )
    .unwrap();
    let mismatch_import = bowline()
        .args([
            "billing",
            "import",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            mismatch_billing.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(mismatch_import.status.success());
    let mismatch_summary: serde_json::Value =
        serde_json::from_slice(&mismatch_import.stdout).unwrap();
    let mismatch_run = mismatch_summary["run_id"].as_str().unwrap();
    let incomplete_analysis = dir.join("analysis-incomplete.yaml");
    fs::write(
        &incomplete_analysis,
        fs::read_to_string(&analysis)
            .unwrap()
            .replace(billing_run_id, mismatch_run),
    )
    .unwrap();
    let incomplete_validate = bowline()
        .args([
            "economics",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--analysis",
            incomplete_analysis.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(incomplete_validate.status.code(), Some(2));
    let incomplete_bundle = dir.join("bundle-incomplete");
    let incomplete_report = bowline()
        .args([
            "economics",
            "report",
            "--config",
            config.to_str().unwrap(),
            "--analysis",
            incomplete_analysis.to_str().unwrap(),
            "--out-dir",
            incomplete_bundle.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(incomplete_report.status.code(), Some(2));
    assert_eq!(fs::read_dir(&incomplete_bundle).unwrap().count(), 7);
    let incomplete_json: serde_json::Value =
        serde_json::from_slice(&fs::read(incomplete_bundle.join("report.json")).unwrap()).unwrap();
    assert_eq!(incomplete_json["reconciliation"]["state"], "incomplete");
}

fn canary_fixture(
    dir: &Path,
    base_url: &str,
    cases: usize,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let ledger = dir.join("ledger");
    let policy = dir.join("policy.yaml");
    fs::write(
        &policy,
        "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n    require:\n      supply_class: [public-api]\n",
    )
    .unwrap();
    let registry = dir.join("registry.json");
    fs::write(&registry, r#"{"feed_version":"test","entries":[{"id":"public/candidate","model":"candidate-model","location":"test","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0},"ratings":{},"available":true}]}"#).unwrap();
    let config = dir.join("bowline.yaml");
    fs::write(&config, format!("listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: public/candidate\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n", policy.display(), registry.display(), ledger.display())).unwrap();
    let cases_path = dir.join("cases.jsonl");
    let mut rows = String::new();
    for index in 0..cases {
        rows.push_str(&format!(r#"{{"case_id":"case-{index}","request":{{"input":"status"}},"expected":{{"answer":"ok"}}}}"#));
        rows.push('\n');
    }
    fs::write(&cases_path, rows).unwrap();
    let dataset = dir.join("dataset.yaml");
    fs::write(&dataset, "version: 1\ndataset_id: synthetic\nprotocol: responses\ncases_file: cases.jsonl\ntask_class: mechanical\npolicy_identity:\n  app: support\n  tags: [test]\n").unwrap();
    let evaluators = dir.join("evaluators.yaml");
    fs::write(&evaluators, "version: 1\nevaluators:\n  - { id: answer, kind: exact-match, expected_key: answer, required: true }\n").unwrap();
    let canary = dir.join("canary.yaml");
    fs::write(&canary, format!("version: 1\ncandidates:\n  - supply_id: public/candidate\n    base_url: {base_url}\n    authorization_env: BOWLINE_TEST_CANDIDATE_AUTHORIZATION\nrunner:\n  send_customer_content: false\n  concurrency: 2\n  per_candidate_concurrency: 1\n  max_requests: 100\n  max_wall_time_ms: 1000\n  request_timeout_ms: 500\n  shutdown_grace_ms: 1000\n  max_response_bytes: 65536\n  max_observed_tokens: 10000\n  max_observed_cost_usd: 10.0\n  writer_queue_capacity: 16\npromotion:\n  min_samples: 1\n  min_pass_rate: 0.0\n  min_wilson_lower_95: 0.0\n  max_error_rate: 1.0\n  max_p95_latency_ms: 1000\n  max_age_ms: 60000\n")).unwrap();
    (config, dataset, evaluators, canary)
}

fn canary_args(config: &Path, dataset: &Path, evaluators: &Path, canary: &Path) -> Vec<String> {
    vec![
        "--config".into(),
        config.display().to_string(),
        "--dataset".into(),
        dataset.display().to_string(),
        "--evaluators".into(),
        evaluators.display().to_string(),
        "--canary".into(),
        canary.display().to_string(),
    ]
}

#[test]
fn canary_validate_is_atomic_and_offline() {
    let dir = tempdir("canary-validate");
    let (config, dataset, evaluators, canary) = canary_fixture(&dir, "http://127.0.0.1:1/v1/", 1);
    let mut args = vec!["canary".into(), "validate".into()];
    args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    let output = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("valid"));
    assert!(!dir.join("ledger/quality-runs").exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("test-secret"));

    let missing_secret = bowline()
        .args(&args)
        .env_remove("BOWLINE_TEST_CANDIDATE_AUTHORIZATION")
        .output()
        .unwrap();
    assert_ne!(missing_secret.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&missing_secret.stderr)
        .contains("BOWLINE_TEST_CANDIDATE_AUTHORIZATION"));
    assert!(!String::from_utf8_lossy(&missing_secret.stderr).contains("Bearer"));
    assert!(!dir.join("ledger/quality-runs").exists());

    fs::write(
        &canary,
        format!(
            "{}\nunknown_field: true\n",
            fs::read_to_string(&canary).unwrap()
        ),
    )
    .unwrap();
    let invalid = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
        .output()
        .unwrap();
    assert_ne!(invalid.status.code(), Some(0));
    assert!(!dir.join("ledger/quality-runs").exists());
}

#[test]
fn shipped_quality_examples_validate_offline_without_persistence_or_leakage() {
    let root = bowline_root();
    let example = root.join("examples/canary");
    for file in [
        "dataset.yaml",
        "cases.jsonl",
        "evaluators.yaml",
        "canary.yaml",
        "rubric.md",
    ] {
        assert!(example.join(file).is_file(), "missing example {file}");
    }
    let temp = tempdir("shipped-quality-example");
    let config = temp.join("bowline.yaml");
    let ledger = temp.join("ledger");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            ledger.display(),
        ),
    )
    .unwrap();
    let output = bowline()
        .args([
            "canary",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--dataset",
            example.join("dataset.yaml").to_str().unwrap(),
            "--evaluators",
            example.join("evaluators.yaml").to_str().unwrap(),
            "--canary",
            example.join("canary.yaml").to_str().unwrap(),
        ])
        .env("BOWLINE_CANARY_AUTHORIZATION", "Bearer synthetic-candidate")
        .env("BOWLINE_JUDGE_AUTHORIZATION", "Bearer synthetic-judge")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!ledger.exists());
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for forbidden in [
        "Return the single word ok",
        "Synthetic evaluation rubric",
        "synthetic-candidate",
        "synthetic-judge",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "validation leaked {forbidden}"
        );
    }
}

#[test]
fn shipped_actionable_economics_examples_are_strict_and_offline_validating() {
    let root = bowline_root();
    let billing = root.join("examples/billing");
    let economics = root.join("examples/economics");
    for path in [
        billing.join("canonical.jsonl"),
        billing.join("mapped.csv"),
        billing.join("mapping.yaml"),
        economics.join("analysis.yaml"),
    ] {
        assert!(path.is_file(), "missing example {}", path.display());
    }
    let temp = fs::canonicalize(tempdir("shipped-economics-examples")).unwrap();
    let ledger = temp.join("ledger");
    fs::create_dir(&ledger).unwrap();
    let config = temp.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            ledger.display(),
        ),
    )
    .unwrap();
    for (source, mapping) in [
        (billing.join("canonical.jsonl"), None),
        (
            billing.join("mapped.csv"),
            Some(billing.join("mapping.yaml")),
        ),
    ] {
        let mut command = bowline();
        command.args([
            "billing",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            source.to_str().unwrap(),
        ]);
        if let Some(mapping) = mapping {
            command.args(["--mapping", mapping.to_str().unwrap()]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            source.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("valid: 2 rows"));
    }
    assert_eq!(fs::read_dir(&ledger).unwrap().count(), 0);

    let output = bowline()
        .args([
            "economics",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--analysis",
            economics.join("analysis.yaml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown traffic run"));
    assert_eq!(fs::read_dir(&ledger).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn canary_validate_rejects_unsafe_cases_paths_before_reading() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("canary-cases-path");
    let (config, dataset, evaluators, canary) = canary_fixture(&dir, "http://127.0.0.1:1/v1/", 1);
    let outside = dir.parent().unwrap().join(format!(
        "outside-cases-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&outside, "ARBITRARY-SENTINEL-CONTENT").unwrap();
    let mut args = vec!["canary".into(), "validate".into()];
    args.extend(canary_args(&config, &dataset, &evaluators, &canary));

    for cases_file in [
        format!("../{}", outside.file_name().unwrap().to_string_lossy()),
        outside.display().to_string(),
    ] {
        fs::write(
            &dataset,
            format!("version: 1\ndataset_id: synthetic\nprotocol: responses\ncases_file: {cases_file}\ntask_class: mechanical\npolicy_identity:\n  app: support\n  tags: [test]\n"),
        )
        .unwrap();
        let output = bowline()
            .args(&args)
            .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(
            stderr.contains("invalid dataset manifest"),
            "stderr: {stderr}"
        );
        assert!(!stderr.contains("ARBITRARY-SENTINEL-CONTENT"));
        assert!(!stderr.contains(&outside.display().to_string()));
        assert!(!dir.join("ledger/quality-runs").exists());
    }

    let link = dir.join("cases-link.jsonl");
    symlink(&outside, &link).unwrap();
    fs::write(&dataset, "version: 1\ndataset_id: synthetic\nprotocol: responses\ncases_file: cases-link.jsonl\ntask_class: mechanical\npolicy_identity:\n  app: support\n  tags: [test]\n").unwrap();
    let output = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    // The symlink is rejected at open() time (O_NOFOLLOW), before any check-then-use gap, so the
    // failure surfaces as an open error rather than the post-open "must be a regular non-symlink
    // file" check (which still guards non-regular files that do open successfully, e.g. FIFOs).
    assert!(
        stderr.contains("failed to open dataset cases"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("ARBITRARY-SENTINEL-CONTENT"));
    assert!(!dir.join("ledger/quality-runs").exists());
}

#[test]
fn canary_validate_judge_rubric_is_regular_bounded_and_atomic() {
    let dir = tempdir("canary-judge-rubric");
    let (config, dataset, evaluators, canary) = canary_fixture(&dir, "http://127.0.0.1:1/v1/", 1);
    let registry_path = dir.join("registry.json");
    let mut registry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&registry_path).unwrap()).unwrap();
    let mut judge = registry["entries"][0].clone();
    judge["id"] = "public/judge".into();
    judge["model"] = "judge-model".into();
    registry["entries"].as_array_mut().unwrap().push(judge);
    fs::write(&registry_path, serde_json::to_vec(&registry).unwrap()).unwrap();
    let rubric = dir.join("rubric.md");
    fs::write(&rubric, "Synthetic rubric.").unwrap();
    let source = format!(
        "{}\njudge:\n  supply_id: public/judge\n  base_url: http://127.0.0.1:2/v1/\n  authorization_env: BOWLINE_TEST_JUDGE_AUTHORIZATION\n  rubric_file: rubric.md\n  required: true\n  send_customer_content: true\n  score_threshold: 0.8\n  concurrency: 1\n  request_timeout_ms: 500\n  max_response_bytes: 16384\n",
        fs::read_to_string(&canary).unwrap()
    );
    fs::write(&canary, source).unwrap();
    let mut args = vec!["canary".into(), "validate".into()];
    args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    let valid = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer candidate")
        .env("BOWLINE_TEST_JUDGE_AUTHORIZATION", "Bearer judge")
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert!(!dir.join("ledger/quality-runs").exists());

    fs::write(&rubric, vec![b'x'; 64 * 1024 + 1]).unwrap();
    let oversized = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer candidate")
        .env("BOWLINE_TEST_JUDGE_AUTHORIZATION", "Bearer judge")
        .output()
        .unwrap();
    assert!(!oversized.status.success());
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("judge rubric exceeds byte limit"));
    assert!(!dir.join("ledger/quality-runs").exists());

    fs::remove_file(&rubric).unwrap();
    fs::create_dir(&rubric).unwrap();
    let non_regular = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer candidate")
        .env("BOWLINE_TEST_JUDGE_AUTHORIZATION", "Bearer judge")
        .output()
        .unwrap();
    assert!(!non_regular.status.success());
    assert!(String::from_utf8_lossy(&non_regular.stderr)
        .contains("judge rubric must be a regular non-symlink file"));
    assert!(!dir.join("ledger/quality-runs").exists());
}

#[test]
fn canary_run_is_bounded_single_dispatch_and_reconciled() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();
    let primary = TcpListener::bind("127.0.0.1:0").unwrap();
    primary.set_nonblocking(true).unwrap();
    let primary_addr = primary.local_addr().unwrap();
    let base_url = format!("http://{server_addr}/v1/");
    let dir = tempdir("canary-run");
    let (config, dataset, evaluators, canary) = canary_fixture(&dir, &base_url, 1);
    let config_source = fs::read_to_string(&config)
        .unwrap()
        .replace("http://127.0.0.1:9", &format!("http://{primary_addr}"));
    fs::write(&config, config_source).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).ok();
        if request.is_empty() {
            return;
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.contains("POST /v1/responses"));
        assert!(request.contains("\"model\":\"candidate-model\""));
        let body = r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":2,"output_tokens":1}}"#;
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
    });
    let mut args = vec!["canary".into(), "run".into()];
    args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    args.push("--json".into());
    let output = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
        .output()
        .unwrap();
    if !output.status.success() {
        let _ = std::net::TcpStream::connect(server_addr);
    }
    server.join().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["accepted"], 1);
    assert_eq!(summary["recorded"], 1);
    assert_eq!(summary["candidate_dispatches"], 1);
    assert_eq!(summary["clean_shutdown"], true);
    assert!(
        matches!(primary.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("test-secret"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("status"));
}

#[test]
fn canary_freshness_starts_at_completion_and_has_exact_report_boundaries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let dir = tempdir("canary-completion-freshness");
    let (config, dataset, evaluators, canary) =
        canary_fixture(&dir, &format!("http://{address}/v1/"), 1);
    let source = fs::read_to_string(&canary)
        .unwrap()
        .replace("max_age_ms: 60000", "max_age_ms: 1");
    fs::write(&canary, source).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).ok();
        thread::sleep(std::time::Duration::from_millis(20));
        let body = r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":2,"output_tokens":1}}"#;
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
    });
    let mut run_args = vec!["canary".into(), "run".into()];
    run_args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    run_args.push("--json".into());
    let run = bowline()
        .args(run_args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    let run_id = summary["run_id"].as_str().unwrap();
    let directory = dir.join("ledger/quality-runs").join(run_id);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("quality-report.json")).unwrap()).unwrap();
    let started_at = manifest["started_at_ms"].as_u64().unwrap();
    let completed_at = manifest["completed_at_ms"].as_u64().unwrap();
    let valid_until = manifest["valid_until_ms"].as_u64().unwrap();
    assert!(
        completed_at > started_at + 1,
        "run did not outlast max_age_ms"
    );
    assert_eq!(valid_until, completed_at + 1);
    assert_eq!(report["completed_at_ms"], completed_at);
    assert_eq!(report["valid_until_ms"], valid_until);
    assert_eq!(report["as_of_ms"], completed_at);
    assert_eq!(report["stale"], false);

    for verify_inputs in [false, true] {
        for (as_of_ms, stale) in [(valid_until, false), (valid_until + 1, true)] {
            let mut args = vec![
                "canary".to_owned(),
                "report".to_owned(),
                "--config".to_owned(),
                config.display().to_string(),
                "--run-id".to_owned(),
                run_id.to_owned(),
                "--as-of-ms".to_owned(),
                as_of_ms.to_string(),
                "--json".to_owned(),
            ];
            if verify_inputs {
                args.extend([
                    "--dataset".to_owned(),
                    dataset.display().to_string(),
                    "--evaluators".to_owned(),
                    evaluators.display().to_string(),
                    "--canary".to_owned(),
                    canary.display().to_string(),
                ]);
            }
            let output = bowline().args(args).output().unwrap();
            assert!(
                output.status.success(),
                "stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let projected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(projected["as_of_ms"], as_of_ms);
            assert_eq!(projected["stale"], stale);
        }
    }
}

#[test]
fn canary_cancellation_and_writer_failure_are_incomplete() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();
    let base_url = format!("http://{server_addr}/v1/");
    let dir = tempdir("canary-cancel");
    let (config, dataset, evaluators, canary) = canary_fixture(&dir, &base_url, 1);
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::sleep(std::time::Duration::from_millis(1500));
    });
    let source = fs::read_to_string(&canary)
        .unwrap()
        .replace("max_wall_time_ms: 1000", "max_wall_time_ms: 50")
        .replace("request_timeout_ms: 500", "request_timeout_ms: 50");
    fs::write(&canary, source).unwrap();
    let mut args = vec!["canary".into(), "run".into()];
    args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    args.push("--json".into());
    let output = bowline()
        .args(&args)
        .env("BOWLINE_TEST_CANDIDATE_AUTHORIZATION", "Bearer test-secret")
        .output()
        .unwrap();
    if output.status.code() != Some(0) {
        let _ = std::net::TcpStream::connect(server_addr);
    }
    server.join().unwrap();
    assert_ne!(output.status.code(), Some(0));
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["clean_shutdown"], false);
    assert_eq!(summary["cancelled"], true);
    assert_eq!(summary["accepted"], summary["recorded"]);
}

#[test]
fn canary_report_rejects_mismatched_inputs_and_redacts_content() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let dir = tempdir("canary-report");
    let (config, dataset, evaluators, canary) =
        canary_fixture(&dir, &format!("http://{address}/v1/"), 1);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).ok();
        let body = r#"{"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":2,"output_tokens":1}}"#;
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
    });
    let mut run_args = vec!["canary".into(), "run".into()];
    run_args.extend(canary_args(&config, &dataset, &evaluators, &canary));
    run_args.push("--json".into());
    let run = bowline()
        .args(run_args)
        .env(
            "BOWLINE_TEST_CANDIDATE_AUTHORIZATION",
            "Bearer report-secret",
        )
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    let run_id = summary["run_id"].as_str().unwrap();

    let stored_args = vec![
        "canary".to_owned(),
        "report".to_owned(),
        "--config".to_owned(),
        config.display().to_string(),
        "--run-id".to_owned(),
        run_id.to_owned(),
        "--as-of-ms".to_owned(),
        "1".to_owned(),
        "--json".to_owned(),
    ];
    let stored = bowline().args(&stored_args).output().unwrap();
    assert!(
        stored.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&stored.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stored.stdout).unwrap();
    assert_eq!(report["run_id"], run_id);
    assert_eq!(report["as_of_ms"], 1);
    assert!(report["candidates"][0]["assessment"]["completion_verdict"].is_string());

    let mut matching_args = stored_args[..6].to_vec();
    matching_args.extend([
        "--dataset".to_owned(),
        dataset.display().to_string(),
        "--evaluators".to_owned(),
        evaluators.display().to_string(),
        "--canary".to_owned(),
        canary.display().to_string(),
        "--json".to_owned(),
    ]);
    let matching = bowline().args(&matching_args).output().unwrap();
    assert!(
        matching.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&matching.stderr)
    );
    let verified: serde_json::Value = serde_json::from_slice(&matching.stdout).unwrap();
    assert!(verified["as_of_ms"].as_u64().unwrap() > 0);

    let run_directory = dir.join("ledger/quality-runs").join(run_id);
    let report_path = run_directory.join("quality-report.json");
    let original_report = fs::read(&report_path).unwrap();
    let mut tampered_report: serde_json::Value = serde_json::from_slice(&original_report).unwrap();
    tampered_report["candidates"][0]["assessment"]["metrics"]["quality_pass_count"] =
        serde_json::json!(999);
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&tampered_report).unwrap(),
    )
    .unwrap();
    for (mode, args) in [("stored", &stored_args), ("verification", &matching_args)] {
        let rejected = bowline().args(args).output().unwrap();
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            !rejected.status.success(),
            "{mode} accepted report tampering"
        );
        assert!(
            stderr.contains("quality report evidence mismatch"),
            "{mode} stderr: {stderr}"
        );
    }
    fs::write(&report_path, &original_report).unwrap();

    let manifest_path = run_directory.join("manifest.json");
    let original_manifest = fs::read(&manifest_path).unwrap();
    let mut unbound_manifest: serde_json::Value =
        serde_json::from_slice(&original_manifest).unwrap();
    unbound_manifest["outcomes_digest"] = serde_json::Value::Null;
    unbound_manifest["quality_report_digest"] = serde_json::Value::Null;
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&unbound_manifest).unwrap(),
    )
    .unwrap();
    let unbound = bowline().args(&stored_args).output().unwrap();
    assert!(!unbound.status.success());
    assert!(String::from_utf8_lossy(&unbound.stderr).contains("quality report evidence mismatch"));
    fs::write(&manifest_path, original_manifest).unwrap();

    let mut partial_args = stored_args[..6].to_vec();
    partial_args.extend(["--dataset".to_owned(), dataset.display().to_string()]);
    let partial = bowline().args(partial_args).output().unwrap();
    assert!(!partial.status.success());
    assert!(String::from_utf8_lossy(&partial.stderr)
        .contains("dataset, evaluators, and canary must be provided together"));

    fs::write(
        &evaluators,
        format!(
            "{}\n# CUSTOMER-CONTENT-SENTINEL\n",
            fs::read_to_string(&evaluators).unwrap()
        ),
    )
    .unwrap();
    let mut verify_args = stored_args[..6].to_vec();
    verify_args.extend([
        "--dataset".to_owned(),
        dataset.display().to_string(),
        "--evaluators".to_owned(),
        evaluators.display().to_string(),
        "--canary".to_owned(),
        canary.display().to_string(),
    ]);
    let mismatch = bowline().args(verify_args).output().unwrap();
    let stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(!mismatch.status.success());
    assert!(
        stderr.contains("quality verification digest mismatch"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("report-secret"));
    assert!(!stderr.contains("CUSTOMER-CONTENT-SENTINEL"));
    assert!(!String::from_utf8_lossy(&stored.stdout).contains("status"));
}

fn tempdir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moves forward")
        .as_nanos();
    let dir = env::temp_dir().join(format!("bowline-cli-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("tempdir created");
    dir
}

fn absent_ledger_config(dir: &Path) -> PathBuf {
    let root = bowline_root();
    let ledger_dir = dir.join("missing-ledger");
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            r#"
listen: 127.0.0.1:0
upstream: http://127.0.0.1:9999
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
"#,
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            ledger_dir.display()
        ),
    )
    .expect("config written");
    config
}

#[test]
fn policy_validate_ok_prints_digest() {
    let root = bowline_root();

    let output = bowline()
        .current_dir(&root)
        .args(["policy", "validate", "policies/default.yaml"])
        .output()
        .expect("bowline runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("ok sha256:"), "stdout: {stdout}");
    assert_eq!(stdout.trim().len(), "ok sha256:".len() + 64);
}

#[test]
fn policy_validate_bad_yaml_exits_1() {
    let dir = tempdir("bad-policy");
    let policy = dir.join("bad.yaml");
    fs::write(&policy, "version: [").expect("bad policy written");

    let output = bowline()
        .args(["policy", "validate", policy.to_str().expect("utf8 path")])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to parse policy bundle"),
        "stderr: {stderr}"
    );
}

#[test]
fn report_on_absent_ledger_says_absent() {
    let dir = tempdir("absent-ledger");
    let config = absent_ledger_config(&dir);

    let output = bowline()
        .args(["report", "--config", config.to_str().expect("utf8 path")])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no ledger found"), "stdout: {stdout}");
    assert!(stdout.contains("Frontier reference:"), "stdout: {stdout}");
}

fn all_owned_registry_config(dir: &Path) -> PathBuf {
    let root = bowline_root();
    let ledger_dir = dir.join("missing-ledger");
    let registry_feed = dir.join("all-owned-feed.json");
    fs::write(
        &registry_feed,
        r#"{
  "feed_version": "test-all-owned",
  "entries": [
    {
      "id": "local/qwen3-32b",
      "model": "qwen3-32b",
      "location": "Customer-owned workstation",
      "attributes": {
        "class": "owned",
        "jurisdiction": "local",
        "retention": "none",
        "training_use": false,
        "cloud_act_exposure": false
      },
      "price": null,
      "ratings": { "mechanical": 0.82, "heavy-lifting": 0.84 },
      "available": true
    }
  ]
}
"#,
    )
    .expect("all-owned registry feed written");
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            r#"
listen: 127.0.0.1:0
upstream: http://127.0.0.1:9999
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
"#,
            root.join("policies/default.yaml").display(),
            registry_feed.display(),
            ledger_dir.display(),
        ),
    )
    .expect("config written");
    config
}

#[test]
fn report_on_all_owned_registry_degrades_to_na_instead_of_erroring() {
    let dir = tempdir("all-owned-registry");
    let config = all_owned_registry_config(&dir);

    let output = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--allow-incomplete",
        ])
        .output()
        .expect("bowline runs");

    assert!(
        output.status.success(),
        "a 100%-owned fleet is a success state, not an error — stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Frontier reference: `n/a — no frontier reference`"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("- All-frontier reference cost: n/a — no frontier reference"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("- Savings vs all-frontier: n/a — no frontier reference"),
        "stdout: {stdout}"
    );
}

#[test]
fn registry_show_lists_seeded_entries() {
    let root = bowline_root();

    let output = bowline()
        .current_dir(&root)
        .args(["registry", "show", "--config", "bowline.example.yaml"])
        .output()
        .expect("bowline runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("openai/gpt-5.5"), "stdout: {stdout}");
    assert!(stdout.contains("public-api"), "stdout: {stdout}");
    assert!(stdout.contains("local/qwen3-32b"), "stdout: {stdout}");
}

#[test]
fn health_command_requires_a_ready_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("health endpoint binds");
    let url = format!(
        "http://{}/health/ready",
        listener.local_addr().expect("health endpoint address")
    );
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("health probe accepted");
        let mut request = [0_u8; 1024];
        let read = stream.read(&mut request).expect("health probe read");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health/ready "));
        let body = r#"{"mode":"shadow","ready":true}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("health response written");
    });

    let output = bowline()
        .args(["health", "--url", &url])
        .output()
        .expect("bowline health runs");
    server.join().expect("health endpoint exits");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ready");
}

#[test]
fn health_command_rejects_redirect_without_contacting_target() {
    let redirect_target = TcpListener::bind("127.0.0.1:0").expect("redirect target binds");
    redirect_target
        .set_nonblocking(true)
        .expect("redirect target becomes nonblocking");
    let redirect_target_url = format!(
        "http://{}/health/ready",
        redirect_target
            .local_addr()
            .expect("redirect target address")
    );
    let redirect_source = TcpListener::bind("127.0.0.1:0").expect("redirect source binds");
    let source_url = format!(
        "http://{}/health/ready",
        redirect_source
            .local_addr()
            .expect("redirect source address")
    );
    let server = thread::spawn(move || {
        let (mut stream, _) = redirect_source.accept().expect("health probe accepted");
        let mut request = [0_u8; 1024];
        let read = stream.read(&mut request).expect("health probe read");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health/ready "));
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: {redirect_target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("redirect response written");
    });

    let output = bowline()
        .args(["health", "--url", &source_url])
        .output()
        .expect("bowline health runs");
    server.join().expect("redirect source exits");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        matches!(redirect_target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "redirect target must receive zero contacts"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), "not ready");
}

#[test]
fn serve_rejects_missing_config_with_clear_error() {
    let output = bowline()
        .args(["serve", "--config", "/no/such/bowline.yaml"])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read config /no/such/bowline.yaml"),
        "stderr: {stderr}"
    );
}

#[test]
fn report_requires_run_id_when_multiple_manifests_exist() {
    let dir = tempdir("ambiguous-runs");
    let config = run_report_config(&dir);
    let first = create_run(&dir.join("ledger"), false);
    let second = create_run(&dir.join("ledger"), false);

    let output = bowline()
        .args(["report", "--config", config.to_str().expect("utf8 path")])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("multiple runs"), "stderr: {stderr}");
    assert!(stderr.contains(&first), "stderr: {stderr}");
    assert!(stderr.contains(&second), "stderr: {stderr}");
}

#[test]
fn incomplete_report_renders_and_exits_2_unless_explicitly_allowed() {
    let dir = tempdir("incomplete-run");
    let config = run_report_config(&dir);
    let run_id = create_run(&dir.join("ledger"), true);

    let output = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--run-id",
            &run_id,
        ])
        .output()
        .expect("bowline runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("- Complete: false"));

    let allowed = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--run-id",
            &run_id,
            "--allow-incomplete",
        ])
        .output()
        .expect("bowline runs");
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(String::from_utf8_lossy(&allowed.stdout).contains("- Complete: false"));
}

#[test]
fn incomplete_raw_ledger_report_publishes_and_exits_2_unless_explicitly_allowed() {
    let dir = tempdir("incomplete-raw-ledger");
    let config = run_report_config(&dir);
    let ledger_dir = dir.join("ledger");
    let (ledger, recovery) = Ledger::open(&ledger_dir).expect("raw ledger opens");
    assert!(matches!(
        recovery,
        bowline_core::ledger::RecoveryOutcome::Absent
    ));
    drop(ledger);
    fs::OpenOptions::new()
        .append(true)
        .open(ledger_dir.join("decisions.bwl"))
        .expect("raw ledger file opens")
        .write_all(b"x")
        .expect("torn tail written");
    let (_, recovery) = Ledger::read_all(&ledger_dir).expect("torn raw ledger remains readable");
    assert!(matches!(
        recovery,
        bowline_core::ledger::RecoveryOutcome::TornTail { .. }
    ));
    let output_path = dir.join("raw-report.json");

    let output = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--json",
            "--out",
            output_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).expect("incomplete report published"))
            .expect("incomplete report renders as JSON");
    assert_eq!(report["report"]["complete"], false);
    assert_eq!(
        report["report"]["ledger_state"],
        "torn-tail (1 bytes discarded)"
    );
    assert_eq!(report["ledger_note"], "ledger repaired from torn tail");

    let allowed = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--json",
            "--out",
            output_path.to_str().expect("utf8 path"),
            "--allow-incomplete",
        ])
        .output()
        .expect("bowline runs");
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).expect("allowed report published"))
            .expect("allowed report renders as JSON");
    assert_eq!(report["report"]["complete"], false);
}

#[cfg(unix)]
#[test]
fn incomplete_shadow_report_atomically_replaces_output_without_touching_symlink_target() {
    let dir = tempdir("incomplete-shadow-atomic-output");
    let config = run_report_config(&dir);
    let run_id = create_run(&dir.join("ledger"), true);
    let sentinel = dir.join("sentinel.txt");
    fs::write(&sentinel, b"preserve-me").unwrap();
    let output_path = dir.join("shadow-report.md");
    std::os::unix::fs::symlink(&sentinel, &output_path).unwrap();

    let output = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--run-id",
            &run_id,
            "--out",
            output_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserve-me");
    assert!(fs::symlink_metadata(&output_path).unwrap().is_file());
    assert!(fs::read_to_string(&output_path)
        .unwrap()
        .contains("- Complete: false"));
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));

    let allowed = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 path"),
            "--run-id",
            &run_id,
            "--out",
            output_path.to_str().expect("utf8 path"),
            "--allow-incomplete",
        ])
        .output()
        .expect("bowline runs");
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn incomplete_authority_report_publishes_and_exits_2_unless_explicitly_allowed() {
    let dir = tempdir("incomplete-authority-report");
    let manifest = create_cancelled_authority_run(&dir);
    let output_path = dir.join("authority-report.json");

    let output = bowline()
        .args([
            "report",
            "--authority-manifest",
            manifest.to_str().unwrap(),
            "--json",
            "--out",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(report["complete"], false);
    assert!(report["totals"]["enforced_modeled_delta_micros"].is_null());

    let allowed = bowline()
        .args([
            "report",
            "--authority-manifest",
            manifest.to_str().unwrap(),
            "--json",
            "--out",
            output_path.to_str().unwrap(),
            "--allow-incomplete",
        ])
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(report["complete"], false);
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

fn create_cancelled_authority_run(root: &Path) -> PathBuf {
    let digest = |_ch: char| format!("sha256:{}", "a".repeat(64));
    let directory = root.join("authority");
    let store = AuthorityRunStoreV2::create(
        &directory,
        AuthorityRunDigestsV2 {
            enforcement: digest('e'),
            actuator_set: digest('a'),
            grant_set: digest('g'),
        },
    )
    .unwrap();
    let snapshot = store.snapshot();
    let mut ledger =
        AuthorityLedgerV2::create(&directory, &snapshot.records_file, 1024 * 1024).unwrap();
    let facts = AuthoritySelectionFactsV2::canonical_candidate(7);
    let decision = AuthorityDecisionV2 {
        decision_id: "decision-1".into(),
        replaces_decision_id: None,
        configured_fallback_target: None,
        ts_ms: 10,
        route_id: "chat-canary".into(),
        mode: RouteMode::CanaryEnforce,
        protocol: AuthorityProtocol::ChatCompletions,
        task_class: TaskClass::HeavyLifting,
        workload_identity_digest: Some(digest('w')),
        app: Some("support".into()),
        resolved_tags: vec!["production".into()],
        requested_supply_id: Some("owned/a".into()),
        reason: SelectionReason::CandidateSelected,
        evidence_state: EvidenceState::Presented,
        selection_facts: facts.clone(),
        target: PlanTarget::Candidate,
        intended_dispatch: 1,
        grant: Some(AuthorityGrantBindingV2 {
            grant_digest: digest('g'),
            expires_at_ms: 100,
            economics_source_digest: digest('x'),
            quality_source_digest: digest('q'),
            opportunity_digest: digest('o'),
        }),
        selected_supply_id: Some("owned/a".into()),
        baseline_supply_id: Some("public/b".into()),
        actuator_identity_digest: Some(digest('i')),
        actuator_config_digest: Some(digest('a')),
        enforcement_config_digest: digest('e'),
        route_config_digest: digest('r'),
        model_rewritten: true,
    };
    let outcome = AuthorityOutcomeV2 {
        decision_id: decision.decision_id.clone(),
        replaces_decision_id: None,
        ts_ms: 20,
        route_id: decision.route_id.clone(),
        mode: decision.mode,
        protocol: decision.protocol,
        task_class: decision.task_class,
        workload_identity_digest: decision.workload_identity_digest.clone(),
        app: decision.app.clone(),
        resolved_tags: decision.resolved_tags.clone(),
        requested_supply_id: decision.requested_supply_id.clone(),
        selection_facts: facts,
        grant_digest: decision.grant.as_ref().map(|g| g.grant_digest.clone()),
        grant_expires_at_ms: decision.grant.as_ref().map(|g| g.expires_at_ms),
        model_rewritten: true,
        selected_supply_id: decision.selected_supply_id.clone(),
        baseline_supply_id: decision.baseline_supply_id.clone(),
        actuator_identity_digest: decision.actuator_identity_digest.clone(),
        actuator_config_digest: decision.actuator_config_digest.clone(),
        enforcement_config_digest: decision.enforcement_config_digest.clone(),
        route_config_digest: decision.route_config_digest.clone(),
        target: PlanTarget::Candidate,
        fallback_reason: None,
        circuit_before: CircuitStateV2::Closed,
        circuit_after: CircuitStateV2::Closed,
        actual_dispatch: 1,
        completion: CompletionStateV2::Cancelled,
        candidate_failure: None,
        status: Some(200),
        input_tokens: None,
        output_tokens: None,
        usage_source: UsageSource::Missing,
        observed_actual_cost_micros: None,
        approved_counterfactual_cost_micros: None,
        enforced_modeled_delta_micros: None,
    };
    let decision = AuthorityRecordV2::decision(store.accept().unwrap(), decision).unwrap();
    ledger.append(&decision).unwrap();
    store.recorded(1).unwrap();
    let outcome = AuthorityRecordV2::outcome(store.accept().unwrap(), outcome).unwrap();
    ledger.append(&outcome).unwrap();
    store.recorded(2).unwrap();
    let (bytes, records_digest) = ledger.integrity().unwrap();
    store
        .finish(true, Some(bytes), Some(records_digest))
        .unwrap();
    let manifest = store.manifest_path().to_path_buf();
    drop(ledger);
    drop(store);
    manifest
}

#[test]
fn report_rejects_owned_cost_digest_mismatch_but_allows_legacy_unbound() {
    let dir = tempdir("owned-cost-provenance");
    let root = bowline_root();
    let registry_source = fs::read_to_string(root.join("registry/feed.json")).expect("registry");
    let registry = Registry::from_json(&registry_source).expect("registry parses");
    let catalog_a_source = "monthly_amortization_usd: 100\nmonthly_power_usd: 0\nmonthly_ops_usd: 0\nmonthly_capacity_mtok: 100\n";
    let catalog_b_source = "monthly_amortization_usd: 200\nmonthly_power_usd: 0\nmonthly_ops_usd: 0\nmonthly_capacity_mtok: 100\n";
    let catalog_a =
        load_owned_cost_catalog(Some(catalog_a_source), Some("local/qwen3-32b"), &registry)
            .expect("catalog A");
    let tco_b = dir.join("tco-b.yaml");
    fs::write(&tco_b, catalog_b_source).expect("catalog B written");
    let config = dir.join("report.yaml");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9999\nactual_supply_id: local/qwen3-32b\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\ntco: {}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display(),
            tco_b.display(),
        ),
    )
    .expect("report config");

    let bound_run = create_run_with_owned_cost_digest(
        &dir.join("ledger"),
        false,
        Some(catalog_a.normalized_digest().to_string()),
    );
    let rejected = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 config"),
            "--run-id",
            &bound_run,
        ])
        .output()
        .expect("bowline runs");
    assert_eq!(rejected.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("owned-cost catalog digest mismatch"),
        "{stderr}"
    );
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("# Bowline Shadow Report"));

    let legacy_run = create_run_with_owned_cost_digest(&dir.join("ledger"), false, None);
    let legacy = bowline()
        .args([
            "report",
            "--config",
            config.to_str().expect("utf8 config"),
            "--run-id",
            &legacy_run,
        ])
        .output()
        .expect("bowline runs");
    assert!(
        legacy.status.success(),
        "{}",
        String::from_utf8_lossy(&legacy.stderr)
    );
}

#[test]
fn preflight_invalid_config_emits_stable_json_without_authorization() {
    let dir = tempdir("preflight-invalid");
    let root = bowline_root();
    let config = dir.join("invalid.yaml");
    fs::write(
        &config,
        format!(
            r#"listen: 0.0.0.0:8080
upstream: ftp://example.test
actual_supply_id: ''
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
trusted_proxy_cidrs: []
"#,
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display(),
        ),
    )
    .expect("invalid config written");

    let output = bowline()
        .env("BOWLINE_PREFLIGHT_AUTHORIZATION", "Bearer must-not-leak")
        .args([
            "preflight",
            "--config",
            config.to_str().expect("utf8 path"),
            "--json",
        ])
        .output()
        .expect("bowline runs");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("preflight JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["checks"][0]["id"], "config");
    assert_eq!(json["checks"][0]["status"], "fail");
    assert!(json["checks"][0]["remediation"].is_string());
    assert!(!stdout.contains("must-not-leak"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-leak"));
}

#[test]
fn dynamic_attribution_config_and_preflight_are_strict() {
    let dir = tempdir("dynamic-attribution-config");
    let root = bowline_root();
    let config_path = dir.join("dynamic.yaml");
    let valid = format!(
        r#"listen: 127.0.0.1:0
upstream: http://127.0.0.1:9
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
attribution:
  version: 1
  response_header: x-upstream-supply-ref
  namespace: deployment
  mappings:
    - {{value: prod-secret-token-east, supply_id: openai/gpt-5-mini}}
    - {{value: west, supply_id: local/qwen3-32b}}
"#,
        root.join("policies/default.yaml").display(),
        root.join("registry/feed.json").display(),
        dir.join("ledger").display()
    );
    let parsed = Config::from_yaml(&valid).expect("valid dynamic config parses");
    parsed
        .validate()
        .expect("valid dynamic config validates without legacy supply");
    let registry_source = fs::read_to_string(root.join("registry/feed.json")).expect("registry");
    let registry = Registry::from_json(&registry_source).expect("registry parses");
    let digest = parsed
        .attribution_digest(&registry)
        .expect("attribution digest");
    let changed_header = Config::from_yaml(&valid.replace(
        "response_header: x-upstream-supply-ref",
        "response_header: x-upstream-deployment-ref",
    ))
    .expect("changed config");
    assert_ne!(
        digest,
        changed_header
            .attribution_digest(&registry)
            .expect("changed digest")
    );

    for invalid in [
        valid.replace("version: 1", "version: 2"),
        valid.replace("namespace: deployment", "namespace: ''"),
        valid.replace(
            "namespace: deployment",
            &format!("namespace: {}", "x".repeat(257)),
        ),
        valid.replace("value: west", "value: ''"),
        valid.replace("value: west", &format!("value: {}", "x".repeat(257))),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            &format!("response_header: x-{}", "x".repeat(129)),
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: authorization",
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: proxy-authorization",
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: cookie",
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: set-cookie",
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: x-api-key",
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: x-auth-token",
        ),
        valid.replace(
            "response_header: x-upstream-supply-ref",
            "response_header: x-client-secret",
        ),
        valid.replace(
            "    - {value: west, supply_id: local/qwen3-32b}\n",
            "    - {value: prod-secret-token-east, supply_id: local/qwen3-32b}\n",
        ),
    ] {
        let config = Config::from_yaml(&invalid).expect("strict shape still parses");
        assert!(
            config.validate().is_err(),
            "invalid dynamic config validated"
        );
    }

    fs::write(&config_path, &valid).expect("config written");
    let output = bowline()
        .args([
            "preflight",
            "--config",
            config_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("preflight runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("attribution-mapping-1"));
    assert!(stdout.contains("attribution-mapping-2"));
    assert!(stdout.contains("openai/gpt-5-mini"));
    assert!(stdout.contains("local/qwen3-32b"));
    assert!(!stdout.contains("prod-secret-token-east"));

    let unknown = valid.replace("openai/gpt-5-mini", "missing/supply");
    fs::write(&config_path, unknown).expect("unknown config");
    let output = bowline()
        .args([
            "preflight",
            "--config",
            config_path.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("preflight runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("unknown supply id"));

    let legacy = valid_yaml_without_attribution(&root, &dir);
    Config::from_yaml(&legacy)
        .expect("legacy parses")
        .validate()
        .expect("legacy remains valid");
}

#[test]
fn dynamic_attribution_response_header_rejects_surrounding_whitespace() {
    let dir = tempdir("dynamic-attribution-header-whitespace");
    let root = bowline_root();
    let config_path = dir.join("dynamic.yaml");
    for response_header in [" x-upstream-supply-ref", "x-upstream-supply-ref "] {
        let source = format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\nattribution:\n  version: 1\n  response_header: '{response_header}'\n  namespace: deployment\n  mappings:\n    - {{value: east, supply_id: openai/gpt-5-mini}}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display(),
        );
        let config = Config::from_yaml(&source).expect("shape parses");
        assert!(
            config.validate().is_err(),
            "surrounding response-header whitespace validated"
        );

        fs::write(&config_path, source).expect("config written");
        let output = bowline()
            .args([
                "preflight",
                "--config",
                config_path.to_str().expect("utf8"),
                "--json",
            ])
            .output()
            .expect("preflight runs");
        assert_eq!(output.status.code(), Some(1));
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("preflight JSON");
        assert_eq!(json["checks"][0]["id"], "config");
        assert_eq!(json["checks"][0]["status"], "fail");
        assert!(!output
            .stdout
            .windows(b"attribution-mapping-1".len())
            .any(|window| { window == b"attribution-mapping-1" }));
    }
}

#[test]
fn import_observations_rejects_duplicate_atomically() {
    for (name, setup, expected) in [
        (
            "duplicate",
            ImportFailure::Duplicate,
            "duplicate event_id first seen at line 1, duplicated at line 2",
        ),
        ("malformed", ImportFailure::Malformed, "input.jsonl:2"),
        (
            "over-limit",
            ImportFailure::OverLimit,
            "input exceeds 16777216 bytes",
        ),
        (
            "invalid-profile",
            ImportFailure::InvalidProfile,
            "missing required target latency_ms",
        ),
        (
            "invalid-constant-empty-input",
            ImportFailure::InvalidConstant,
            "constant event_id",
        ),
    ] {
        let dir = tempdir(&format!("import-atomic-{name}"));
        let fixture = import_fixture(&dir);
        match setup {
            ImportFailure::Duplicate => fs::write(
                &fixture.input,
                format!(
                    "{}\n{}\n",
                    raw_import_event("same", 20),
                    raw_import_event("same", 10)
                ),
            )
            .expect("duplicate input"),
            ImportFailure::Malformed => fs::write(
                &fixture.input,
                format!("{}\n{{\n", raw_import_event("first", 20)),
            )
            .expect("malformed input"),
            ImportFailure::OverLimit => {
                fs::write(&fixture.input, vec![b'x'; 16 * 1024 * 1024 + 1]).expect("large input")
            }
            ImportFailure::InvalidProfile => {
                fs::write(
                    &fixture.input,
                    format!("{}\n", raw_import_event("valid", 20)),
                )
                .expect("valid input");
                let profile = fs::read_to_string(&fixture.profile).expect("profile");
                fs::write(
                    &fixture.profile,
                    profile.replace("  latency_ms: /latency_ms\n", ""),
                )
                .expect("invalid profile")
            }
            ImportFailure::InvalidConstant => {
                fs::write(&fixture.input, "").expect("empty input");
                let profile = fs::read_to_string(&fixture.profile).expect("profile");
                fs::write(
                    &fixture.profile,
                    profile
                        .replace("  event_id: /request_id\n", "")
                        .replace("constants:\n", "constants:\n  event_id: '   '\n"),
                )
                .expect("invalid constant profile")
            }
        }

        let output = run_import(&fixture, true);
        assert_eq!(output.status.code(), Some(1), "{name}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{name}: {stderr}");
        assert!(!stderr.contains("SENSITIVE_SENTINEL"), "{name}: {stderr}");
        assert!(
            RunStore::list_manifests(&fixture.ledger)
                .expect("manifest list")
                .is_empty(),
            "{name} created a run before complete prevalidation"
        );
    }
}

#[test]
fn import_observations_reconciles_managed_run() {
    let dir = tempdir("import-reconcile");
    let fixture = import_fixture(&dir);
    let input = format!(
        "{}\n{}\n",
        raw_import_event("req-a", 20),
        raw_import_event("req-b", 10)
    );
    fs::write(&fixture.input, &input).expect("input");

    let first = run_import(&fixture, true);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("safe JSON summary");
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["accepted"], 2);
    assert_eq!(summary["recorded"], 2);
    assert_eq!(summary["incomplete"], 0);
    assert_eq!(summary["cross_run_deduplication"], "not-performed");
    assert_eq!(summary.as_object().expect("summary object").len(), 6);
    let first_run = summary["run_id"].as_str().expect("run id").to_string();

    let manifests = RunStore::list_manifests(&fixture.ledger).expect("manifest list");
    assert_eq!(manifests.len(), 1);
    let manifest = &manifests[0];
    assert_eq!(manifest.run_id, first_run);
    assert_eq!(manifest.accepted, 2);
    assert_eq!(manifest.recorded, 2);
    assert_eq!(manifest.dropped, 0);
    assert!(manifest.clean_shutdown);
    assert!(manifest.writer_healthy);
    assert!(manifest.attribution_digest.is_some());
    assert!(manifest.owned_cost_digest.is_some());
    assert!(manifest.passive_profile_digest.is_some());
    assert_eq!(
        manifest.passive_input_digest.as_deref(),
        Some(format!("sha256:{:x}", Sha256::digest(input.as_bytes())).as_str())
    );
    let (records, recoveries) =
        SegmentedLedger::read_run(&fixture.ledger, &first_run).expect("records");
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|record| record.observation_source == ObservationSource::Passive));
    let root = bowline_root();
    let registry_source = fs::read_to_string(root.join("registry/feed.json")).expect("registry");
    let registry = Registry::from_json(&registry_source).expect("registry parses");
    let owned_costs = load_owned_cost_catalog(None, Some(""), &registry).expect("empty costs");
    let report = compute_run_report(
        &records,
        &recoveries,
        manifest,
        &registry,
        &owned_costs,
        &Default::default(),
        None,
    )
    .expect("run report");
    assert_eq!(
        report.protocol_coverage.by_source[&ObservationSource::Passive],
        2
    );

    fs::write(
        &fixture.input,
        format!("{}\n", raw_import_event("req-c", 30)),
    )
    .expect("changed input");
    let second = run_import(&fixture, false);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let human = String::from_utf8_lossy(&second.stdout);
    assert!(
        human.contains("cross-run deduplication is not performed"),
        "{human}"
    );
    assert!(!human.contains("SENSITIVE_SENTINEL"));
    let manifests = RunStore::list_manifests(&fixture.ledger).expect("manifest list");
    assert_eq!(manifests.len(), 2);
    assert_ne!(manifests[0].run_id, manifests[1].run_id);
    assert_ne!(
        manifests[0].passive_input_digest,
        manifests[1].passive_input_digest
    );
}

#[test]
fn import_observations_preserves_line_sequence() {
    let dir = tempdir("import-order");
    let fixture = import_fixture(&dir);
    fs::write(
        &fixture.input,
        format!(
            "{}\n{}\n{}\n",
            raw_import_event("req-first", 300),
            raw_import_event("req-second", 100),
            raw_import_event("req-third", 200)
        ),
    )
    .expect("out-of-order timestamps");

    let output = run_import(&fixture, true);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifests = RunStore::list_manifests(&fixture.ledger).expect("manifest list");
    let manifest = manifests.last().expect("manifest");
    let (records, _) =
        SegmentedLedger::read_run(&fixture.ledger, &manifest.run_id).expect("records");
    assert_eq!(
        records
            .iter()
            .map(|record| (record.sequence, record.ts_ms, record.id.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some(1), 300, "req-first"),
            (Some(2), 100, "req-second"),
            (Some(3), 200, "req-third"),
        ]
    );
}

#[test]
fn import_observations_writer_drop_is_nonzero_and_manifest_is_incomplete() {
    let dir = tempdir("import-writer-drop");
    let fixture = import_fixture(&dir);
    let config = fs::read_to_string(&fixture.config).expect("config");
    fs::write(
        &fixture.config,
        format!("{config}\nruntime:\n  ledger_segment_bytes: 256\n"),
    )
    .expect("tiny segment config");
    fs::write(
        &fixture.input,
        format!("{}\n", raw_import_event("req-drop", 1)),
    )
    .expect("input");

    let output = run_import(&fixture, true);
    assert_eq!(output.status.code(), Some(1));
    let manifests = RunStore::list_manifests(&fixture.ledger).expect("manifest list");
    assert_eq!(manifests.len(), 1);
    let manifest = &manifests[0];
    assert_eq!(manifest.accepted, 1);
    assert_eq!(manifest.recorded, 0);
    assert_eq!(manifest.dropped, 1);
    assert!(!manifest.writer_healthy);
}

#[cfg(unix)]
#[test]
fn import_observations_rejects_non_regular_inputs_without_blocking() {
    use std::{os::unix::fs::symlink, process::Stdio, time::Duration};

    let dir = tempdir("import-file-kinds");
    let fixture = import_fixture(&dir);
    let regular = dir.join("regular.jsonl");
    fs::write(&regular, format!("{}\n", raw_import_event("regular", 1))).unwrap();

    symlink(&regular, &fixture.input).unwrap();
    let output = run_import(&fixture, true);
    assert_eq!(output.status.code(), Some(1));
    fs::remove_file(&fixture.input).unwrap();

    fs::create_dir(&fixture.input).unwrap();
    let output = run_import(&fixture, true);
    assert_eq!(output.status.code(), Some(1));
    fs::remove_dir(&fixture.input).unwrap();

    assert!(Command::new("mkfifo")
        .arg(&fixture.input)
        .status()
        .unwrap()
        .success());
    let mut command = import_command(&fixture, true);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("import child");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO import blocked");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(1));
    assert!(RunStore::list_manifests(&fixture.ledger)
        .unwrap()
        .is_empty());
}

#[test]
fn preflight_validates_all_required_dependencies_and_redacts_auth() {
    let dir = tempdir("preflight-valid");
    let root = bowline_root();
    let listener = TcpListener::bind("127.0.0.1:0").expect("model endpoint binds");
    let upstream = format!(
        "http://{}",
        listener.local_addr().expect("endpoint address")
    );
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("model probe accepted");
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).expect("model probe read");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.contains("authorization: Bearer preflight-secret"));
        let body = r#"{"object":"list","data":[{"id":"gpt-5-mini"}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("model response written");
    });
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            r#"listen: 127.0.0.1:0
upstream: {upstream}
actual_supply_id: openai/gpt-5-mini
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
"#,
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display(),
        ),
    )
    .expect("valid config written");

    let output = bowline()
        .env("BOWLINE_PREFLIGHT_AUTHORIZATION", "Bearer preflight-secret")
        .args([
            "preflight",
            "--config",
            config.to_str().expect("utf8 path"),
            "--json",
        ])
        .output()
        .expect("bowline runs");
    server.join().expect("model endpoint exits");

    assert!(
        output.status.success(),
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("preflight JSON");
    let ids = json["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .map(|check| check["id"].as_str().expect("stable check id"))
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            "config",
            "policy",
            "registry",
            "tco",
            "ledger",
            "local-endpoints",
            "upstream-models",
            "model-resolution"
        ]
    );
    assert!(json["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .all(|check| check["status"] == "pass"));
    assert!(!stdout.contains("preflight-secret"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("preflight-secret"));
}

fn run_report_config(dir: &Path) -> PathBuf {
    let root = bowline_root();
    let config = dir.join("run-report.yaml");
    fs::write(
        &config,
        format!(
            r#"listen: 127.0.0.1:0
upstream: http://127.0.0.1:9999
actual_supply_id: openai/gpt-5-mini
policy_bundle: {}
registry_feed: {}
ledger_dir: {}
"#,
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            dir.join("ledger").display()
        ),
    )
    .expect("run report config written");
    config
}

fn valid_yaml_without_attribution(root: &Path, dir: &Path) -> String {
    format!(
        "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9999\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n",
        root.join("policies/default.yaml").display(),
        root.join("registry/feed.json").display(),
        dir.join("legacy-ledger").display(),
    )
}

fn create_run(ledger_dir: &Path, incomplete: bool) -> String {
    create_run_with_owned_cost_digest(ledger_dir, incomplete, None)
}

fn create_run_with_owned_cost_digest(
    ledger_dir: &Path,
    incomplete: bool,
    owned_cost: Option<String>,
) -> String {
    let store = RunStore::create(
        ledger_dir,
        RunDigests {
            policy: "sha256:policy".to_string(),
            registry: "sha256:registry".to_string(),
            attribution: None,
            owned_cost,
            passive_profile: None,
            passive_input: None,
        },
        RunLimits {
            segment_bytes: 1024,
            max_segments: 4,
        },
    )
    .expect("run starts");
    let run_id = store.run_id();
    if incomplete {
        let sequence = store.accept().expect("request accepted");
        store.dropped(sequence).expect("drop disclosed");
    }
    store.finish(true).expect("run finishes");
    run_id
}

enum ImportFailure {
    Duplicate,
    Malformed,
    OverLimit,
    InvalidProfile,
    InvalidConstant,
}

struct ImportFixture {
    config: PathBuf,
    input: PathBuf,
    profile: PathBuf,
    ledger: PathBuf,
}

fn import_fixture(dir: &Path) -> ImportFixture {
    let root = bowline_root();
    let ledger = dir.join("ledger");
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9999\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\nattribution:\n  version: 1\n  response_header: x-upstream-supply\n  namespace: deployment\n  mappings:\n    - {{value: east, supply_id: openai/gpt-5-mini}}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            ledger.display(),
        ),
    )
    .expect("import config");
    let profile = dir.join("profile.yaml");
    fs::write(
        &profile,
        r#"version: 1
kind: test-import-v1
source_contract: test-import-contract-v1
attribution_namespace: deployment
timestamp_unit: milliseconds
fields:
  event_id: /request_id
  observed_at_ms: /observed_at_ms
  route: /route
  model: /model
  actual_supply_value: /deployment
  status: /status
  latency_ms: /latency_ms
  input_tokens: /input_tokens
  output_tokens: /output_tokens
  dimensions.app: /app
constants:
  method: POST
  streamed: false
"#,
    )
    .expect("import profile");
    ImportFixture {
        config,
        input: dir.join("input.jsonl"),
        profile,
        ledger,
    }
}

fn raw_import_event(id: &str, observed_at_ms: u64) -> String {
    format!(
        r#"{{"request_id":"{id}","observed_at_ms":{observed_at_ms},"route":"/v1/responses","model":"gpt-5-mini","deployment":"east","status":200,"latency_ms":25,"input_tokens":10,"output_tokens":5,"app":"support"}}"#
    )
}

fn run_import(fixture: &ImportFixture, json: bool) -> std::process::Output {
    import_command(fixture, json)
        .output()
        .expect("bowline import runs")
}

fn import_command(fixture: &ImportFixture, json: bool) -> Command {
    let mut command = bowline();
    command.args([
        "import",
        "observations",
        "--config",
        fixture.config.to_str().expect("config UTF-8"),
        "--input",
        fixture.input.to_str().expect("input UTF-8"),
        "--profile",
        fixture.profile.to_str().expect("profile UTF-8"),
    ]);
    if json {
        command.arg("--json");
    }
    command
}

#[test]
fn billing_validate_writes_nothing_and_import_creates_one_private_complete_run() {
    let dir = tempdir("billing-cli");
    let root = bowline_root();
    let ledger = dir.join("ledger");
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            ledger.display(),
        ),
    )
    .unwrap();
    let billing = dir.join("billing.jsonl");
    fs::write(&billing, r#"{"schema_version":1,"row_id":"synthetic-1","period_start_ms":1,"period_end_ms":2,"supply_id":"openai/gpt-5-mini","currency":"USD","charge_basis":"inference-usage-net","charge_usd":"1.250000","request_count":1,"input_tokens":2,"output_tokens":3}
"#).unwrap();

    let validate = bowline()
        .args([
            "billing",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            billing.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(!ledger.join("billing-runs").exists());

    let imported = bowline()
        .args([
            "billing",
            "import",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            billing.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["rows"], 1);
    assert_eq!(summary["charge_usd_micros"], 1_250_000);
    assert!(summary.get("source_path").is_none());
    let runs = fs::read_dir(ledger.join("billing-runs"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(runs.len(), 1);
    let manifest = bowline_core::billing_run::BillingRunStore::load_manifest(
        &fs::canonicalize(runs[0].path()).unwrap(),
    )
    .unwrap();
    assert!(manifest.clean_shutdown && manifest.reconciled());
}

#[test]
fn billing_mapping_is_the_only_csv_selector_and_mapped_import_is_supported() {
    let dir = tempdir("billing-cli-mapping");
    let root = bowline_root();
    let ledger = dir.join("ledger");
    let config = dir.join("bowline.yaml");
    fs::write(&config, format!("listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\nactual_supply_id: openai/gpt-5-mini\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n", root.join("policies/default.yaml").display(), root.join("registry/feed.json").display(), ledger.display())).unwrap();
    let csv = dir.join("billing.csv");
    fs::write(&csv, "id,start,end,supply,currency,basis,charge\r\nrow,1,2,openai/gpt-5-mini,USD,inference-usage-net,1.0\r\n").unwrap();
    let mapping = dir.join("mapping.yaml");
    fs::write(&mapping, "version: 1\ndelimiter: comma\ncolumns:\n  row_id: id\n  period_start_ms: start\n  period_end_ms: end\n  supply_id: supply\n  currency: currency\n  charge_basis: basis\n  charge_usd: charge\n").unwrap();
    let no_mapping = bowline()
        .args([
            "billing",
            "validate",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            csv.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!no_mapping.status.success());
    assert!(!ledger.join("billing-runs").exists());
    let mapped = bowline()
        .args([
            "billing",
            "import",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            csv.to_str().unwrap(),
            "--mapping",
            mapping.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        mapped.status.success(),
        "{}",
        String::from_utf8_lossy(&mapped.stderr)
    );
    assert_eq!(
        fs::read_dir(ledger.join("billing-runs")).unwrap().count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn billing_public_inputs_reject_symlinks_without_creating_a_run() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("billing-cli-symlink");
    let root = bowline_root();
    let ledger = dir.join("ledger");
    let config = dir.join("bowline.yaml");
    fs::write(&config, format!("listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\n", root.join("policies/default.yaml").display(), root.join("registry/feed.json").display(), ledger.display())).unwrap();
    let real = dir.join("real.jsonl");
    fs::write(&real, "CUSTOMER-CONTENT-SENTINEL").unwrap();
    let link = dir.join("billing.jsonl");
    symlink(&real, &link).unwrap();
    let output = bowline()
        .args([
            "billing",
            "import",
            "--config",
            config.to_str().unwrap(),
            "--billing",
            link.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!ledger.join("billing-runs").exists());
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!rendered.contains("CUSTOMER-CONTENT-SENTINEL"));
}
