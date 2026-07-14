#[cfg(test)]
mod tests {
    use super::*;
    use bowline_core::economics::{
        ActionableEconomicsReport, AnalysisMode, BuildProvenance, ReconciliationReport,
        ReconciliationState, SelectedEvidence, SelectedTrafficEvidence,
    };
    use bowline_core::enforcement::RouteMode;
    use bowline_core::report::{
        ControlledEnforcementModeRow, ControlledEnforcementReport, ControlledEnforcementTotals,
    };
    use std::os::unix::fs::PermissionsExt;

    fn empty_report() -> ActionableEconomicsReport {
        ActionableEconomicsReport {
            schema_version: 1,
            mode: AnalysisMode::ModeledOnly,
            as_of_ms: 2,
            window_start_ms: 1,
            window_end_ms: 2,
            complete: false,
            build_provenance: BuildProvenance {
                package_version: env!("CARGO_PKG_VERSION").into(),
                source_revision: source_revision().unwrap(),
            },
            global_blockers: vec![],
            source_bindings: vec![],
            selected_evidence: SelectedEvidence {
                traffic: SelectedTrafficEvidence {
                    run_id: "synthetic-traffic".into(),
                    records_digest: format!("sha256:{}", "1".repeat(64)),
                    manifest_digest: format!("sha256:{}", "2".repeat(64)),
                    recovery_digest: format!("sha256:{}", "3".repeat(64)),
                },
                billing: None,
                quality: vec![],
            },
            reconciliation: ReconciliationReport {
                state: ReconciliationState::NotRequested,
                eligible_records: 0,
                matched_records: 0,
                unmatched_records: 0,
                total_provider_rows: 0,
                matched_provider_rows: 0,
                unmatched_provider_rows: 0,
                qualified_provider_rows: 0,
                total_imported_charge_micros: 0,
                matched_imported_charge_micros: 0,
                qualified_imported_charge_micros: 0,
                modeled_actual_cost_micros: None,
                record_coverage_ppm: None,
                row_presence_charge_coverage_ppm: None,
                qualified_charge_coverage_ppm: None,
                charge_variance_micros: None,
                charge_variance_ppm: None,
                request_delta: None,
                input_token_delta: None,
                output_token_delta: None,
                request_count_available_rows: 0,
                request_count_total_rows: 0,
                input_token_available_rows: 0,
                input_token_total_rows: 0,
                output_token_available_rows: 0,
                output_token_total_rows: 0,
                rows: vec![],
                exceptions: vec![],
            },
            dimensions: vec![],
            opportunities: vec![],
        }
    }

    #[test]
    fn controlled_enforcement_formats_have_exact_canonical_parity() {
        let totals = ControlledEnforcementTotals {
            decisions: 6,
            candidate_dispatches: 2,
            pre_dispatch_rejections: 1,
            bypasses: 1,
            fail_closed: 1,
            failures: 1,
            cancellations: 1,
            incomplete: 2,
            observed_enforced_cost_micros: Some(700_000),
            enforced_modeled_delta_micros: Some(-300_000),
        };
        let report = ControlledEnforcementReport {
            schema_version: 1,
            authority_schema_version: 2,
            complete: true,
            run_id: "synthetic-authority-run".into(),
            records_digest: format!("sha256:{}", "a".repeat(64)),
            totals: totals.clone(),
            by_mode: vec![ControlledEnforcementModeRow {
                mode: RouteMode::Enforce,
                totals,
            }],
            shadow_opportunity: None,
        };

        let payloads = render_controlled_enforcement_payloads(&report).unwrap();
        assert_eq!(
            payloads.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["report.csv", "report.html", "report.json", "report.md"]
        );
        let json: serde_json::Value = serde_json::from_slice(&payloads["report.json"]).unwrap();
        assert_eq!(json["totals"]["observed_enforced_cost_micros"], 700_000);
        assert_eq!(json["totals"]["enforced_modeled_delta_micros"], "-300000");
        assert!(json["shadow_opportunity"].is_null());

        let markdown = String::from_utf8(payloads["report.md"].clone()).unwrap();
        let html = String::from_utf8(payloads["report.html"].clone()).unwrap();
        let csv = String::from_utf8(payloads["report.csv"].clone()).unwrap();
        for rendered in [&markdown, &html, &csv] {
            assert!(rendered.contains("0.700000"));
            assert!(rendered.contains("-0.300000"));
            assert!(rendered.contains("not-available"));
            assert!(!rendered.to_ascii_lowercase().contains("realized savings"));
        }
        assert!(markdown.contains("Enforced modeled cost delta"));
        assert!(markdown.contains("Shadow modeled opportunity"));
        assert!(csv.contains("observed_enforced_cost_usd"));
        assert!(csv.contains("enforced_modeled_cost_delta_usd"));
        assert!(csv.contains("shadow_modeled_opportunity_usd"));
    }

    fn synthetic_portfolio() -> ActionableEconomicsReport {
        serde_json::from_value(serde_json::json!({
            "schema_version":1,"mode":"billing-reconciled","as_of_ms":2000,"window_start_ms":1000,"window_end_ms":2000,"complete":false,"build_provenance":{"package_version":"0.1.0-dev","source_revision":"unavailable"},
            "global_blockers":["reconciliation-incomplete"],"source_bindings":[],
            "selected_evidence":{"traffic":{"run_id":"synthetic-traffic","records_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","manifest_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","recovery_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"},"billing":null,"quality":[]},
            "reconciliation":{"state":"incomplete","eligible_records":4,"matched_records":3,"unmatched_records":1,"total_provider_rows":2,"matched_provider_rows":1,"unmatched_provider_rows":1,"qualified_provider_rows":1,"total_imported_charge_micros":4000000,"matched_imported_charge_micros":3000000,"qualified_imported_charge_micros":3000000,"modeled_actual_cost_micros":3000000,"record_coverage_ppm":750000,"row_presence_charge_coverage_ppm":750000,"qualified_charge_coverage_ppm":750000,"charge_variance_micros":0,"charge_variance_ppm":0,"request_delta":0,"input_token_delta":0,"output_token_delta":0,"request_count_available_rows":2,"request_count_total_rows":2,"input_token_available_rows":2,"input_token_total_rows":2,"output_token_available_rows":2,"output_token_total_rows":2,
              "rows":[{"row_id":"provider-row","supply_id":"public/actual","period_start_ms":1000,"period_end_ms":2000,"imported_charge_micros":3000000,"present":true,"qualified":true,"matched_records":3,"modeled_actual_cost_micros":3000000,"request_delta":0,"input_token_delta":0,"output_token_delta":0}],
              "exceptions":[{"code":"unmatched-provider-row","supply_id":"public/unmatched","row_id":"unmatched-row","record_id":null}]},
            "dimensions":[{"dimensions":{"app":"=synthetic,<script>","team":"ops","environment":"prod","cost_center":"cc-1","general_tags":["region:east"],"complete":true},"task_class":"mechanical","protocol":"chat-completions","actual_supply_id":"public/actual","record_count":4,"input_tokens":400,"output_tokens":200,"modeled_actual_cost_micros":3000000,"compliant_records":2,"violation_records":1,"unknown_policy_records":1}],
            "opportunities":[
              {"key":{"app":"synthetic","team":"ops","environment":"prod","cost_center":"cc-1","general_tags":[],"task_class":"mechanical","protocol":"chat-completions","actual_supply_id":"public/actual","candidate_supply_id":"owned/eligible"},"record_count":1,"input_tokens":100,"output_tokens":50,"actual_cost_micros":1000000,"candidate_cost_micros":100000,"observed_delta_micros":900000,"annualized_delta_micros":28381058640000i64,"compliant_records":1,"violation_records":0,"unknown_policy_records":0,"policy_violation_reason":null,"quality":{"run_id":"quality-eligible","verdict":"eligible","completed_at_ms":1500,"age_ms":500},"reconciliation_state":"qualified","eligible":true,"status":"billing-reconciled-eligible","blockers":[]},
              {"key":{"app":"synthetic","team":"ops","environment":"prod","cost_center":"cc-1","general_tags":[],"task_class":"mechanical","protocol":"chat-completions","actual_supply_id":"public/actual","candidate_supply_id":"owned/stale"},"record_count":1,"input_tokens":100,"output_tokens":50,"actual_cost_micros":1000000,"candidate_cost_micros":100000,"observed_delta_micros":900000,"annualized_delta_micros":null,"compliant_records":1,"violation_records":0,"unknown_policy_records":0,"policy_violation_reason":null,"quality":{"run_id":"quality-stale","verdict":"eligible","completed_at_ms":1000,"age_ms":1000},"reconciliation_state":"qualified","eligible":false,"status":"billing-reconciled-incomplete","blockers":["quality-stale"]},
              {"key":{"app":"synthetic","team":"ops","environment":"prod","cost_center":"cc-1","general_tags":[],"task_class":"mechanical","protocol":"chat-completions","actual_supply_id":"public/actual","candidate_supply_id":"owned/failed"},"record_count":1,"input_tokens":100,"output_tokens":50,"actual_cost_micros":1000000,"candidate_cost_micros":100000,"observed_delta_micros":900000,"annualized_delta_micros":null,"compliant_records":0,"violation_records":1,"unknown_policy_records":0,"policy_violation_reason":"actual-supply-not-in-recorded-feasible-set","quality":{"run_id":"quality-failed","verdict":"quality-failed","completed_at_ms":1500,"age_ms":500},"reconciliation_state":"qualified","eligible":false,"status":"billing-reconciled-incomplete","blockers":["policy-violation","quality-not-eligible"]},
              {"key":{"app":"synthetic","team":"ops","environment":"prod","cost_center":"cc-1","general_tags":[],"task_class":"mechanical","protocol":"chat-completions","actual_supply_id":"unassigned","candidate_supply_id":"owned/unreconciled"},"record_count":1,"input_tokens":100,"output_tokens":50,"actual_cost_micros":null,"candidate_cost_micros":100000,"observed_delta_micros":null,"annualized_delta_micros":null,"compliant_records":0,"violation_records":0,"unknown_policy_records":1,"policy_violation_reason":null,"quality":null,"reconciliation_state":"incomplete","eligible":false,"status":"billing-reconciled-incomplete","blockers":["missing-attribution","policy-unknown","reconciliation-incomplete"]}
            ]
        })).unwrap()
    }

    #[test]
    fn bundle_has_exact_deterministic_payloads_and_safe_html() {
        let report = empty_report();
        let first = render_payloads(&report).unwrap();
        let second = render_payloads(&report).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 6);
        assert_eq!(
            first.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "dimensions.csv",
                "opportunities.csv",
                "reconciliation.csv",
                "report.html",
                "report.json",
                "report.md",
            ]
        );
        let html = std::str::from_utf8(&first["report.html"]).unwrap();
        assert!(html.contains("Content-Security-Policy"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn synthetic_portfolio_preserves_cross_format_rows_and_escapes_injection() {
        let payloads = render_payloads(&synthetic_portfolio()).unwrap();
        let json = String::from_utf8(payloads["report.json"].clone()).unwrap();
        let markdown = String::from_utf8(payloads["report.md"].clone()).unwrap();
        let html = String::from_utf8(payloads["report.html"].clone()).unwrap();
        let dimensions = String::from_utf8(payloads["dimensions.csv"].clone()).unwrap();
        let opportunities = String::from_utf8(payloads["opportunities.csv"].clone()).unwrap();
        assert!(
            json.contains("quality-stale")
                && markdown.contains("quality-stale")
                && html.contains("quality-stale")
                && opportunities.contains("quality-stale")
        );
        assert!(dimensions.contains("'=synthetic,<script>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(opportunities.lines().count() >= 5);

        let mut opportunity_reader = csv::Reader::from_reader(opportunities.as_bytes());
        let headers = opportunity_reader.headers().unwrap().clone();
        let rows = opportunity_reader
            .records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let field = |row: &csv::StringRecord, name: &str| {
            row.get(headers.iter().position(|header| header == name).unwrap())
                .unwrap()
                .to_owned()
        };
        let eligible = rows
            .iter()
            .find(|row| field(row, "candidate_supply_id") == "owned/eligible")
            .unwrap();
        assert_eq!(field(eligible, "quality_run_id"), "quality-eligible");
        assert_eq!(field(eligible, "quality_verdict"), "eligible");
        assert_eq!(field(eligible, "quality_age_ms"), "500");
        assert_eq!(field(eligible, "reconciliation_state"), "qualified");
        assert_eq!(field(eligible, "compliant_records"), "1");
        assert_eq!(field(eligible, "annualized_delta_usd"), "28381058.640000");

        let reconciliation = String::from_utf8(payloads["reconciliation.csv"].clone()).unwrap();
        let mut reconciliation_reader = csv::Reader::from_reader(reconciliation.as_bytes());
        let reconciliation_headers = reconciliation_reader.headers().unwrap().clone();
        let reconciliation_rows = reconciliation_reader
            .records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let rfield = |row: &csv::StringRecord, name: &str| {
            row.get(
                reconciliation_headers
                    .iter()
                    .position(|header| header == name)
                    .unwrap(),
            )
            .unwrap()
            .to_owned()
        };
        let portfolio = reconciliation_rows
            .iter()
            .find(|row| rfield(row, "kind") == "portfolio")
            .unwrap();
        assert_eq!(rfield(portfolio, "portfolio_state"), "incomplete");
        assert_eq!(rfield(portfolio, "eligible_records"), "4");
        assert_eq!(rfield(portfolio, "qualified_charge_coverage_ppm"), "750000");
        assert_eq!(rfield(portfolio, "total_imported_charge_usd"), "4.000000");
        assert!(reconciliation_rows
            .iter()
            .any(|row| rfield(row, "kind") == "row" && rfield(row, "row_id") == "provider-row"));
        assert!(reconciliation_rows
            .iter()
            .any(|row| rfield(row, "kind") == "exception"
                && rfield(row, "code") == "unmatched-provider-row"));
    }

    #[test]
    fn csv_cells_are_rfc4180_quoted_and_formula_neutralized() {
        assert_eq!(csv_cell("=SUM(A1:A2)"), "'=".to_owned() + "SUM(A1:A2)");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_cell("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn source_revision_is_validated_at_compile_time_boundary() {
        assert_eq!(validate_source_revision(None).unwrap(), "unavailable");
        assert_eq!(
            validate_source_revision(Some(&"a".repeat(40))).unwrap(),
            "a".repeat(40)
        );
        assert!(validate_source_revision(Some("HEAD")).is_err());
        assert!(validate_source_revision(Some(&"g".repeat(40))).is_err());
    }

    #[test]
    fn bundle_manifest_carries_the_exact_authoritative_selected_evidence() {
        let report = empty_report();
        let payloads = render_payloads(&report).unwrap();
        let (bytes, _) = build_manifest(
            &report,
            &payloads,
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
        let manifest: BundleManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest.selected_evidence, report.selected_evidence);

        let mut tampered = report.clone();
        tampered.selected_evidence.traffic.manifest_digest = "sha256:tampered".into();
        assert!(render_payloads(&tampered).is_err());
    }

    #[test]
    fn private_bundle_is_mode_safe_and_refuses_replacement() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = std::fs::canonicalize(root.path()).unwrap();
        let report = empty_report();
        let payloads = render_payloads(&report).unwrap();
        let (manifest, _) = build_manifest(
            &report,
            &payloads,
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
        publish_bundle(&parent, "report", &payloads, &manifest).unwrap();
        let final_dir = parent.join("report");
        assert_eq!(
            std::fs::metadata(&final_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut names = std::fs::read_dir(&final_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                "dimensions.csv",
                "manifest.json",
                "opportunities.csv",
                "reconciliation.csv",
                "report.html",
                "report.json",
                "report.md"
            ]
        );
        for name in names {
            assert_eq!(
                std::fs::metadata(final_dir.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(publish_bundle(&parent, "report", &payloads, &manifest).is_err());
        assert!(!parent.join(".report.lock").exists());

        let parent_link = parent.join("parent-link");
        std::os::unix::fs::symlink(&parent, &parent_link).unwrap();
        assert!(publish_bundle(&parent_link, "linked", &payloads, &manifest).is_err());
        let final_link = parent.join("linked-final");
        std::os::unix::fs::symlink(parent.join("report"), &final_link).unwrap();
        assert!(publish_bundle(&parent, "linked-final", &payloads, &manifest).is_err());
        assert!(std::fs::symlink_metadata(&final_link)
            .unwrap()
            .file_type()
            .is_symlink());

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let attempts = (0..2)
            .map(|_| {
                let parent = parent.clone();
                let payloads = payloads.clone();
                let manifest = manifest.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    publish_bundle(&parent, "race", &payloads, &manifest)
                })
            })
            .collect::<Vec<_>>();
        let results = attempts
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(std::fs::read_dir(parent.join("race")).unwrap().count(), 7);
        assert!(!parent.join(".race.lock").exists());
        assert!(!std::fs::read_dir(&parent).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".race.staging-")));
    }

    #[test]
    fn publication_rejects_parent_components_before_creating_artifacts() {
        let cwd = std::env::current_dir().unwrap();
        let root = tempfile::tempdir_in(&cwd).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let inner = root.join("inner");
        let a = inner.join("a");
        let normalized_single = inner.join("b");
        let normalized_repeated = root.join("b");
        let mistaken = a.join("b");
        for directory in [
            &inner,
            &a,
            &normalized_single,
            &normalized_repeated,
            &mistaken,
        ] {
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let report = empty_report();
        let payloads = render_payloads(&report).unwrap();
        let (manifest, _) = build_manifest(
            &report,
            &payloads,
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
        let relative_root = root.strip_prefix(&cwd).unwrap();
        let cases = [
            (
                inner.join("a").join("..").join("b"),
                "absolute-parent",
                normalized_single.as_path(),
            ),
            (
                relative_root.join("inner/a/../b"),
                "relative-parent",
                normalized_single.as_path(),
            ),
            (
                inner.join("a").join("../..").join("b"),
                "repeated-parent",
                normalized_repeated.as_path(),
            ),
        ];
        for (unsafe_parent, final_name, normalized) in cases {
            assert!(publish_bundle(&unsafe_parent, final_name, &payloads, &manifest).is_err());
            for parent in [normalized, mistaken.as_path()] {
                assert!(!parent.join(final_name).exists());
                assert!(!parent.join(format!(".{final_name}.lock")).exists());
                assert!(!std::fs::read_dir(parent).unwrap().any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".{final_name}.staging-"))));
            }
        }
    }

    #[test]
    fn publication_boundary_swaps_are_anchored_and_cleanup_is_inode_conditional() {
        fn fixture() -> (
            tempfile::TempDir,
            std::path::PathBuf,
            BTreeMap<String, Vec<u8>>,
            Vec<u8>,
        ) {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let root_path = std::fs::canonicalize(root.path()).unwrap();
            let parent = root_path.join("parent");
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            let report = empty_report();
            let payloads = render_payloads(&report).unwrap();
            let (manifest, _) = build_manifest(
                &report,
                &payloads,
                format!("sha256:{}", "a".repeat(64)),
                format!("sha256:{}", "b".repeat(64)),
            )
            .unwrap();
            (root, parent, payloads, manifest)
        }
        fn staging(parent: &Path) -> std::path::PathBuf {
            std::fs::read_dir(parent)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .contains(".bundle.staging-")
                })
                .unwrap()
        }

        let (_root, parent, payloads, manifest) = fixture();
        let held = parent.with_file_name("held-parent");
        let attacker = parent.clone();
        publish_bundle_with_hook(&parent, "bundle", &payloads, &manifest, |phase| {
            if phase == PublishPhase::PostAnchor {
                std::fs::rename(&attacker, &held).unwrap();
                std::fs::create_dir(&attacker).unwrap();
                std::fs::set_permissions(&attacker, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                std::fs::write(attacker.join("sentinel"), b"attacker").unwrap();
            }
        })
        .unwrap();
        assert!(held.join("bundle/manifest.json").is_file());
        assert_eq!(
            std::fs::read(attacker.join("sentinel")).unwrap(),
            b"attacker"
        );
        assert!(!attacker.join("bundle").exists());

        let (_root, parent, payloads, manifest) = fixture();
        let held_lock = parent.join("held-lock");
        let lock = parent.join(".bundle.lock");
        let result = publish_bundle_with_hook(&parent, "bundle", &payloads, &manifest, |phase| {
            if phase == PublishPhase::PostLock {
                std::fs::rename(&lock, &held_lock).unwrap();
                std::fs::write(&lock, b"attacker-lock").unwrap();
            }
        });
        assert!(result.is_err() && !parent.join("bundle").exists());
        assert_eq!(std::fs::read(&lock).unwrap(), b"attacker-lock");

        let (_root, parent, payloads, manifest) = fixture();
        let moved = parent.join("moved-staging");
        let target = parent.join("attacker-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"attacker").unwrap();
        let result = publish_bundle_with_hook(&parent, "bundle", &payloads, &manifest, |phase| {
            if phase == PublishPhase::PostStaging {
                let found = staging(&parent);
                std::fs::rename(&found, &moved).unwrap();
                std::os::unix::fs::symlink(&target, &found).unwrap();
            }
        });
        assert!(result.is_err() && !parent.join("bundle").exists());
        assert_eq!(std::fs::read(target.join("sentinel")).unwrap(), b"attacker");

        let (_root, parent, payloads, manifest) = fixture();
        let result = publish_bundle_with_hook(&parent, "bundle", &payloads, &manifest, |phase| {
            if phase == PublishPhase::PreSync {
                let found = staging(&parent);
                let file = found.join("report.json");
                std::fs::remove_file(&file).unwrap();
                std::fs::write(&file, b"attacker-payload").unwrap();
            }
        });
        assert!(result.is_err() && !parent.join("bundle").exists());
        let found = staging(&parent);
        assert_eq!(
            std::fs::read(found.join("report.json")).unwrap(),
            b"attacker-payload"
        );

        let (_root, parent, payloads, manifest) = fixture();
        let result = publish_bundle_with_hook(&parent, "bundle", &payloads, &manifest, |phase| {
            if phase == PublishPhase::PreRename {
                std::fs::create_dir(parent.join("bundle")).unwrap();
                std::fs::write(parent.join("bundle/sentinel"), b"destination").unwrap();
            }
        });
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(parent.join("bundle/sentinel")).unwrap(),
            b"destination"
        );
        assert!(!parent.join(".bundle.lock").exists());

        let (_root, parent, payloads, manifest) = fixture();
        let lock = parent.join(".bundle.lock");
        let held_lock = parent.join("held-lock");
        publish_bundle_with_hook(&parent, "bundle", &payloads, &manifest, |phase| {
            if phase == PublishPhase::PreCleanup {
                std::fs::rename(&lock, &held_lock).unwrap();
                std::fs::write(&lock, b"cleanup-sentinel").unwrap();
            }
        })
        .unwrap();
        assert!(parent.join("bundle/manifest.json").is_file());
        assert_eq!(std::fs::read(&lock).unwrap(), b"cleanup-sentinel");
    }
}
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs,
    io::Write,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::ffi::OsStrExt,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result};
use bowline_core::economics::{ActionableEconomicsReport, Blocker};
use bowline_core::report::{ControlledEnforcementReport, ControlledEnforcementTotals};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::safe_path::anchored_components;

pub const PAYLOAD_NAMES: [&str; 6] = [
    "dimensions.csv",
    "opportunities.csv",
    "reconciliation.csv",
    "report.html",
    "report.json",
    "report.md",
];
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub package_version: String,
    pub source_revision: String,
    pub analysis_digest: String,
    pub config_digest: String,
    pub source_bindings_digest: String,
    pub selected_evidence: bowline_core::economics::SelectedEvidence,
    pub artifacts: Vec<ArtifactBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleSummary {
    pub bundle_digest: String,
    pub artifact_count: usize,
    pub complete: bool,
}

pub fn validate_source_revision(value: Option<&str>) -> Result<String> {
    match value {
        None | Some("") => Ok("unavailable".to_owned()),
        Some(value)
            if (value.len() == 40 || value.len() == 64)
                && value.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok(value.to_ascii_lowercase())
        }
        Some(_) => anyhow::bail!("invalid compile-time source revision"),
    }
}

pub fn source_revision() -> Result<String> {
    validate_source_revision(option_env!("BOWLINE_SOURCE_REVISION"))
}

fn enum_name<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"invalid\"".into())
        .trim_matches('"')
        .to_owned()
}

fn fixed_usd(value: Option<u64>) -> String {
    value.map_or_else(
        || "not-available".into(),
        |v| format!("{}.{:06}", v / 1_000_000, v % 1_000_000),
    )
}

fn fixed_signed_usd(value: Option<i128>) -> String {
    value.map_or_else(
        || "not-available".into(),
        |v| {
            let sign = if v < 0 { "-" } else { "" };
            let magnitude = v.unsigned_abs();
            format!(
                "{sign}{}.{:06}",
                magnitude / 1_000_000,
                magnitude % 1_000_000
            )
        },
    )
}

fn controlled_totals_values(
    scope: String,
    totals: &ControlledEnforcementTotals,
    shadow_groups: String,
    shadow_delta: String,
) -> Vec<String> {
    vec![
        scope,
        totals.decisions.to_string(),
        totals.candidate_dispatches.to_string(),
        totals.pre_dispatch_rejections.to_string(),
        totals.bypasses.to_string(),
        totals.fail_closed.to_string(),
        totals.failures.to_string(),
        totals.cancellations.to_string(),
        totals.incomplete.to_string(),
        fixed_usd(totals.observed_enforced_cost_micros),
        fixed_signed_usd(totals.enforced_modeled_delta_micros.map(i128::from)),
        shadow_groups,
        shadow_delta,
    ]
}

fn controlled_enforcement_csv(report: &ControlledEnforcementReport) -> String {
    let mut out = csv_row([
        "scope",
        "decisions",
        "candidate_dispatches",
        "pre_dispatch_rejections",
        "bypasses",
        "fail_closed",
        "failures",
        "cancellations",
        "incomplete",
        "observed_enforced_cost_usd",
        "enforced_modeled_cost_delta_usd",
        "shadow_opportunity_groups",
        "shadow_modeled_opportunity_usd",
    ]);
    let (shadow_groups, shadow_delta) = report.shadow_opportunity.as_ref().map_or_else(
        || (String::new(), "not-available".to_owned()),
        |shadow| {
            (
                shadow.groups.to_string(),
                fixed_signed_usd(shadow.modeled_delta_micros),
            )
        },
    );
    let totals =
        controlled_totals_values("total".into(), &report.totals, shadow_groups, shadow_delta);
    out.push_str(&csv_row(totals.iter().map(String::as_str)));
    for row in &report.by_mode {
        let values = controlled_totals_values(
            format!("mode:{}", enum_name(&row.mode)),
            &row.totals,
            String::new(),
            String::new(),
        );
        out.push_str(&csv_row(values.iter().map(String::as_str)));
    }
    out
}

fn controlled_enforcement_markdown(report: &ControlledEnforcementReport) -> String {
    let canonical = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());
    let (shadow_groups, shadow_delta) = report.shadow_opportunity.as_ref().map_or_else(
        || ("not-available".to_owned(), "not-available".to_owned()),
        |shadow| {
            (
                shadow.groups.to_string(),
                fixed_signed_usd(shadow.modeled_delta_micros),
            )
        },
    );
    format!(
        "# Bowline Controlled Enforcement Report\n\nComplete: `{}`  \nAuthority schema: `v{}`  \nDecisions: `{}`  \nCandidate dispatches: `{}`  \nPre-dispatch rejections: `{}`  \nBypasses: `{}`  \nFail-closed: `{}`  \nFailures: `{}`  \nCancellations: `{}`  \nIncomplete: `{}`  \nObserved enforced cost: `${}`  \nEnforced modeled cost delta: `${}`  \nShadow opportunity groups: `{}`  \nShadow modeled opportunity: `${}`\n\nEnforced outcomes and shadow opportunity are separate evidence classes.\n\n## Canonical evidence\n\n{}",
        report.complete,
        report.authority_schema_version,
        report.totals.decisions,
        report.totals.candidate_dispatches,
        report.totals.pre_dispatch_rejections,
        report.totals.bypasses,
        report.totals.fail_closed,
        report.totals.failures,
        report.totals.cancellations,
        report.totals.incomplete,
        fixed_usd(report.totals.observed_enforced_cost_micros),
        fixed_signed_usd(report.totals.enforced_modeled_delta_micros.map(i128::from)),
        shadow_groups,
        shadow_delta,
        canonical
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>()
    )
}

pub fn render_controlled_enforcement_payloads(
    report: &ControlledEnforcementReport,
) -> Result<BTreeMap<String, Vec<u8>>> {
    if report.schema_version != 1 || report.authority_schema_version != 2 {
        anyhow::bail!("unsupported controlled-enforcement report schema");
    }
    let markdown = controlled_enforcement_markdown(report);
    let escaped = html_escape(&markdown);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'\"><title>Bowline Controlled Enforcement Report</title><style>body{{font:15px system-ui;max-width:72rem;margin:2rem auto;padding:0 1rem;white-space:pre-wrap}}</style></head><body>{escaped}</body></html>\n"
    );
    let mut payloads = BTreeMap::new();
    payloads.insert(
        "report.csv".into(),
        controlled_enforcement_csv(report).into_bytes(),
    );
    payloads.insert("report.html".into(), html.into_bytes());
    payloads.insert("report.json".into(), serde_json::to_vec_pretty(report)?);
    payloads.insert("report.md".into(), markdown.into_bytes());
    if payloads
        .values()
        .any(|value| value.len() > MAX_ARTIFACT_BYTES)
    {
        anyhow::bail!("controlled-enforcement report artifact exceeds byte limit");
    }
    Ok(payloads)
}

fn blockers(values: &[Blocker]) -> String {
    values.iter().map(enum_name).collect::<Vec<_>>().join(";")
}

pub fn csv_cell(value: &str) -> String {
    let safe = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if safe.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", safe.replace('"', "\"\""))
    } else {
        safe
    }
}

fn csv_row<'a>(cells: impl IntoIterator<Item = &'a str>) -> String {
    let mut line = cells
        .into_iter()
        .map(csv_cell)
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

fn dimensions_csv(report: &ActionableEconomicsReport) -> String {
    let mut out = csv_row([
        "app",
        "team",
        "environment",
        "cost_center",
        "general_tags",
        "task_class",
        "protocol",
        "actual_supply_id",
        "record_count",
        "input_tokens",
        "output_tokens",
        "modeled_actual_cost_usd",
        "compliant_records",
        "violation_records",
        "unknown_policy_records",
    ]);
    for row in &report.dimensions {
        let values = vec![
            row.dimensions.app.clone(),
            row.dimensions.team.clone(),
            row.dimensions.environment.clone(),
            row.dimensions.cost_center.clone(),
            row.dimensions.general_tags.join(";"),
            enum_name(&row.task_class),
            enum_name(&row.protocol),
            row.actual_supply_id.clone(),
            row.record_count.to_string(),
            row.input_tokens
                .map_or("not-available".into(), |v| v.to_string()),
            row.output_tokens
                .map_or("not-available".into(), |v| v.to_string()),
            fixed_usd(row.modeled_actual_cost_micros),
            row.compliant_records.to_string(),
            row.violation_records.to_string(),
            row.unknown_policy_records.to_string(),
        ];
        out.push_str(&csv_row(values.iter().map(String::as_str)));
    }
    out
}

fn opportunities_csv(report: &ActionableEconomicsReport) -> String {
    let mut out = csv_row([
        "app",
        "team",
        "environment",
        "cost_center",
        "general_tags",
        "task_class",
        "protocol",
        "actual_supply_id",
        "candidate_supply_id",
        "record_count",
        "input_tokens",
        "output_tokens",
        "actual_cost_usd",
        "candidate_cost_usd",
        "observed_delta_usd",
        "annualized_delta_usd",
        "compliant_records",
        "violation_records",
        "unknown_policy_records",
        "policy_violation_reason",
        "quality_run_id",
        "quality_verdict",
        "quality_completed_at_ms",
        "quality_age_ms",
        "reconciliation_state",
        "eligible",
        "status",
        "blockers",
    ]);
    for row in &report.opportunities {
        let values = vec![
            row.key.app.clone(),
            row.key.team.clone(),
            row.key.environment.clone(),
            row.key.cost_center.clone(),
            row.key.general_tags.join(";"),
            enum_name(&row.key.task_class),
            enum_name(&row.key.protocol),
            row.key.actual_supply_id.clone(),
            row.key.candidate_supply_id.clone(),
            row.record_count.to_string(),
            row.input_tokens
                .map_or("not-available".into(), |v| v.to_string()),
            row.output_tokens
                .map_or("not-available".into(), |v| v.to_string()),
            fixed_usd(row.actual_cost_micros),
            fixed_usd(row.candidate_cost_micros),
            fixed_signed_usd(row.observed_delta_micros),
            fixed_usd(row.annualized_delta_micros),
            row.compliant_records.to_string(),
            row.violation_records.to_string(),
            row.unknown_policy_records.to_string(),
            row.policy_violation_reason.clone().unwrap_or_default(),
            row.quality
                .as_ref()
                .map(|value| value.run_id.clone())
                .unwrap_or_default(),
            row.quality
                .as_ref()
                .map(|value| enum_name(&value.verdict))
                .unwrap_or_else(|| "not-available".into()),
            row.quality
                .as_ref()
                .map(|value| value.completed_at_ms.to_string())
                .unwrap_or_else(|| "not-available".into()),
            row.quality
                .as_ref()
                .map(|value| value.age_ms.to_string())
                .unwrap_or_else(|| "not-available".into()),
            enum_name(&row.reconciliation_state),
            row.eligible.to_string(),
            row.status.clone(),
            blockers(&row.blockers),
        ];
        out.push_str(&csv_row(values.iter().map(String::as_str)));
    }
    out
}

fn reconciliation_csv(report: &ActionableEconomicsReport) -> String {
    let mut out = csv_row([
        "kind",
        "row_id",
        "supply_id",
        "record_id",
        "period_start_ms",
        "period_end_ms",
        "imported_charge_usd",
        "present",
        "qualified",
        "matched_records",
        "modeled_actual_cost_usd",
        "request_delta",
        "input_token_delta",
        "output_token_delta",
        "code",
        "portfolio_state",
        "eligible_records",
        "matched_records_total",
        "unmatched_records",
        "total_provider_rows",
        "matched_provider_rows",
        "unmatched_provider_rows",
        "qualified_provider_rows",
        "total_imported_charge_usd",
        "matched_imported_charge_usd",
        "qualified_imported_charge_usd",
        "portfolio_modeled_actual_cost_usd",
        "record_coverage_ppm",
        "row_presence_charge_coverage_ppm",
        "qualified_charge_coverage_ppm",
        "charge_variance_usd",
        "charge_variance_ppm",
        "portfolio_request_delta",
        "portfolio_input_token_delta",
        "portfolio_output_token_delta",
        "request_count_available_rows",
        "request_count_total_rows",
        "input_token_available_rows",
        "input_token_total_rows",
        "output_token_available_rows",
        "output_token_total_rows",
    ]);
    let reconciliation = &report.reconciliation;
    let portfolio = vec![
        "portfolio".into(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        enum_name(&reconciliation.state),
        reconciliation.eligible_records.to_string(),
        reconciliation.matched_records.to_string(),
        reconciliation.unmatched_records.to_string(),
        reconciliation.total_provider_rows.to_string(),
        reconciliation.matched_provider_rows.to_string(),
        reconciliation.unmatched_provider_rows.to_string(),
        reconciliation.qualified_provider_rows.to_string(),
        fixed_usd(Some(reconciliation.total_imported_charge_micros)),
        fixed_usd(Some(reconciliation.matched_imported_charge_micros)),
        fixed_usd(Some(reconciliation.qualified_imported_charge_micros)),
        fixed_usd(reconciliation.modeled_actual_cost_micros),
        reconciliation
            .record_coverage_ppm
            .map_or("not-available".into(), |v| v.to_string()),
        reconciliation
            .row_presence_charge_coverage_ppm
            .map_or("not-available".into(), |v| v.to_string()),
        reconciliation
            .qualified_charge_coverage_ppm
            .map_or("not-available".into(), |v| v.to_string()),
        fixed_signed_usd(reconciliation.charge_variance_micros),
        reconciliation
            .charge_variance_ppm
            .map_or("not-available".into(), |v| v.to_string()),
        reconciliation
            .request_delta
            .map_or("not-available".into(), |v| v.to_string()),
        reconciliation
            .input_token_delta
            .map_or("not-available".into(), |v| v.to_string()),
        reconciliation
            .output_token_delta
            .map_or("not-available".into(), |v| v.to_string()),
        reconciliation.request_count_available_rows.to_string(),
        reconciliation.request_count_total_rows.to_string(),
        reconciliation.input_token_available_rows.to_string(),
        reconciliation.input_token_total_rows.to_string(),
        reconciliation.output_token_available_rows.to_string(),
        reconciliation.output_token_total_rows.to_string(),
    ];
    out.push_str(&csv_row(portfolio.iter().map(String::as_str)));
    for row in &report.reconciliation.rows {
        let mut values = vec![
            "row".into(),
            row.row_id.clone(),
            row.supply_id.clone(),
            String::new(),
            row.period_start_ms.to_string(),
            row.period_end_ms.to_string(),
            fixed_usd(Some(row.imported_charge_micros)),
            row.present.to_string(),
            row.qualified.to_string(),
            row.matched_records.to_string(),
            fixed_usd(row.modeled_actual_cost_micros),
            row.request_delta
                .map_or("not-available".into(), |v| v.to_string()),
            row.input_token_delta
                .map_or("not-available".into(), |v| v.to_string()),
            row.output_token_delta
                .map_or("not-available".into(), |v| v.to_string()),
            String::new(),
        ];
        values.extend(std::iter::repeat_n(String::new(), 26));
        out.push_str(&csv_row(values.iter().map(String::as_str)));
    }
    for row in &report.reconciliation.exceptions {
        let mut values = vec![
            "exception".into(),
            row.row_id.clone().unwrap_or_default(),
            row.supply_id.clone().unwrap_or_default(),
            row.record_id.clone().unwrap_or_default(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            row.code.clone(),
        ];
        values.extend(std::iter::repeat_n(String::new(), 26));
        out.push_str(&csv_row(values.iter().map(String::as_str)));
    }
    out
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn markdown(report: &ActionableEconomicsReport) -> String {
    let summary = format!("# Bowline Actionable Economics Report\n\nMode: `{}`  \nWindow: `{}` to `{}`  \nComplete: `{}`\n\n## Reconciliation\n\nState: `{}`  \nEligible records: `{}`  \nMatched records: `{}`  \nQualified charge: `${}`\n\n## Dimensions\n\n{} dimension rows.\n\n## Opportunities\n\n{} opportunity rows. Values are counterfactual modeled evidence, not realized savings or forecasts.\n",enum_name(&report.mode),report.window_start_ms,report.window_end_ms,report.complete,enum_name(&report.reconciliation.state),report.reconciliation.eligible_records,report.reconciliation.matched_records,fixed_usd(Some(report.reconciliation.qualified_imported_charge_micros)),report.dimensions.len(),report.opportunities.len());
    let canonical = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());
    summary
        + "\n## Canonical evidence\n\n"
        + &canonical
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect::<String>()
}

fn html(report: &ActionableEconomicsReport) -> String {
    let md = html_escape(&markdown(report));
    format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'\"><title>Bowline Actionable Economics Report</title><style>body{{font:15px system-ui;max-width:72rem;margin:2rem auto;padding:0 1rem;white-space:pre-wrap}}code{{font-family:monospace}}</style></head><body>{md}</body></html>\n")
}

pub fn render_payloads(report: &ActionableEconomicsReport) -> Result<BTreeMap<String, Vec<u8>>> {
    report.selected_evidence.validate()?;
    let json = serde_json::to_vec_pretty(report)?;
    let mut payloads = BTreeMap::new();
    payloads.insert("dimensions.csv".into(), dimensions_csv(report).into_bytes());
    payloads.insert(
        "opportunities.csv".into(),
        opportunities_csv(report).into_bytes(),
    );
    payloads.insert(
        "reconciliation.csv".into(),
        reconciliation_csv(report).into_bytes(),
    );
    payloads.insert("report.html".into(), html(report).into_bytes());
    payloads.insert("report.json".into(), json);
    payloads.insert("report.md".into(), markdown(report).into_bytes());
    if payloads.values().any(|v| v.len() > MAX_ARTIFACT_BYTES) {
        anyhow::bail!("economics artifact exceeds byte limit");
    }
    Ok(payloads)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn bundle_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"bowline.economics.bundle.v1\0");
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

pub fn build_manifest(
    report: &ActionableEconomicsReport,
    payloads: &BTreeMap<String, Vec<u8>>,
    analysis_digest: String,
    config_digest: String,
) -> Result<(Vec<u8>, String)> {
    report.selected_evidence.validate()?;
    if report.build_provenance.package_version != env!("CARGO_PKG_VERSION")
        || report.build_provenance.source_revision != source_revision()?
    {
        anyhow::bail!("economics report build provenance mismatch");
    }
    if payloads.len() != PAYLOAD_NAMES.len()
        || PAYLOAD_NAMES.iter().any(|n| !payloads.contains_key(*n))
    {
        anyhow::bail!("invalid economics payload set");
    }
    let artifacts = PAYLOAD_NAMES
        .iter()
        .map(|name| {
            let bytes = &payloads[*name];
            ArtifactBinding {
                name: (*name).into(),
                size_bytes: bytes.len() as u64,
                sha256: sha256(bytes),
            }
        })
        .collect();
    let manifest = BundleManifest {
        schema_version: 1,
        package_version: report.build_provenance.package_version.clone(),
        source_revision: report.build_provenance.source_revision.clone(),
        analysis_digest,
        config_digest,
        source_bindings_digest: sha256(&serde_json::to_vec(&report.source_bindings)?),
        selected_evidence: report.selected_evidence.clone(),
        artifacts,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let digest = bundle_digest(&bytes);
    Ok((bytes, digest))
}

struct RelativeCleanup {
    parent_fd: RawFd,
    staging_fd: RawFd,
    staging: CString,
    files: Vec<(CString, (u64, u64), fs::File)>,
    lock: CString,
    staging_inode: (u64, u64),
    lock_inode: (u64, u64),
    active: bool,
}
impl Drop for RelativeCleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        for (file, inode, _) in &self.files {
            unsafe {
                if inode_at(self.staging_fd, file) == Some(*inode) {
                    libc::unlinkat(self.staging_fd, file.as_ptr(), 0);
                }
            }
        }
        unsafe {
            if inode_at(self.parent_fd, &self.staging) == Some(self.staging_inode) {
                libc::unlinkat(self.parent_fd, self.staging.as_ptr(), libc::AT_REMOVEDIR);
            }
            if inode_at(self.parent_fd, &self.lock) == Some(self.lock_inode) {
                libc::unlinkat(self.parent_fd, self.lock.as_ptr(), 0);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishPhase {
    PostAnchor,
    PostLock,
    PostStaging,
    PreWrite,
    PreSync,
    PreRename,
    PreCleanup,
}

pub fn publish_bundle(
    parent: &Path,
    final_name: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
    manifest: &[u8],
) -> Result<()> {
    publish_bundle_inner(parent, final_name, payloads, manifest, |_| {})
}

#[cfg(test)]
fn publish_bundle_with_hook<F: FnMut(PublishPhase)>(
    parent: &Path,
    final_name: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
    manifest: &[u8],
    hook: F,
) -> Result<()> {
    publish_bundle_inner(parent, final_name, payloads, manifest, hook)
}

fn publish_bundle_inner<F: FnMut(PublishPhase)>(
    parent: &Path,
    final_name: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
    manifest: &[u8],
    mut hook: F,
) -> Result<()> {
    if final_name.is_empty() || final_name.contains('/') || final_name == "." || final_name == ".."
    {
        anyhow::bail!("invalid output directory name");
    }
    let parent_file = open_anchored_directory(parent)?;
    let parent_fd = parent_file.as_raw_fd();
    let meta = parent_file.metadata()?;
    if !meta.file_type().is_dir()
        || meta.permissions().mode() & 0o777 != 0o700
        || meta.uid() != unsafe { libc::geteuid() }
    {
        anyhow::bail!("economics output parent must be an owner-private directory");
    }
    hook(PublishPhase::PostAnchor);
    let final_component = CString::new(final_name)?;
    let lock = CString::new(format!(".{final_name}.lock"))?;
    let lock_fd = unsafe {
        libc::openat(
            parent_fd,
            lock.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if lock_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("economics output is locked");
    }
    let lock_file = unsafe { fs::File::from_raw_fd(lock_fd) };
    let lock_inode = inode_of(&lock_file)?;
    hook(PublishPhase::PostLock);
    let staging = CString::new(format!(".{final_name}.staging-{}", Uuid::new_v4()))?;
    if unsafe { libc::mkdirat(parent_fd, staging.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let staging_fd = unsafe {
        libc::openat(
            parent_fd,
            staging.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if staging_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let staging_file = unsafe { fs::File::from_raw_fd(staging_fd) };
    let staging_inode = inode_of(&staging_file)?;
    hook(PublishPhase::PostStaging);
    let mut cleanup = RelativeCleanup {
        parent_fd,
        staging_fd: staging_file.as_raw_fd(),
        staging: staging.clone(),
        files: Vec::new(),
        lock: lock.clone(),
        staging_inode,
        lock_inode,
        active: true,
    };
    verify_publication_names(parent_fd, &staging, staging_inode, &lock, lock_inode)?;
    hook(PublishPhase::PreWrite);
    verify_publication_names(parent_fd, &staging, staging_inode, &lock, lock_inode)?;
    for (name, bytes) in payloads {
        let name = CString::new(name.as_str())?;
        let file = write_private_at(staging_file.as_raw_fd(), &name, bytes)?;
        let inode = inode_of(&file)?;
        cleanup.files.push((name, inode, file));
    }
    let manifest_name = CString::new("manifest.json")?;
    let manifest_file = write_private_at(staging_file.as_raw_fd(), &manifest_name, manifest)?;
    let manifest_inode = inode_of(&manifest_file)?;
    cleanup
        .files
        .push((manifest_name, manifest_inode, manifest_file));
    hook(PublishPhase::PreSync);
    verify_publication_names(parent_fd, &staging, staging_inode, &lock, lock_inode)?;
    verify_payload_inodes(staging_file.as_raw_fd(), &cleanup.files)?;
    staging_file.sync_all()?;
    hook(PublishPhase::PreRename);
    verify_publication_names(parent_fd, &staging, staging_inode, &lock, lock_inode)?;
    verify_payload_inodes(staging_file.as_raw_fd(), &cleanup.files)?;
    no_replace_rename_at(parent_fd, &staging, &final_component)?;
    parent_file.sync_all()?;
    drop(lock_file);
    hook(PublishPhase::PreCleanup);
    if inode_at(parent_fd, &lock) == Some(lock_inode) {
        unsafe {
            libc::unlinkat(parent_fd, lock.as_ptr(), 0);
        }
    }
    cleanup.active = false;
    Ok(())
}

fn verify_publication_names(
    parent_fd: RawFd,
    staging: &CString,
    staging_inode: (u64, u64),
    lock: &CString,
    lock_inode: (u64, u64),
) -> Result<()> {
    if inode_at(parent_fd, staging) != Some(staging_inode)
        || inode_at(parent_fd, lock) != Some(lock_inode)
    {
        anyhow::bail!("economics publication object was replaced");
    }
    Ok(())
}

fn verify_payload_inodes(
    directory_fd: RawFd,
    files: &[(CString, (u64, u64), fs::File)],
) -> Result<()> {
    if files
        .iter()
        .any(|(name, inode, _)| inode_at(directory_fd, name) != Some(*inode))
    {
        anyhow::bail!("economics payload was replaced");
    }
    Ok(())
}

fn inode_of(file: &fs::File) -> Result<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    // libc::dev_t is already u64 on Linux but narrower on macOS.
    #[allow(clippy::unnecessary_cast)]
    let device = stat.st_dev as u64;
    Ok((device, stat.st_ino))
}

fn inode_at(directory_fd: RawFd, name: &CString) -> Option<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    // libc::dev_t is already u64 on Linux but narrower on macOS.
    #[allow(clippy::unnecessary_cast)]
    let device = stat.st_dev as u64;
    Some((device, stat.st_ino))
}

fn write_private_at(directory_fd: RawFd, name: &CString, bytes: &[u8]) -> Result<fs::File> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        anyhow::bail!("artifact exceeds byte limit");
    }
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(f)
}
fn open_anchored_directory(path: &Path) -> Result<fs::File> {
    let names = anchored_components(path, "economics output")?;
    let root = CString::new("/")?;
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut directory = unsafe { fs::File::from_raw_fd(fd) };
    for name in names {
        let name = CString::new(name.as_bytes())?;
        let next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(std::io::Error::last_os_error())
                .context("economics path contains an unsafe directory component");
        }
        directory = unsafe { fs::File::from_raw_fd(next) };
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn no_replace_rename_at(parent_fd: RawFd, from: &CString, to: &CString) -> Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent_fd,
            from.as_ptr(),
            parent_fd,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn no_replace_rename_at(parent_fd: RawFd, from: &CString, to: &CString) -> Result<()> {
    let rc = unsafe {
        libc::renameatx_np(
            parent_fd,
            from.as_ptr(),
            parent_fd,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn no_replace_rename_at(_: RawFd, _: &CString, _: &CString) -> Result<()> {
    anyhow::bail!("atomic no-replace directory publish unsupported on this platform")
}
