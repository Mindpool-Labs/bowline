use std::{
    collections::BTreeMap,
    ffi::CString,
    fs,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use bowline_core::{
    billing_run::BillingRunStore,
    config::{load_owned_cost_catalog, Config},
    economics::{
        analyze, canonical_billing_rows_digest, canonical_quality_projection_digest,
        canonical_traffic_records_digest, BuildProvenance, CostRate, EconomicsAnalysis,
        EconomicsInput, EconomicsRecord, EvidenceBindings, QualityJoinEvidence,
        QualitySourceBinding,
    },
    ledger::{DecisionRecord, SegmentedLedger, UsageSource},
    policy::PolicyBundle,
    quality::QualityProtocol,
    quality_report::{
        load_quality_report_document, quality_report_digest, quality_report_v2_digest,
        quality_workload_identity_digest, validate_quality_report_evidence,
        validate_quality_report_v2_evidence, QualityReport, QualityReportDocument, QualityReportV2,
    },
    quality_run::{QualityLedger, QualityRunStore},
    report::ReportDimensions,
    run::{RunManifest, RunStore},
    supply::{Registry, SupplyClass},
    traffic::ProtocolKind,
};
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::economics_render::{
    build_manifest, publish_bundle, render_payloads, source_revision, BundleSummary,
};
use crate::safe_path::anchored_components;

const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: EconomicsCommand,
}
#[derive(Subcommand, Debug, Clone)]
enum EconomicsCommand {
    Validate(InputArgs),
    Report(ReportArgs),
}
#[derive(ClapArgs, Debug, Clone)]
struct InputArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    analysis: PathBuf,
}
#[derive(ClapArgs, Debug, Clone)]
struct ReportArgs {
    #[command(flatten)]
    input: InputArgs,
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long)]
    json: bool,
}

struct Prepared {
    report: bowline_core::economics::ActionableEconomicsReport,
    analysis_digest: String,
    config_digest: String,
}

pub fn run(args: Args) -> Result<ExitCode> {
    match args.command {
        EconomicsCommand::Validate(input) => validate(input),
        EconomicsCommand::Report(args) => report(args),
    }
}

fn validate(args: InputArgs) -> Result<ExitCode> {
    let prepared = prepare(&args)?;
    println!(
        "valid: {} dimension rows, {} opportunity rows, complete={}",
        prepared.report.dimensions.len(),
        prepared.report.opportunities.len(),
        prepared.report.complete
    );
    Ok(report_exit_code(&prepared.report))
}

fn report(args: ReportArgs) -> Result<ExitCode> {
    let prepared = prepare(&args.input)?;
    let payloads = render_payloads(&prepared.report)?;
    let (manifest, bundle_digest) = build_manifest(
        &prepared.report,
        &payloads,
        prepared.analysis_digest,
        prepared.config_digest,
    )?;
    let parent = args
        .out_dir
        .parent()
        .context("out-dir must have an existing parent")?;
    let name = args
        .out_dir
        .file_name()
        .and_then(|v| v.to_str())
        .context("out-dir must have a UTF-8 final component")?;
    publish_bundle(parent, name, &payloads, &manifest)?;
    let summary = BundleSummary {
        bundle_digest,
        artifact_count: payloads.len(),
        complete: prepared.report.complete,
    };
    if args.json {
        println!("{}", serde_json::to_string(&summary)?)
    } else {
        println!(
            "economics bundle written: {} artifacts; complete={}",
            summary.artifact_count, summary.complete
        );
    }
    Ok(report_exit_code(&prepared.report))
}

fn report_exit_code(report: &bowline_core::economics::ActionableEconomicsReport) -> ExitCode {
    use bowline_core::economics::{AnalysisMode, Blocker, ReconciliationState};
    let quality_or_reconciliation_incomplete = report.opportunities.iter().any(|row| {
        row.blockers.iter().any(|blocker| {
            matches!(
                blocker,
                Blocker::QualityMissing
                    | Blocker::QualityNonJoinable
                    | Blocker::QualityEvidenceMismatch
                    | Blocker::QualityStale
                    | Blocker::QualityNotEligible
                    | Blocker::ReconciliationIncomplete
            )
        })
    });
    let reconciliation_incomplete = report.mode == AnalysisMode::BillingReconciled
        && report.reconciliation.state != ReconciliationState::Qualified;
    if report.complete && !quality_or_reconciliation_incomplete && !reconciliation_incomplete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn prepare(args: &InputArgs) -> Result<Prepared> {
    let config_bytes = read_regular(&args.config, MAX_CONFIG_BYTES, "Bowline config")?;
    let config_text = std::str::from_utf8(&config_bytes).context("Bowline config is not UTF-8")?;
    let mut config = Config::from_yaml(config_text).context("invalid Bowline config")?;
    resolve_config_paths(&mut config, &args.config);
    config.validate().context("invalid Bowline config")?;
    let analysis_bytes = read_regular(
        &args.analysis,
        bowline_core::economics::MAX_ANALYSIS_YAML_BYTES,
        "economics analysis",
    )?;
    let analysis = EconomicsAnalysis::from_yaml(
        std::str::from_utf8(&analysis_bytes).context("economics analysis is not UTF-8")?,
    )
    .context("invalid economics analysis")?;
    let analysis_digest = analysis.digest()?;
    let config_digest = digest_bytes(&serde_json::to_vec(&config)?);
    let policy_bytes = read_regular(&config.policy_bundle, MAX_CONFIG_BYTES, "policy bundle")?;
    let policy = PolicyBundle::from_yaml(std::str::from_utf8(&policy_bytes)?)
        .context("invalid policy bundle")?;
    let registry_bytes = read_regular(&config.registry_feed, MAX_CONFIG_BYTES, "registry feed")?;
    let registry = Registry::from_json(std::str::from_utf8(&registry_bytes)?)
        .context("invalid registry feed")?;
    let registry_digest = digest_bytes(&registry_bytes);
    let tco_source = config
        .tco
        .as_ref()
        .map(|path| read_regular(path, MAX_CONFIG_BYTES, "owned-cost catalog"))
        .transpose()?
        .map(|b| String::from_utf8(b).context("owned-cost catalog is not UTF-8"))
        .transpose()?;
    let owned = load_owned_cost_catalog(
        tco_source.as_deref(),
        Some(&config.actual_supply_id),
        &registry,
    )
    .context("invalid owned-cost catalog")?;
    let owned_digest = owned.normalized_digest().to_owned();
    let rates = registry
        .entries
        .iter()
        .filter_map(|entry| {
            let rate = entry
                .price
                .map(|p| CostRate {
                    input_per_mtok_usd: p.input_per_mtok_usd,
                    output_per_mtok_usd: p.output_per_mtok_usd,
                })
                .or_else(|| {
                    (entry.attributes.class == SupplyClass::Owned)
                        .then(|| owned.cost_per_mtok(&entry.id))
                        .flatten()
                        .map(|p| CostRate {
                            input_per_mtok_usd: p,
                            output_per_mtok_usd: p,
                        })
                });
            rate.map(|rate| (entry.id.clone(), rate))
        })
        .collect::<BTreeMap<_, _>>();

    let traffic_manifest = RunStore::list_manifests_hardened(&config.ledger_dir)?
        .into_iter()
        .find(|m| m.run_id == analysis.traffic_run_id)
        .context("unknown traffic run")?;
    let traffic = SegmentedLedger::read_authoritative_run(&config.ledger_dir, &traffic_manifest)
        .context("traffic run integrity mismatch")?;
    let records = traffic
        .iter()
        .filter(|r| r.ts_ms >= analysis.window_start_ms && r.ts_ms < analysis.window_end_ms)
        .map(decision_to_economics)
        .collect::<Result<Vec<_>>>()?;
    let traffic_records_digest = canonical_traffic_records_digest(&records)?;
    let traffic_integrity = traffic_manifest.clean_shutdown
        && traffic_manifest.writer_healthy
        && traffic_manifest.accepted == traffic_manifest.recorded
        && traffic_manifest.dropped == 0;
    let traffic_manifest_digest =
        canonical_digest(b"bowline.economics.traffic-manifest.v1", &traffic_manifest)?;
    let traffic_recovery_digest = canonical_digest(
        b"bowline.economics.traffic-recovery.v1",
        &(
            "clean",
            traffic.len() as u64,
            traffic_manifest.segments.len() as u64,
        ),
    )?;
    let traffic_manifest_recovery_digest = traffic_binding_digest(&traffic_manifest)?;

    let (
        billing_rows,
        billing_registry_digest,
        billing_rows_digest,
        billing_manifest_digest,
        billing_recovery_digest,
        billing_manifest_recovery_digest,
        billing_integrity,
    ) = if let Some(run_id) = analysis.billing_run_id.as_deref() {
        let read =
            BillingRunStore::read_complete(&config.ledger_dir.join("billing-runs").join(run_id))
                .context("invalid billing run")?;
        if read.manifest.run_id != run_id
            || read.normalized_digest != read.manifest.normalized_digest
        {
            anyhow::bail!("billing run binding mismatch");
        }
        let rows_digest = canonical_billing_rows_digest(&read.rows)?;
        if rows_digest != read.normalized_digest {
            anyhow::bail!("billing rows digest mismatch");
        }
        let manifest_digest =
            canonical_digest(b"bowline.economics.billing-manifest.v1", &read.manifest)?;
        let recovery_digest = canonical_digest(
            b"bowline.economics.billing-recovery.v1",
            &("clean", read.rows.len() as u64),
        )?;
        let manifest_recovery_digest = canonical_digest(
            b"bowline.economics.billing-manifest-recovery.v1",
            &(read.manifest.clone(), format!("{:?}", read.recovery)),
        )?;
        let integrity = read.manifest.clean_shutdown && read.manifest.reconciled();
        (
            read.rows,
            Some(read.manifest.provenance.registry_digest),
            Some(rows_digest),
            Some(manifest_digest),
            Some(recovery_digest),
            Some(manifest_recovery_digest),
            integrity,
        )
    } else {
        (vec![], None, None, None, None, None, true)
    };

    let mut quality_reports = Vec::new();
    let mut legacy_quality = Vec::new();
    let mut quality_sources = Vec::new();
    for run_id in &analysis.quality_run_ids {
        let dir = config.ledger_dir.join("quality-runs").join(run_id);
        let manifest = QualityRunStore::load_manifest(&dir.join("manifest.json"))
            .context("invalid quality manifest")?;
        let ledger =
            QualityLedger::read_all(&dir, manifest.accepted).context("invalid quality outcomes")?;
        let (schema_version, report_digest, report_outcomes_digest, entries) =
            match load_quality_report_document(&dir)? {
                QualityReportDocument::V2(report) => {
                    validate_quality_report_v2_evidence(&report, &manifest, &ledger)
                        .context("quality evidence binding mismatch")?;
                    if report.run_id != *run_id {
                        anyhow::bail!("quality run id mismatch");
                    }
                    let digest = quality_report_v2_digest(&report)?;
                    let entries = quality_entries(&report);
                    let outcomes_digest = report.outcomes_digest.clone();
                    quality_reports.push(report);
                    (2, digest, outcomes_digest, entries)
                }
                QualityReportDocument::V1(report) => {
                    validate_quality_report_evidence(&report, &manifest, &ledger)
                        .context("legacy quality evidence binding mismatch")?;
                    if report.run_id != *run_id {
                        anyhow::bail!("quality run id mismatch");
                    }
                    let digest = quality_report_digest(&report)?;
                    let entries = legacy_quality_entries(&report);
                    let outcomes_digest = report.outcomes_digest.clone();
                    legacy_quality.extend(entries.iter().cloned());
                    (1, digest, outcomes_digest, entries)
                }
            };
        let outcomes_digest = manifest
            .outcomes_digest
            .clone()
            .context("quality manifest lacks outcomes digest")?;
        let projection = canonical_quality_projection_digest(&entries)?;
        let manifest_digest =
            canonical_digest(b"bowline.economics.quality-manifest.v1", &manifest)?;
        quality_sources.push(QualitySourceBinding {
            run_id: run_id.clone(),
            schema_version,
            manifest_digest: manifest_digest.clone(),
            recomputed_manifest_digest: manifest_digest,
            outcomes_digest,
            recomputed_outcomes_digest: report_outcomes_digest,
            report_digest: report_digest.clone(),
            recomputed_report_digest: report_digest,
            registry_digest: manifest.provenance.registry_digest.clone(),
            owned_cost_digest: manifest
                .provenance
                .owned_cost_digest
                .clone()
                .context("quality run lacks owned-cost digest")?,
            policy_digest: manifest.provenance.policy_digest.clone(),
            join_projection_digest: projection,
        });
    }
    let bindings = EvidenceBindings {
        analysis_digest: analysis_digest.clone(),
        config_digest: config_digest.clone(),
        recomputed_config_digest: config_digest.clone(),
        traffic_records_digest,
        traffic_manifest_digest: traffic_manifest_digest.clone(),
        recomputed_traffic_manifest_digest: traffic_manifest_digest,
        traffic_recovery_digest: traffic_recovery_digest.clone(),
        recomputed_traffic_recovery_digest: traffic_recovery_digest,
        traffic_manifest_recovery_digest: traffic_manifest_recovery_digest.clone(),
        recomputed_traffic_manifest_recovery_digest: traffic_manifest_recovery_digest,
        billing_rows_digest,
        billing_manifest_digest: billing_manifest_digest.clone(),
        recomputed_billing_manifest_digest: billing_manifest_digest,
        billing_recovery_digest: billing_recovery_digest.clone(),
        recomputed_billing_recovery_digest: billing_recovery_digest,
        billing_manifest_recovery_digest: billing_manifest_recovery_digest.clone(),
        recomputed_billing_manifest_recovery_digest: billing_manifest_recovery_digest,
        registry_digest: registry_digest.clone(),
        traffic_registry_digest: traffic_manifest.registry_digest.clone(),
        billing_registry_digest,
        owned_cost_digest: owned_digest.clone(),
        traffic_owned_cost_digest: traffic_manifest
            .owned_cost_digest
            .clone()
            .context("traffic run lacks owned-cost digest")?,
        policy_digest: policy.digest().to_owned(),
        traffic_policy_digest: traffic_manifest.policy_digest.clone(),
        quality_sources,
        traffic_integrity_complete: traffic_integrity,
        billing_integrity_complete: billing_integrity,
    };
    let report = analyze(EconomicsInput {
        analysis,
        records,
        billing_rows,
        quality_reports,
        legacy_quality,
        build_provenance: BuildProvenance {
            package_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_revision: source_revision()?,
        },
        rates,
        bindings,
    })
    .context("economics analysis failed")?;
    Ok(Prepared {
        report,
        analysis_digest,
        config_digest,
    })
}

fn decision_to_economics(record: &DecisionRecord) -> Result<EconomicsRecord> {
    let sequence = record.sequence.context("traffic record lacks sequence")?;
    let protocol = record.protocol;
    let qp = match protocol {
        ProtocolKind::ChatCompletions => QualityProtocol::Chat,
        ProtocolKind::Responses => QualityProtocol::Responses,
        ProtocolKind::Embeddings => {
            anyhow::bail!("Embeddings traffic has no promotion-authority quality protocol")
        }
        ProtocolKind::Unsupported => {
            anyhow::bail!("unknown traffic protocol cannot enter promotion economics")
        }
    };
    let app = record.identity.app.as_deref().unwrap_or("unassigned");
    let workload_identity_digest =
        quality_workload_identity_digest(qp, app, &record.identity.tags)?;
    Ok(EconomicsRecord {
        id: record.id.clone(),
        sequence,
        ts_ms: record.ts_ms,
        coverage_status: record.coverage_status,
        dimensions: ReportDimensions::from_resolved_identity(&record.identity),
        workload_identity_digest,
        task_class: record.decision.task_class,
        protocol,
        actual_supply_id: record.actual.supply_id.clone(),
        candidate_supply_id: record.decision.shadow.as_ref().map(|p| p.supply_id.clone()),
        recorded_feasible_ids: record.decision.feasible_ids.clone(),
        input_tokens: record.actual.input_tokens,
        output_tokens: record.actual.output_tokens,
        usage_observed: record.actual.usage_source == UsageSource::Observed,
        recorded_actual_cost_usd: record.actual.est_cost_usd,
    })
}

fn quality_entries(report: &QualityReportV2) -> Vec<QualityJoinEvidence> {
    report
        .candidates
        .iter()
        .map(|c| QualityJoinEvidence {
            run_id: report.run_id.clone(),
            schema_version: 2,
            completed_at_ms: report.completed_at_ms,
            valid_until_ms: report.valid_until_ms,
            workload_identity_digest: Some(c.workload_identity_digest.clone()),
            task_class: c.evidence.task_class,
            protocol: match c.evidence.protocol {
                QualityProtocol::Chat => ProtocolKind::ChatCompletions,
                QualityProtocol::Responses => ProtocolKind::Responses,
            },
            candidate_supply_id: c.evidence.candidate_supply_id.clone(),
            effective_verdict: c.evidence.assessment.effective_verdict,
            manifest_valid: true,
            outcomes_digest_valid: true,
            report_digest_valid: true,
        })
        .collect()
}

fn legacy_quality_entries(report: &QualityReport) -> Vec<QualityJoinEvidence> {
    report
        .candidates
        .iter()
        .map(|candidate| QualityJoinEvidence {
            run_id: report.run_id.clone(),
            schema_version: 1,
            completed_at_ms: report.completed_at_ms,
            valid_until_ms: report.valid_until_ms,
            workload_identity_digest: None,
            task_class: candidate.task_class,
            protocol: match candidate.protocol {
                QualityProtocol::Chat => ProtocolKind::ChatCompletions,
                QualityProtocol::Responses => ProtocolKind::Responses,
            },
            candidate_supply_id: candidate.candidate_supply_id.clone(),
            effective_verdict: candidate.assessment.effective_verdict,
            manifest_valid: report.reconciled
                && report.clean_shutdown
                && !report.cancelled
                && report.writer_healthy,
            outcomes_digest_valid: true,
            report_digest_valid: true,
        })
        .collect()
}

fn traffic_binding_digest(manifest: &RunManifest) -> Result<String> {
    canonical_digest(b"bowline.economics.traffic-manifest-recovery.v1", manifest)
}
fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    Ok(format!("sha256:{:x}", h.finalize()))
}
fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn read_regular(path: &Path, max: usize, label: &str) -> Result<Vec<u8>> {
    read_regular_inner(path, max, label, |_| {})
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InputReadPhase {
    DirectoryOpened(String),
    FileOpened,
}

#[cfg(test)]
fn read_regular_with_hook<F: FnMut(InputReadPhase)>(
    path: &Path,
    max: usize,
    label: &str,
    hook: F,
) -> Result<Vec<u8>> {
    read_regular_inner(path, max, label, hook)
}

fn read_regular_inner<F: FnMut(InputReadPhase)>(
    path: &Path,
    max: usize,
    label: &str,
    mut hook: F,
) -> Result<Vec<u8>> {
    let names = anchored_components(path, label)?;
    let (file_name, directories) = names.split_last().context("input path has no filename")?;
    let root = CString::new("/")?;
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to anchor input path");
    }
    let mut directory = unsafe { fs::File::from_raw_fd(root_fd) };
    for name in directories {
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("unsafe directory while opening {label}"));
        }
        directory = unsafe { fs::File::from_raw_fd(fd) };
        hook(InputReadPhase::DirectoryOpened(
            name.to_string_lossy().into_owned(),
        ));
    }
    let file_name = CString::new(file_name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open {label}"));
    }
    let f = unsafe { fs::File::from_raw_fd(fd) };
    hook(InputReadPhase::FileOpened);
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max as u64 {
        anyhow::bail!("{label} must be a bounded regular non-symlink file");
    }
    let mut b = Vec::with_capacity(m.len() as usize);
    f.take(max as u64 + 1).read_to_end(&mut b)?;
    if b.len() > max {
        anyhow::bail!("{label} exceeds byte limit");
    }
    Ok(b)
}

fn resolve_config_paths(config: &mut Config, path: &Path) {
    if let Some(base) = path.parent() {
        config.policy_bundle = resolve(base, &config.policy_bundle);
        config.registry_feed = resolve(base, &config.registry_feed);
        config.ledger_dir = resolve(base, &config.ledger_dir);
        config.tco = config.tco.as_ref().map(|p| resolve(base, p));
    }
}
fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod filesystem_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn anchored_input_read_survives_component_and_filename_swaps() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let parent = root.join("economics-input-anchor");
        fs::create_dir(&parent).unwrap();
        let input = parent.join("analysis.yaml");
        fs::write(&input, b"original").unwrap();
        let held = root.join("held-input-anchor");
        let attacker = root.join("attacker-input-anchor");
        fs::create_dir(&attacker).unwrap();
        fs::write(attacker.join("analysis.yaml"), b"attacker").unwrap();
        let bytes = read_regular_with_hook(&input, 64, "analysis", |phase| {
            if phase == InputReadPhase::DirectoryOpened("economics-input-anchor".into()) {
                fs::rename(&parent, &held).unwrap();
                symlink(&attacker, &parent).unwrap();
            }
        })
        .unwrap();
        assert_eq!(bytes, b"original");
        assert_eq!(
            fs::read(attacker.join("analysis.yaml")).unwrap(),
            b"attacker"
        );

        let original = held.join("analysis.yaml");
        let bytes = read_regular_with_hook(&original, 64, "analysis", |phase| {
            if phase == InputReadPhase::FileOpened {
                fs::rename(&original, held.join("opened-original")).unwrap();
                fs::write(&original, b"replacement").unwrap();
            }
        })
        .unwrap();
        assert_eq!(bytes, b"original");
        assert_eq!(fs::read(&original).unwrap(), b"replacement");
    }
}
