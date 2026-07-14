use std::{
    env,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use anyhow::Context;
use bowline_core::{
    config::{load_owned_cost_catalog, Config},
    policy::{PolicyBundle, WorkloadIdentity},
    quality::{
        assess_promotion, load_quality_dataset, parse_quality_dataset_manifest, PromotionCriteria,
        PromotionInput, PromotionWorkload, MAX_CASES_BYTES, MAX_EVALUATORS_BYTES,
        MAX_MANIFEST_BYTES,
    },
    quality_report::{
        canonical_outcomes_digest, load_quality_report_document, quality_report_v2_digest,
        quality_workload_identity_digest, render_quality_markdown, render_quality_markdown_v2,
        validate_quality_report_evidence, validate_quality_report_v2_evidence,
        write_quality_report_v2, QualityReport, QualityReportDocument, QualityReportV2,
    },
    quality_run::{QualityLedger, QualityProvenance, QualityRunPlan, QualityRunStore},
    supply::Registry,
};
use bowline_gateway::{
    canary::{
        parse_canary_config, planned_candidate_requests, prepare_canary_with_rubric, run_canary,
        CanaryRunSummary, MAX_CANARY_BYTES,
    },
    judge::MAX_RUBRIC_BYTES,
    quality_writer::{spawn_managed_quality_writer, ManagedQualityWriterOptions},
};
use clap::{Args as ClapArgs, Subcommand};
use sha2::{Digest, Sha256};

const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: CanaryCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum CanaryCommand {
    Validate(InputArgs),
    Run(RunArgs),
    Report(ReportArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct InputArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    dataset: PathBuf,
    #[arg(long)]
    evaluators: PathBuf,
    #[arg(long)]
    canary: PathBuf,
}

#[derive(ClapArgs, Debug, Clone)]
struct RunArgs {
    #[command(flatten)]
    input: InputArgs,
    #[arg(long)]
    json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
struct ReportArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    as_of_ms: Option<u64>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    dataset: Option<PathBuf>,
    #[arg(long)]
    evaluators: Option<PathBuf>,
    #[arg(long)]
    canary: Option<PathBuf>,
}

struct Preflight {
    config: Config,
    dataset: Arc<bowline_core::quality::LoadedQualityDataset>,
    prepared: bowline_gateway::canary::PreparedCanary,
    provenance: QualityProvenance,
    planned: u64,
    policy: PolicyBundle,
    registry: Registry,
    registry_digest: String,
    owned_costs: bowline_core::config::OwnedCostCatalog,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.command {
        CanaryCommand::Validate(input) => {
            let preflight = preflight(&input, true)?;
            println!(
                "valid: {} candidates, {} cases, {} planned requests",
                preflight.prepared.config.candidates.len(),
                preflight.dataset.cases.len(),
                preflight.planned
            );
            Ok(ExitCode::SUCCESS)
        }
        CanaryCommand::Run(args) => run_command(args),
        CanaryCommand::Report(args) => report_command(args),
    }
}

fn run_command(args: RunArgs) -> anyhow::Result<ExitCode> {
    let preflight = preflight(&args.input, true)?;
    let candidate_credits = preflight
        .prepared
        .candidate_request_count(preflight.dataset.cases.len())?;
    let judge_credits = preflight
        .prepared
        .judge_request_count(preflight.dataset.cases.len())?;
    let quality_root = preflight.config.ledger_dir.join("quality-runs");
    let writer = spawn_managed_quality_writer(ManagedQualityWriterOptions {
        root: quality_root,
        provenance: preflight.provenance.clone(),
        plan: QualityRunPlan {
            planned_request_upper_bound: preflight.planned,
            reserved_candidate_credits: candidate_credits,
            reserved_judge_credits: judge_credits,
            max_age_ms: preflight.prepared.config.promotion.max_age_ms,
        },
        queue_capacity: preflight.prepared.config.runner.writer_queue_capacity,
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create canary runtime")?;
    let prepared = preflight.prepared.clone();
    let dataset = Arc::clone(&preflight.dataset);
    let (summary, incomplete) =
        runtime.block_on(run_canary(prepared.clone(), Arc::clone(&dataset), writer))?;
    persist_report(&preflight, &prepared, &dataset, &summary.run_id)?;
    emit_summary(&summary, args.json)?;
    Ok(if incomplete {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn persist_report(
    preflight: &Preflight,
    prepared: &bowline_gateway::canary::PreparedCanary,
    dataset: &bowline_core::quality::LoadedQualityDataset,
    run_id: &str,
) -> anyhow::Result<()> {
    let directory = preflight
        .config
        .ledger_dir
        .join("quality-runs")
        .join(run_id);
    let manifest = QualityRunStore::load_manifest(&directory.join("manifest.json"))?;
    let ledger = QualityLedger::read_all(&directory, manifest.accepted)?;
    let criteria = PromotionCriteria {
        min_samples: prepared.config.promotion.min_samples,
        min_pass_rate: prepared.config.promotion.min_pass_rate,
        min_wilson_lower_95: prepared.config.promotion.min_wilson_lower_95,
        max_candidate_error_rate: prepared.config.promotion.max_error_rate,
        max_p95_latency_ms: prepared.config.promotion.max_p95_latency_ms,
    };
    let workload = PromotionWorkload {
        app: dataset.manifest.policy_identity.app.clone(),
        tags: dataset.manifest.policy_identity.tags.clone(),
    };
    let judge_required = prepared
        .config
        .judge
        .as_ref()
        .is_some_and(|judge| judge.required);
    let as_of_ms = manifest
        .completed_at_ms
        .context("quality run has no completion time")?;
    let mut candidates = Vec::new();
    for candidate in &prepared.config.candidates {
        candidates.push(assess_promotion(PromotionInput {
            manifest: &manifest,
            outcomes: &ledger.outcomes,
            gaps: &ledger.gaps,
            policy: &preflight.policy,
            registry: &preflight.registry,
            registry_digest: &preflight.registry_digest,
            owned_costs: &preflight.owned_costs,
            workload: &workload,
            candidate_supply_id: &candidate.supply_id,
            task_class: dataset.manifest.task_class,
            protocol: dataset.manifest.protocol,
            dataset_digest: &dataset.digests.dataset_digest,
            evaluator_digest: &dataset.digests.evaluator_digest,
            criteria,
            judge_required,
            as_of_ms,
        })?);
    }
    let legacy_shape = QualityReport::new(
        &manifest,
        candidates,
        as_of_ms,
        prepared.config.judge.is_some(),
        judge_required,
        canonical_outcomes_digest(&ledger.outcomes)?,
    )?;
    let identity = WorkloadIdentity {
        api_key_digest: None,
        route: dataset.manifest.protocol.route().to_owned(),
        app: Some(workload.app.clone()),
        tags: workload.tags.clone(),
    };
    let resolved_tags = preflight.policy.resolve_tags(&identity);
    let workload_digest =
        quality_workload_identity_digest(dataset.manifest.protocol, &workload.app, &resolved_tags)?;
    let report = QualityReportV2::from_v1(legacy_shape, workload_digest)?;
    write_quality_report_v2(&directory, &report)?;
    let stored_report = match load_quality_report_document(&directory)? {
        QualityReportDocument::V2(report) => report,
        QualityReportDocument::V1(_) => anyhow::bail!("new quality run stored a legacy report"),
    };
    QualityRunStore::bind_quality_report(
        &directory,
        stored_report.outcomes_digest.clone(),
        quality_report_v2_digest(&stored_report)?,
    )?;
    Ok(())
}

fn report_command(args: ReportArgs) -> anyhow::Result<ExitCode> {
    uuid::Uuid::parse_str(&args.run_id).context("invalid quality run id")?;
    let config = load_config(&args.config)?;
    let directory = config.ledger_dir.join("quality-runs").join(&args.run_id);
    let manifest = QualityRunStore::load_manifest(&directory.join("manifest.json"))
        .context("failed to load quality run")?;
    let ledger = QualityLedger::read_all(&directory, manifest.accepted)
        .context("failed to load quality outcomes")?;
    let stored =
        load_quality_report_document(&directory).context("failed to load quality report")?;
    match &stored {
        QualityReportDocument::V1(report) => {
            validate_quality_report_evidence(report, &manifest, &ledger)
        }
        QualityReportDocument::V2(report) => {
            validate_quality_report_v2_evidence(report, &manifest, &ledger)
        }
    }
    .context("quality report evidence mismatch")?;

    match (&args.dataset, &args.evaluators, &args.canary) {
        (None, None, None) => {}
        (Some(dataset), Some(evaluators), Some(canary)) => {
            let verification = preflight(
                &InputArgs {
                    config: args.config.clone(),
                    dataset: dataset.clone(),
                    evaluators: evaluators.clone(),
                    canary: canary.clone(),
                },
                false,
            )?;
            if verification.provenance != manifest.provenance {
                anyhow::bail!("quality verification digest mismatch");
            }
            if let QualityReportDocument::V2(report) = &stored {
                let identity = WorkloadIdentity {
                    api_key_digest: None,
                    route: verification.dataset.manifest.protocol.route().to_owned(),
                    app: Some(verification.dataset.manifest.policy_identity.app.clone()),
                    tags: verification.dataset.manifest.policy_identity.tags.clone(),
                };
                let resolved = verification.policy.resolve_tags(&identity);
                let current = quality_workload_identity_digest(
                    verification.dataset.manifest.protocol,
                    &verification.dataset.manifest.policy_identity.app,
                    &resolved,
                )?;
                if current != report.workload_identity_digest {
                    anyhow::bail!("quality workload identity digest mismatch");
                }
            }
        }
        _ => anyhow::bail!("dataset, evaluators, and canary must be provided together"),
    }

    let as_of = args.as_of_ms.unwrap_or_else(now_ms);
    match stored {
        QualityReportDocument::V1(stored) => {
            let report = stored.at_as_of(as_of);
            if args.json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print!("{}", render_quality_markdown(&report));
            }
        }
        QualityReportDocument::V2(stored) => {
            let report = stored.at_as_of(as_of);
            if args.json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print!("{}", render_quality_markdown_v2(&report));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let bytes = read_regular(path, MAX_CONFIG_BYTES, "Bowline config")?;
    let source = std::str::from_utf8(&bytes).context("Bowline config is not UTF-8")?;
    let mut config = Config::from_yaml(source).context("invalid Bowline config")?;
    resolve_config_paths(&mut config, path);
    config.validate().context("invalid Bowline config")?;
    Ok(config)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn preflight(args: &InputArgs, require_secrets: bool) -> anyhow::Result<Preflight> {
    let config_bytes = read_regular(&args.config, MAX_CONFIG_BYTES, "Bowline config")?;
    let config_source =
        std::str::from_utf8(&config_bytes).context("Bowline config is not UTF-8")?;
    let mut config = Config::from_yaml(config_source).context("invalid Bowline config")?;
    resolve_config_paths(&mut config, &args.config);
    config.validate().context("invalid Bowline config")?;

    let policy_bytes = read_regular(&config.policy_bundle, MAX_CONFIG_BYTES, "policy bundle")?;
    let policy_source = std::str::from_utf8(&policy_bytes).context("policy bundle is not UTF-8")?;
    let policy = PolicyBundle::from_yaml(policy_source).context("invalid policy bundle")?;
    let registry_bytes = read_regular(&config.registry_feed, MAX_CONFIG_BYTES, "registry feed")?;
    let registry_source =
        std::str::from_utf8(&registry_bytes).context("registry feed is not UTF-8")?;
    let registry = Registry::from_json(registry_source).context("invalid registry feed")?;
    let registry_digest = format!("sha256:{:x}", Sha256::digest(&registry_bytes));
    let tco_bytes = config
        .tco
        .as_ref()
        .map(|path| read_regular(path, MAX_CONFIG_BYTES, "owned-cost inputs"))
        .transpose()?;
    let tco_source = tco_bytes
        .as_deref()
        .map(std::str::from_utf8)
        .transpose()
        .context("owned-cost inputs are not UTF-8")?;
    let owned_costs = load_owned_cost_catalog(
        tco_source,
        (!config.actual_supply_id.is_empty()).then_some(config.actual_supply_id.as_str()),
        &registry,
    )
    .context("invalid owned-cost inputs")?;

    let manifest_bytes = read_regular(&args.dataset, MAX_MANIFEST_BYTES, "dataset manifest")?;
    let manifest =
        parse_quality_dataset_manifest(&manifest_bytes).context("invalid dataset manifest")?;
    let cases_path = args
        .dataset
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&manifest.cases_file);
    let cases_bytes = read_regular(&cases_path, MAX_CASES_BYTES, "dataset cases")?;
    let evaluator_bytes = read_regular(&args.evaluators, MAX_EVALUATORS_BYTES, "evaluators")?;
    let dataset = load_quality_dataset(&manifest_bytes, &cases_bytes, &evaluator_bytes)
        .context("invalid quality dataset")?;

    let canary_bytes = read_regular(&args.canary, MAX_CANARY_BYTES, "canary config")?;
    let canary_config = parse_canary_config(&canary_bytes).context("invalid canary config")?;
    let rubric = canary_config
        .judge
        .as_ref()
        .map(|judge| {
            let path = args
                .canary
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&judge.rubric_file);
            read_regular(&path, MAX_RUBRIC_BYTES, "judge rubric")
        })
        .transpose()?;
    let prepared =
        prepare_canary_with_rubric(canary_config, &registry, rubric.as_deref(), |name| {
            if require_secrets {
                env::var(name).ok()
            } else {
                Some("Bearer verification-placeholder".into())
            }
        })
        .context("invalid canary candidates")?;
    let planned = planned_candidate_requests(&prepared, dataset.cases.len())?;
    let judge = prepared.judge_provenance();
    let provenance = QualityProvenance {
        dataset_manifest_digest: dataset.digests.dataset_manifest_digest.clone(),
        cases_digest: dataset.digests.cases_digest.clone(),
        dataset_digest: dataset.digests.dataset_digest.clone(),
        evaluator_digest: dataset.digests.evaluator_digest.clone(),
        candidate_config_digest: prepared.candidate_config_digest.clone(),
        policy_digest: policy.digest().to_owned(),
        registry_digest: registry_digest.clone(),
        owned_cost_digest: Some(owned_costs.normalized_digest().to_owned()),
        judge_model_digest: judge.as_ref().map(|value| value.model_digest.clone()),
        judge_rubric_digest: judge.as_ref().map(|value| value.rubric_digest.clone()),
        judge_template_digest: judge.as_ref().map(|value| value.template_digest.clone()),
        judge_config_digest: judge.as_ref().map(|value| value.config_digest.clone()),
        judge_endpoint_digest: judge.as_ref().map(|value| value.endpoint_digest.clone()),
        judge_authorization_reference_digest: judge
            .as_ref()
            .map(|value| value.authorization_reference_digest.clone()),
    };
    Ok(Preflight {
        config,
        dataset: Arc::new(dataset),
        prepared,
        provenance,
        planned,
        policy,
        registry,
        registry_digest,
        owned_costs,
    })
}

fn read_regular(path: &Path, max: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} must be a regular non-symlink file");
    }
    if metadata.len() > max as u64 {
        anyhow::bail!("{label} exceeds byte limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.len() > max {
        anyhow::bail!("{label} exceeds byte limit");
    }
    Ok(bytes)
}

fn resolve_config_paths(config: &mut Config, config_path: &Path) {
    let Some(base) = config_path.parent() else {
        return;
    };
    config.policy_bundle = resolve_path(base, &config.policy_bundle);
    config.registry_feed = resolve_path(base, &config.registry_feed);
    config.ledger_dir = resolve_path(base, &config.ledger_dir);
    config.tco = config.tco.as_ref().map(|path| resolve_path(base, path));
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

fn emit_summary(summary: &CanaryRunSummary, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string(summary)?);
    } else {
        println!("canary run {}", summary.run_id);
        println!("accepted {}", summary.accepted);
        println!("recorded {}", summary.recorded);
        println!("dropped {}", summary.dropped);
        println!("candidate dispatches {}", summary.candidate_dispatches);
        println!("clean shutdown {}", summary.clean_shutdown);
        println!("cancelled {}", summary.cancelled);
    }
    Ok(())
}
