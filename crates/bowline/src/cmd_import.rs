use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use bowline_core::{
    config::{load_owned_cost_catalog, Config},
    decision::QualityFloors,
    policy::PolicyBundle,
    supply::Registry,
    traffic::CoverageStatus,
};
use bowline_gateway::{
    passive::{normalize_passive_event, PassiveNormalizationContext, MAX_INPUT_BYTES},
    profile::{transform_profile_jsonl, TransformProfile, MAX_PROFILE_BYTES},
    writer::{spawn_managed_writer, ManagedWriterOptions},
};
use clap::{Args as ClapArgs, Subcommand};
use sha2::{Digest, Sha256};

use crate::safe_path;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: ImportCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum ImportCommand {
    Observations(ObservationArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct ObservationArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(serde::Serialize)]
struct ImportSummary {
    schema_version: u32,
    run_id: String,
    accepted: u64,
    recorded: u64,
    incomplete: u64,
    cross_run_deduplication: &'static str,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.command {
        ImportCommand::Observations(args) => import_observations(args),
    }
}

fn import_observations(args: ObservationArgs) -> anyhow::Result<ExitCode> {
    let input_bytes = read_bounded(&args.input, MAX_INPUT_BYTES, "input")?;
    let input = std::str::from_utf8(&input_bytes)
        .with_context(|| format!("input {} is not valid UTF-8", args.input.display()))?;
    let profile_bytes = read_bounded(&args.profile, MAX_PROFILE_BYTES, "profile")?;
    let profile_source = std::str::from_utf8(&profile_bytes)
        .with_context(|| format!("profile {} is not valid UTF-8", args.profile.display()))?;
    let profile = TransformProfile::from_yaml(profile_source, &args.profile.display().to_string())?;
    let parsed = transform_profile_jsonl(&profile, input, &args.input.display().to_string())?;

    // Everything above this point is bounded and fully prevalidated. No run or writer exists yet.
    let config = load_config(&args.config)?;
    let policy_source = fs::read_to_string(&config.policy_bundle).with_context(|| {
        format!(
            "failed to read policy bundle {}",
            config.policy_bundle.display()
        )
    })?;
    let policy =
        PolicyBundle::from_yaml(&policy_source).context("failed to parse policy bundle")?;
    let registry_source = fs::read_to_string(&config.registry_feed).with_context(|| {
        format!(
            "failed to read registry feed {}",
            config.registry_feed.display()
        )
    })?;
    let registry =
        Registry::from_json(&registry_source).context("failed to parse registry feed")?;
    let resolver = config.attribution_resolver(&registry)?;
    let tco_source = config
        .tco
        .as_ref()
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read TCO inputs {}", path.display()))
        })
        .transpose()?;
    let owned_costs = load_owned_cost_catalog(
        tco_source.as_deref(),
        Some(&config.actual_supply_id),
        &registry,
    )
    .context("failed to load owned-cost catalog")?;
    let attribution_digest = config.attribution_digest(&registry)?;
    let context = PassiveNormalizationContext {
        policy: policy.clone(),
        registry: registry.clone(),
        resolver,
        owned_costs: owned_costs.clone(),
        floors: config.floors.clone().unwrap_or_else(QualityFloors::default),
    };
    let mut drafts = Vec::with_capacity(parsed.len());
    let mut incomplete = 0_u64;
    for event in &parsed {
        let draft = normalize_passive_event(event, &context)?;
        incomplete += u64::from(draft.record.coverage_status != CoverageStatus::Supported);
        drafts.push(draft);
    }

    let writer = spawn_managed_writer(ManagedWriterOptions {
        directory: config.ledger_dir.clone(),
        policy_digest: policy.digest().to_string(),
        registry_digest: format!("sha256:{:x}", Sha256::digest(registry_source.as_bytes())),
        attribution_digest: Some(attribution_digest),
        owned_cost_digest: Some(owned_costs.normalized_digest().to_string()),
        passive_profile_digest: Some(profile.normalized_digest().to_string()),
        passive_input_digest: Some(format!("sha256:{:x}", Sha256::digest(&input_bytes))),
        segment_bytes: config.runtime.ledger_segment_bytes,
        max_segments: config.runtime.ledger_max_segments,
        queue_capacity: config.runtime.writer_queue_capacity,
    })?;

    let mut enqueue_error = None;
    for mut draft in drafts {
        let record_context = writer.accept_request()?;
        draft.record.run_id = Some(record_context.run_id);
        draft.record.sequence = Some(record_context.sequence);
        if let Err(error) = writer.try_record(draft.record) {
            enqueue_error = Some(error);
            break;
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .context("failed to build import shutdown runtime")?;
    let shutdown_result = runtime.block_on(writer.shutdown(config.runtime.shutdown_grace()));
    let snapshot = writer.health().snapshot();
    if let Some(error) = enqueue_error {
        return Err(error).context("failed to queue passive observation");
    }
    shutdown_result.context("failed to drain managed ledger writer")?;
    if snapshot.accepted != snapshot.recorded + snapshot.dropped
        || snapshot.dropped > 0
        || !snapshot.writer_healthy
        || !snapshot.clean_shutdown
    {
        anyhow::bail!(
            "passive import run {} is incomplete: accepted={} recorded={} dropped={}",
            snapshot.run_id,
            snapshot.accepted,
            snapshot.recorded,
            snapshot.dropped
        );
    }

    let summary = ImportSummary {
        schema_version: 1,
        run_id: snapshot.run_id,
        accepted: snapshot.accepted,
        recorded: snapshot.recorded,
        incomplete,
        cross_run_deduplication: "not-performed",
    };
    if args.json {
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        println!(
            "run {} accepted={} recorded={} incomplete={}; cross-run deduplication is not performed",
            summary.run_id, summary.accepted, summary.recorded, summary.incomplete
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn read_bounded(path: &Path, max: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    safe_path::read_bounded_bytes(path, max).map_err(|failure| match failure {
        safe_path::BoundedReadFailure::Open(error) => {
            anyhow::Error::new(error).context(format!("failed to open {label} {}", path.display()))
        }
        safe_path::BoundedReadFailure::Metadata(error) => anyhow::Error::new(error).context(
            format!("failed to inspect opened {label} {}", path.display()),
        ),
        safe_path::BoundedReadFailure::NotRegular => {
            anyhow::anyhow!("{label} must be a regular file")
        }
        safe_path::BoundedReadFailure::Read(error) => {
            anyhow::Error::new(error).context(format!("failed to read {label} {}", path.display()))
        }
        safe_path::BoundedReadFailure::TooLarge => anyhow::anyhow!("{label} exceeds {max} bytes"),
    })
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let mut config = Config::from_yaml(&source)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    if let Some(base) = path.parent() {
        config.policy_bundle = resolve_path(base, &config.policy_bundle);
        config.registry_feed = resolve_path(base, &config.registry_feed);
        config.ledger_dir = resolve_path(base, &config.ledger_dir);
        config.tco = config.tco.as_ref().map(|value| resolve_path(base, value));
    }
    config
        .validate()
        .with_context(|| format!("invalid config {}", path.display()))?;
    Ok(config)
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
