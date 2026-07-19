use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use bowline_core::{
    config::{load_owned_cost_catalog, Config},
    decision::QualityFloors,
    enforcement::ActiveRuntimeProvenance,
    export::build_evidence_bundle_v1,
    ledger::{canonical_decision_records_digest, SegmentedLedger},
    policy::PolicyBundle,
    report::compute_run_report,
    run::RunStore,
    supply::Registry,
};
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: ExportCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum ExportCommand {
    Evidence(EvidenceArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct EvidenceArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    out: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.command {
        ExportCommand::Evidence(args) => export_evidence(args),
    }
}

fn export_evidence(args: EvidenceArgs) -> anyhow::Result<ExitCode> {
    let config_source = fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read config {}", args.config.display()))?;
    let mut config = Config::from_yaml(&config_source)
        .with_context(|| format!("failed to parse config {}", args.config.display()))?;
    resolve_config_paths(&mut config, &args.config);
    config.validate().context("invalid export configuration")?;

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
    let tco_source = config
        .tco
        .as_deref()
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
    let active = ActiveRuntimeProvenance::from_loaded(&policy, &registry_source, &owned_costs);
    let attribution_digest = config.attribution_digest(&registry)?;

    let manifests = RunStore::list_manifests_hardened(&config.ledger_dir)
        .with_context(|| format!("failed to list runs at {}", config.ledger_dir.display()))?;
    let manifest = manifests
        .iter()
        .find(|manifest| manifest.run_id == args.run_id)
        .with_context(|| format!("unknown run ID {}", args.run_id))?;
    validate_run_provenance(manifest, &active, &attribution_digest)?;

    let (records, recoveries) = if manifest.records_digest.is_some() {
        let records = SegmentedLedger::read_authoritative_run(&config.ledger_dir, manifest)
            .with_context(|| format!("failed to verify decision run {}", manifest.run_id))?;
        let recoveries = manifest
            .segment_inventory
            .iter()
            .map(|segment| bowline_core::ledger::RecoveryOutcome::Clean {
                records: segment.records,
            })
            .collect();
        (records, recoveries)
    } else {
        SegmentedLedger::read_run(&config.ledger_dir, &manifest.run_id)
            .with_context(|| format!("failed to read decision run {}", manifest.run_id))?
    };
    if let Some(expected) = manifest.records_digest.as_deref() {
        let actual = canonical_decision_records_digest(&records)
            .context("failed to verify decision records digest")?;
        if actual != expected {
            anyhow::bail!("records digest mismatch for selected run");
        }
    }
    let frontier_reference = crate::cmd_report::default_frontier_reference(&registry);
    let report = compute_run_report(
        &records,
        &recoveries,
        manifest,
        &registry,
        &owned_costs,
        &config.floors.clone().unwrap_or_else(QualityFloors::default),
        frontier_reference.as_deref(),
    )
    .context("failed to compute run-scoped shadow report")?;
    let bundle = build_evidence_bundle_v1(manifest, &records, &registry.feed_version, report)
        .context("failed to construct evidence export")?;
    let mut bytes = serde_json::to_vec_pretty(&bundle)?;
    bytes.push(b'\n');
    atomic_write_private(&args.out, &bytes)
        .with_context(|| format!("failed to write evidence export {}", args.out.display()))?;
    Ok(ExitCode::SUCCESS)
}

fn validate_run_provenance(
    manifest: &bowline_core::run::RunManifest,
    active: &ActiveRuntimeProvenance,
    attribution_digest: &str,
) -> anyhow::Result<()> {
    if manifest.policy_digest != active.policy_digest() {
        anyhow::bail!("policy digest mismatch for selected run");
    }
    if manifest.registry_digest != active.registry_digest() {
        anyhow::bail!("registry digest mismatch for selected run");
    }
    if manifest.owned_cost_digest.as_deref() != Some(active.owned_cost_digest()) {
        anyhow::bail!("owned-cost catalog digest mismatch for selected run");
    }
    if manifest.attribution_digest.as_deref() != Some(attribution_digest) {
        anyhow::bail!("attribution digest mismatch for selected run");
    }
    Ok(())
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
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid export path")
    })?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
