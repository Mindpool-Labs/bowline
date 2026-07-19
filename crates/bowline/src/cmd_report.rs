use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use bowline_core::{
    config::{load_owned_cost_catalog, Config, OwnedCostCatalog},
    decision::QualityFloors,
    ledger::{AuthorityLedgerV2, Ledger, RecoveryOutcome, SegmentedLedger},
    report::{
        compute_controlled_enforcement_diagnostic_report, compute_report, compute_run_report,
        render_markdown,
    },
    run::{RunManifest, RunStore},
    supply::{Registry, SupplyClass},
};
use clap::{Args as ClapArgs, ValueEnum};

use crate::economics_render::render_controlled_enforcement_payloads;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AuthorityReportFormat {
    Json,
    Markdown,
    Html,
    Csv,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    frontier_reference: Option<String>,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    allow_incomplete: bool,
    #[arg(long)]
    authority_manifest: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = AuthorityReportFormat::Markdown)]
    authority_format: AuthorityReportFormat,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    if let Some(manifest) = args.authority_manifest.as_deref() {
        return run_authority_report(&args, manifest);
    }
    let config_path = args
        .config
        .as_deref()
        .context("--config is required for a shadow report")?;
    let config = load_config(config_path)?;
    let registry = load_registry(&config.registry_feed)?;
    let owned_costs = load_owned_costs(config.tco.as_deref(), &config.actual_supply_id, &registry)?;
    let manifests = RunStore::list_manifests(&config.ledger_dir)
        .with_context(|| format!("failed to list runs at {}", config.ledger_dir.display()))?;
    let frontier_reference = args
        .frontier_reference
        .clone()
        .or_else(|| default_frontier_reference(&registry));
    let selected = select_manifest(&manifests, args.run_id.as_deref())?;
    let (report, recovery) = if let Some(manifest) = selected {
        if manifest
            .owned_cost_digest
            .as_deref()
            .is_some_and(|digest| digest != owned_costs.normalized_digest())
        {
            anyhow::bail!("owned-cost catalog digest mismatch for selected run");
        }
        let (records, recoveries) = SegmentedLedger::read_run(&config.ledger_dir, &manifest.run_id)
            .with_context(|| format!("failed to read decision run {}", manifest.run_id))?;
        let recovery = representative_recovery(&recoveries, records.len() as u64);
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
        (report, recovery)
    } else {
        let (records, recovery) = Ledger::read_all(&config.ledger_dir).with_context(|| {
            format!(
                "failed to read decision ledger at {}",
                config.ledger_dir.display()
            )
        })?;
        let report = compute_report(
            &records,
            &recovery,
            &registry,
            &owned_costs,
            &config.floors.clone().unwrap_or_else(QualityFloors::default),
            frontier_reference.as_deref(),
        )
        .context("failed to compute shadow report")?;
        (report, recovery)
    };
    let output = if args.json {
        serde_json::to_string_pretty(&serde_json::json!({
            "frontier_reference": frontier_reference,
            "ledger_note": ledger_note(&recovery),
            "report": report,
        }))?
    } else {
        render_report_markdown(&report, frontier_reference.as_deref(), &recovery)
    };

    if let Some(out) = args.out {
        atomic_write_report(&out, output.as_bytes())
            .with_context(|| format!("failed to write report {}", out.display()))?;
    } else {
        println!("{output}");
    }

    if !report.complete && !args.allow_incomplete {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_authority_report(args: &Args, manifest: &Path) -> anyhow::Result<ExitCode> {
    let validated = AuthorityLedgerV2::read_validated_authority_diagnostic_run(manifest)
        .context("failed to read validated schema-v2 authority evidence")?;
    let report = compute_controlled_enforcement_diagnostic_report(&validated)
        .context("failed to construct controlled-enforcement report")?;
    let payloads = render_controlled_enforcement_payloads(&report)?;
    let format = if args.json {
        AuthorityReportFormat::Json
    } else {
        args.authority_format
    };
    let name = match format {
        AuthorityReportFormat::Json => "report.json",
        AuthorityReportFormat::Markdown => "report.md",
        AuthorityReportFormat::Html => "report.html",
        AuthorityReportFormat::Csv => "report.csv",
    };
    let output = &payloads[name];
    if let Some(path) = args.out.as_deref() {
        atomic_write_report(path, output)
            .with_context(|| format!("failed to write report {}", path.display()))?;
    } else {
        print!("{}", String::from_utf8_lossy(output));
    }
    if !report.complete && !args.allow_incomplete {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn atomic_write_report(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid report path")
        })?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
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

fn select_manifest<'a>(
    manifests: &'a [RunManifest],
    requested: Option<&str>,
) -> anyhow::Result<Option<&'a RunManifest>> {
    if let Some(run_id) = requested {
        return manifests
            .iter()
            .find(|manifest| manifest.run_id == run_id)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("unknown run ID {run_id}"));
    }
    match manifests {
        [] => Ok(None),
        [manifest] => Ok(Some(manifest)),
        many => anyhow::bail!(
            "multiple runs found; pass --run-id with one of: {}",
            many.iter()
                .map(|manifest| manifest.run_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn representative_recovery(recoveries: &[RecoveryOutcome], records: u64) -> RecoveryOutcome {
    recoveries
        .iter()
        .find(|outcome| !matches!(outcome, RecoveryOutcome::Clean { .. }))
        .cloned()
        .unwrap_or(RecoveryOutcome::Clean { records })
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let mut config = Config::from_yaml(&source)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    resolve_config_paths(&mut config, path);
    Ok(config)
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

fn load_registry(path: &Path) -> anyhow::Result<Registry> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read registry feed {}", path.display()))?;
    Registry::from_json(&source).context("failed to parse registry feed")
}

fn load_owned_costs(
    path: Option<&Path>,
    actual_supply_id: &str,
    registry: &Registry,
) -> anyhow::Result<OwnedCostCatalog> {
    let source = path
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read TCO inputs {}", path.display()))
        })
        .transpose()?;
    load_owned_cost_catalog(source.as_deref(), Some(actual_supply_id), registry)
        .context("failed to load owned-cost catalog")
}

/// Returns `None` when the registry has no priced public-api entry — e.g. an all-owned fleet.
/// That is a success state, not an error (design D-7): the report degrades the frontier-dependent
/// counterfactual cells to "n/a" instead of failing.
pub(crate) fn default_frontier_reference(registry: &Registry) -> Option<String> {
    registry
        .entries
        .iter()
        .filter(|entry| entry.attributes.class == SupplyClass::PublicApi)
        .filter_map(|entry| {
            entry
                .price
                .map(|price| (entry.id.as_str(), price.input_per_mtok_usd))
        })
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
        .map(|(id, _)| id.to_string())
}

fn render_report_markdown(
    report: &bowline_core::report::ShadowReport,
    frontier_reference: Option<&str>,
    recovery: &RecoveryOutcome,
) -> String {
    let rendered = render_markdown(report);
    let frontier_reference_display = frontier_reference.unwrap_or("n/a — no frontier reference");
    let header = format!(
        "# Bowline Shadow Report\n\nFrontier reference: `{frontier_reference_display}`\n\n{}\n\n",
        ledger_note(recovery)
    );
    let marker = "# Bowline Shadow Report\n\n";

    rendered.find(marker).map_or_else(
        || format!("{header}{rendered}"),
        |index| {
            let warning_prefix = &rendered[..index];
            let body = &rendered[index + marker.len()..];
            format!("{header}{warning_prefix}{body}")
        },
    )
}

fn ledger_note(recovery: &RecoveryOutcome) -> &'static str {
    match recovery {
        RecoveryOutcome::Absent => "no ledger found; report is based on 0 records",
        RecoveryOutcome::Clean { .. } => "ledger clean",
        RecoveryOutcome::TornTail { .. } => "ledger repaired from torn tail",
        RecoveryOutcome::Corrupt { .. } => "ledger corrupt; report uses readable records only",
        RecoveryOutcome::Undecodable { .. } => {
            "ledger has an undecodable record (schema drift); report uses readable records only"
        }
    }
}
