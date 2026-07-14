use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use bowline_core::{
    billing_run::{BillingCancellation, BillingImportPhase, BillingRunStore},
    config::Config,
    supply::Registry,
};
use bowline_gateway::billing::{
    parse_canonical_jsonl, parse_mapped_csv, ParsedBilling, MAX_BILLING_INPUT_BYTES,
    MAX_MAPPING_BYTES, MAX_REGISTRY_BYTES,
};
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;

const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: BillingCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum BillingCommand {
    Validate(InputArgs),
    Import(ImportArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct InputArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    billing: PathBuf,
    #[arg(long)]
    mapping: Option<PathBuf>,
}

#[derive(ClapArgs, Debug, Clone)]
struct ImportArgs {
    #[command(flatten)]
    input: InputArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BillingImportSummary {
    schema_version: u32,
    run_id: String,
    rows: u64,
    charge_usd_micros: u64,
    request_count: Option<u64>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    source_format: bowline_core::billing_run::BillingSourceFormat,
    clean_shutdown: bool,
    reconciled: bool,
}

struct BillingPreflight {
    config: Config,
    parsed: ParsedBilling,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.command {
        BillingCommand::Validate(args) => {
            let preflight = preflight(&args)?;
            println!(
                "valid: {} rows, {} charge micro-USD",
                preflight.parsed.validated.totals().rows,
                preflight.parsed.validated.totals().charge_usd_micros
            );
            Ok(ExitCode::SUCCESS)
        }
        BillingCommand::Import(args) => import(args),
    }
}

fn import(args: ImportArgs) -> anyhow::Result<ExitCode> {
    let cancellation = BillingCancellation::new();
    let signal_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create billing signal runtime")?;
    install_billing_signal_handler(&signal_runtime, cancellation.clone())?;
    // Parse and normalize every byte before creating a billing run or its parent directory.
    let preflight = preflight(&args.input)?;
    let root = ensure_private_root(&preflight.config.ledger_dir)?;
    let hook_cancellation = cancellation.clone();
    let store = BillingRunStore::import_under_cancellable(
        &root,
        preflight.parsed.provenance.clone(),
        &preflight.parsed.validated,
        &cancellation,
        move |phase| billing_test_barrier(phase, &hook_cancellation),
    )
    .context("failed to persist billing evidence")?;
    let manifest = store.manifest();
    let summary = BillingImportSummary {
        schema_version: 1,
        run_id: manifest.run_id.clone(),
        rows: manifest.totals.rows,
        charge_usd_micros: manifest.totals.charge_usd_micros,
        request_count: manifest.totals.request_count,
        input_tokens: manifest.totals.input_tokens,
        output_tokens: manifest.totals.output_tokens,
        source_format: manifest.provenance.source_format,
        clean_shutdown: manifest.clean_shutdown,
        reconciled: manifest.reconciled(),
    };
    if args.json {
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        println!(
            "billing run {} rows={} charge_usd_micros={} clean_shutdown={} reconciled={}",
            summary.run_id,
            summary.rows,
            summary.charge_usd_micros,
            summary.clean_shutdown,
            summary.reconciled
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(unix)]
fn install_billing_signal_handler(
    runtime: &tokio::runtime::Runtime,
    cancellation: BillingCancellation,
) -> anyhow::Result<()> {
    let runtime_context = runtime.enter();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("failed to install SIGINT handler")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    drop(runtime_context);
    runtime.spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        cancellation.cancel();
    });
    Ok(())
}

#[cfg(not(unix))]
fn install_billing_signal_handler(
    runtime: &tokio::runtime::Runtime,
    cancellation: BillingCancellation,
) -> anyhow::Result<()> {
    runtime.spawn(async move {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to listen for Ctrl-C: {error}");
        } else {
            cancellation.cancel();
        }
    });
    Ok(())
}

#[cfg(debug_assertions)]
fn billing_test_barrier(phase: BillingImportPhase, cancellation: &BillingCancellation) {
    use std::{thread, time::Duration};

    let Ok(expected) = std::env::var("BOWLINE_TEST_BILLING_BARRIER_PHASE") else {
        return;
    };
    let label = match phase {
        BillingImportPhase::BeforeCompleteTransition => "before",
        BillingImportPhase::AfterCompleteTransition => "after",
    };
    if expected != label {
        return;
    }
    let Ok(directory) = std::env::var("BOWLINE_TEST_BILLING_BARRIER_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let valid_directory = fs::symlink_metadata(&directory)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink());
    if !valid_directory {
        return;
    }
    let marker = directory.join(format!("{label}-complete"));
    if OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(marker)
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"ready\n"))
        .is_err()
    {
        return;
    }
    while !directory.join("continue").is_file() && !cancellation.is_cancelled() {
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(not(debug_assertions))]
fn billing_test_barrier(_phase: BillingImportPhase, _cancellation: &BillingCancellation) {}

fn preflight(args: &InputArgs) -> anyhow::Result<BillingPreflight> {
    let config = load_config(&args.config)?;
    let registry_bytes = read_regular(&config.registry_feed, MAX_REGISTRY_BYTES, "registry feed")?;
    let registry_source =
        std::str::from_utf8(&registry_bytes).context("registry feed is not UTF-8")?;
    let registry = Registry::from_json(registry_source).context("invalid registry feed")?;
    let billing = read_regular(&args.billing, MAX_BILLING_INPUT_BYTES, "billing input")?;
    let parsed = match &args.mapping {
        None => parse_canonical_jsonl(&billing, &registry_bytes, &registry)
            .context("invalid canonical billing JSONL"),
        Some(mapping) => {
            let mapping = read_regular(mapping, MAX_MAPPING_BYTES, "billing mapping")?;
            parse_mapped_csv(&billing, &mapping, &registry_bytes, &registry)
                .context("invalid mapped billing CSV")
        }
    }?;
    Ok(BillingPreflight { config, parsed })
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let bytes = read_regular(path, MAX_CONFIG_BYTES, "Bowline config")?;
    let source = std::str::from_utf8(&bytes).context("Bowline config is not UTF-8")?;
    let mut config = Config::from_yaml(source).context("invalid Bowline config")?;
    if let Some(base) = path.parent() {
        config.policy_bundle = resolve_path(base, &config.policy_bundle);
        config.registry_feed = resolve_path(base, &config.registry_feed);
        config.ledger_dir = resolve_path(base, &config.ledger_dir);
        config.tco = config.tco.as_ref().map(|path| resolve_path(base, path));
    }
    config.validate().context("invalid Bowline config")?;
    Ok(config)
}

fn read_regular(path: &Path, max: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open {label}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {label}"))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} must be a regular non-symlink file");
    }
    if metadata.len() > max as u64 {
        anyhow::bail!("{label} exceeds byte limit");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() > max {
        anyhow::bail!("{label} exceeds byte limit");
    }
    Ok(bytes)
}

fn ensure_private_root(ledger: &Path) -> anyhow::Result<PathBuf> {
    if !ledger.exists() {
        fs::create_dir_all(ledger).context("failed to create ledger directory")?;
    }
    certify_private_directory(ledger, "ledger directory")?;
    // Resolve platform aliases such as macOS `/var` -> `/private/var` before passing the path to
    // the descriptor-relative store, whose no-follow walk intentionally rejects every symlink.
    let ledger = fs::canonicalize(ledger).context("failed to resolve ledger directory")?;
    certify_private_directory(&ledger, "ledger directory")?;
    let billing = ledger.join("billing-runs");
    match fs::create_dir(&billing) {
        Ok(()) => fs::set_permissions(&billing, fs::Permissions::from_mode(0o700))
            .context("failed to secure billing-runs directory")?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("failed to create billing-runs directory"),
    }
    certify_private_directory(&billing, "billing-runs directory")?;
    Ok(billing)
}

fn certify_private_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to inspect {label}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("{label} must be a regular directory");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure {label}"))?;
    }
    Ok(())
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}
