use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use bowline_core::{
    config::Config,
    supply::{Price, Registry, SupplyClass},
};
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Show(ConfigArgs),
    Probe(ConfigArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct ConfigArgs {
    #[arg(long)]
    config: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Show(args) => show(args),
        Command::Probe(args) => probe(args),
    }
}

fn show(args: ConfigArgs) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    let registry = load_registry(&config.registry_feed)?;

    println!(
        "{:<32} {:<16} {:<12} {:<24} availability",
        "id", "class", "jurisdiction", "price"
    );
    for entry in registry.entries {
        println!(
            "{:<32} {:<16} {:<12} {:<24} {}",
            entry.id,
            supply_class(entry.attributes.class),
            entry.attributes.jurisdiction,
            price_label(entry.price.as_ref()),
            availability_label(entry.available)
        );
    }

    Ok(())
}

fn probe(args: ConfigArgs) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build probe runtime")?;

    runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .context("failed to build probe client")?;

        for endpoint in config.local_endpoints {
            let url = format!("{}/v1/models", endpoint.url.trim_end_matches('/'));
            let status = match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => "reachable",
                _ => "unreachable",
            };
            println!("{}\t{status}", endpoint.supply_id);
        }

        Ok(())
    })
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

fn supply_class(class: SupplyClass) -> &'static str {
    match class {
        SupplyClass::Owned => "owned",
        SupplyClass::VpcOpenWeights => "vpc-open-weights",
        SupplyClass::VpcFrontier => "vpc-frontier",
        SupplyClass::PublicApi => "public-api",
    }
}

fn price_label(price: Option<&Price>) -> String {
    price.map_or_else(
        || "n/a".to_string(),
        |price| {
            format!(
                "in ${:.2}/out ${:.2}",
                price.input_per_mtok_usd, price.output_per_mtok_usd
            )
        },
    )
}

fn availability_label(available: Option<bool>) -> &'static str {
    match available {
        Some(true) => "available",
        Some(false) => "unavailable",
        None => "unknown",
    }
}
