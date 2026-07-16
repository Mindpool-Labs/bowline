use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use bowline_core::{
    config::{load_owned_cost_catalog, redact_url, Config, OwnedCostCatalog},
    decision::QualityFloors,
    policy::PolicyBundle,
    supply::Registry,
};
use bowline_gateway::{
    serve_with_runtime_factory,
    writer::{spawn_managed_writer, ManagedWriterOptions},
    GatewayDeps,
};
use clap::Args as ClapArgs;
use sha2::{Digest, Sha256};

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[arg(long)]
    config: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let config = load_config(&args.config)?;
    let policy = load_policy(&config.policy_bundle)?;
    let (registry, registry_source, registry_digest) = load_registry(&config.registry_feed)?;
    config.attribution_resolver(&registry)?;
    let owned_costs = load_owned_costs(config.tco.as_deref(), &config.actual_supply_id, &registry)?;
    let attribution_digest = config.attribution_digest(&registry)?;
    let writer_options = ManagedWriterOptions {
        directory: config.ledger_dir.clone(),
        policy_digest: policy.digest().to_string(),
        registry_digest,
        attribution_digest: Some(attribution_digest),
        owned_cost_digest: Some(owned_costs.normalized_digest().to_string()),
        passive_profile_digest: None,
        passive_input_digest: None,
        segment_bytes: config.runtime.ledger_segment_bytes,
        max_segments: config.runtime.ledger_max_segments,
        queue_capacity: config.runtime.writer_queue_capacity,
    };

    tracing_subscriber::fmt::try_init().ok();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build gateway runtime")?
        .block_on(async move {
            let startup_config = config.clone();
            serve_with_runtime_factory(
                config,
                move || {
                    let writer = spawn_managed_writer(writer_options)?;
                    let deps = GatewayDeps::managed_with_provenance(
                        policy.clone(),
                        &registry_source,
                        startup_config
                            .floors
                            .clone()
                            .unwrap_or_else(QualityFloors::default),
                        owned_costs,
                        writer.clone(),
                    )?;
                    print_startup_summary(
                        &startup_config,
                        policy.digest(),
                        &writer.health().snapshot().run_id,
                    );
                    Ok(deps)
                },
                shutdown_signal(),
            )
            .await
        })
}

pub(crate) fn load_config(path: &Path) -> anyhow::Result<Config> {
    let path = absolute_config_path(path)?;
    let source = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let mut config = Config::from_yaml(&source)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    resolve_config_paths(&mut config, &path);
    config
        .validate()
        .with_context(|| format!("invalid config {}", path.display()))?;
    Ok(config)
}

pub(crate) fn absolute_config_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to resolve current directory for --config")?
            .join(path))
    }
}

fn resolve_config_paths(config: &mut Config, config_path: &Path) {
    let Some(base) = config_path.parent() else {
        return;
    };

    config.policy_bundle = resolve_path(base, &config.policy_bundle);
    config.registry_feed = resolve_path(base, &config.registry_feed);
    config.ledger_dir = resolve_path(base, &config.ledger_dir);
    config.tco = config.tco.as_ref().map(|path| resolve_path(base, path));
    config.enforcement = config
        .enforcement
        .as_ref()
        .map(|path| resolve_path(base, path));
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

pub(crate) fn load_policy(path: &Path) -> anyhow::Result<PolicyBundle> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy bundle {}", path.display()))?;
    PolicyBundle::from_yaml(&source).context("failed to parse policy bundle")
}

pub(crate) fn load_registry(path: &Path) -> anyhow::Result<(Registry, String, String)> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read registry feed {}", path.display()))?;
    let registry = Registry::from_json(&source).context("failed to parse registry feed")?;
    let digest = format!("sha256:{:x}", Sha256::digest(source.as_bytes()));
    Ok((registry, source, digest))
}

pub(crate) fn load_owned_costs(
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

fn print_startup_summary(config: &Config, policy_digest: &str, run_id: &str) {
    if config.enforcement.is_some() {
        println!("mode CONTROLLED (configured enforcement)");
    } else {
        println!("mode SHADOW (observing only)");
    }
    println!("listen {}", config.listen);
    println!("upstream {}", redact_url(&config.upstream));
    println!("policy digest {policy_digest}");
    println!("run id {run_id}");
    println!("ledger recording healthy");
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler installs");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("failed to listen for Ctrl-C: {error}");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to listen for Ctrl-C: {error}");
        }
    }
}
