use std::{fs, path::PathBuf, process::ExitCode, time::SystemTime};

use anyhow::Context;
use bowline_core::enforcement::{
    operator_safe_route_id, ActiveRuntimeProvenance, AuthorityProtocol, EnforcementConfigV1,
};
use bowline_gateway::enforcement_loader::seal_promotion_authorization_for_route;

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: PromotionCommand,
}

#[derive(clap::Subcommand, Debug, Clone)]
enum PromotionCommand {
    Seal {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        route: String,
    },
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    match args.command {
        PromotionCommand::Seal { config, route } => seal(config, route),
    }
}

fn seal(config_path: PathBuf, route_id: String) -> anyhow::Result<ExitCode> {
    let config = super::cmd_serve::load_config(&config_path)?;
    let policy = super::cmd_serve::load_policy(&config.policy_bundle)?;
    let (registry, registry_source, _) = super::cmd_serve::load_registry(&config.registry_feed)?;
    let owned_costs = super::cmd_serve::load_owned_costs(
        config.tco.as_deref(),
        &config.actual_supply_id,
        &registry,
    )?;
    let active = ActiveRuntimeProvenance::from_loaded(&policy, &registry_source, &owned_costs);
    let enforcement_path = config
        .enforcement
        .as_deref()
        .context("promotion seal requires configured enforcement")?;
    let source = fs::read_to_string(enforcement_path).with_context(|| {
        format!(
            "failed to read enforcement bundle {}",
            enforcement_path.display()
        )
    })?;
    let validated = EnforcementConfigV1::from_yaml(&source)
        .context("failed to parse enforcement bundle")?
        .validate()
        .context("failed to validate enforcement bundle")?;
    let route = validated
        .route(&route_id)
        .filter(|route| {
            matches!(
                route.protocol,
                AuthorityProtocol::ChatCompletions | AuthorityProtocol::Responses
            ) && route.promotion.is_some()
        })
        .context("promotion seal requires one matching Chat or Responses route")?;
    let evidence_root = enforcement_path
        .parent()
        .context("enforcement bundle has no evidence root")?;
    let authorization = seal_promotion_authorization_for_route(
        &validated,
        &route.route_id,
        evidence_root,
        &active,
        current_time_ms(),
    )
    .with_context(|| {
        format!(
            "failed to seal promotion authorization for {}",
            operator_safe_route_id(&route.route_id)
        )
    })?;
    println!(
        "sealed promotion authorization route {} digest {}",
        operator_safe_route_id(&route.route_id),
        authorization.authorization_digest
    );
    Ok(ExitCode::SUCCESS)
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_seal_route_rendering_neutralizes_unicode_formatting() {
        assert_eq!(
            operator_safe_route_id("support\u{202e}evil\u{2028}next"),
            "support\\u{202e}evil\\u{2028}next"
        );
    }
}
