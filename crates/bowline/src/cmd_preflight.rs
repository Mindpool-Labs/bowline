use std::{
    env, fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use bowline_core::{
    config::{load_owned_cost_catalog, Config},
    enforcement::{ActiveRuntimeProvenance, EnforcementConfigV1, KillReadResult},
    policy::PolicyBundle,
    supply::Registry,
};
use bowline_gateway::{
    actuator::ActuatorRegistry,
    enforcement_loader::{
        load_verified_promotion_grant, load_verified_recommendation_evidence, KillStateReader,
    },
};
use clap::Args as ClapArgs;
use serde::Serialize;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    schema_version: u32,
    checks: Vec<Check>,
}

#[derive(Debug, Serialize)]
struct Check {
    id: String,
    status: CheckStatus,
    message: String,
    remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Pass,
    Degraded,
    Fail,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let mut checks = Vec::new();
    let config_path = match super::cmd_serve::absolute_config_path(&args.config) {
        Ok(path) => path,
        Err(error) => {
            checks.push(fail(
                "config",
                format!("configuration path could not be resolved: {error}"),
                "provide a readable --config path",
            ));
            return emit(args.json, checks);
        }
    };
    let source = match fs::read_to_string(&config_path) {
        Ok(source) => source,
        Err(error) => {
            checks.push(fail(
                "config",
                format!("configuration could not be read: {error}"),
                "provide a readable --config path",
            ));
            return emit(args.json, checks);
        }
    };
    let mut config = match Config::from_yaml(&source) {
        Ok(config) => config,
        Err(error) => {
            checks.push(fail(
                "config",
                error.to_string(),
                "fix the YAML shape and remove unknown fields",
            ));
            return emit(args.json, checks);
        }
    };
    resolve_config_paths(&mut config, &config_path);
    if let Err(error) = config.validate() {
        checks.push(fail(
            "config",
            error.to_string(),
            "correct the named field using docs/configuration.md",
        ));
        return emit(args.json, checks);
    }
    checks.push(pass("config", "configuration is valid"));

    let policy = match load_policy(&config.policy_bundle) {
        Ok(policy) => {
            checks.push(pass(
                "policy",
                format!("policy bundle is valid ({})", policy.digest()),
            ));
            Some(policy)
        }
        Err(error) => {
            checks.push(fail(
                "policy",
                error.to_string(),
                "validate and correct the policy bundle",
            ));
            None
        }
    };

    let registry = match load_registry(&config.registry_feed) {
        Ok((registry, registry_source)) => {
            match config.attribution_resolver(&registry) {
                Ok(_) => checks.push(pass(
                    "registry",
                    "registry and attribution targets are valid",
                )),
                Err(error) => checks.push(fail(
                    "registry",
                    error.to_string(),
                    "add every exact attribution supply target or correct the configuration",
                )),
            }
            if let Some(attribution) = &config.attribution {
                for (index, mapping) in attribution.mappings.iter().enumerate() {
                    let id = format!("attribution-mapping-{}", index + 1);
                    if registry.by_id(&mapping.supply_id).is_some() {
                        checks.push(pass(
                            id,
                            format!("configured mapping targets {}", mapping.supply_id),
                        ));
                    } else {
                        checks.push(fail(
                            id,
                            format!("unknown supply id {}", mapping.supply_id),
                            "add the exact supply target to the registry",
                        ));
                    }
                }
            }
            Some((registry, registry_source))
        }
        Err(error) => {
            checks.push(fail(
                "registry",
                error.to_string(),
                "correct the registry feed and rerun preflight",
            ));
            None
        }
    };

    let owned_costs = match (config.tco.as_deref(), registry.as_ref()) {
        (Some(path), Some((registry, _))) => match fs::read_to_string(path)
            .context("failed to read TCO inputs")
            .and_then(|source| {
                load_owned_cost_catalog(
                    Some(&source),
                    (!config.actual_supply_id.trim().is_empty())
                        .then_some(config.actual_supply_id.as_str()),
                    registry,
                )
                .map_err(anyhow::Error::from)
            }) {
            Ok(costs) => {
                checks.push(pass("tco", "TCO inputs are valid"));
                Some(costs)
            }
            Err(error) => {
                checks.push(fail(
                    "tco",
                    error.to_string(),
                    "provide finite non-negative costs and positive monthly capacity",
                ));
                None
            }
        },
        (None, Some((registry, _))) => {
            checks.push(pass("tco", "owned-supply TCO is not configured"));
            load_owned_cost_catalog(
                None,
                (!config.actual_supply_id.trim().is_empty())
                    .then_some(config.actual_supply_id.as_str()),
                registry,
            )
            .ok()
        }
        (None, None) => {
            checks.push(pass("tco", "owned-supply TCO is not configured"));
            None
        }
        (Some(_), None) => {
            checks.push(fail(
                "tco",
                "cannot validate TCO without a valid registry",
                "correct the registry feed and rerun preflight",
            ));
            None
        }
    };
    let active = policy.as_ref().and_then(|policy| {
        registry
            .as_ref()
            .zip(owned_costs.as_ref())
            .map(|((_, source), costs)| ActiveRuntimeProvenance::from_loaded(policy, source, costs))
    });

    match probe_ledger(&config.ledger_dir) {
        Ok(()) => checks.push(pass("ledger", "ledger directory is writable and unlocked")),
        Err(error) => checks.push(fail(
            "ledger",
            error.to_string(),
            "fix volume permissions or stop the other Bowline writer",
        )),
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create preflight runtime")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.runtime.connect_timeout())
        .build()
        .context("failed to build preflight HTTP client")?;
    if config.enforcement.is_some() {
        checks.extend(runtime.block_on(preflight_enforcement(
            &config,
            registry.as_ref().map(|(registry, _)| registry),
            active.as_ref(),
        )));
    }
    let local_result = runtime.block_on(probe_local_endpoints(&client, &config));
    match local_result {
        Ok(message) => checks.push(pass("local-endpoints", message)),
        Err(error) => checks.push(fail(
            "local-endpoints",
            error.to_string(),
            "correct or remove unreachable local_endpoints entries",
        )),
    }

    let models = runtime.block_on(probe_upstream_models(&client, &config));
    match &models {
        Ok(models) => checks.push(pass(
            "upstream-models",
            format!("upstream returned {} model identifiers", models.len()),
        )),
        Err(error) => checks.push(fail(
            "upstream-models",
            error.to_string(),
            "ensure upstream /v1/models is reachable and authorization is valid",
        )),
    }

    match (registry.as_ref(), models.as_ref()) {
        (Some((registry, _)), Ok(models)) => {
            let mut supply_ids = config
                .attribution
                .iter()
                .flat_map(|attribution| attribution.mappings.iter())
                .map(|mapping| mapping.supply_id.as_str())
                .collect::<Vec<_>>();
            if !config.actual_supply_id.trim().is_empty() {
                supply_ids.push(&config.actual_supply_id);
            }
            let resolved = models.iter().any(|model| {
                supply_ids
                    .iter()
                    .any(|supply_id| registry.resolve_model(supply_id, model).is_some())
            });
            if resolved {
                checks.push(pass(
                    "model-resolution",
                    "upstream model identifier matches the configured actual supply",
                ));
            } else {
                checks.push(fail(
                    "model-resolution",
                    "no upstream model identifier matches the configured actual supply",
                    "add the exact provider identifier as the canonical model or an alias",
                ));
            }
        }
        _ => checks.push(fail(
            "model-resolution",
            "model resolution could not run because a prerequisite failed",
            "resolve registry and upstream-model failures, then rerun preflight",
        )),
    }

    emit(args.json, checks)
}

fn emit(json: bool, checks: Vec<Check>) -> anyhow::Result<ExitCode> {
    let failed = checks.iter().any(|check| check.status == CheckStatus::Fail);
    let report = PreflightReport {
        schema_version: 1,
        checks,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for check in &report.checks {
            println!(
                "{:>4} {:<18} {}",
                status_label(check.status),
                check.id,
                check.message
            );
            if let Some(remediation) = &check.remediation {
                println!("     remediation: {remediation}");
            }
        }
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn pass(id: impl Into<String>, message: impl Into<String>) -> Check {
    Check {
        id: id.into(),
        status: CheckStatus::Pass,
        message: message.into(),
        remediation: None,
    }
}

fn fail(
    id: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> Check {
    Check {
        id: id.into(),
        status: CheckStatus::Fail,
        message: message.into(),
        remediation: Some(remediation.into()),
    }
}

fn status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "PASS",
        CheckStatus::Degraded => "DEGRADED",
        CheckStatus::Fail => "FAIL",
    }
}

fn enforcement_probe_status(
    probe_succeeded: bool,
    fallbacks: &[bowline_core::enforcement::FallbackMode],
) -> CheckStatus {
    if probe_succeeded {
        CheckStatus::Pass
    } else if fallbacks.contains(&bowline_core::enforcement::FallbackMode::FailClosed) {
        CheckStatus::Fail
    } else {
        CheckStatus::Degraded
    }
}

fn load_policy(path: &Path) -> anyhow::Result<PolicyBundle> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy bundle {}", path.display()))?;
    PolicyBundle::from_yaml(&source).context("failed to parse policy bundle")
}

fn load_registry(path: &Path) -> anyhow::Result<(Registry, String)> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read registry feed {}", path.display()))?;
    let registry = Registry::from_json(&source).context("failed to parse registry feed")?;
    Ok((registry, source))
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

async fn preflight_enforcement(
    config: &Config,
    registry: Option<&Registry>,
    active: Option<&ActiveRuntimeProvenance>,
) -> Vec<Check> {
    let Some(path) = config.enforcement.as_deref() else {
        return vec![];
    };
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            return vec![fail(
                "enforcement-config",
                format!("enforcement bundle could not be read: {error}"),
                "provide a readable enforcement bundle",
            )]
        }
    };
    let raw = match EnforcementConfigV1::from_yaml(&source)
        .and_then(|raw| raw.clone().validate().map(|validated| (raw, validated)))
    {
        Ok(value) => value,
        Err(error) => {
            return vec![fail(
                "enforcement-config",
                error.to_string(),
                "correct the strict enforcement bundle",
            )]
        }
    };
    let (raw, validated) = raw;
    let Some(active) = active else {
        return vec![fail(
            "enforcement-evidence",
            "active provenance is unavailable",
            "correct policy, registry, and owned-cost inputs",
        )];
    };
    let evidence_root = path.parent().unwrap_or_else(|| Path::new("."));
    for route in validated.authority_routes() {
        if let Err(error) = load_verified_promotion_grant(
            &validated,
            &route.route_id,
            evidence_root,
            active,
            current_time_ms(),
        ) {
            return vec![fail(
                "enforcement-evidence",
                format!("authority evidence is invalid: {error}"),
                "supply fresh exact schema-v2 quality and economics evidence",
            )];
        }
    }
    for route in validated.routes().filter(|route| {
        route.mode == bowline_core::enforcement::RouteMode::Recommend && route.promotion.is_some()
    }) {
        if let Err(error) = load_verified_recommendation_evidence(
            &validated,
            &route.route_id,
            evidence_root,
            active,
            current_time_ms(),
        ) {
            return vec![fail(
                "enforcement-evidence",
                format!("recommendation evidence is invalid: {error}"),
                "supply fresh exact schema-v2 quality and economics evidence",
            )];
        }
    }
    let kill = &raw.kill_switch;
    let kill_state = match KillStateReader::open(Path::new(&kill.trust_root), &kill.relative_path) {
        Ok(reader) => reader.read_kill_state(),
        Err(error) => {
            return vec![fail(
                "enforcement-kill",
                error.to_string(),
                "repair the private kill-switch trust root and file",
            )]
        }
    };
    if !matches!(kill_state, KillReadResult::Armed | KillReadResult::Bypass) {
        return vec![fail(
            "enforcement-kill",
            format!("kill-switch state is not trusted: {kill_state:?}"),
            "repair the private kill-switch file or set it to bypass",
        )];
    }
    let Some(registry) = registry else {
        return vec![fail(
            "enforcement-actuators",
            "actuators cannot be checked without a valid registry",
            "correct the registry and rerun preflight",
        )];
    };
    let actuators = match ActuatorRegistry::new(
        raw.global_candidate_in_flight,
        raw.actuators.iter().cloned(),
    ) {
        Ok(actuators) => actuators,
        Err(error) => {
            return vec![fail(
                "enforcement-actuators",
                error.to_string(),
                "correct actuator bounds and references",
            )]
        }
    };
    let mut checks = vec![pass(
        "enforcement-config",
        format!("controlled enforcement is valid; kill state is {kill_state:?}"),
    )];
    for actuator in &raw.actuators {
        let fallbacks = validated
            .authority_routes()
            .filter(|route| route.promoted_supply_id.as_deref() == Some(&actuator.supply_id))
            .filter_map(|route| route.fallback)
            .collect::<Vec<_>>();
        if fallbacks.is_empty() {
            continue;
        }
        let Some(model) = registry
            .by_id(&actuator.supply_id)
            .map(|entry| entry.model.as_str())
        else {
            checks.push(fail(
                "enforcement-actuator",
                "an authority actuator is absent from the registry",
                "add the exact actuator supply to the registry",
            ));
            continue;
        };
        let authorization = match env::var(&actuator.authorization_env)
            .ok()
            .and_then(|secret| reqwest::header::HeaderValue::from_str(&secret).ok())
        {
            Some(value) => value,
            None => {
                checks.push(fail(
                    "enforcement-actuator",
                    "an actuator authorization environment reference is unavailable or invalid",
                    "set the referenced authorization environment value",
                ));
                continue;
            }
        };
        let succeeded = actuators
            .run_startup_probe(&actuator.supply_id, model, Some(authorization))
            .await
            .unwrap_or(false);
        let operationally_available = succeeded && kill_state == KillReadResult::Armed;
        let status = enforcement_probe_status(operationally_available, &fallbacks);
        let message = match status {
            CheckStatus::Pass => "authority actuator probe succeeded",
            CheckStatus::Degraded if !succeeded => {
                "authority actuator probe failed; bypass routes remain ready/degraded"
            }
            CheckStatus::Degraded => "kill switch is bypass; bypass routes remain ready/degraded",
            CheckStatus::Fail if !succeeded => {
                "authority actuator probe failed; an active fail-closed route is unready"
            }
            CheckStatus::Fail => "kill switch is bypass; an active fail-closed route is unready",
        };
        checks.push(Check {
            id: "enforcement-actuator-probe".into(),
            status,
            message: message.into(),
            remediation: (status != CheckStatus::Pass)
                .then(|| "restore the actuator and rerun preflight".into()),
        });
    }
    checks
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn probe_ledger(directory: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(directory)?;
    let lock_path = directory.join("writer.lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("ledger directory is locked by another writer"))?;
    let probe_path = directory.join(format!(".preflight-{}.tmp", std::process::id()));
    let mut probe = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&probe_path)?;
    probe.write_all(b"bowline-preflight")?;
    probe.sync_all()?;
    fs::remove_file(probe_path)?;
    lock.unlock()?;
    Ok(())
}

async fn probe_local_endpoints(
    client: &reqwest::Client,
    config: &Config,
) -> anyhow::Result<String> {
    for endpoint in &config.local_endpoints {
        let url = format!("{}/v1/models", endpoint.url.trim_end_matches('/'));
        let response = tokio::time::timeout(
            config.runtime.response_header_timeout(),
            client.get(url).send(),
        )
        .await
        .context("local endpoint timed out")??;
        if !response.status().is_success() {
            anyhow::bail!(
                "local endpoint {} returned {}",
                endpoint.supply_id,
                response.status()
            );
        }
    }
    Ok(if config.local_endpoints.is_empty() {
        "no local endpoints configured".to_string()
    } else {
        format!(
            "{} local endpoints are reachable",
            config.local_endpoints.len()
        )
    })
}

async fn probe_upstream_models(
    client: &reqwest::Client,
    config: &Config,
) -> anyhow::Result<Vec<String>> {
    let url = format!("{}/v1/models", config.upstream.trim_end_matches('/'));
    let mut request = client.get(url);
    if let Ok(authorization) = env::var("BOWLINE_PREFLIGHT_AUTHORIZATION") {
        request = request.header("authorization", authorization);
    }
    let response = tokio::time::timeout(config.runtime.response_header_timeout(), request.send())
        .await
        .context("upstream model probe timed out")??
        .error_for_status()
        .context("upstream model probe failed")?;
    let value: serde_json::Value = response.json().await.context("invalid /v1/models JSON")?;
    let models = value
        .get("data")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    if models.is_empty() {
        anyhow::bail!("upstream /v1/models returned no model identifiers");
    }
    Ok(models)
}

#[cfg(test)]
mod controlled_enforcement_tests {
    use super::*;
    use bowline_core::enforcement::FallbackMode;

    #[test]
    fn failed_actuator_probe_is_degraded_for_bypass_and_failed_for_fail_closed() {
        assert_eq!(
            enforcement_probe_status(false, &[FallbackMode::Bypass]),
            CheckStatus::Degraded
        );
        assert_eq!(
            enforcement_probe_status(false, &[FallbackMode::FailClosed]),
            CheckStatus::Fail
        );
        assert_eq!(
            enforcement_probe_status(false, &[FallbackMode::Bypass, FallbackMode::FailClosed]),
            CheckStatus::Fail
        );
        assert_eq!(
            enforcement_probe_status(true, &[FallbackMode::FailClosed]),
            CheckStatus::Pass
        );
    }
}
