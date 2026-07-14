use std::{fs, path::PathBuf, process::ExitCode, time::Duration};

use anyhow::Context;
use bowline_core::{
    config::Config,
    enforcement::{EnforcementConfigV1, FallbackMode, RouteMode, ValidatedEnforcement},
};
use clap::Args as ClapArgs;
use serde::Serialize;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8080/health/ready")]
    url: String,
    #[arg(long)]
    local_config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    if let Some(path) = args.local_config.as_deref() {
        return run_local_diagnostics(path, args.json);
    }
    let url = reqwest::Url::parse(&args.url).context("health URL is invalid")?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("health URL must use HTTP or HTTPS");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create health-check runtime")?;
    let ready = runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build health-check client")?;
        let response = tokio::time::timeout(Duration::from_secs(5), client.get(url).send())
            .await
            .context("health check timed out")??;
        Ok::<bool, anyhow::Error>(response.status().is_success())
    })?;
    if ready {
        println!("ready");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("not ready");
        Ok(ExitCode::FAILURE)
    }
}

#[derive(Debug, Serialize)]
struct LocalEnforcementDiagnostics {
    schema_version: u32,
    routes: Vec<LocalRouteDiagnostic>,
}

#[derive(Debug, Serialize)]
struct LocalRouteDiagnostic {
    route_id: String,
    mode: RouteMode,
    fallback: Option<FallbackMode>,
    promotion_evidence_configured: bool,
}

fn local_enforcement_diagnostics(validated: &ValidatedEnforcement) -> LocalEnforcementDiagnostics {
    LocalEnforcementDiagnostics {
        schema_version: 1,
        routes: validated
            .routes()
            .map(|route| LocalRouteDiagnostic {
                route_id: route.route_id.clone(),
                mode: route.mode,
                fallback: route.fallback,
                promotion_evidence_configured: route.promotion.is_some(),
            })
            .collect(),
    }
}

fn run_local_diagnostics(path: &std::path::Path, json: bool) -> anyhow::Result<ExitCode> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read configuration {}", path.display()))?;
    let config = Config::from_yaml(&source).context("failed to parse configuration")?;
    let enforcement = config
        .enforcement
        .context("configuration has no controlled-enforcement bundle")?;
    let enforcement = if enforcement.is_absolute() {
        enforcement
    } else {
        path.parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(enforcement)
    };
    let source = fs::read_to_string(&enforcement).with_context(|| {
        format!(
            "failed to read controlled-enforcement bundle {}",
            enforcement.display()
        )
    })?;
    let diagnostics = local_enforcement_diagnostics(
        &EnforcementConfigV1::from_yaml(&source)
            .context("failed to parse controlled-enforcement bundle")?
            .validate()
            .context("failed to validate controlled-enforcement bundle")?,
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&diagnostics)?);
    } else {
        for route in diagnostics.routes {
            println!(
                "{} mode={:?} fallback={:?} evidence_configured={}",
                route.route_id, route.mode, route.fallback, route.promotion_evidence_configured
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::local_enforcement_diagnostics;
    use bowline_core::enforcement::EnforcementConfigV1;

    #[test]
    fn local_diagnostics_expose_sanitized_route_detail_only() {
        let raw = EnforcementConfigV1::from_yaml(
            r#"
version: 1
global_candidate_in_flight: 1
kill_switch:
  trust_root: /private/kill
  relative_path: state
actuators: []
routes:
  - route_id: support-chat
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    mode: observe
    rollout_ppm: 0
"#,
        )
        .unwrap();
        let diagnostics = local_enforcement_diagnostics(&raw.validate().unwrap());
        let json = serde_json::to_string(&diagnostics).unwrap();
        assert!(json.contains("support-chat"));
        assert!(json.contains("observe"));
        for forbidden in [
            "trust_root",
            "/private/kill",
            "authorization_env",
            "base_url",
            "workload",
            "supply_id",
            "model",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
