use std::{fs, path::PathBuf, process::ExitCode};

use anyhow::Context;
use bowline_core::enforcement::EnforcementConfigV1;
use bowline_gateway::enforcement_loader::{atomic_write_kill_state, KillWriteState};
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Arm(Location),
    Bypass(Location),
}

#[derive(ClapArgs, Debug, Clone)]
struct Location {
    #[arg(long)]
    enforcement: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let (location, state) = match args.command {
        Command::Arm(location) => (location, KillWriteState::Armed),
        Command::Bypass(location) => (location, KillWriteState::Bypass),
    };
    let source = fs::read_to_string(&location.enforcement).with_context(|| {
        format!(
            "failed to read enforcement bundle {}",
            location.enforcement.display()
        )
    })?;
    let config =
        EnforcementConfigV1::from_yaml(&source).context("failed to parse enforcement bundle")?;
    config
        .validate()
        .context("failed to validate enforcement bundle")?;
    atomic_write_kill_state(
        config.kill_switch.trust_root.as_ref(),
        &config.kill_switch.relative_path,
        state,
    )
    .context("failed to atomically update kill state")?;
    Ok(ExitCode::SUCCESS)
}
