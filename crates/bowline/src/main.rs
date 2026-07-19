#![recursion_limit = "256"]

use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod cmd_billing;
mod cmd_canary;
mod cmd_economics;
mod cmd_export;
mod cmd_health;
mod cmd_import;
mod cmd_kill;
mod cmd_policy;
mod cmd_preflight;
mod cmd_promotion;
mod cmd_registry;
mod cmd_report;
mod cmd_serve;
mod economics_render;
mod safe_path;

#[derive(Parser)]
#[command(name = "bowline", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Billing(cmd_billing::Args),
    Canary(cmd_canary::Args),
    Economics(cmd_economics::Args),
    Export(cmd_export::Args),
    Health(cmd_health::Args),
    Import(cmd_import::Args),
    Kill(cmd_kill::Args),
    Preflight(cmd_preflight::Args),
    Promotion(cmd_promotion::Args),
    Serve(cmd_serve::Args),
    Report(cmd_report::Args),
    Policy(cmd_policy::Args),
    Registry(cmd_registry::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Billing(args) => cmd_billing::run(args),
        Command::Canary(args) => cmd_canary::run(args),
        Command::Economics(args) => cmd_economics::run(args),
        Command::Export(args) => cmd_export::run(args),
        Command::Health(args) => cmd_health::run(args),
        Command::Import(args) => cmd_import::run(args),
        Command::Kill(args) => cmd_kill::run(args),
        Command::Preflight(args) => cmd_preflight::run(args),
        Command::Promotion(args) => cmd_promotion::run(args),
        Command::Serve(args) => cmd_serve::run(args).map(|()| ExitCode::SUCCESS),
        Command::Report(args) => cmd_report::run(args),
        Command::Policy(args) => cmd_policy::run(args).map(|()| ExitCode::SUCCESS),
        Command::Registry(args) => cmd_registry::run(args).map(|()| ExitCode::SUCCESS),
    }
}
