use std::{fs, path::PathBuf};

use anyhow::Context;
use bowline_core::policy::PolicyBundle;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Validate(ValidateArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct ValidateArgs {
    file: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Validate(validate) => validate_policy(validate),
    }
}

fn validate_policy(args: ValidateArgs) -> anyhow::Result<()> {
    let source = fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read policy bundle {}", args.file.display()))?;
    let policy = PolicyBundle::from_yaml(&source).context("failed to parse policy bundle")?;

    println!("ok {}", policy.digest());
    Ok(())
}
