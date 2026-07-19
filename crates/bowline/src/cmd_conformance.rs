//! `bowline conformance`: an offline, no-write validator that lets a collector author check a
//! producer file against the passive-event contract using the exact shared validation the real
//! importer uses (see `bowline-gateway::passive` and `bowline-gateway::profile`). Both subcommands
//! print one versioned JSON result to stdout and exit nonzero on the first rejection; neither ever
//! touches config, policy, registry, or a ledger.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use bowline_gateway::{
    contract::{PassiveContractError, PassiveContractReasonCode, PassiveContractResult},
    passive::{parse_canonical_jsonl_named, MAX_INPUT_BYTES},
    profile::{transform_profile_jsonl, TransformProfile, MAX_PROFILE_BYTES},
};
use clap::{Args as ClapArgs, Subcommand};

use crate::safe_path::{self, BoundedReadFailure};

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    command: ConformanceCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum ConformanceCommand {
    /// Validate a file already in the canonical passive-event schema.
    Canonical(CanonicalArgs),
    /// Validate a producer file against a collector profile, exactly as import would transform it.
    Collector(CollectorArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct CanonicalArgs {
    #[arg(long)]
    input: PathBuf,
}

#[derive(ClapArgs, Debug, Clone)]
struct CollectorArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    input: PathBuf,
}

#[derive(Clone, Copy)]
enum ReadKind {
    Input,
    Profile,
}

pub fn run(args: Args) -> anyhow::Result<ExitCode> {
    let result = match args.command {
        ConformanceCommand::Canonical(args) => run_canonical(&args),
        ConformanceCommand::Collector(args) => run_collector(&args),
    };
    print_result(result)
}

fn run_canonical(args: &CanonicalArgs) -> PassiveContractResult {
    let input = match read_utf8(&args.input, MAX_INPUT_BYTES, ReadKind::Input) {
        Ok(source) => source,
        Err(error) => return PassiveContractResult::rejected(error),
    };
    match parse_canonical_jsonl_named(&input, &args.input.display().to_string()) {
        Ok(events) => PassiveContractResult::accepted(events.len() as u64),
        Err(error) => PassiveContractResult::rejected(PassiveContractError::from(&error)),
    }
}

fn run_collector(args: &CollectorArgs) -> PassiveContractResult {
    let profile_source = match read_utf8(&args.profile, MAX_PROFILE_BYTES, ReadKind::Profile) {
        Ok(source) => source,
        Err(error) => return PassiveContractResult::rejected(error),
    };
    let profile =
        match TransformProfile::from_yaml(&profile_source, &args.profile.display().to_string()) {
            Ok(profile) => profile,
            Err(error) => {
                return PassiveContractResult::rejected(PassiveContractError::from(&error))
            }
        };
    let input = match read_utf8(&args.input, MAX_INPUT_BYTES, ReadKind::Input) {
        Ok(source) => source,
        Err(error) => return PassiveContractResult::rejected(error),
    };
    match transform_profile_jsonl(&profile, &input, &args.input.display().to_string()) {
        Ok(events) => PassiveContractResult::accepted(events.len() as u64),
        Err(error) => PassiveContractResult::rejected(PassiveContractError::from(&error)),
    }
}

/// Reads a file with the identical file-safety and byte-bound rules import prevalidation applies
/// (`safe_path::read_bounded_bytes`), then classifies any failure into the fixed v1 reason codes.
fn read_utf8(path: &Path, max: usize, kind: ReadKind) -> Result<String, PassiveContractError> {
    let bytes = safe_path::read_bounded_bytes(path, max).map_err(|failure| {
        let reason_code = match (kind, &failure) {
            (ReadKind::Input, BoundedReadFailure::TooLarge) => {
                PassiveContractReasonCode::InputTooLarge
            }
            (ReadKind::Profile, BoundedReadFailure::TooLarge) => {
                PassiveContractReasonCode::ProfileTooLarge
            }
            (ReadKind::Input, _) => PassiveContractReasonCode::UnsafeInputPath,
            (ReadKind::Profile, _) => PassiveContractReasonCode::UnsafeProfilePath,
        };
        let label = match kind {
            ReadKind::Input => "input",
            ReadKind::Profile => "profile",
        };
        PassiveContractError {
            reason_code,
            line: None,
            message: format!("{label} {}: {failure}", path.display()),
        }
    })?;
    String::from_utf8(bytes).map_err(|error| {
        let reason_code = match kind {
            ReadKind::Input => PassiveContractReasonCode::InvalidUtf8Input,
            ReadKind::Profile => PassiveContractReasonCode::InvalidUtf8Profile,
        };
        let label = match kind {
            ReadKind::Input => "input",
            ReadKind::Profile => "profile",
        };
        PassiveContractError {
            reason_code,
            line: None,
            message: format!("{label} {} is not valid UTF-8: {error}", path.display()),
        }
    })
}

fn print_result(result: PassiveContractResult) -> anyhow::Result<ExitCode> {
    let accepted = result.is_accepted();
    println!("{}", serde_json::to_string(&result)?);
    Ok(if accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
