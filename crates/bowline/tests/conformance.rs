//! Parity tests between the real importer's prevalidation and `bowline conformance`. Both consume
//! the same shared validation in `bowline-gateway`; these tests assert that neither CLI wrapper
//! diverges from that shared code path or from each other.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use bowline_core::run::RunStore;
use bowline_gateway::passive::parse_canonical_jsonl_named;
use serde::Deserialize;

fn bowline() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bowline"))
}

fn bowline_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives under workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/conformance")
        .join(name)
}

/// Several call sites share one literal `name` (for example every case in
/// `assert_collector_rejection_matches_import`), and cargo test runs test functions on multiple
/// threads by default; nanosecond timestamps alone are not guaranteed unique across threads on
/// every platform's clock resolution, so an atomic counter disambiguates same-name, same-instant
/// callers deterministically.
fn tempdir(name: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moves forward")
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "bowline-conformance-{name}-{}-{nanos}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("tempdir created");
    dir
}

struct ImportFixture {
    config: PathBuf,
    input: PathBuf,
    profile: PathBuf,
    ledger: PathBuf,
}

/// Mirrors `crates/bowline/tests/cli.rs`'s `import_fixture`: same policy/registry/attribution
/// wiring, so import's prevalidation is exercised exactly as a real operator would run it.
fn import_fixture(dir: &Path) -> ImportFixture {
    let root = bowline_root();
    let ledger = dir.join("ledger");
    let config = dir.join("bowline.yaml");
    fs::write(
        &config,
        format!(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:9999\npolicy_bundle: {}\nregistry_feed: {}\nledger_dir: {}\nattribution:\n  version: 1\n  response_header: x-upstream-supply\n  namespace: deployment\n  mappings:\n    - {{value: east, supply_id: openai/gpt-5-mini}}\n",
            root.join("policies/default.yaml").display(),
            root.join("registry/feed.json").display(),
            ledger.display(),
        ),
    )
    .expect("import config");
    let profile = dir.join("profile.yaml");
    fs::copy(fixture_path("collector-profile.yaml"), &profile).expect("profile fixture copied");
    ImportFixture {
        config,
        input: dir.join("input.jsonl"),
        profile,
        ledger,
    }
}

fn run_import(fixture: &ImportFixture) -> Output {
    bowline()
        .args([
            "import",
            "observations",
            "--config",
            fixture.config.to_str().unwrap(),
            "--input",
            fixture.input.to_str().unwrap(),
            "--profile",
            fixture.profile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("bowline import runs")
}

/// Runs `bowline import observations` prevalidation only: any config path works, because
/// prevalidation (input/profile read, schema/profile validation) runs before config is touched.
/// This lets failure-class parity tests skip building a real policy/registry environment.
fn run_import_prevalidation(input: &Path, profile: &Path) -> Output {
    bowline()
        .args([
            "import",
            "observations",
            "--config",
            "/nonexistent/bowline.yaml",
            "--input",
            input.to_str().unwrap(),
            "--profile",
            profile.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("bowline import runs")
}

fn run_conformance_collector(profile: &Path, input: &Path) -> Output {
    bowline()
        .args([
            "conformance",
            "collector",
            "--profile",
            profile.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
        ])
        .output()
        .expect("bowline conformance collector runs")
}

fn run_conformance_canonical(input: &Path) -> Output {
    bowline()
        .args([
            "conformance",
            "canonical",
            "--input",
            input.to_str().unwrap(),
        ])
        .output()
        .expect("bowline conformance canonical runs")
}

#[derive(Debug, Deserialize)]
struct ContractResult {
    result_version: u32,
    accepted: Option<u64>,
    error: Option<ContractError>,
}

#[derive(Debug, Deserialize)]
struct ContractError {
    reason_code: String,
    line: Option<usize>,
    #[allow(dead_code)]
    message: String,
}

fn parse_result(output: &Output) -> ContractResult {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "conformance result did not parse as JSON: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

// ---------------------------------------------------------------------------------------------
// Canonical mode: parity with the shared gateway parser directly (there is no profile-free
// "real importer" invocation to shell out to, since `bowline import observations` always
// transforms through a profile; the parity claim here is that the CLI wrapper does not diverge
// from the exact shared function it wraps).
// ---------------------------------------------------------------------------------------------

#[test]
fn canonical_valid_input_matches_direct_gateway_parse() {
    let input = fixture_path("canonical-valid.jsonl");
    let source = fs::read_to_string(&input).expect("fixture readable");
    let direct = parse_canonical_jsonl_named(&source, &input.display().to_string())
        .expect("direct parse accepts fixture");

    let output = run_conformance_canonical(&input);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = parse_result(&output);
    assert_eq!(result.result_version, 1);
    assert!(result.error.is_none());
    assert_eq!(result.accepted, Some(direct.len() as u64));
}

#[test]
fn canonical_malformed_json_is_first_error_at_the_same_line() {
    assert_canonical_rejection_matches_direct_parse(
        "malformed-json-canonical.jsonl",
        "InvalidEvent",
    );
}

#[test]
fn canonical_schema_invalid_is_first_error_at_the_same_line() {
    assert_canonical_rejection_matches_direct_parse(
        "schema-invalid-canonical.jsonl",
        "InvalidEvent",
    );
}

#[test]
fn canonical_duplicate_id_is_first_error_at_the_same_line() {
    assert_canonical_rejection_matches_direct_parse(
        "duplicate-id-canonical.jsonl",
        "DuplicateEventId",
    );
}

#[test]
fn canonical_oversized_line_is_first_error_at_the_same_line() {
    assert_canonical_rejection_matches_direct_parse(
        "oversized-line-canonical.jsonl",
        "LineTooLarge",
    );
}

#[test]
fn canonical_invalid_utf8_input_is_rejected() {
    let input = fixture_path("invalid-utf8-canonical.jsonl");
    let output = run_conformance_canonical(&input);
    assert!(!output.status.success());
    let result = parse_result(&output);
    let error = result.error.expect("invalid utf8 rejected");
    assert_eq!(error.reason_code, "invalid-utf8-input");
    assert_eq!(error.line, None);
}

#[test]
fn canonical_oversized_input_is_rejected_the_same_as_direct_parse() {
    let oversized = "x".repeat(16 * 1024 * 1024 + 1);
    let direct = parse_canonical_jsonl_named(&oversized, "<memory>").expect_err("direct rejects");
    assert!(direct.to_string().contains("exceeds"));

    let dir = tempdir("canonical-oversized-input");
    let input = dir.join("oversized.jsonl");
    fs::write(&input, &oversized).expect("oversized input written");
    let output = run_conformance_canonical(&input);
    assert!(!output.status.success());
    let result = parse_result(&output);
    let error = result.error.expect("oversized input rejected");
    assert_eq!(error.reason_code, "input-too-large");
    assert_eq!(error.line, None);
}

#[test]
fn canonical_event_count_exceeded_is_rejected_the_same_as_direct_parse() {
    const MAX_EVENTS: usize = 100_000;
    let mut events = String::new();
    for index in 0..=MAX_EVENTS {
        if index > 0 {
            events.push('\n');
        }
        events.push_str(&format!(
            r#"{{"schema_version":1,"event_id":"e{index}","observed_at_ms":0,"method":"POST","route":"/v1/completions","status":200,"streamed":false,"latency_ms":0,"dimensions":{{}}}}"#
        ));
    }
    let direct = parse_canonical_jsonl_named(&events, "<memory>").expect_err("direct rejects");
    assert!(direct.to_string().contains("event count exceeds"));

    let dir = tempdir("canonical-event-count");
    let input = dir.join("many.jsonl");
    fs::write(&input, &events).expect("event count fixture written");
    let output = run_conformance_canonical(&input);
    assert!(!output.status.success());
    let result = parse_result(&output);
    let error = result.error.expect("event count exceeded rejected");
    assert_eq!(error.reason_code, "event-count-exceeded");
    assert_eq!(error.line, Some(MAX_EVENTS + 1));
}

#[cfg(unix)]
#[test]
fn canonical_nonregular_input_is_rejected_without_blocking() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("canonical-nonregular");
    let regular = dir.join("regular.jsonl");
    fs::copy(fixture_path("canonical-valid.jsonl"), &regular).expect("regular file");

    let symlinked = dir.join("via-symlink.jsonl");
    symlink(&regular, &symlinked).expect("symlink created");
    let output = run_conformance_canonical(&symlinked);
    assert!(!output.status.success());
    let result = parse_result(&output);
    assert_eq!(
        result.error.expect("symlink rejected").reason_code,
        "unsafe-input-path"
    );

    let directory = dir.join("a-directory");
    fs::create_dir(&directory).expect("directory created");
    let output = run_conformance_canonical(&directory);
    assert!(!output.status.success());
    let result = parse_result(&output);
    assert_eq!(
        result.error.expect("directory rejected").reason_code,
        "unsafe-input-path"
    );
}

fn assert_canonical_rejection_matches_direct_parse(fixture: &str, expected_reason_code: &str) {
    let input = fixture_path(fixture);
    let source = fs::read_to_string(&input).unwrap_or_else(|_| {
        // Invalid-UTF-8 fixtures cannot round-trip through `read_to_string`; not used here.
        panic!("fixture {fixture} must be valid UTF-8 for this comparison")
    });
    let direct_error = parse_canonical_jsonl_named(&source, &input.display().to_string())
        .expect_err("direct rejects");

    let output = run_conformance_canonical(&input);
    assert!(!output.status.success(), "fixture: {fixture}");
    let result = parse_result(&output);
    let error = result
        .error
        .unwrap_or_else(|| panic!("{fixture}: expected rejection"));
    assert_eq!(
        error.reason_code,
        kebab(expected_reason_code),
        "fixture: {fixture}"
    );

    let direct_line = match &direct_error {
        bowline_gateway::passive::PassiveError::Line { line, .. } => Some(*line),
        bowline_gateway::passive::PassiveError::Input { .. } => None,
    };
    assert_eq!(error.line, direct_line, "fixture: {fixture}");
}

#[test]
fn published_schema_accepts_valid_events_and_rejects_the_schema_invalid_fixture() {
    let root = bowline_root();
    let schema: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("schemas/passive-event-v1.schema.json")).expect("schema readable"),
    )
    .expect("schema is JSON");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("schema compiles");

    let valid = fs::read_to_string(fixture_path("canonical-valid.jsonl")).expect("valid fixture");
    for line in valid.lines() {
        let event: serde_json::Value = serde_json::from_str(line).expect("fixture line is JSON");
        assert!(
            validator.validate(&event).is_ok(),
            "valid fixture line failed schema validation: {line}"
        );
    }

    let invalid = fs::read_to_string(fixture_path("schema-invalid-canonical.jsonl"))
        .expect("schema-invalid fixture");
    let second_line = invalid.lines().nth(1).expect("fixture has a second line");
    let event: serde_json::Value = serde_json::from_str(second_line).expect("fixture line is JSON");
    assert!(
        validator.validate(&event).is_err(),
        "out-of-range status should fail schema validation"
    );

    // A whitespace-only event_id passes a bare `minLength: 1` check but is rejected by the real
    // validator's `trim().is_empty()` rule (`validate_required` in bowline-gateway::passive). The
    // schema's `pattern: "\\S"` must reject it too, and the CLI (which shares the real validator)
    // must reject the same line for the same reason — three independent checkers, one verdict.
    let whitespace_line = valid
        .lines()
        .next()
        .expect("valid fixture has a first line")
        .replace("\"chat-1\"", "\"   \"");
    let whitespace_event: serde_json::Value =
        serde_json::from_str(&whitespace_line).expect("whitespace event line is JSON");
    assert!(
        validator.validate(&whitespace_event).is_err(),
        "whitespace-only event_id should fail schema validation"
    );

    let direct_error = parse_canonical_jsonl_named(&whitespace_line, "<memory>")
        .expect_err("whitespace-only event_id should fail the real validator");
    assert!(
        direct_error.to_string().contains("event_id"),
        "{direct_error}"
    );

    let dir = tempdir("schema-whitespace-event-id");
    let input = dir.join("whitespace.jsonl");
    fs::write(&input, format!("{whitespace_line}\n")).expect("whitespace fixture written");
    let output = run_conformance_canonical(&input);
    assert!(!output.status.success());
    let result = parse_result(&output);
    let error = result
        .error
        .expect("whitespace-only event_id should be rejected by conformance");
    assert_eq!(error.reason_code, "invalid-event");
    assert_eq!(error.line, Some(1));
}

// ---------------------------------------------------------------------------------------------
// Shipped reference integrations. `integrations/litellm` and `integrations/envoy` each ship a
// profile and a fixture; these prove the shipped pair validates via `bowline conformance
// collector`, the exact command a real collector author would run. As documented in each
// integration's README, this is a serializer/formatter-output contract check against a synthetic
// fixture, not a live LiteLLM or Envoy integration test.
// ---------------------------------------------------------------------------------------------

#[test]
fn litellm_reference_integration_conforms() {
    let root = bowline_root();
    let profile = root.join("integrations/litellm/profile.yaml");
    let input = root.join("integrations/litellm/fixture.jsonl");
    let output = run_conformance_collector(&profile, &input);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = parse_result(&output);
    assert!(result.error.is_none());
    assert_eq!(result.accepted, Some(1));
}

#[test]
fn envoy_reference_integration_conforms() {
    let root = bowline_root();
    let profile = root.join("integrations/envoy/profile.yaml");
    let input = root.join("integrations/envoy/fixture.jsonl");
    let output = run_conformance_collector(&profile, &input);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = parse_result(&output);
    assert!(result.error.is_none());
    assert_eq!(result.accepted, Some(1));
}

// ---------------------------------------------------------------------------------------------
// Collector mode: parity with the real `bowline import observations` prevalidation, since import
// always ingests through a profile transform (the same shared `transform_profile_jsonl`).
// ---------------------------------------------------------------------------------------------

#[test]
fn collector_valid_input_matches_import_accepted_count() {
    let dir = tempdir("collector-valid");
    let fixture = import_fixture(&dir);
    fs::copy(fixture_path("collector-valid.jsonl"), &fixture.input).expect("input copied");

    let import_output = run_import(&fixture);
    assert!(
        import_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&import_output.stderr)
    );
    let import_summary: serde_json::Value =
        serde_json::from_slice(&import_output.stdout).expect("import summary is JSON");

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(
        conformance_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&conformance_output.stderr)
    );
    let result = parse_result(&conformance_output);
    assert_eq!(result.result_version, 1);
    assert!(result.error.is_none());
    assert_eq!(
        result.accepted,
        Some(import_summary["accepted"].as_u64().expect("accepted count"))
    );
}

#[test]
fn collector_malformed_json_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-malformed.jsonl",
        None,
        "InvalidEvent",
        Some(2),
    );
}

#[test]
fn collector_schema_invalid_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-schema-invalid.jsonl",
        None,
        "InvalidEvent",
        Some(2),
    );
}

#[test]
fn collector_duplicate_id_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-duplicate.jsonl",
        None,
        "DuplicateEventId",
        Some(2),
    );
}

#[test]
fn collector_oversized_line_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-oversized-line.jsonl",
        None,
        "LineTooLarge",
        Some(2),
    );
}

#[test]
fn collector_forbidden_profile_pointer_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-valid.jsonl",
        Some("forbidden-pointer-profile.yaml"),
        "ForbiddenProfilePointer",
        None,
    );
}

#[test]
fn collector_missing_required_target_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-valid.jsonl",
        Some("missing-required-target-profile.yaml"),
        "MissingRequiredTarget",
        None,
    );
}

#[test]
fn collector_malformed_profile_matches_import_rejection() {
    assert_collector_rejection_matches_import(
        "collector-valid.jsonl",
        Some("malformed-profile.yaml"),
        "MalformedProfile",
        None,
    );
}

#[test]
fn collector_invalid_utf8_input_matches_import_rejection() {
    let dir = tempdir("collector-invalid-utf8-input");
    let fixture = import_fixture(&dir);
    fs::copy(fixture_path("collector-invalid-utf8.jsonl"), &fixture.input).expect("input copied");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    let error = result.error.expect("invalid utf8 input rejected");
    assert_eq!(error.reason_code, "invalid-utf8-input");
    assert_eq!(error.line, None);
}

#[test]
fn collector_invalid_utf8_profile_matches_import_rejection() {
    let dir = tempdir("collector-invalid-utf8-profile");
    let fixture = import_fixture(&dir);
    fs::copy(fixture_path("collector-valid.jsonl"), &fixture.input).expect("input copied");
    fs::copy(fixture_path("invalid-utf8-profile.yaml"), &fixture.profile).expect("profile copied");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    let error = result.error.expect("invalid utf8 profile rejected");
    assert_eq!(error.reason_code, "invalid-utf8-profile");
    assert_eq!(error.line, None);
}

#[test]
fn collector_oversized_input_matches_import_rejection() {
    let dir = tempdir("collector-oversized-input");
    let fixture = import_fixture(&dir);
    fs::write(&fixture.input, vec![b'x'; 16 * 1024 * 1024 + 1]).expect("oversized input");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());
    assert!(String::from_utf8_lossy(&import_output.stderr).contains("input exceeds"));

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    let error = result.error.expect("oversized input rejected");
    assert_eq!(error.reason_code, "input-too-large");
}

#[test]
fn collector_oversized_profile_matches_import_rejection() {
    let dir = tempdir("collector-oversized-profile");
    let fixture = import_fixture(&dir);
    fs::copy(fixture_path("collector-valid.jsonl"), &fixture.input).expect("input copied");
    fs::write(&fixture.profile, vec![b'x'; 256 * 1024 + 1]).expect("oversized profile");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());
    assert!(String::from_utf8_lossy(&import_output.stderr).contains("profile exceeds"));

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    let error = result.error.expect("oversized profile rejected");
    assert_eq!(error.reason_code, "profile-too-large");
}

#[cfg(unix)]
#[test]
fn collector_nonregular_input_matches_import_rejection_without_blocking() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("collector-nonregular-input");
    let fixture = import_fixture(&dir);
    let regular = dir.join("regular.jsonl");
    fs::copy(fixture_path("collector-valid.jsonl"), &regular).expect("regular file");
    symlink(&regular, &fixture.input).expect("symlink created");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    assert_eq!(
        result.error.expect("symlink input rejected").reason_code,
        "unsafe-input-path"
    );
}

#[cfg(unix)]
#[test]
fn collector_nonregular_profile_matches_import_rejection_without_blocking() {
    use std::os::unix::fs::symlink;

    let dir = tempdir("collector-nonregular-profile");
    let fixture = import_fixture(&dir);
    fs::copy(fixture_path("collector-valid.jsonl"), &fixture.input).expect("input copied");
    let regular = dir.join("regular-profile.yaml");
    fs::copy(fixture_path("collector-profile.yaml"), &regular).expect("regular profile");
    fs::remove_file(&fixture.profile).expect("remove generated profile");
    symlink(&regular, &fixture.profile).expect("symlink created");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    assert_eq!(
        result.error.expect("symlink profile rejected").reason_code,
        "unsafe-profile-path"
    );

    fs::remove_file(&fixture.profile).expect("remove symlinked profile");
    fs::create_dir(&fixture.profile).expect("directory profile created");

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(!import_output.status.success());

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(!conformance_output.status.success());
    let result = parse_result(&conformance_output);
    assert_eq!(
        result
            .error
            .expect("directory profile rejected")
            .reason_code,
        "unsafe-profile-path"
    );
}

fn assert_collector_rejection_matches_import(
    input_fixture: &str,
    profile_fixture: Option<&str>,
    expected_reason_code: &str,
    expected_line: Option<usize>,
) {
    let dir = tempdir("collector-rejection");
    let fixture = import_fixture(&dir);
    fs::copy(fixture_path(input_fixture), &fixture.input).expect("input copied");
    if let Some(profile_fixture) = profile_fixture {
        fs::copy(fixture_path(profile_fixture), &fixture.profile).expect("profile copied");
    }

    let import_output = run_import_prevalidation(&fixture.input, &fixture.profile);
    assert!(
        !import_output.status.success(),
        "case: {input_fixture}/{profile_fixture:?}"
    );
    assert!(
        RunStore::list_manifests(&fixture.ledger)
            .expect("manifest list")
            .is_empty(),
        "case: {input_fixture}/{profile_fixture:?}: rejected import created a run"
    );

    let conformance_output = run_conformance_collector(&fixture.profile, &fixture.input);
    assert!(
        !conformance_output.status.success(),
        "case: {input_fixture}/{profile_fixture:?}"
    );
    let result = parse_result(&conformance_output);
    let error = result
        .error
        .unwrap_or_else(|| panic!("case: {input_fixture}/{profile_fixture:?}: expected rejection"));
    let expected_kebab = kebab(expected_reason_code);
    assert_eq!(
        error.reason_code, expected_kebab,
        "case: {input_fixture}/{profile_fixture:?}"
    );
    assert_eq!(
        error.line, expected_line,
        "case: {input_fixture}/{profile_fixture:?}"
    );
}

/// Converts a PascalCase reason-code identifier (as written in tests, matching the Rust enum
/// variant name) into the kebab-case string the JSON wire format uses.
fn kebab(pascal: &str) -> String {
    let mut out = String::new();
    for (index, ch) in pascal.char_indices() {
        if ch.is_uppercase() && index > 0 {
            out.push('-');
        }
        out.extend(ch.to_lowercase());
    }
    out
}
