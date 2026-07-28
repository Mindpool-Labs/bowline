//! Typed passive-event contract result shared by the real importer's prevalidation and the
//! `bowline conformance` runner. This module adds a stable, versioned classification on top of the
//! existing [`crate::passive::PassiveError`] and [`crate::profile::ProfileError`] display text; it
//! does not change that text or any import behavior.

use serde::Serialize;

use crate::{passive::PassiveError, profile::ProfileError};

/// Fixed for `result_version: 1`. A new violation class requires a new result version; existing
/// codes must not change meaning once published.
pub const PASSIVE_CONTRACT_RESULT_VERSION: u32 = 1;

/// Stable v1 reason-code vocabulary for passive-event contract violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassiveContractReasonCode {
    /// The input path could not be safely opened as a regular, non-symlink file.
    UnsafeInputPath,
    /// The profile path could not be safely opened as a regular, non-symlink file.
    UnsafeProfilePath,
    /// The input bytes are not valid UTF-8.
    InvalidUtf8Input,
    /// The profile bytes are not valid UTF-8.
    InvalidUtf8Profile,
    /// The input exceeds the compiled maximum byte size.
    InputTooLarge,
    /// The profile exceeds the compiled maximum byte size.
    ProfileTooLarge,
    /// A single input line exceeds the compiled maximum byte size.
    LineTooLarge,
    /// The input contains more events than the compiled maximum.
    EventCountExceeded,
    /// The profile itself is invalid: bad YAML, unsupported version, unknown or duplicate
    /// target, unsupported timestamp unit, or an unusable constant.
    MalformedProfile,
    /// A profile field pointer is unsafe: it targets a forbidden (prompt/content/credential)
    /// segment, or uses a malformed JSON Pointer escape.
    ForbiddenProfilePointer,
    /// A target required by the canonical schema has no mapping in the profile, or is absent or
    /// null for a specific event.
    MissingRequiredTarget,
    /// Two events in the same input share an `event_id`.
    DuplicateEventId,
    /// An individual event line failed canonical schema validation: malformed JSON, an unknown
    /// or wrong-typed field, or a bounds/format rule.
    InvalidEvent,
}

/// A single rejection: the first violation encountered, by line order.
#[derive(Debug, Clone, Serialize)]
pub struct PassiveContractError {
    pub reason_code: PassiveContractReasonCode,
    /// 1-based source line, absent for whole-file (not per-event) violations.
    pub line: Option<usize>,
    pub message: String,
}

/// A versioned, whole-file conformance result: either the accepted event count, or the first
/// error encountered.
#[derive(Debug, Clone, Serialize)]
pub struct PassiveContractResult {
    pub result_version: u32,
    pub accepted: Option<u64>,
    pub error: Option<PassiveContractError>,
}

impl PassiveContractResult {
    pub fn accepted(count: u64) -> Self {
        Self {
            result_version: PASSIVE_CONTRACT_RESULT_VERSION,
            accepted: Some(count),
            error: None,
        }
    }

    pub fn rejected(error: PassiveContractError) -> Self {
        Self {
            result_version: PASSIVE_CONTRACT_RESULT_VERSION,
            accepted: None,
            error: Some(error),
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.error.is_none()
    }
}

impl From<&PassiveError> for PassiveContractError {
    fn from(error: &PassiveError) -> Self {
        let (line, reason_code) = match error {
            PassiveError::Line { line, reason, .. } => (Some(*line), classify_line_reason(reason)),
            PassiveError::Input { reason, .. } => (None, classify_input_reason(reason)),
        };
        Self {
            reason_code,
            line,
            message: error.to_string(),
        }
    }
}

impl From<&ProfileError> for PassiveContractError {
    fn from(error: &ProfileError) -> Self {
        let (line, reason_code) = match error {
            ProfileError::Profile { reason, .. } => (None, classify_profile_reason(reason)),
            ProfileError::Source { line, reason, .. } => {
                (Some(*line), classify_line_reason(reason))
            }
            ProfileError::Input { reason, .. } => (None, classify_input_reason(reason)),
        };
        Self {
            reason_code,
            line,
            message: error.to_string(),
        }
    }
}

fn classify_input_reason(reason: &str) -> PassiveContractReasonCode {
    if reason.contains("exceeds") {
        PassiveContractReasonCode::InputTooLarge
    } else {
        PassiveContractReasonCode::InvalidEvent
    }
}

fn classify_line_reason(reason: &str) -> PassiveContractReasonCode {
    if reason.contains("event count exceeds") {
        PassiveContractReasonCode::EventCountExceeded
    } else if reason.contains("line exceeds") {
        PassiveContractReasonCode::LineTooLarge
    } else if reason.contains("duplicate event_id") {
        PassiveContractReasonCode::DuplicateEventId
    } else if reason.contains("required target") && reason.contains("absent or null") {
        PassiveContractReasonCode::MissingRequiredTarget
    } else {
        PassiveContractReasonCode::InvalidEvent
    }
}

fn classify_profile_reason(reason: &str) -> PassiveContractReasonCode {
    if reason.contains("profile exceeds compiled size limit") {
        PassiveContractReasonCode::ProfileTooLarge
    } else if reason.contains("forbidden source pointer segment")
        || reason.contains("invalid JSON pointer escape")
    {
        PassiveContractReasonCode::ForbiddenProfilePointer
    } else if reason.contains("missing required target") {
        PassiveContractReasonCode::MissingRequiredTarget
    } else {
        PassiveContractReasonCode::MalformedProfile
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        passive::parse_canonical_jsonl_named,
        profile::{transform_profile_jsonl, TransformProfile},
    };

    use super::*;

    #[test]
    fn canonical_violations_classify_to_the_documented_reason_codes() {
        let event = |replacement: (&str, &str)| {
            let base = r#"{"schema_version":1,"event_id":"evt-1","observed_at_ms":1783785600123,"method":"POST","route":"/v1/chat/completions","status":200,"streamed":false,"latency_ms":25,"dimensions":{}}"#;
            base.replace(replacement.0, replacement.1)
        };

        let unknown_field = event(("\"status\":200", "\"status\":200,\"prompt\":\"x\""));
        let error = parse_canonical_jsonl_named(&unknown_field, "in.jsonl").unwrap_err();
        assert_eq!(
            PassiveContractError::from(&error).reason_code,
            PassiveContractReasonCode::InvalidEvent
        );

        let oversized_line = format!("{}\n{}", event(("evt-1", "evt-first")), "x".repeat(20_000));
        let error = parse_canonical_jsonl_named(&oversized_line, "in.jsonl").unwrap_err();
        let contract = PassiveContractError::from(&error);
        assert_eq!(
            contract.reason_code,
            PassiveContractReasonCode::LineTooLarge
        );
        assert_eq!(contract.line, Some(2));

        let duplicate = format!("{}\n{}", event(("x", "x")), event(("x", "x")));
        let error = parse_canonical_jsonl_named(&duplicate, "in.jsonl").unwrap_err();
        let contract = PassiveContractError::from(&error);
        assert_eq!(
            contract.reason_code,
            PassiveContractReasonCode::DuplicateEventId
        );
        assert_eq!(contract.line, Some(2));

        let oversized_input = "x".repeat(17 * 1024 * 1024);
        let error = parse_canonical_jsonl_named(&oversized_input, "in.jsonl").unwrap_err();
        assert_eq!(
            PassiveContractError::from(&error).reason_code,
            PassiveContractReasonCode::InputTooLarge
        );
    }

    #[test]
    fn profile_violations_classify_to_the_documented_reason_codes() {
        let profile_source = |replacement: (&str, &str)| {
            let base = "version: 1\nkind: test-jsonl-v1\nsource_contract: test-v1\ntimestamp_unit: milliseconds\nfields:\n  event_id: /request_id\n  observed_at_ms: /started_at_ms\n  route: /route\n  status: /status_code\n  latency_ms: /latency_ms\nconstants:\n  method: POST\n  streamed: false\n";
            base.replace(replacement.0, replacement.1)
        };

        let malformed = profile_source(("version: 1", "version: 2"));
        let error = TransformProfile::from_yaml(&malformed, "profile.yaml").unwrap_err();
        assert_eq!(
            PassiveContractError::from(&error).reason_code,
            PassiveContractReasonCode::MalformedProfile
        );

        let forbidden = profile_source(("  route: /route\n", "  route: /headers/authorization\n"));
        let error = TransformProfile::from_yaml(&forbidden, "profile.yaml").unwrap_err();
        assert_eq!(
            PassiveContractError::from(&error).reason_code,
            PassiveContractReasonCode::ForbiddenProfilePointer
        );

        let missing = profile_source(("  latency_ms: /latency_ms\n", ""));
        let error = TransformProfile::from_yaml(&missing, "profile.yaml").unwrap_err();
        assert_eq!(
            PassiveContractError::from(&error).reason_code,
            PassiveContractReasonCode::MissingRequiredTarget
        );

        let profile = TransformProfile::from_yaml(&profile_source(("x", "x")), "profile.yaml")
            .expect("profile loads");
        let raw_missing_latency = r#"{"request_id":"req-1","started_at_ms":1783785600123,"route":"/v1/responses","status_code":200}"#;
        let source = format!(
            "{}\n{raw_missing_latency}",
            r#"{"request_id":"req-first","started_at_ms":1783785600123,"route":"/v1/responses","status_code":200,"latency_ms":25}"#
        );
        let error = transform_profile_jsonl(&profile, &source, "in.jsonl").unwrap_err();
        let contract = PassiveContractError::from(&error);
        assert_eq!(
            contract.reason_code,
            PassiveContractReasonCode::MissingRequiredTarget
        );
        assert_eq!(contract.line, Some(2));
    }
}
