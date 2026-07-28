//! External-approval artifact binding for promotion authorizations.
//!
//! Bowline never interprets who approved a promotion, what role they held, or what process
//! produced their sign-off. An `ApprovalArtifactV1` is machine-checkable evidence that some
//! externally produced approval workflow bound itself to one exact, already-sealed promotion
//! authorization before Bowline will honor it. The artifact is expected to sit alongside a
//! sealed `crate::enforcement::PromotionAuthorizationV1` at `<authorization_path>.approval.json`;
//! its signature envelope (see `crate::envelope`) is
//! `<authorization_path>.approval.json.signature.json`.
//!
//! This module performs exactly three checks, in this order: the artifact's signature envelope
//! verifies against a configured key (see `crate::envelope::verify_envelope`); the artifact names
//! the exact evidence digests it is bound to; and the artifact is fresh. Everything else about
//! the artifact — who `approver` names, what it means, how it was produced — is opaque and
//! carried through unread.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::envelope::verify_envelope;

/// The only supported approval artifact schema version.
pub const APPROVAL_ARTIFACT_VERSION: u32 = 1;

/// Named digests the approval artifact attests it was produced against. Every named digest must
/// exactly match the corresponding digest already produced by cryptographically verified
/// evidence; this is the only binding Bowline performs. It never interprets what the approver
/// reviewed or how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSourceEvidenceV1 {
    pub economics_source_digest: String,
    pub quality_source_digest: String,
}

/// A strict, externally produced approval artifact bound to one sealed promotion authorization.
///
/// ```json
/// {
///   "artifact_version": 1,
///   "descriptor_sha256": "sha256:...",
///   "source_evidence": {
///     "economics_source_digest": "sha256:...",
///     "quality_source_digest": "sha256:..."
///   },
///   "approver": "<opaque, uninterpreted identifier>",
///   "issued_at_ms": 0,
///   "expires_at_ms": 0
/// }
/// ```
///
/// `approver` is carried through unread: Bowline never parses, compares, or acts on its contents
/// beyond storing it as an opaque, byte-bounded string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalArtifactV1 {
    pub artifact_version: u32,
    pub descriptor_sha256: String,
    pub source_evidence: ApprovalSourceEvidenceV1,
    pub approver: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// The exact promotion evidence digests an approval artifact must name, taken from an already
/// cryptographically verified `crate::enforcement::ValidatedPromotionDocuments`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBindingExpectation {
    pub descriptor_sha256: String,
    pub economics_source_digest: String,
    pub quality_source_digest: String,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("approval artifact signature verification failed")]
    SignatureInvalid,
    #[error("approval artifact does not name the exact evidence it is bound to")]
    Unbound,
    #[error("approval artifact is expired or outside its permitted freshness window")]
    Expired,
}

/// Checks that `artifact` names the exact evidence digests in `expected`. This is the only
/// binding Bowline performs; it never inspects `approver`.
pub fn validate_binding(
    artifact: &ApprovalArtifactV1,
    expected: &ApprovalBindingExpectation,
) -> Result<(), ApprovalError> {
    if artifact.artifact_version != APPROVAL_ARTIFACT_VERSION
        || artifact.descriptor_sha256 != expected.descriptor_sha256
        || artifact.source_evidence.economics_source_digest != expected.economics_source_digest
        || artifact.source_evidence.quality_source_digest != expected.quality_source_digest
    {
        return Err(ApprovalError::Unbound);
    }
    Ok(())
}

/// Checks that `artifact` is fresh at `now_ms` under a configured `max_age_seconds`.
///
/// All three of the following must hold: `issued_at_ms <= now_ms <= expires_at_ms`; `now_ms -
/// issued_at_ms <= max_age_seconds` (converted to milliseconds); and `expires_at_ms -
/// issued_at_ms <= max_age_seconds` (converted to milliseconds) — an approval cannot claim a
/// validity window longer than the configured maximum age, regardless of when it is checked.
pub fn is_fresh(artifact: &ApprovalArtifactV1, max_age_seconds: u64, now_ms: u64) -> bool {
    let max_age_ms = max_age_seconds.saturating_mul(1_000);
    artifact.issued_at_ms <= now_ms
        && now_ms <= artifact.expires_at_ms
        && now_ms.saturating_sub(artifact.issued_at_ms) <= max_age_ms
        && artifact.expires_at_ms.saturating_sub(artifact.issued_at_ms) <= max_age_ms
}

/// Verifies a signature envelope over an exact approval artifact's bytes, then parses, binds,
/// and freshness-checks it, in that order. Bytes are never re-read: `payload_bytes` is parsed
/// directly, once, after (and only after) it has verified against `envelope_bytes`.
///
/// Precedence: a signature failure is reported before any parsing is attempted; parsing failure
/// or a binding mismatch is reported as `Unbound` before freshness is ever considered; freshness
/// is only checked once the artifact both parses and is exactly bound.
pub fn verify_approval_artifact(
    payload_bytes: &[u8],
    envelope_bytes: &[u8],
    allowed_keys: &[String],
    expected: &ApprovalBindingExpectation,
    max_age_seconds: u64,
    now_ms: u64,
) -> Result<ApprovalArtifactV1, ApprovalError> {
    verify_envelope(payload_bytes, envelope_bytes, allowed_keys)
        .map_err(|_| ApprovalError::SignatureInvalid)?;
    let artifact: ApprovalArtifactV1 =
        serde_json::from_slice(payload_bytes).map_err(|_| ApprovalError::Unbound)?;
    validate_binding(&artifact, expected)?;
    if !is_fresh(&artifact, max_age_seconds, now_ms) {
        return Err(ApprovalError::Expired);
    }
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectation() -> ApprovalBindingExpectation {
        ApprovalBindingExpectation {
            descriptor_sha256: "sha256:aaaa".into(),
            economics_source_digest: "sha256:bbbb".into(),
            quality_source_digest: "sha256:cccc".into(),
        }
    }

    fn bound_artifact() -> ApprovalArtifactV1 {
        ApprovalArtifactV1 {
            artifact_version: APPROVAL_ARTIFACT_VERSION,
            descriptor_sha256: "sha256:aaaa".into(),
            source_evidence: ApprovalSourceEvidenceV1 {
                economics_source_digest: "sha256:bbbb".into(),
                quality_source_digest: "sha256:cccc".into(),
            },
            approver: "external-workflow".into(),
            issued_at_ms: 1_000,
            expires_at_ms: 4_600,
        }
    }

    #[test]
    fn exact_binding_matches() {
        assert_eq!(validate_binding(&bound_artifact(), &expectation()), Ok(()));
    }

    #[test]
    fn descriptor_mismatch_is_unbound() {
        let mut artifact = bound_artifact();
        artifact.descriptor_sha256 = "sha256:zzzz".into();
        assert_eq!(
            validate_binding(&artifact, &expectation()),
            Err(ApprovalError::Unbound)
        );
    }

    #[test]
    fn economics_digest_mismatch_is_unbound() {
        let mut artifact = bound_artifact();
        artifact.source_evidence.economics_source_digest = "sha256:zzzz".into();
        assert_eq!(
            validate_binding(&artifact, &expectation()),
            Err(ApprovalError::Unbound)
        );
    }

    #[test]
    fn quality_digest_mismatch_is_unbound() {
        let mut artifact = bound_artifact();
        artifact.source_evidence.quality_source_digest = "sha256:zzzz".into();
        assert_eq!(
            validate_binding(&artifact, &expectation()),
            Err(ApprovalError::Unbound)
        );
    }

    #[test]
    fn unsupported_artifact_version_is_unbound() {
        let mut artifact = bound_artifact();
        artifact.artifact_version = 2;
        assert_eq!(
            validate_binding(&artifact, &expectation()),
            Err(ApprovalError::Unbound)
        );
    }

    #[test]
    fn fresh_within_window_and_age() {
        // issued 1_000, expires 4_600 (window 3_600ms), max age 3_600s, now 2_000.
        assert!(is_fresh(&bound_artifact(), 3_600, 2_000));
    }

    #[test]
    fn future_issue_time_is_not_fresh() {
        let artifact = bound_artifact();
        assert!(!is_fresh(&artifact, 3_600, artifact.issued_at_ms - 1));
    }

    #[test]
    fn now_past_expiry_is_not_fresh() {
        let artifact = bound_artifact();
        assert!(!is_fresh(&artifact, 3_600, artifact.expires_at_ms + 1));
    }

    #[test]
    fn stale_age_past_max_age_is_not_fresh() {
        let mut artifact = bound_artifact();
        // Widen the claimed window so only the absolute-age check can fail.
        artifact.expires_at_ms = artifact.issued_at_ms + 3_600_000_000;
        let now_ms = artifact.issued_at_ms + 3_601_000; // 3,601s after issuance.
        assert!(!is_fresh(&artifact, 3_600, now_ms));
    }

    #[test]
    fn overlong_validity_window_is_not_fresh() {
        let mut artifact = bound_artifact();
        artifact.expires_at_ms = artifact.issued_at_ms + 3_601_000; // 3,601s window.
        assert!(!is_fresh(&artifact, 3_600, artifact.issued_at_ms));
    }

    #[test]
    fn boundary_ages_are_exactly_fresh() {
        let mut artifact = bound_artifact();
        artifact.expires_at_ms = artifact.issued_at_ms + 3_600_000; // exactly 3,600s.
        assert!(is_fresh(
            &artifact,
            3_600,
            artifact.issued_at_ms + 3_600_000
        ));
    }

    #[test]
    fn rejects_duplicate_field() {
        let json = r#"{"artifact_version":1,"artifact_version":1,"descriptor_sha256":"sha256:aaaa","source_evidence":{"economics_source_digest":"sha256:bbbb","quality_source_digest":"sha256:cccc"},"approver":"x","issued_at_ms":1000,"expires_at_ms":4600}"#;
        assert!(serde_json::from_str::<ApprovalArtifactV1>(json).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let json = r#"{"artifact_version":1,"descriptor_sha256":"sha256:aaaa","source_evidence":{"economics_source_digest":"sha256:bbbb","quality_source_digest":"sha256:cccc"},"approver":"x","issued_at_ms":1000,"expires_at_ms":4600,"extra":1}"#;
        assert!(serde_json::from_str::<ApprovalArtifactV1>(json).is_err());
    }

    #[test]
    fn rejects_missing_named_digest() {
        let json = r#"{"artifact_version":1,"descriptor_sha256":"sha256:aaaa","source_evidence":{"economics_source_digest":"sha256:bbbb"},"approver":"x","issued_at_ms":1000,"expires_at_ms":4600}"#;
        assert!(serde_json::from_str::<ApprovalArtifactV1>(json).is_err());
    }

    #[test]
    fn rejects_extra_source_evidence_field() {
        let json = r#"{"artifact_version":1,"descriptor_sha256":"sha256:aaaa","source_evidence":{"economics_source_digest":"sha256:bbbb","quality_source_digest":"sha256:cccc","extra":"sha256:dddd"},"approver":"x","issued_at_ms":1000,"expires_at_ms":4600}"#;
        assert!(serde_json::from_str::<ApprovalArtifactV1>(json).is_err());
    }

    #[test]
    fn unconfigured_allow_list_never_verifies_anything() {
        let error =
            verify_approval_artifact(b"{}", b"{}", &[], &expectation(), 3_600, 2_000).unwrap_err();
        assert_eq!(error, ApprovalError::SignatureInvalid);
    }
}
