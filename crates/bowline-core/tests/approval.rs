//! Integration tests for external-approval artifact binding, using real Standard-Minisign
//! fixtures signed with throwaway keys (see `tests/fixtures/approval/`).

use bowline_core::approval::{verify_approval_artifact, ApprovalBindingExpectation, ApprovalError};

const DESCRIPTOR: &str = "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const ECONOMICS: &str = "sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
const QUALITY: &str = "sha256:c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

fn expected() -> ApprovalBindingExpectation {
    ApprovalBindingExpectation {
        descriptor_sha256: DESCRIPTOR.into(),
        economics_source_digest: ECONOMICS.into(),
        quality_source_digest: QUALITY.into(),
    }
}

fn fixture(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approval")
            .join(dir)
            .join(name),
    )
    .unwrap_or_else(|error| panic!("reading fixture {dir}/{name}: {error}"))
}

fn allowed_keys(dir: &str) -> Vec<String> {
    vec![String::from_utf8(fixture(dir, "public-key.txt")).expect("utf8 public key fixture")]
}

#[test]
fn valid_artifact_verifies_binds_and_is_fresh() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("valid", "envelope.json");
    let keys = allowed_keys("valid");
    // issued_at_ms 1_700_000_000_000, expires_at_ms 1_700_003_600_000 (3,600s window).
    let artifact = verify_approval_artifact(
        &payload,
        &envelope,
        &keys,
        &expected(),
        3_600,
        1_700_001_000_000,
    )
    .expect("valid fixture must verify, bind, and be fresh");
    assert_eq!(artifact.descriptor_sha256, DESCRIPTOR);
    assert_eq!(artifact.approver, "external-approval-workflow");
}

#[test]
fn bad_signature_is_rejected_before_anything_else() {
    let payload = fixture("bad-signature", "payload.json");
    let envelope = fixture("bad-signature", "envelope.json");
    // The allow-list only contains the *legitimate* fixture key; this artifact was signed by an
    // untrusted throwaway key, mirroring an operator whose configured verify_keys do not include
    // the key that actually produced this signature.
    let keys = allowed_keys("valid");
    let error = verify_approval_artifact(
        &payload,
        &envelope,
        &keys,
        &expected(),
        3_600,
        1_700_001_000_000,
    )
    .unwrap_err();
    assert_eq!(error, ApprovalError::SignatureInvalid);
}

#[test]
fn validly_signed_but_unbound_artifact_is_rejected() {
    let payload = fixture("unbound", "payload.json");
    let envelope = fixture("unbound", "envelope.json");
    let keys = allowed_keys("unbound");
    // Signature verifies, but the fixture's quality_source_digest deliberately does not match
    // `expected()`.
    let error = verify_approval_artifact(
        &payload,
        &envelope,
        &keys,
        &expected(),
        3_600,
        1_700_001_000_000,
    )
    .unwrap_err();
    assert_eq!(error, ApprovalError::Unbound);
}

#[test]
fn validly_signed_and_bound_but_expired_artifact_is_rejected() {
    let payload = fixture("expired", "payload.json");
    let envelope = fixture("expired", "envelope.json");
    let keys = allowed_keys("expired");
    // Signature verifies and binding matches, but `now_ms` here is chosen far past both the
    // fixture's claimed expiry and its permitted maximum age.
    let error = verify_approval_artifact(
        &payload,
        &envelope,
        &keys,
        &expected(),
        3_600,
        1_700_001_000_000,
    )
    .unwrap_err();
    assert_eq!(error, ApprovalError::Expired);
}

#[test]
fn valid_signature_over_malformed_artifact_bytes_is_unbound_not_a_panic() {
    // A signer can only attest to bytes; it cannot guarantee those bytes are a well-formed
    // `ApprovalArtifactV1`. This fixture is validly signed by an allowed key, but its payload is
    // missing the required `quality_source_digest` field. It must be rejected as `Unbound`,
    // exactly like a structurally sound but mismatched artifact, never a startup failure or a
    // panic.
    let payload = fixture("malformed-payload", "payload.json");
    let envelope = fixture("malformed-payload", "envelope.json");
    let keys = allowed_keys("malformed-payload");
    let artifact = verify_approval_artifact(
        &payload,
        &envelope,
        &keys,
        &expected(),
        3_600,
        1_700_001_000_000,
    );
    assert_eq!(artifact.unwrap_err(), ApprovalError::Unbound);
}

#[test]
fn unconfigured_allow_list_never_verifies_anything() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("valid", "envelope.json");
    let error = verify_approval_artifact(
        &payload,
        &envelope,
        &[],
        &expected(),
        3_600,
        1_700_001_000_000,
    )
    .unwrap_err();
    assert_eq!(error, ApprovalError::SignatureInvalid);
}
