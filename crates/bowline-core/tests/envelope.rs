//! Integration tests for standard-Minisign signature envelopes over bounded evidence, using
//! real test vectors signed with a throwaway key (see `tests/fixtures/envelope/`).

use bowline_core::envelope::{verify_envelope, EnvelopeError, MAX_ENVELOPE_PAYLOAD_BYTES};

fn fixture(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/envelope")
            .join(dir)
            .join(name),
    )
    .unwrap_or_else(|error| panic!("reading fixture {dir}/{name}: {error}"))
}

fn allowed_keys(dir: &str) -> Vec<String> {
    vec![String::from_utf8(fixture(dir, "public-key.txt")).expect("utf8 public key fixture")]
}

#[test]
fn valid_envelope_verifies_against_the_exact_payload() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("valid", "envelope.json");
    let keys = allowed_keys("valid");
    verify_envelope(&payload, &envelope, &keys).expect("valid fixture must verify");
}

#[test]
fn tampered_payload_fails_digest_check() {
    let payload = fixture("tampered", "payload.json");
    let envelope = fixture("tampered", "envelope.json");
    let keys = allowed_keys("tampered");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert_eq!(error, EnvelopeError::DigestMismatch);
}

#[test]
fn wrong_configured_key_is_rejected() {
    let payload = fixture("wrong-key", "payload.json");
    let envelope = fixture("wrong-key", "envelope.json");
    // The allow-list only contains the *other* (non-signing) key, mirroring an operator whose
    // configured verify_keys do not include the key that actually produced this signature.
    let keys = allowed_keys("wrong-key");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert_eq!(error, EnvelopeError::UnknownKey);
}

#[test]
fn forged_key_id_attribution_is_rejected() {
    // The envelope's `key_id` field claims the configured key signed this, but the actual
    // `minisign_signature` bytes were produced by a different secret key. `UnknownKey` would
    // never be returned here (the claimed id matches a configured key), so this exercises the
    // cryptographic verification failure path distinctly from `wrong_configured_key_is_rejected`,
    // which never gets past the key-id lookup.
    let payload = fixture("forged-key-id", "payload.json");
    let envelope = fixture("forged-key-id", "envelope.json");
    let keys = allowed_keys("forged-key-id");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert_eq!(error, EnvelopeError::SignatureInvalid);
}

#[test]
fn duplicate_field_envelope_is_rejected() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("malformed", "duplicate-field.json");
    let keys = allowed_keys("valid");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert!(matches!(error, EnvelopeError::Malformed(_)), "{error:?}");
}

#[test]
fn unknown_field_envelope_is_rejected() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("malformed", "unknown-field.json");
    let keys = allowed_keys("valid");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert!(matches!(error, EnvelopeError::Malformed(_)), "{error:?}");
}

#[test]
fn missing_field_envelope_is_rejected() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("malformed", "missing-field.json");
    let keys = allowed_keys("valid");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert!(matches!(error, EnvelopeError::Malformed(_)), "{error:?}");
}

#[test]
fn non_json_envelope_is_rejected() {
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("malformed", "not-json.json");
    let keys = allowed_keys("valid");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert!(matches!(error, EnvelopeError::Malformed(_)), "{error:?}");
}

#[test]
fn payload_over_the_64_kib_bound_is_rejected_even_with_a_valid_envelope() {
    let mut payload = fixture("valid", "payload.json");
    payload.resize(MAX_ENVELOPE_PAYLOAD_BYTES + 1, b' ');
    let envelope = fixture("valid", "envelope.json");
    let keys = allowed_keys("valid");
    let error = verify_envelope(&payload, &envelope, &keys).unwrap_err();
    assert_eq!(error, EnvelopeError::PayloadTooLarge);
}

#[test]
fn unconfigured_allow_list_never_verifies_anything() {
    // With no allowed keys at all, even a structurally perfect, correctly-signed envelope must
    // never verify: no envelope-supplied key is ever trusted.
    let payload = fixture("valid", "payload.json");
    let envelope = fixture("valid", "envelope.json");
    let error = verify_envelope(&payload, &envelope, &[]).unwrap_err();
    assert_eq!(error, EnvelopeError::UnknownKey);
}
