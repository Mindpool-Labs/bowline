//! Standard-Minisign signature envelopes for authority/promotion evidence.
//!
//! An envelope is a small JSON document that sits alongside a bounded evidence file (for
//! example `<authorization_path>.signature.json` next to `<authorization_path>`) and carries a
//! standard [Minisign](https://jedisct1.github.io/minisign/) signature over the *exact* bytes of
//! that evidence file. Verification never trusts anything the envelope claims about which key
//! signed it: the only keys ever used to verify a signature are the operator-configured
//! `verify_keys`. The envelope's own `key_id` field is informational only and is cross-checked
//! against a configured key id before any cryptographic verification is attempted, purely to
//! give a precise, typed rejection reason; it never selects trust on its own.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The only supported envelope schema version.
pub const SIGNATURE_ENVELOPE_VERSION: u32 = 1;
/// The only supported signature algorithm identifier.
pub const MINISIGN_ED25519_ALGORITHM: &str = "minisign-ed25519";
/// Bound on the exact payload bytes an envelope may authenticate. Matches the bounded
/// `PromotionAuthorizationV1` file this envelope schema is designed to sit alongside.
pub const MAX_ENVELOPE_PAYLOAD_BYTES: usize = 64 * 1024;
/// Bound on the serialized envelope document itself.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// A standard-Minisign signature envelope over an exact, bounded payload.
///
/// ```json
/// {
///   "envelope_version": 1,
///   "algorithm": "minisign-ed25519",
///   "key_id": "<minisign-key-id>",
///   "payload_sha256": "sha256:...",
///   "minisign_signature": "<complete .minisig text>"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureEnvelopeV1 {
    pub envelope_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub payload_sha256: String,
    pub minisign_signature: String,
}

const ENVELOPE_FIELDS: &[&str] = &[
    "envelope_version",
    "algorithm",
    "key_id",
    "payload_sha256",
    "minisign_signature",
];

impl<'de> Deserialize<'de> for SignatureEnvelopeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            EnvelopeVersion,
            Algorithm,
            KeyId,
            PayloadSha256,
            MinisignSignature,
        }

        struct EnvelopeVisitor;

        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = SignatureEnvelopeV1;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a signature envelope object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut envelope_version: Option<u32> = None;
                let mut algorithm: Option<String> = None;
                let mut key_id: Option<String> = None;
                let mut payload_sha256: Option<String> = None;
                let mut minisign_signature: Option<String> = None;
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::EnvelopeVersion => {
                            if envelope_version.is_some() {
                                return Err(de::Error::duplicate_field("envelope_version"));
                            }
                            envelope_version = Some(map.next_value()?);
                        }
                        Field::Algorithm => {
                            if algorithm.is_some() {
                                return Err(de::Error::duplicate_field("algorithm"));
                            }
                            algorithm = Some(map.next_value()?);
                        }
                        Field::KeyId => {
                            if key_id.is_some() {
                                return Err(de::Error::duplicate_field("key_id"));
                            }
                            key_id = Some(map.next_value()?);
                        }
                        Field::PayloadSha256 => {
                            if payload_sha256.is_some() {
                                return Err(de::Error::duplicate_field("payload_sha256"));
                            }
                            payload_sha256 = Some(map.next_value()?);
                        }
                        Field::MinisignSignature => {
                            if minisign_signature.is_some() {
                                return Err(de::Error::duplicate_field("minisign_signature"));
                            }
                            minisign_signature = Some(map.next_value()?);
                        }
                    }
                }
                Ok(SignatureEnvelopeV1 {
                    envelope_version: envelope_version
                        .ok_or_else(|| de::Error::missing_field("envelope_version"))?,
                    algorithm: algorithm.ok_or_else(|| de::Error::missing_field("algorithm"))?,
                    key_id: key_id.ok_or_else(|| de::Error::missing_field("key_id"))?,
                    payload_sha256: payload_sha256
                        .ok_or_else(|| de::Error::missing_field("payload_sha256"))?,
                    minisign_signature: minisign_signature
                        .ok_or_else(|| de::Error::missing_field("minisign_signature"))?,
                })
            }
        }

        deserializer.deserialize_struct("SignatureEnvelopeV1", ENVELOPE_FIELDS, EnvelopeVisitor)
    }
}

/// A configured Minisign public key, parsed from the standard `minisign.pub` two-line format
/// (`untrusted comment: minisign public key <ID>` followed by the base64-encoded key).
struct ConfiguredKey {
    key_id: String,
    public_key: minisign_verify::PublicKey,
}

fn parse_configured_key(raw: &str) -> Option<ConfiguredKey> {
    let public_key = minisign_verify::PublicKey::decode(raw).ok()?;
    let comment = public_key.untrusted_comment()?;
    let key_id = comment
        .rsplit(' ')
        .next()
        .filter(|candidate| {
            candidate.len() == 16 && candidate.chars().all(|c| c.is_ascii_hexdigit())
        })
        .map(str::to_ascii_uppercase)?;
    Some(ConfiguredKey { key_id, public_key })
}

/// Validates that a configured `verify_keys` entry is a well-formed standard minisign public
/// key with a recoverable key id. Used at configuration-validation time so malformed keys are a
/// startup-time configuration error, not a per-verification ambiguity.
pub fn validate_configured_key(raw: &str) -> Result<(), EnvelopeError> {
    parse_configured_key(raw)
        .map(|_| ())
        .ok_or(EnvelopeError::MalformedConfiguredKey)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("envelope payload exceeds the {MAX_ENVELOPE_PAYLOAD_BYTES}-byte bound")]
    PayloadTooLarge,
    #[error("envelope document exceeds the {MAX_ENVELOPE_BYTES}-byte bound")]
    EnvelopeTooLarge,
    #[error("envelope is not valid JSON: {0}")]
    Malformed(String),
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    #[error("payload digest does not match the envelope")]
    DigestMismatch,
    #[error("minisign signature is malformed")]
    MalformedSignature,
    #[error("a configured verify key is not a standard minisign public key")]
    MalformedConfiguredKey,
    #[error("no configured key id matches the envelope")]
    UnknownKey,
    #[error("minisign signature verification failed")]
    SignatureInvalid,
}

/// Verifies a standard-Minisign signature envelope over `payload_bytes`.
///
/// Verifies, in order: the payload size bound, the envelope size bound, the exact envelope
/// schema (rejecting unknown, duplicate, or missing fields), the envelope version and
/// algorithm, the recomputed SHA-256 digest of the exact payload bytes, and a standard Minisign
/// signature produced by one of the `allowed_keys`. The envelope's own `key_id` is used only to
/// select which *configured* key to attempt; no envelope-supplied key material is ever trusted.
pub fn verify_envelope(
    payload_bytes: &[u8],
    envelope_bytes: &[u8],
    allowed_keys: &[String],
) -> Result<(), EnvelopeError> {
    if payload_bytes.len() > MAX_ENVELOPE_PAYLOAD_BYTES {
        return Err(EnvelopeError::PayloadTooLarge);
    }
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(EnvelopeError::EnvelopeTooLarge);
    }
    let envelope: SignatureEnvelopeV1 = serde_json::from_slice(envelope_bytes)
        .map_err(|error| EnvelopeError::Malformed(error.to_string()))?;
    if envelope.envelope_version != SIGNATURE_ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if envelope.algorithm != MINISIGN_ED25519_ALGORITHM {
        return Err(EnvelopeError::UnsupportedAlgorithm);
    }
    let expected_digest = format!("sha256:{:x}", Sha256::digest(payload_bytes));
    if envelope.payload_sha256 != expected_digest {
        return Err(EnvelopeError::DigestMismatch);
    }
    let signature = minisign_verify::Signature::decode(&envelope.minisign_signature)
        .map_err(|_| EnvelopeError::MalformedSignature)?;
    let matched_key = allowed_keys
        .iter()
        .filter_map(|raw| parse_configured_key(raw))
        .find(|configured| configured.key_id.eq_ignore_ascii_case(&envelope.key_id));
    let Some(configured) = matched_key else {
        return Err(EnvelopeError::UnknownKey);
    };
    configured
        .public_key
        .verify(payload_bytes, &signature, false)
        .map_err(|_| EnvelopeError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"test payload bytes\n";

    fn digest_of(payload: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(payload))
    }

    fn envelope_json(key_id: &str, payload_sha256: &str, signature: &str) -> String {
        format!(
            "{{\"envelope_version\":1,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"{key_id}\",\"payload_sha256\":\"{payload_sha256}\",\"minisign_signature\":{signature}}}"
        )
    }

    #[test]
    fn rejects_unknown_field() {
        let json = br#"{"envelope_version":1,"algorithm":"minisign-ed25519","key_id":"AA","payload_sha256":"sha256:x","minisign_signature":"x","extra":1}"#;
        let error = verify_envelope(PAYLOAD, json, &[]).unwrap_err();
        assert!(matches!(error, EnvelopeError::Malformed(_)));
    }

    #[test]
    fn rejects_duplicate_field() {
        let json = br#"{"envelope_version":1,"envelope_version":1,"algorithm":"minisign-ed25519","key_id":"AA","payload_sha256":"sha256:x","minisign_signature":"x"}"#;
        let error = verify_envelope(PAYLOAD, json, &[]).unwrap_err();
        assert!(matches!(error, EnvelopeError::Malformed(_)));
    }

    #[test]
    fn rejects_missing_field() {
        let json = br#"{"envelope_version":1,"algorithm":"minisign-ed25519","key_id":"AA","payload_sha256":"sha256:x"}"#;
        let error = verify_envelope(PAYLOAD, json, &[]).unwrap_err();
        assert!(matches!(error, EnvelopeError::Malformed(_)));
    }

    #[test]
    fn rejects_oversized_payload() {
        let oversized = vec![0u8; MAX_ENVELOPE_PAYLOAD_BYTES + 1];
        let json = envelope_json("AA", &digest_of(&oversized), "\"x\"");
        let error = verify_envelope(&oversized, json.as_bytes(), &[]).unwrap_err();
        assert_eq!(error, EnvelopeError::PayloadTooLarge);
    }

    #[test]
    fn rejects_oversized_envelope() {
        let mut oversized_signature = "\"".to_string();
        oversized_signature.push_str(&"a".repeat(MAX_ENVELOPE_BYTES));
        oversized_signature.push('"');
        let json = envelope_json("AA", &digest_of(PAYLOAD), &oversized_signature);
        let error = verify_envelope(PAYLOAD, json.as_bytes(), &[]).unwrap_err();
        assert_eq!(error, EnvelopeError::EnvelopeTooLarge);
    }

    #[test]
    fn rejects_unsupported_version() {
        let json = format!(
            "{{\"envelope_version\":2,\"algorithm\":\"minisign-ed25519\",\"key_id\":\"AA\",\"payload_sha256\":\"{}\",\"minisign_signature\":\"x\"}}",
            digest_of(PAYLOAD)
        );
        let error = verify_envelope(PAYLOAD, json.as_bytes(), &[]).unwrap_err();
        assert_eq!(error, EnvelopeError::UnsupportedVersion);
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let json = format!(
            "{{\"envelope_version\":1,\"algorithm\":\"minisign-legacy\",\"key_id\":\"AA\",\"payload_sha256\":\"{}\",\"minisign_signature\":\"x\"}}",
            digest_of(PAYLOAD)
        );
        let error = verify_envelope(PAYLOAD, json.as_bytes(), &[]).unwrap_err();
        assert_eq!(error, EnvelopeError::UnsupportedAlgorithm);
    }

    #[test]
    fn rejects_digest_mismatch() {
        let json = envelope_json(
            "AA",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "\"x\"",
        );
        let error = verify_envelope(PAYLOAD, json.as_bytes(), &[]).unwrap_err();
        assert_eq!(error, EnvelopeError::DigestMismatch);
    }

    #[test]
    fn rejects_malformed_signature_text() {
        let json = envelope_json("AA", &digest_of(PAYLOAD), "\"not-a-real-signature\"");
        let error = verify_envelope(PAYLOAD, json.as_bytes(), &[]).unwrap_err();
        assert_eq!(error, EnvelopeError::MalformedSignature);
    }

    #[test]
    fn rejects_malformed_configured_key() {
        assert_eq!(
            validate_configured_key("not a key"),
            Err(EnvelopeError::MalformedConfiguredKey)
        );
    }
}
