use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::supply::Registry;

const MAX_REFERENCE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionRef {
    pub namespace: String,
    pub value: String,
}

impl AttributionRef {
    pub fn validate(&self) -> Result<(), AttributionError> {
        validate_reference_part("namespace", &self.namespace)?;
        validate_reference_part("value", &self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionInput {
    Absent,
    Single(AttributionRef),
    Ambiguous,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttributionSource {
    #[default]
    LegacyConfigured,
    InlineResponseHeader,
    PassiveEvent,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttributionStatus {
    #[default]
    StaticConfigured,
    Attributed,
    Missing,
    UnknownReference,
    Ambiguous,
    ModelMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionRule {
    pub namespace: String,
    pub value: String,
    pub supply_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionResult {
    pub status: AttributionStatus,
    pub source: AttributionSource,
    pub reference: Option<AttributionRef>,
    pub supply_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttributionResolver {
    rules: BTreeMap<(String, String), String>,
    legacy_actual_supply_id: Option<String>,
    normalized_digest: String,
}

impl AttributionResolver {
    pub fn new(
        rules: Vec<AttributionRule>,
        legacy_actual_supply_id: Option<String>,
        registry: &Registry,
    ) -> Result<Self, AttributionError> {
        let mut keys = BTreeSet::new();
        let mut normalized = Vec::with_capacity(rules.len());
        let mut by_key = BTreeMap::new();
        for rule in rules {
            AttributionRef {
                namespace: rule.namespace.clone(),
                value: rule.value.clone(),
            }
            .validate()?;
            if rule.supply_id.trim().is_empty() {
                return Err(AttributionError::EmptySupplyId);
            }
            if registry.by_id(&rule.supply_id).is_none() {
                return Err(AttributionError::UnknownSupply(rule.supply_id));
            }
            let key = (rule.namespace.clone(), rule.value.clone());
            if !keys.insert(key.clone()) {
                return Err(AttributionError::DuplicateReference {
                    namespace: rule.namespace,
                    value: rule.value,
                });
            }
            by_key.insert(key, rule.supply_id.clone());
            normalized.push(rule);
        }
        if let Some(legacy) = legacy_actual_supply_id.as_deref() {
            if legacy.trim().is_empty() {
                return Err(AttributionError::EmptySupplyId);
            }
            if registry.by_id(legacy).is_none() {
                return Err(AttributionError::UnknownSupply(legacy.to_string()));
            }
        }
        normalized.sort_by(|left, right| {
            (&left.namespace, &left.value, &left.supply_id).cmp(&(
                &right.namespace,
                &right.value,
                &right.supply_id,
            ))
        });
        let normalized_bytes = serde_json::to_vec(&(normalized, &legacy_actual_supply_id))
            .map_err(|error| AttributionError::Serialization(error.to_string()))?;
        let normalized_digest = format!("sha256:{:x}", Sha256::digest(normalized_bytes));

        Ok(Self {
            rules: by_key,
            legacy_actual_supply_id,
            normalized_digest,
        })
    }

    pub fn normalized_digest(&self) -> &str {
        &self.normalized_digest
    }
}

pub fn resolve_actual_supply(
    resolver: &AttributionResolver,
    registry: &Registry,
    input: AttributionInput,
    presented_model: Option<&str>,
    source: AttributionSource,
) -> AttributionResult {
    match input {
        AttributionInput::Absent => {
            if source == AttributionSource::InlineResponseHeader {
                if let Some(supply_id) = resolver.legacy_actual_supply_id.as_deref() {
                    return compatible_result(
                        registry,
                        supply_id,
                        presented_model,
                        AttributionSource::LegacyConfigured,
                        AttributionStatus::StaticConfigured,
                        None,
                    );
                }
            }
            result(
                AttributionStatus::Missing,
                source,
                None,
                None,
                Some("missing-attribution"),
            )
        }
        AttributionInput::Ambiguous => result(
            AttributionStatus::Ambiguous,
            source,
            None,
            None,
            Some("ambiguous-attribution-reference"),
        ),
        AttributionInput::Single(reference) => {
            if reference.validate().is_err() {
                return result(
                    AttributionStatus::UnknownReference,
                    source,
                    Some(reference),
                    None,
                    Some("invalid-attribution-reference"),
                );
            }
            let key = (reference.namespace.clone(), reference.value.clone());
            let Some(supply_id) = resolver.rules.get(&key) else {
                return result(
                    AttributionStatus::UnknownReference,
                    source,
                    Some(reference),
                    None,
                    Some("unknown-attribution-reference"),
                );
            };
            compatible_result(
                registry,
                supply_id,
                presented_model,
                source,
                AttributionStatus::Attributed,
                Some(reference),
            )
        }
    }
}

fn compatible_result(
    registry: &Registry,
    supply_id: &str,
    presented_model: Option<&str>,
    source: AttributionSource,
    success_status: AttributionStatus,
    reference: Option<AttributionRef>,
) -> AttributionResult {
    if presented_model
        .and_then(|model| registry.resolve_model(supply_id, model))
        .is_none()
    {
        return result(
            AttributionStatus::ModelMismatch,
            source,
            reference,
            None,
            Some("attribution-model-mismatch"),
        );
    }
    result(
        success_status,
        source,
        reference,
        Some(supply_id.to_string()),
        None,
    )
}

fn result(
    status: AttributionStatus,
    source: AttributionSource,
    reference: Option<AttributionRef>,
    supply_id: Option<String>,
    reason: Option<&str>,
) -> AttributionResult {
    AttributionResult {
        status,
        source,
        reference,
        supply_id,
        reason: reason.map(str::to_string),
    }
}

fn validate_reference_part(field: &'static str, value: &str) -> Result<(), AttributionError> {
    if value.trim().is_empty() {
        return Err(AttributionError::InvalidReferencePart {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > MAX_REFERENCE_BYTES {
        return Err(AttributionError::InvalidReferencePart {
            field,
            reason: "exceeds 256 bytes",
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum AttributionError {
    #[error("invalid attribution {field}: {reason}")]
    InvalidReferencePart {
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate attribution reference {namespace}:{value}")]
    DuplicateReference { namespace: String, value: String },
    #[error("attribution supply ID must not be empty")]
    EmptySupplyId,
    #[error("unknown attribution supply ID {0}")]
    UnknownSupply(String),
    #[error("failed to normalize attribution configuration: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use crate::supply::Registry;

    use super::*;

    fn registry() -> Registry {
        Registry::from_json(
            r#"{
  "feed_version": "test",
  "entries": [
    {
      "id": "public/east",
      "model": "shared-model",
      "aliases": ["shared-model-2026"],
      "location": "east",
      "attributes": {"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":true},
      "price": {"input_per_mtok_usd":1.0,"output_per_mtok_usd":2.0},
      "ratings": {"mechanical":0.9}
    },
    {
      "id": "public/west",
      "model": "shared-model",
      "location": "west",
      "attributes": {"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":true},
      "price": {"input_per_mtok_usd":3.0,"output_per_mtok_usd":4.0},
      "ratings": {"mechanical":0.9}
    }
  ]
}"#,
        )
        .expect("registry parses")
    }

    fn reference(value: &str) -> AttributionRef {
        AttributionRef {
            namespace: "deployment".to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn exact_reference_maps_intended_supply() {
        let registry = registry();
        let resolver = AttributionResolver::new(
            vec![AttributionRule {
                namespace: "deployment".to_string(),
                value: "east-prod".to_string(),
                supply_id: "public/east".to_string(),
            }],
            Some("public/west".to_string()),
            &registry,
        )
        .expect("resolver is valid");

        let result = resolve_actual_supply(
            &resolver,
            &registry,
            AttributionInput::Single(reference("east-prod")),
            Some("shared-model"),
            AttributionSource::InlineResponseHeader,
        );

        assert_eq!(result.status, AttributionStatus::Attributed);
        assert_eq!(result.supply_id.as_deref(), Some("public/east"));
    }

    #[test]
    fn duplicate_reference_keys_fail_validation() {
        let registry = registry();
        let duplicate = AttributionRule {
            namespace: "deployment".to_string(),
            value: "same".to_string(),
            supply_id: "public/east".to_string(),
        };

        let error = AttributionResolver::new(vec![duplicate.clone(), duplicate], None, &registry)
            .expect_err("duplicate key must fail");

        assert!(matches!(error, AttributionError::DuplicateReference { .. }));
    }

    #[test]
    fn incomplete_or_invalid_attribution_has_no_supply() {
        let registry = registry();
        let resolver = AttributionResolver::new(
            vec![AttributionRule {
                namespace: "deployment".to_string(),
                value: "east-prod".to_string(),
                supply_id: "public/east".to_string(),
            }],
            None,
            &registry,
        )
        .expect("resolver is valid");

        let cases = [
            (AttributionInput::Absent, None, AttributionStatus::Missing),
            (
                AttributionInput::Single(reference("unknown")),
                Some("shared-model"),
                AttributionStatus::UnknownReference,
            ),
            (
                AttributionInput::Ambiguous,
                Some("shared-model"),
                AttributionStatus::Ambiguous,
            ),
            (
                AttributionInput::Single(reference("east-prod")),
                Some("different-model"),
                AttributionStatus::ModelMismatch,
            ),
        ];

        for (input, model, expected) in cases {
            let result = resolve_actual_supply(
                &resolver,
                &registry,
                input,
                model,
                AttributionSource::PassiveEvent,
            );
            assert_eq!(result.status, expected);
            assert_eq!(result.supply_id, None);
        }
    }

    #[test]
    fn legacy_fallback_only_applies_to_absent_inline_reference() {
        let registry = registry();
        let resolver =
            AttributionResolver::new(Vec::new(), Some("public/west".to_string()), &registry)
                .expect("resolver is valid");

        let absent = resolve_actual_supply(
            &resolver,
            &registry,
            AttributionInput::Absent,
            Some("shared-model"),
            AttributionSource::InlineResponseHeader,
        );
        let present_invalid = resolve_actual_supply(
            &resolver,
            &registry,
            AttributionInput::Single(reference("unknown")),
            Some("shared-model"),
            AttributionSource::InlineResponseHeader,
        );
        let passive_absent = resolve_actual_supply(
            &resolver,
            &registry,
            AttributionInput::Absent,
            Some("shared-model"),
            AttributionSource::PassiveEvent,
        );

        assert_eq!(absent.status, AttributionStatus::StaticConfigured);
        assert_eq!(absent.source, AttributionSource::LegacyConfigured);
        assert_eq!(absent.supply_id.as_deref(), Some("public/west"));
        assert_eq!(present_invalid.supply_id, None);
        assert_eq!(passive_absent.supply_id, None);
    }
}
