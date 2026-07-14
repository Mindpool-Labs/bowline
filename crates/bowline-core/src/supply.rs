use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupplyClass {
    Owned,
    VpcOpenWeights,
    VpcFrontier,
    PublicApi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Retention {
    None,
    Days30,
    Indefinite,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskClass {
    Mechanical,
    HeavyLifting,
    TasteSensitive,
    Judgment,
    Unclassified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyAttributes {
    pub class: SupplyClass,
    pub jurisdiction: String,
    pub retention: Retention,
    pub training_use: bool,
    pub cloud_act_exposure: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Price {
    pub input_per_mtok_usd: f64,
    pub output_per_mtok_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyEntry {
    pub id: String,
    pub model: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub location: String,
    pub attributes: SupplyAttributes,
    pub price: Option<Price>,
    pub ratings: BTreeMap<TaskClass, f32>,
    #[serde(default)]
    pub available: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default, rename = "_note")]
    pub note: Option<String>,
    pub feed_version: String,
    pub entries: Vec<SupplyEntry>,
}

impl Registry {
    pub fn from_json(s: &str) -> Result<Self, SupplyError> {
        let registry: Registry =
            serde_json::from_str(s).map_err(|err| SupplyError::Parse(err.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn by_id(&self, id: &str) -> Option<&SupplyEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn resolve_model(&self, supply_id: &str, presented_model: &str) -> Option<&SupplyEntry> {
        let entry = self.by_id(supply_id)?;
        (entry.model == presented_model
            || entry.aliases.iter().any(|alias| alias == presented_model))
        .then_some(entry)
    }

    pub fn resolve_unique_model(&self, presented_model: &str) -> Option<&SupplyEntry> {
        let mut matches = self.entries.iter().filter(|entry| {
            entry.model == presented_model
                || entry.aliases.iter().any(|alias| alias == presented_model)
        });
        let entry = matches.next()?;
        matches.next().is_none().then_some(entry)
    }

    pub fn resolve_actual_entry(
        &self,
        supply_id: Option<&str>,
        presented_model: &str,
    ) -> Option<&SupplyEntry> {
        match supply_id {
            Some(supply_id) => self.resolve_model(supply_id, presented_model),
            None => self.resolve_unique_model(presented_model),
        }
    }

    fn validate(&self) -> Result<(), SupplyError> {
        let mut ids = HashSet::new();

        for entry in &self.entries {
            if !ids.insert(entry.id.as_str()) {
                return Err(SupplyError::DuplicateId(entry.id.clone()));
            }

            let mut model_identifiers = HashSet::from([entry.model.as_str()]);
            for alias in &entry.aliases {
                if !model_identifiers.insert(alias) {
                    return Err(SupplyError::DuplicateModelIdentifier {
                        id: entry.id.clone(),
                        value: alias.clone(),
                    });
                }
            }

            if let Some(price) = &entry.price {
                validate_price(entry, "input_per_mtok_usd", price.input_per_mtok_usd)?;
                validate_price(entry, "output_per_mtok_usd", price.output_per_mtok_usd)?;
            }

            for (&class, &rating) in &entry.ratings {
                if !(0.0..=1.0).contains(&rating) {
                    return Err(SupplyError::RatingOutOfRange {
                        id: entry.id.clone(),
                        class,
                    });
                }
            }
        }

        Ok(())
    }
}

fn validate_price(entry: &SupplyEntry, field: &'static str, value: f64) -> Result<(), SupplyError> {
    if !value.is_finite() || value < 0.0 {
        Err(SupplyError::InvalidPrice {
            id: entry.id.clone(),
            field,
        })
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SupplyError {
    #[error("failed to parse supply registry: {0}")]
    Parse(String),
    #[error("duplicate supply id: {0}")]
    DuplicateId(String),
    #[error("duplicate model identifier {value} in supply id {id}")]
    DuplicateModelIdentifier { id: String, value: String },
    #[error("invalid {field} for supply id {id}: must be finite and non-negative")]
    InvalidPrice { id: String, field: &'static str },
    #[error("rating out of range for supply id {id}, task class {class:?}")]
    RatingOutOfRange { id: String, class: TaskClass },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const FIXTURE: &str = r#"
{
  "feed_version": "2026-07-09.test",
  "entries": [
    {
      "id": "local/qwen3-32b",
      "model": "qwen3-32b",
      "location": "Customer-owned workstation",
      "attributes": {
        "class": "owned",
        "jurisdiction": "local",
        "retention": "none",
        "training_use": false,
        "cloud_act_exposure": false
      },
      "price": null,
      "ratings": {
        "mechanical": 0.82,
        "heavy-lifting": 0.84,
        "taste-sensitive": 0.62,
        "judgment": 0.58
      },
      "available": true
    },
    {
      "id": "openai/gpt-5-mini",
      "model": "gpt-5-mini",
      "location": "OpenAI public API, US",
      "attributes": {
        "class": "public-api",
        "jurisdiction": "us",
        "retention": "days30",
        "training_use": false,
        "cloud_act_exposure": true
      },
      "price": {
        "input_per_mtok_usd": 0.25,
        "output_per_mtok_usd": 2.0
      },
      "ratings": {
        "mechanical": 0.8,
        "heavy-lifting": 0.52,
        "taste-sensitive": 0.63,
        "judgment": 0.5
      }
    }
  ]
}
"#;

    #[test]
    fn registry_parses_seeded_feed() {
        let registry = Registry::from_json(FIXTURE).expect("fixture should parse");

        assert_eq!(registry.entries.len(), 2);

        let entry = registry.by_id("local/qwen3-32b").expect("entry exists");
        assert_eq!(entry.attributes.class, SupplyClass::Owned);
        assert_eq!(entry.attributes.jurisdiction, "local");
        assert_eq!(entry.attributes.retention, Retention::None);
        assert!(!entry.attributes.training_use);
        assert!(!entry.attributes.cloud_act_exposure);
        assert!(entry.price.is_none());
        assert_eq!(entry.available, Some(true));
    }

    #[test]
    fn duplicate_ids_rejected() {
        let json = r#"
{
  "feed_version": "2026-07-09.test",
  "entries": [
    {
      "id": "same",
      "model": "a",
      "location": "A",
      "attributes": {
        "class": "owned",
        "jurisdiction": "local",
        "retention": "none",
        "training_use": false,
        "cloud_act_exposure": false
      },
      "price": null,
      "ratings": { "mechanical": 0.5 }
    },
    {
      "id": "same",
      "model": "b",
      "location": "B",
      "attributes": {
        "class": "public-api",
        "jurisdiction": "us",
        "retention": "days30",
        "training_use": false,
        "cloud_act_exposure": true
      },
      "price": {
        "input_per_mtok_usd": 1.0,
        "output_per_mtok_usd": 2.0
      },
      "ratings": { "mechanical": 0.8 }
    }
  ]
}
"#;

        let err = Registry::from_json(json).expect_err("duplicate id should fail");

        assert!(matches!(err, SupplyError::DuplicateId(id) if id == "same"));
    }

    #[test]
    fn rating_out_of_range_rejected() {
        let json = r#"
{
  "feed_version": "2026-07-09.test",
  "entries": [
    {
      "id": "openai/gpt-5.5",
      "model": "gpt-5.5",
      "location": "OpenAI public API, US",
      "attributes": {
        "class": "public-api",
        "jurisdiction": "us",
        "retention": "days30",
        "training_use": false,
        "cloud_act_exposure": true
      },
      "price": {
        "input_per_mtok_usd": 5.0,
        "output_per_mtok_usd": 15.0
      },
      "ratings": { "judgment": 1.2 }
    }
  ]
}
"#;

        let err = Registry::from_json(json).expect_err("out-of-range rating should fail");

        assert!(
            matches!(err, SupplyError::RatingOutOfRange { id, class } if id == "openai/gpt-5.5" && class == TaskClass::Judgment)
        );
    }

    #[test]
    fn registry_exposes_no_first_match_model_lookup() {
        let first_match_api = ["pub fn ", "by_model"].concat();
        assert!(!include_str!("supply.rs").contains(&first_match_api));
    }

    #[test]
    fn unique_model_lookup_rejects_duplicate_locations() {
        let json = FIXTURE.replace("\"model\": \"gpt-5-mini\"", "\"model\": \"qwen3-32b\"");
        let registry = Registry::from_json(&json).expect("duplicate model fixture parses");

        assert!(registry.resolve_unique_model("qwen3-32b").is_none());
        assert_eq!(
            registry
                .resolve_unique_model("gpt-5-mini")
                .map(|entry| entry.id.as_str()),
            None
        );
    }

    #[test]
    fn alias_resolves_to_one_canonical_entry() {
        let json = FIXTURE.replace(
            "\"model\": \"gpt-5-mini\",",
            "\"model\": \"gpt-5-mini\",\n      \"aliases\": [\"gpt-5-mini-2026-06-01\"],",
        );
        let registry = Registry::from_json(&json).expect("alias fixture parses");

        let entry = registry
            .resolve_model("openai/gpt-5-mini", "gpt-5-mini-2026-06-01")
            .expect("alias resolves");

        assert_eq!(entry.id, "openai/gpt-5-mini");
        assert!(registry
            .resolve_model("openai/gpt-5-mini", "GPT-5-MINI-2026-06-01")
            .is_none());
    }

    #[test]
    fn duplicate_alias_inside_entry_is_rejected() {
        let json = FIXTURE.replace(
            "\"model\": \"gpt-5-mini\",",
            "\"model\": \"gpt-5-mini\",\n      \"aliases\": [\"same\", \"same\"],",
        );

        let err = Registry::from_json(&json).expect_err("duplicate alias must fail");

        assert!(
            matches!(err, SupplyError::DuplicateModelIdentifier { id, value } if id == "openai/gpt-5-mini" && value == "same")
        );
    }

    #[test]
    fn same_model_at_different_locations_is_allowed_but_resolution_is_scoped() {
        let json = FIXTURE.replace("\"model\": \"gpt-5-mini\"", "\"model\": \"qwen3-32b\"");
        let registry = Registry::from_json(&json).expect("same model at another location is valid");

        assert_eq!(
            registry
                .resolve_model("openai/gpt-5-mini", "qwen3-32b")
                .expect("configured supply matches")
                .id,
            "openai/gpt-5-mini"
        );
        assert!(registry
            .resolve_model("missing/supply", "qwen3-32b")
            .is_none());
    }

    #[test]
    fn negative_price_is_rejected() {
        let json = FIXTURE.replace(
            "\"input_per_mtok_usd\": 0.25",
            "\"input_per_mtok_usd\": -0.25",
        );

        let err = Registry::from_json(&json).expect_err("negative price must fail");

        assert!(
            matches!(err, SupplyError::InvalidPrice { id, field } if id == "openai/gpt-5-mini" && field == "input_per_mtok_usd")
        );
    }

    #[test]
    fn seeded_feed_file_is_valid() {
        let registry = Registry::from_json(include_str!("../../../registry/feed.json"))
            .expect("seeded feed should parse");

        let classes = registry
            .entries
            .iter()
            .map(|entry| entry.attributes.class)
            .collect::<BTreeSet<_>>();

        assert_eq!(registry.feed_version, "2026-07-09.1");
        assert_eq!(registry.entries.len(), 10);
        assert_eq!(
            registry.note.as_deref(),
            Some("Seeded illustrative feed — verify prices before relying on counterfactuals.")
        );
        assert!(classes.contains(&SupplyClass::Owned));
        assert!(classes.contains(&SupplyClass::VpcOpenWeights));
        assert!(classes.contains(&SupplyClass::VpcFrontier));
        assert!(classes.contains(&SupplyClass::PublicApi));
    }

    /// Locks the exact identity and load-bearing attributes of every entry in the real
    /// shipped feed (`registry/feed.json`). `class`/`jurisdiction`/`retention`/
    /// `training_use`/`cloud_act_exposure` gate `policy::feasible`, `price`/`ratings`/
    /// `available` drive `decision::choose_shadow` and `report`'s cheapest-clearing scan —
    /// a silent rename, jurisdiction change, or a fabricated price on an owned entry would
    /// otherwise pass CI and poison the counterfactual. If a change here is deliberate,
    /// update this lock test in the same commit.
    #[test]
    fn seeded_feed_file_entries_are_locked() {
        struct Expected {
            id: &'static str,
            class: SupplyClass,
            jurisdiction: &'static str,
            retention: Retention,
            training_use: bool,
            cloud_act_exposure: bool,
            price: Option<(f64, f64)>,
            ratings: &'static [(TaskClass, f32)],
            available: Option<bool>,
        }

        const EXPECTED: &[Expected] = &[
            Expected {
                id: "openai/gpt-5.5",
                class: SupplyClass::PublicApi,
                jurisdiction: "us",
                retention: Retention::Days30,
                training_use: false,
                cloud_act_exposure: true,
                price: Some((5.0, 25.0)),
                ratings: &[
                    (TaskClass::Mechanical, 0.94),
                    (TaskClass::HeavyLifting, 0.93),
                    (TaskClass::TasteSensitive, 0.91),
                    (TaskClass::Judgment, 0.94),
                ],
                available: None,
            },
            Expected {
                id: "openai/gpt-5-mini",
                class: SupplyClass::PublicApi,
                jurisdiction: "us",
                retention: Retention::Days30,
                training_use: false,
                cloud_act_exposure: true,
                price: Some((0.25, 2.0)),
                ratings: &[
                    (TaskClass::Mechanical, 0.82),
                    (TaskClass::HeavyLifting, 0.52),
                    (TaskClass::TasteSensitive, 0.62),
                    (TaskClass::Judgment, 0.5),
                ],
                available: None,
            },
            Expected {
                id: "anthropic/claude-sonnet-5",
                class: SupplyClass::PublicApi,
                jurisdiction: "us",
                retention: Retention::Days30,
                training_use: false,
                cloud_act_exposure: true,
                price: Some((3.0, 15.0)),
                ratings: &[
                    (TaskClass::Mechanical, 0.91),
                    (TaskClass::HeavyLifting, 0.9),
                    (TaskClass::TasteSensitive, 0.9),
                    (TaskClass::Judgment, 0.92),
                ],
                available: None,
            },
            Expected {
                id: "anthropic/claude-haiku-4.5",
                class: SupplyClass::PublicApi,
                jurisdiction: "us",
                retention: Retention::Days30,
                training_use: false,
                cloud_act_exposure: true,
                price: Some((1.0, 5.0)),
                ratings: &[
                    (TaskClass::Mechanical, 0.86),
                    (TaskClass::HeavyLifting, 0.66),
                    (TaskClass::TasteSensitive, 0.72),
                    (TaskClass::Judgment, 0.62),
                ],
                available: None,
            },
            Expected {
                id: "bedrock-eu/claude-sonnet-5",
                class: SupplyClass::VpcFrontier,
                jurisdiction: "eu",
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: true,
                price: Some((3.0, 15.0)),
                ratings: &[
                    (TaskClass::Mechanical, 0.91),
                    (TaskClass::HeavyLifting, 0.9),
                    (TaskClass::TasteSensitive, 0.9),
                    (TaskClass::Judgment, 0.92),
                ],
                available: None,
            },
            Expected {
                id: "vpc/qwen3-32b",
                class: SupplyClass::VpcOpenWeights,
                jurisdiction: "eu",
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: false,
                price: Some((0.35, 0.55)),
                ratings: &[
                    (TaskClass::Mechanical, 0.82),
                    (TaskClass::HeavyLifting, 0.85),
                    (TaskClass::TasteSensitive, 0.63),
                    (TaskClass::Judgment, 0.6),
                ],
                available: None,
            },
            Expected {
                id: "vpc/llama-3.3-70b",
                class: SupplyClass::VpcOpenWeights,
                jurisdiction: "eu",
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: false,
                price: Some((0.45, 0.7)),
                ratings: &[
                    (TaskClass::Mechanical, 0.83),
                    (TaskClass::HeavyLifting, 0.85),
                    (TaskClass::TasteSensitive, 0.66),
                    (TaskClass::Judgment, 0.61),
                ],
                available: None,
            },
            Expected {
                id: "local/llama-3.3-70b",
                class: SupplyClass::Owned,
                jurisdiction: "local",
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: false,
                price: None,
                ratings: &[
                    (TaskClass::Mechanical, 0.83),
                    (TaskClass::HeavyLifting, 0.85),
                    (TaskClass::TasteSensitive, 0.66),
                    (TaskClass::Judgment, 0.61),
                ],
                available: None,
            },
            Expected {
                id: "local/qwen3-32b",
                class: SupplyClass::Owned,
                jurisdiction: "local",
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: false,
                price: None,
                ratings: &[
                    (TaskClass::Mechanical, 0.82),
                    (TaskClass::HeavyLifting, 0.85),
                    (TaskClass::TasteSensitive, 0.63),
                    (TaskClass::Judgment, 0.6),
                ],
                available: None,
            },
            Expected {
                id: "bedrock-us/claude-haiku-4.5",
                class: SupplyClass::VpcFrontier,
                jurisdiction: "us",
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: true,
                price: Some((1.0, 5.0)),
                ratings: &[
                    (TaskClass::Mechanical, 0.86),
                    (TaskClass::HeavyLifting, 0.66),
                    (TaskClass::TasteSensitive, 0.72),
                    (TaskClass::Judgment, 0.62),
                ],
                available: None,
            },
        ];

        let registry = Registry::from_json(include_str!("../../../registry/feed.json"))
            .expect("seeded feed should parse");

        let actual_ids: BTreeSet<&str> = registry
            .entries
            .iter()
            .map(|entry| entry.id.as_str())
            .collect();
        let expected_ids: BTreeSet<&str> = EXPECTED.iter().map(|entry| entry.id).collect();
        assert_eq!(
            actual_ids, expected_ids,
            "registry/feed.json drifted: entry id set changed (added/removed/renamed) — \
             if this change is deliberate, update this lock test in the same commit"
        );

        for expected in EXPECTED {
            let entry = registry.by_id(expected.id).unwrap_or_else(|| {
                panic!(
                    "registry/feed.json drifted: entry {:?} is missing — \
                     if this change is deliberate, update this lock test in the same commit",
                    expected.id
                )
            });

            assert_eq!(
                entry.attributes.class, expected.class,
                "registry/feed.json drifted: {} supply class changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );
            assert_eq!(
                entry.attributes.jurisdiction, expected.jurisdiction,
                "registry/feed.json drifted: {} jurisdiction changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );
            assert_eq!(
                entry.attributes.retention, expected.retention,
                "registry/feed.json drifted: {} retention changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );
            assert_eq!(
                entry.attributes.training_use, expected.training_use,
                "registry/feed.json drifted: {} training_use changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );
            assert_eq!(
                entry.attributes.cloud_act_exposure, expected.cloud_act_exposure,
                "registry/feed.json drifted: {} cloud_act_exposure changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );

            match (&entry.price, expected.price) {
                (None, None) => {}
                (Some(price), Some((input, output))) => {
                    assert_eq!(
                        price.input_per_mtok_usd, input,
                        "registry/feed.json drifted: {} input price changed — \
                         if this change is deliberate, update this lock test in the same commit",
                        expected.id
                    );
                    assert_eq!(
                        price.output_per_mtok_usd, output,
                        "registry/feed.json drifted: {} output price changed — \
                         if this change is deliberate, update this lock test in the same commit",
                        expected.id
                    );
                }
                _ => panic!(
                    "registry/feed.json drifted: {} price presence changed — \
                     if this change is deliberate, update this lock test in the same commit",
                    expected.id
                ),
            }

            // Owned supply is priced via TCO inputs, never via the feed — a fabricated
            // feed price would poison the counterfactual, so this is asserted directly
            // in addition to the presence check above.
            if expected.class == SupplyClass::Owned {
                assert!(
                    entry.price.is_none(),
                    "registry/feed.json drifted: owned entry {} gained a feed price \
                     (owned supply must be priced via TCO inputs, never the feed) — \
                     if this change is deliberate, update this lock test in the same commit",
                    expected.id
                );
            }

            let expected_ratings: BTreeMap<TaskClass, f32> =
                expected.ratings.iter().copied().collect();
            assert_eq!(
                entry.ratings, expected_ratings,
                "registry/feed.json drifted: {} ratings changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );

            assert_eq!(
                entry.available, expected.available,
                "registry/feed.json drifted: {} availability changed — \
                 if this change is deliberate, update this lock test in the same commit",
                expected.id
            );
        }
    }
}
