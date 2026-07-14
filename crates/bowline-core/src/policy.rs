use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::supply::{Registry, Retention, SupplyClass, SupplyEntry, TaskClass};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub api_key_digest: Option<String>,
    pub route: String,
    pub app: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyBundle {
    _source_bytes: Vec<u8>,
    digest: String,
    identities: Vec<IdentityRule>,
    rules: Vec<PolicyRule>,
    default_rule_index: usize,
}

impl PolicyBundle {
    pub fn from_yaml(source: &str) -> Result<Self, PolicyError> {
        let schema: PolicySchema =
            serde_yaml::from_str(source).map_err(|err| PolicyError::Parse(err.to_string()))?;

        if schema.version != 1 {
            return Err(PolicyError::UnsupportedVersion(schema.version));
        }

        let default_rule_index = schema
            .rules
            .iter()
            .position(|rule| rule.default)
            .ok_or(PolicyError::MissingDefaultRule)?;

        Ok(Self {
            _source_bytes: source.as_bytes().to_vec(),
            digest: digest_source(source),
            identities: schema.identities,
            rules: schema.rules,
            default_rule_index,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn resolve_tags(&self, identity: &WorkloadIdentity) -> Vec<String> {
        let mut tags = Vec::new();

        for tag in &identity.tags {
            push_unique(&mut tags, tag);
        }

        for rule in &self.identities {
            if rule.matcher.matches(identity) {
                for tag in &rule.tags {
                    push_unique(&mut tags, tag);
                }
            }
        }
        tags.sort();
        tags.dedup();
        tags
    }

    pub fn feasible<'a>(
        &self,
        identity: &WorkloadIdentity,
        registry: &'a Registry,
    ) -> Vec<&'a SupplyEntry> {
        let tags = self.resolve_tags(identity);
        let rule = self.rule_for(identity, &tags);

        registry
            .entries
            .iter()
            .filter(|entry| rule.require.matches(entry))
            .collect()
    }

    pub fn task_class_for(&self, identity: &WorkloadIdentity) -> TaskClass {
        let tags = self.resolve_tags(identity);
        self.rule_for(identity, &tags)
            .task_class
            .unwrap_or(TaskClass::Unclassified)
    }

    fn rule_for<'a>(&'a self, identity: &WorkloadIdentity, tags: &[String]) -> &'a PolicyRule {
        self.rules
            .iter()
            .find(|rule| !rule.default && rule.matches(identity, tags))
            .unwrap_or(&self.rules[self.default_rule_index])
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy bundle: {0}")]
    Parse(String),
    #[error("policy bundle requires a default rule")]
    MissingDefaultRule,
    #[error("unsupported policy bundle version: {0}")]
    UnsupportedVersion(u64),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySchema {
    version: u64,
    #[serde(default)]
    identities: Vec<IdentityRule>,
    rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRule {
    #[serde(rename = "match")]
    matcher: IdentityMatcher,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityMatcher {
    api_key_digest: Option<String>,
    route: Option<String>,
    app: Option<String>,
}

impl IdentityMatcher {
    fn matches(&self, identity: &WorkloadIdentity) -> bool {
        self.api_key_digest
            .as_ref()
            .is_none_or(|digest| identity.api_key_digest.as_ref() == Some(digest))
            && self
                .route
                .as_ref()
                .is_none_or(|route| identity.route == *route)
            && self
                .app
                .as_ref()
                .is_none_or(|app| identity.app.as_ref() == Some(app))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRule {
    #[serde(rename = "name")]
    _name: String,
    #[serde(default)]
    subject: Option<Subject>,
    #[serde(default)]
    default: bool,
    task_class: Option<TaskClass>,
    #[serde(default)]
    require: Requirements,
}

impl PolicyRule {
    fn matches(&self, identity: &WorkloadIdentity, tags: &[String]) -> bool {
        self.subject
            .as_ref()
            .is_some_and(|subject| subject.matches(identity, tags))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    #[serde(default)]
    tags: Vec<String>,
    app: Option<String>,
    route: Option<String>,
}

impl Subject {
    fn matches(&self, identity: &WorkloadIdentity, identity_tags: &[String]) -> bool {
        self.tags
            .iter()
            .all(|tag| identity_tags.iter().any(|identity_tag| identity_tag == tag))
            && self
                .app
                .as_ref()
                .is_none_or(|app| identity.app.as_ref() == Some(app))
            && self
                .route
                .as_ref()
                .is_none_or(|route| identity.route == *route)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirements {
    supply_class: Option<Vec<SupplyClass>>,
    jurisdiction: Option<Vec<String>>,
    retention: Option<Vec<Retention>>,
    training_use: Option<bool>,
    cloud_act_exposure: Option<bool>,
}

impl Requirements {
    fn matches(&self, entry: &SupplyEntry) -> bool {
        self.supply_class
            .as_ref()
            .is_none_or(|classes| classes.contains(&entry.attributes.class))
            && self
                .jurisdiction
                .as_ref()
                .is_none_or(|jurisdictions| jurisdictions.contains(&entry.attributes.jurisdiction))
            && self
                .retention
                .as_ref()
                .is_none_or(|retentions| retentions.contains(&entry.attributes.retention))
            && self
                .training_use
                .is_none_or(|training_use| entry.attributes.training_use == training_use)
            && self.cloud_act_exposure.is_none_or(|cloud_act_exposure| {
                entry.attributes.cloud_act_exposure == cloud_act_exposure
            })
    }
}

fn digest_source(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    format!("sha256:{digest:x}")
}

fn push_unique(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply::Registry;

    const POLICY: &str = r#"
version: 1
identities:
  - match: { app: support-bot }
    tags: [customer-data]
  - match: { route: /v1/chat/completions, api_key_digest: "sha256:ab12" }
    tags: [internal]
rules:
  - name: customer-data-stays-sovereign
    subject: { tags: [customer-data] }
    task_class: heavy-lifting
    require:
      supply_class: [owned, vpc-open-weights]
      cloud_act_exposure: false
      retention: [none]
  - name: internal-can-use-public-api
    subject: { tags: [internal] }
    require:
      supply_class: [public-api]
  - name: default
    default: true
    require:
      supply_class: [owned, vpc-open-weights, vpc-frontier, public-api]
"#;

    fn customer_identity() -> WorkloadIdentity {
        WorkloadIdentity {
            api_key_digest: None,
            route: "/v1/chat/completions".to_string(),
            app: Some("support-bot".to_string()),
            tags: Vec::new(),
        }
    }

    fn fixture_registry() -> Registry {
        Registry::from_json(include_str!("../../../registry/feed.json"))
            .expect("fixture registry should parse")
    }

    #[test]
    fn digest_is_stable_and_content_addressed() {
        let policy = PolicyBundle::from_yaml(POLICY).expect("policy should parse");
        let same = PolicyBundle::from_yaml(POLICY).expect("same source should parse");
        let changed = PolicyBundle::from_yaml(&POLICY.replace("support-bot", "support-bot-v2"))
            .expect("changed source should parse");

        assert_eq!(policy.digest(), same.digest());
        assert_ne!(policy.digest(), changed.digest());

        let hex = policy
            .digest()
            .strip_prefix("sha256:")
            .expect("digest should include sha256 prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn resolve_tags_matches_app() {
        let policy = PolicyBundle::from_yaml(POLICY).expect("policy should parse");

        let tags = policy.resolve_tags(&customer_identity());

        assert_eq!(tags, vec!["customer-data"]);
    }

    #[test]
    fn feasible_filters_by_supply_class_and_cloud_act() {
        let policy = PolicyBundle::from_yaml(POLICY).expect("policy should parse");
        let registry = fixture_registry();

        let entries = policy.feasible(&customer_identity(), &registry);

        assert!(!entries.is_empty());
        assert!(entries.iter().all(|entry| matches!(
            entry.attributes.class,
            SupplyClass::Owned | SupplyClass::VpcOpenWeights
        )));
        assert!(entries
            .iter()
            .all(|entry| !entry.attributes.cloud_act_exposure));
        assert!(entries
            .iter()
            .all(|entry| entry.attributes.retention == Retention::None));
    }

    #[test]
    fn feasible_filters_by_jurisdiction_allowlist() {
        let policy = PolicyBundle::from_yaml(
            r#"
version: 1
rules:
  - name: default
    default: true
    require:
      jurisdiction: [eu]
"#,
        )
        .expect("policy should parse");
        let registry = fixture_registry();

        let entries = policy.feasible(&customer_identity(), &registry);

        assert!(!entries.is_empty());
        assert!(registry
            .entries
            .iter()
            .any(|entry| entry.attributes.jurisdiction != "eu"));
        assert!(entries
            .iter()
            .all(|entry| entry.attributes.jurisdiction == "eu"));
    }

    #[test]
    fn feasible_filters_out_entries_with_training_use_when_disallowed() {
        let policy = PolicyBundle::from_yaml(
            r#"
version: 1
rules:
  - name: default
    default: true
    require:
      training_use: false
"#,
        )
        .expect("policy should parse");
        let mut registry = fixture_registry();
        let training_entry = registry
            .entries
            .iter_mut()
            .find(|entry| entry.id == "openai/gpt-5.5")
            .expect("fixture entry exists");
        training_entry.attributes.training_use = true;

        let entries = policy.feasible(&customer_identity(), &registry);

        assert!(!entries.is_empty());
        assert!(registry
            .entries
            .iter()
            .any(|entry| entry.attributes.training_use));
        assert!(entries.iter().all(|entry| !entry.attributes.training_use));
        assert!(!entries.iter().any(|entry| entry.id == "openai/gpt-5.5"));
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = PolicyBundle::from_yaml(POLICY).expect("policy should parse");
        let registry = fixture_registry();
        let identity = WorkloadIdentity {
            api_key_digest: Some("sha256:ab12".to_string()),
            route: "/v1/chat/completions".to_string(),
            app: Some("support-bot".to_string()),
            tags: Vec::new(),
        };

        let entries = policy.feasible(&identity, &registry);

        assert!(!entries.is_empty());
        assert!(entries.iter().all(|entry| matches!(
            entry.attributes.class,
            SupplyClass::Owned | SupplyClass::VpcOpenWeights
        )));
        assert_eq!(policy.task_class_for(&identity), TaskClass::HeavyLifting);
    }

    #[test]
    fn missing_default_rule_is_parse_error() {
        let yaml = r#"
version: 1
rules:
  - name: only-rule
    require:
      supply_class: [owned]
"#;

        let err = PolicyBundle::from_yaml(yaml).expect_err("missing default should fail");

        assert!(matches!(err, PolicyError::MissingDefaultRule));
    }

    #[test]
    fn unknown_require_key_is_parse_error() {
        let yaml = r#"
version: 1
rules:
  - name: default
    default: true
    require:
      supply_class_typo: [owned]
"#;

        let err = PolicyBundle::from_yaml(yaml).expect_err("unknown require key should fail");

        assert!(matches!(err, PolicyError::Parse(_)));
    }

    #[test]
    fn default_policy_file_parses() {
        let policy = PolicyBundle::from_yaml(include_str!("../../../policies/default.yaml"))
            .expect("default policy file should parse");

        assert!(policy.digest().starts_with("sha256:"));
    }
}
