use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};

use crate::{
    attribution::{AttributionRef, AttributionResolver, AttributionRule},
    decision::QualityFloors,
    ledger::{MAX_SEGMENTS, MAX_SEGMENT_BYTES},
    supply::{Registry, SupplyClass},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub upstream: String,
    #[serde(default)]
    pub actual_supply_id: String,
    pub policy_bundle: PathBuf,
    pub registry_feed: PathBuf,
    #[serde(default)]
    pub local_endpoints: Vec<LocalEndpoint>,
    pub ledger_dir: PathBuf,
    #[serde(default)]
    pub tco: Option<PathBuf>,
    #[serde(default)]
    pub attribution: Option<InlineAttributionConfig>,
    #[serde(default)]
    pub floors: Option<QualityFloors>,
    #[serde(default)]
    pub enforcement: Option<PathBuf>,
    #[serde(default = "default_trusted_proxy_cidrs")]
    pub trusted_proxy_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineAttributionConfig {
    pub version: u32,
    pub response_header: String,
    pub namespace: String,
    pub mappings: Vec<InlineAttributionMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineAttributionMapping {
    pub value: String,
    pub supply_id: String,
}

impl InlineAttributionConfig {
    pub fn rules(&self) -> Vec<AttributionRule> {
        self.mappings
            .iter()
            .map(|mapping| AttributionRule {
                namespace: self.namespace.clone(),
                value: mapping.value.clone(),
                supply_id: mapping.supply_id.clone(),
            })
            .collect()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::invalid("attribution.version", "must equal 1"));
        }
        validate_response_header(&self.response_header)?;
        if self.mappings.is_empty() || self.mappings.len() > 1_024 {
            return Err(ConfigError::invalid(
                "attribution.mappings",
                "must contain 1..=1024 mappings",
            ));
        }
        let mut keys = std::collections::BTreeSet::new();
        for mapping in &self.mappings {
            AttributionRef {
                namespace: self.namespace.clone(),
                value: mapping.value.clone(),
            }
            .validate()
            .map_err(|error| ConfigError::invalid("attribution.mappings", error.to_string()))?;
            if mapping.supply_id.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "attribution.mappings",
                    "supply id must not be empty",
                ));
            }
            if !keys.insert(mapping.value.as_str()) {
                return Err(ConfigError::invalid(
                    "attribution.mappings",
                    "duplicate namespace/value key",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_response_header_timeout_ms")]
    pub response_header_timeout_ms: u64,
    #[serde(default = "default_stream_idle_timeout_ms")]
    pub stream_idle_timeout_ms: u64,
    #[serde(default = "default_shutdown_grace_ms")]
    pub shutdown_grace_ms: u64,
    #[serde(default = "default_writer_queue_capacity")]
    pub writer_queue_capacity: usize,
    #[serde(default = "default_accounting_limit_bytes")]
    pub accounting_limit_bytes: usize,
    #[serde(default = "default_ledger_segment_bytes")]
    pub ledger_segment_bytes: u64,
    #[serde(default = "default_ledger_max_segments")]
    pub ledger_max_segments: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            response_header_timeout_ms: default_response_header_timeout_ms(),
            stream_idle_timeout_ms: default_stream_idle_timeout_ms(),
            shutdown_grace_ms: default_shutdown_grace_ms(),
            writer_queue_capacity: default_writer_queue_capacity(),
            accounting_limit_bytes: default_accounting_limit_bytes(),
            ledger_segment_bytes: default_ledger_segment_bytes(),
            ledger_max_segments: default_ledger_max_segments(),
        }
    }
}

impl RuntimeConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn response_header_timeout(&self) -> Duration {
        Duration::from_millis(self.response_header_timeout_ms)
    }

    pub fn stream_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.stream_idle_timeout_ms)
    }

    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.shutdown_grace_ms)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_positive("runtime.connect_timeout_ms", self.connect_timeout_ms)?;
        validate_positive(
            "runtime.response_header_timeout_ms",
            self.response_header_timeout_ms,
        )?;
        validate_positive(
            "runtime.stream_idle_timeout_ms",
            self.stream_idle_timeout_ms,
        )?;
        validate_positive("runtime.shutdown_grace_ms", self.shutdown_grace_ms)?;
        validate_positive("runtime.writer_queue_capacity", self.writer_queue_capacity)?;
        validate_positive(
            "runtime.accounting_limit_bytes",
            self.accounting_limit_bytes,
        )?;
        validate_positive("runtime.ledger_segment_bytes", self.ledger_segment_bytes)?;
        validate_positive("runtime.ledger_max_segments", self.ledger_max_segments)?;
        if self.ledger_segment_bytes > MAX_SEGMENT_BYTES {
            return Err(ConfigError::invalid(
                "runtime.ledger_segment_bytes",
                format!("must not exceed {MAX_SEGMENT_BYTES}"),
            ));
        }
        if self.ledger_max_segments > MAX_SEGMENTS {
            return Err(ConfigError::invalid(
                "runtime.ledger_max_segments",
                format!("must not exceed {MAX_SEGMENTS}"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEndpoint {
    pub supply_id: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcoInputs {
    pub monthly_amortization_usd: f64,
    pub monthly_power_usd: f64,
    pub monthly_ops_usd: f64,
    pub monthly_capacity_mtok: f64,
}

#[derive(Debug, Clone)]
pub struct OwnedCostCatalog {
    costs_per_mtok: BTreeMap<String, f64>,
    normalized_digest: String,
}

impl Default for OwnedCostCatalog {
    fn default() -> Self {
        Self::from_costs(BTreeMap::new())
    }
}

impl OwnedCostCatalog {
    fn from_costs(costs_per_mtok: BTreeMap<String, f64>) -> Self {
        let normalized = serde_json::to_vec(&costs_per_mtok)
            .expect("a string-to-f64 cost map is JSON serializable");
        let normalized_digest = format!("sha256:{:x}", Sha256::digest(normalized));
        Self {
            costs_per_mtok,
            normalized_digest,
        }
    }

    pub fn cost_per_mtok(&self, supply_id: &str) -> Option<f64> {
        self.costs_per_mtok.get(supply_id).copied()
    }

    pub fn normalized_digest(&self) -> &str {
        &self.normalized_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(costs_per_mtok: BTreeMap<String, f64>) -> Self {
        Self::from_costs(costs_per_mtok)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedCostCatalogV2 {
    version: u32,
    supplies: BTreeMap<String, TcoInputs>,
}

impl TcoInputs {
    pub fn owned_cost_per_mtok(&self) -> f64 {
        (self.monthly_amortization_usd + self.monthly_power_usd + self.monthly_ops_usd)
            / self.monthly_capacity_mtok
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_non_negative_finite("monthly_amortization_usd", self.monthly_amortization_usd)?;
        validate_non_negative_finite("monthly_power_usd", self.monthly_power_usd)?;
        validate_non_negative_finite("monthly_ops_usd", self.monthly_ops_usd)?;
        if !self.monthly_capacity_mtok.is_finite() || self.monthly_capacity_mtok <= 0.0 {
            return Err(ConfigError::invalid(
                "monthly_capacity_mtok",
                "must be finite and greater than zero",
            ));
        }
        Ok(())
    }
}

impl Config {
    pub fn from_yaml(s: &str) -> Result<Self, ConfigError> {
        serde_yaml::from_str(s).map_err(|err| ConfigError::Parse(err.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let listen = self
            .listen
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::invalid("listen", "must be a valid IP socket address"))?;
        let upstream = Url::parse(&self.upstream)
            .map_err(|_| ConfigError::invalid("upstream", "must be a valid HTTP(S) URL"))?;
        if !matches!(upstream.scheme(), "http" | "https") || upstream.host().is_none() {
            return Err(ConfigError::invalid(
                "upstream",
                "must be a valid HTTP(S) URL",
            ));
        }
        if !upstream.username().is_empty() || upstream.password().is_some() {
            return Err(ConfigError::invalid(
                "upstream",
                "must not contain URL userinfo; provide credentials through an approved secret source",
            ));
        }
        if upstream
            .query_pairs()
            .any(|(key, _)| is_sensitive_query_key(&key))
        {
            return Err(ConfigError::invalid(
                "upstream",
                "must not contain credential-bearing query parameters",
            ));
        }
        if self.attribution.is_none() && self.actual_supply_id.trim().is_empty() {
            return Err(ConfigError::invalid(
                "actual_supply_id",
                "must name the registry entry representing the configured upstream",
            ));
        }
        if let Some(attribution) = &self.attribution {
            attribution.validate()?;
        }
        if !listen.ip().is_loopback() && self.trusted_proxy_cidrs.is_empty() {
            return Err(ConfigError::invalid(
                "trusted_proxy_cidrs",
                "a non-loopback listener requires at least one trusted proxy CIDR",
            ));
        }
        if let Some(floors) = &self.floors {
            for value in floors.0.values() {
                if !value.is_finite() || !(0.0..=1.0).contains(value) {
                    return Err(ConfigError::invalid(
                        "floors",
                        "every quality floor must be finite and within 0.0..=1.0",
                    ));
                }
            }
        }
        if self
            .enforcement
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::invalid(
                "enforcement",
                "must name an enforcement bundle when present",
            ));
        }
        self.runtime.validate()
    }

    pub fn attribution_resolver(
        &self,
        registry: &Registry,
    ) -> Result<AttributionResolver, ConfigError> {
        let rules = self
            .attribution
            .as_ref()
            .map(InlineAttributionConfig::rules)
            .unwrap_or_default();
        let legacy =
            (!self.actual_supply_id.trim().is_empty()).then(|| self.actual_supply_id.clone());
        AttributionResolver::new(rules, legacy, registry)
            .map_err(|error| ConfigError::invalid("attribution", error.to_string()))
    }

    pub fn attribution_digest(&self, registry: &Registry) -> Result<String, ConfigError> {
        let resolver = self.attribution_resolver(registry)?;
        let header = self
            .attribution
            .as_ref()
            .map(|config| config.response_header.to_ascii_lowercase());
        let namespace = self
            .attribution
            .as_ref()
            .map(|config| config.namespace.as_str());
        let normalized =
            serde_json::to_vec(&(1_u32, header, namespace, resolver.normalized_digest()))
                .map_err(|error| ConfigError::Parse(error.to_string()))?;
        Ok(format!("sha256:{:x}", Sha256::digest(normalized)))
    }
}

fn validate_response_header(value: &str) -> Result<(), ConfigError> {
    if value != value.trim() {
        return Err(ConfigError::invalid(
            "attribution.response_header",
            "must not contain leading or trailing whitespace",
        ));
    }
    let header = value.to_ascii_lowercase();
    if header.is_empty() || header.len() > 128 {
        return Err(ConfigError::invalid(
            "attribution.response_header",
            "must contain 1..=128 bytes",
        ));
    }
    if !header
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ConfigError::invalid(
            "attribution.response_header",
            "must be a valid HTTP header name",
        ));
    }
    let compact = header.replace('-', "");
    if [
        "authorization",
        "cookie",
        "apikey",
        "token",
        "secret",
        "proxyauth",
    ]
    .iter()
    .any(|forbidden| compact.contains(forbidden))
    {
        return Err(ConfigError::invalid(
            "attribution.response_header",
            "must not name a credential-bearing or secret header",
        ));
    }
    Ok(())
}

pub fn load_tco(s: &str) -> Result<TcoInputs, ConfigError> {
    serde_yaml::from_str(s).map_err(|err| ConfigError::Parse(err.to_string()))
}

pub fn load_owned_cost_catalog(
    source: Option<&str>,
    legacy_actual_supply_id: Option<&str>,
    registry: &Registry,
) -> Result<OwnedCostCatalog, ConfigError> {
    let Some(source) = source else {
        return Ok(OwnedCostCatalog::default());
    };
    let value: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|err| ConfigError::Parse(err.to_string()))?;
    let mut inputs = BTreeMap::new();
    if value.get("version").is_some() {
        let catalog: OwnedCostCatalogV2 =
            serde_yaml::from_value(value).map_err(|err| ConfigError::Parse(err.to_string()))?;
        if catalog.version != 2 {
            return Err(ConfigError::invalid("tco.version", "must equal 2"));
        }
        inputs = catalog.supplies;
    } else {
        let supply_id = legacy_actual_supply_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ConfigError::invalid(
                    "actual_supply_id",
                    "is required to bind a legacy TCO document to an exact owned supply",
                )
            })?;
        let legacy: TcoInputs =
            serde_yaml::from_value(value).map_err(|err| ConfigError::Parse(err.to_string()))?;
        inputs.insert(supply_id.to_string(), legacy);
    }

    let mut costs = BTreeMap::new();
    for (supply_id, input) in inputs {
        if supply_id.trim().is_empty() {
            return Err(ConfigError::invalid(
                "tco.supplies",
                "supply id must not be empty",
            ));
        }
        let entry = registry.by_id(&supply_id).ok_or_else(|| {
            ConfigError::invalid("tco.supplies", format!("unknown supply id {supply_id}"))
        })?;
        if entry.attributes.class != SupplyClass::Owned {
            return Err(ConfigError::invalid(
                "tco.supplies",
                format!("supply id {supply_id} is not owned"),
            ));
        }
        input.validate()?;
        costs.insert(supply_id, input.owned_cost_per_mtok());
    }
    Ok(OwnedCostCatalog::from_costs(costs))
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse config: {0}")]
    Parse(String),
    #[error("invalid configuration field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

impl ConfigError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            reason: reason.into(),
        }
    }
}

pub fn redact_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "<invalid-url>".to_string();
    };
    if !url.username().is_empty() {
        let _ = url.set_username("");
    }
    if url.password().is_some() {
        let _ = url.set_password(None);
    }
    let pairs = url
        .query_pairs()
        .map(|(key, value)| {
            let redacted = if is_sensitive_query_key(&key) {
                "REDACTED"
            } else {
                value.as_ref()
            };
            (key.into_owned(), redacted.to_string())
        })
        .collect::<Vec<_>>();
    if !pairs.is_empty() {
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.to_string()
}

pub fn endpoint_identity(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "<invalid-url>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string().trim_end_matches('/').to_string()
}

fn is_sensitive_query_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .map(|character| match character {
            '-' | '.' => '_',
            _ => character.to_ascii_lowercase(),
        })
        .collect::<String>();

    matches!(
        normalized.as_str(),
        "api_key"
            | "apikey"
            | "key"
            | "token"
            | "access_token"
            | "password"
            | "secret"
            | "x_api_key"
            | "client_secret"
            | "refresh_token"
            | "id_token"
            | "authorization"
            | "auth"
            | "sig"
            | "signature"
            | "x_amz_signature"
            | "x_amz_credential"
            | "x_amz_security_token"
            | "x_goog_signature"
            | "x_goog_credential"
    )
}

/// Shared credential-free endpoint contract for canary and enforcement actuators.
#[derive(Debug, Error)]
#[error("invalid credential-free endpoint")]
pub struct EndpointValidationError;

pub fn validate_credential_free_endpoint(
    source: &str,
    remote_acknowledged: bool,
    require_v1_path: bool,
) -> Result<Url, EndpointValidationError> {
    if source.contains('%') || source.chars().any(char::is_control) {
        return Err(EndpointValidationError);
    }
    let url = Url::parse(source).map_err(|_| EndpointValidationError)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "http" | "https")
        || require_v1_path && !(url.path().ends_with("/v1/") || url.path().ends_with("/v1"))
        || path_contains_credential_material(url.path())
    {
        return Err(EndpointValidationError);
    }
    let loopback = url.host().is_some_and(|host| match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    });
    if (!remote_acknowledged || url.scheme() == "http") && !loopback {
        return Err(EndpointValidationError);
    }
    Ok(url)
}

fn path_contains_credential_material(path: &str) -> bool {
    path.contains('%')
        || path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .any(|segment| {
                let normalized = segment.to_ascii_lowercase();
                matches!(
                    normalized.as_str(),
                    "apikey" | "authtoken" | "accesstoken" | "clientsecret"
                ) || normalized
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|word| {
                        matches!(
                            word,
                            "token"
                                | "key"
                                | "secret"
                                | "password"
                                | "auth"
                                | "authorization"
                                | "credential"
                                | "credentials"
                                | "bearer"
                                | "sk"
                        )
                    })
            })
}

fn validate_positive<T>(field: &'static str, value: T) -> Result<(), ConfigError>
where
    T: PartialEq + Default,
{
    if value == T::default() {
        Err(ConfigError::invalid(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

fn validate_non_negative_finite(field: &'static str, value: f64) -> Result<(), ConfigError> {
    if !value.is_finite() || value < 0.0 {
        Err(ConfigError::invalid(
            field,
            "must be finite and non-negative",
        ))
    } else {
        Ok(())
    }
}

fn default_trusted_proxy_cidrs() -> Vec<IpNet> {
    [
        IpAddr::from([127, 0, 0, 1]),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .map(IpNet::from)
    .collect()
}

fn default_connect_timeout_ms() -> u64 {
    2_000
}

fn default_response_header_timeout_ms() -> u64 {
    300_000
}

fn default_stream_idle_timeout_ms() -> u64 {
    300_000
}

fn default_shutdown_grace_ms() -> u64 {
    30_000
}

fn default_writer_queue_capacity() -> usize {
    1_024
}

fn default_accounting_limit_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_ledger_segment_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_ledger_max_segments() -> u32 {
    32
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::supply::Registry;

    use super::*;

    #[test]
    fn example_config_parses() {
        let config = Config::from_yaml(include_str!("../../../bowline.example.yaml"))
            .expect("example parses");

        assert_eq!(config.listen, "0.0.0.0:8080");
        assert_eq!(config.upstream, "http://127.0.0.1:9999");
        assert_eq!(config.policy_bundle, PathBuf::from("policies/default.yaml"));
        assert_eq!(config.registry_feed, PathBuf::from("registry/feed.json"));
        assert_eq!(config.ledger_dir, PathBuf::from("./ledger"));
        assert_eq!(config.tco, None);
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r#"
listen: 0.0.0.0:8080
upstream: http://127.0.0.1:9999
policy_bundle: policies/default.yaml
registry_feed: registry/feed.json
ledger_dir: ./ledger
surprise: nope
"#;

        let err = Config::from_yaml(yaml).expect_err("unknown field should fail");

        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn tco_cost_per_mtok_math() {
        let tco = load_tco(include_str!("../../../tco.example.yaml")).expect("example tco parses");

        assert_eq!(tco.monthly_amortization_usd, 1200.0);
        assert_eq!(tco.monthly_power_usd, 300.0);
        assert_eq!(tco.monthly_ops_usd, 500.0);
        assert_eq!(tco.monthly_capacity_mtok, 2000.0);
        assert_eq!(tco.owned_cost_per_mtok(), 1.0);
    }

    #[test]
    fn owned_cost_catalog_prices_exact_supply_ids() {
        let registry = Registry::from_json(
            r#"{"feed_version":"test","entries":[
              {"id":"owned/a","model":"a","location":"a","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}},
              {"id":"owned/b","model":"b","location":"b","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{}},
              {"id":"public/c","model":"c","location":"c","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":true},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0},"ratings":{}}
            ]}"#,
        )
        .expect("registry parses");

        let legacy = load_owned_cost_catalog(Some(&tco_yaml()), Some("owned/a"), &registry)
            .expect("legacy catalog loads");
        assert_eq!(legacy.cost_per_mtok("owned/a"), Some(1.0));
        assert_eq!(legacy.cost_per_mtok("owned/b"), None);

        let v2 = load_owned_cost_catalog(
            Some(
                r#"version: 2
supplies:
  owned/a: {monthly_amortization_usd: 100, monthly_power_usd: 0, monthly_ops_usd: 0, monthly_capacity_mtok: 100}
  owned/b: {monthly_amortization_usd: 300, monthly_power_usd: 0, monthly_ops_usd: 0, monthly_capacity_mtok: 100}
"#,
            ),
            Some("owned/a"),
            &registry,
        )
        .expect("v2 catalog loads");
        assert_eq!(v2.cost_per_mtok("owned/a"), Some(1.0));
        assert_eq!(v2.cost_per_mtok("owned/b"), Some(3.0));
        assert_eq!(v2.cost_per_mtok("missing"), None);

        for invalid in [
            "version: 2\nsupplies:\n  missing: {monthly_amortization_usd: 1, monthly_power_usd: 0, monthly_ops_usd: 0, monthly_capacity_mtok: 1}\n",
            "version: 2\nsupplies:\n  public/c: {monthly_amortization_usd: 1, monthly_power_usd: 0, monthly_ops_usd: 0, monthly_capacity_mtok: 1}\n",
        ] {
            assert!(load_owned_cost_catalog(Some(invalid), None, &registry).is_err());
        }
    }

    #[test]
    fn production_config_rejects_unsafe_values() {
        let invalid = [
            (
                "listen",
                valid_yaml().replace("0.0.0.0:8080", "not-a-socket"),
            ),
            (
                "upstream scheme",
                valid_yaml().replace("http://127.0.0.1:9999", "ftp://example.test"),
            ),
            (
                "connect timeout",
                valid_yaml().replace("connect_timeout_ms: 2000", "connect_timeout_ms: 0"),
            ),
            (
                "queue capacity",
                valid_yaml().replace("writer_queue_capacity: 1024", "writer_queue_capacity: 0"),
            ),
            (
                "accounting limit",
                valid_yaml().replace(
                    "accounting_limit_bytes: 2097152",
                    "accounting_limit_bytes: 0",
                ),
            ),
            (
                "segment bytes",
                valid_yaml().replace("ledger_segment_bytes: 67108864", "ledger_segment_bytes: 0"),
            ),
            (
                "segment bytes above compiled ceiling",
                valid_yaml().replace(
                    "ledger_segment_bytes: 67108864",
                    "ledger_segment_bytes: 67108865",
                ),
            ),
            (
                "segment count",
                valid_yaml().replace("ledger_max_segments: 32", "ledger_max_segments: 0"),
            ),
            (
                "segment count above compiled ceiling",
                valid_yaml().replace("ledger_max_segments: 32", "ledger_max_segments: 1025"),
            ),
            (
                "trusted proxy",
                valid_yaml().replace("127.0.0.0/8", "not-a-cidr"),
            ),
            (
                "actual supply",
                valid_yaml().replace(
                    "actual_supply_id: openai/gpt-5-mini",
                    "actual_supply_id: ''",
                ),
            ),
        ];

        for (name, yaml) in invalid {
            if let Ok(config) = Config::from_yaml(&yaml) {
                assert!(config.validate().is_err(), "{name} must fail validation");
            }
        }
    }

    #[test]
    fn non_loopback_listener_requires_trusted_proxy() {
        let yaml = valid_yaml().replace(
            "trusted_proxy_cidrs:\n  - 127.0.0.0/8",
            "trusted_proxy_cidrs: []",
        );
        let config = Config::from_yaml(&yaml).expect("fixture parses");

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidField {
                field: "trusted_proxy_cidrs",
                ..
            })
        ));
    }

    #[test]
    fn tco_rejects_negative_non_finite_and_zero_capacity() {
        for (field, yaml) in [
            (
                "monthly_amortization_usd",
                tco_yaml().replace(
                    "monthly_amortization_usd: 1200",
                    "monthly_amortization_usd: -1",
                ),
            ),
            (
                "monthly_power_usd",
                tco_yaml().replace("monthly_power_usd: 300", "monthly_power_usd: .inf"),
            ),
            (
                "monthly_capacity_mtok",
                tco_yaml().replace("monthly_capacity_mtok: 2000", "monthly_capacity_mtok: 0"),
            ),
        ] {
            let tco = load_tco(&yaml).expect("fixture parses");
            assert!(
                matches!(tco.validate(), Err(ConfigError::InvalidField { field: actual, .. }) if actual == field),
                "{field} must fail validation"
            );
        }
    }

    #[test]
    fn quality_floor_outside_unit_interval_is_rejected() {
        let yaml = format!("{}\nfloors:\n  judgment: 1.1\n", valid_yaml());
        let config = Config::from_yaml(&yaml).expect("fixture parses");

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidField {
                field: "floors",
                ..
            })
        ));
    }

    #[test]
    fn upstream_url_redaction_removes_userinfo_and_sensitive_query_values() {
        assert_eq!(
            redact_url("https://user:secret@example.test/v1?api_key=secret&region=us"),
            "https://example.test/v1?api_key=REDACTED&region=us"
        );
        assert_eq!(
            redact_url("https://example.test/v1?token=secret&password=secret&key=secret"),
            "https://example.test/v1?token=REDACTED&password=REDACTED&key=REDACTED"
        );
    }

    #[test]
    fn endpoint_identity_removes_credentials_query_and_fragment() {
        assert_eq!(
            endpoint_identity(
                "https://user:secret@example.test/v1?token=secret&region=us#fragment"
            ),
            "https://example.test/v1",
        );
    }

    #[test]
    fn endpoint_identity_is_stable_for_invalid_input() {
        assert_eq!(endpoint_identity("not a url"), "<invalid-url>");
    }

    #[test]
    fn upstream_rejects_userinfo_credentials() {
        for upstream in [
            "https://user@example.test/v1",
            "https://user:secret@example.test/v1",
        ] {
            let config =
                Config::from_yaml(&valid_yaml().replace("http://127.0.0.1:9999", upstream))
                    .expect("fixture parses");

            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidField {
                    field: "upstream",
                    ..
                })
            ));
        }
    }

    #[test]
    fn upstream_rejects_sensitive_query_credentials_case_insensitively() {
        for key in [
            "api_key",
            "apikey",
            "key",
            "token",
            "access_token",
            "password",
            "secret",
            "API_KEY",
        ] {
            let upstream = format!("https://example.test/v1?{key}=credential&region=us");
            let config =
                Config::from_yaml(&valid_yaml().replace("http://127.0.0.1:9999", &upstream))
                    .expect("fixture parses");

            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidField {
                    field: "upstream",
                    ..
                })
            ));
        }
    }

    #[test]
    fn upstream_rejects_common_credential_query_variants() {
        for key in [
            "x_api_key",
            "x-api-key",
            "X.Api.Key",
            "client_secret",
            "client-secret",
            "refresh_token",
            "refresh.token",
            "id_token",
            "authorization",
            "auth",
            "sig",
            "signature",
            "x_amz_signature",
            "X-Amz-Credential",
            "x.amz.security.token",
            "x_goog_signature",
            "X-Goog-Credential",
        ] {
            let upstream = format!("https://example.test/v1?{key}=credential&region=us");
            let config =
                Config::from_yaml(&valid_yaml().replace("http://127.0.0.1:9999", &upstream))
                    .expect("fixture parses");

            assert!(
                matches!(
                    config.validate(),
                    Err(ConfigError::InvalidField {
                        field: "upstream",
                        ..
                    })
                ),
                "{key} must fail validation"
            );
        }
    }

    #[test]
    fn upstream_redacts_common_credential_query_variants() {
        for key in [
            "x_api_key",
            "x-api-key",
            "X.Api.Key",
            "client_secret",
            "client-secret",
            "refresh_token",
            "refresh.token",
            "id_token",
            "authorization",
            "auth",
            "sig",
            "signature",
            "x_amz_signature",
            "X-Amz-Credential",
            "x.amz.security.token",
            "x_goog_signature",
            "X-Goog-Credential",
        ] {
            let upstream = format!("https://example.test/v1?{key}=credential&region=us");

            assert_eq!(
                redact_url(&upstream),
                format!("https://example.test/v1?{key}=REDACTED&region=us"),
                "{key} must be redacted"
            );
        }
    }

    #[test]
    fn upstream_allows_non_sensitive_query_parameters() {
        let config = Config::from_yaml(&valid_yaml().replace(
            "http://127.0.0.1:9999",
            "https://example.test/v1?api-version=2025-01-01&region=us&signature-version=v4&tokenizer=bpe",
        ))
        .expect("fixture parses");

        config.validate().expect("non-sensitive query is valid");
        assert_eq!(
            redact_url(&config.upstream),
            "https://example.test/v1?api-version=2025-01-01&region=us&signature-version=v4&tokenizer=bpe"
        );
    }

    fn valid_yaml() -> String {
        r#"listen: 0.0.0.0:8080
upstream: http://127.0.0.1:9999
actual_supply_id: openai/gpt-5-mini
policy_bundle: policies/default.yaml
registry_feed: registry/feed.json
ledger_dir: ./ledger
trusted_proxy_cidrs:
  - 127.0.0.0/8
runtime:
  connect_timeout_ms: 2000
  response_header_timeout_ms: 300000
  stream_idle_timeout_ms: 300000
  shutdown_grace_ms: 30000
  writer_queue_capacity: 1024
  accounting_limit_bytes: 2097152
  ledger_segment_bytes: 67108864
  ledger_max_segments: 32
"#
        .to_string()
    }

    fn tco_yaml() -> String {
        r#"monthly_amortization_usd: 1200
monthly_power_usd: 300
monthly_ops_usd: 500
monthly_capacity_mtok: 2000
"#
        .to_string()
    }
}
