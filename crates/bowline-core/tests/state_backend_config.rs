use bowline_core::config::{Config, StateBackendConfig};

const BASE: &str = r#"
listen: 127.0.0.1:3000
upstream: http://127.0.0.1:11434
actual_supply_id: local/test
policy_bundle: policy.yaml
registry_feed: registry.json
ledger_dir: ledger
"#;

#[test]
fn absent_state_backend_preserves_local_default() {
    let config = Config::from_yaml(BASE).unwrap();

    assert_eq!(config.state_backend, None);
    config.validate().unwrap();
}

#[test]
fn versioned_local_state_backend_is_accepted() {
    let config = Config::from_yaml(&format!(
        "{BASE}\nstate_backend:\n  version: 1\n  kind: local\n"
    ))
    .unwrap();

    assert_eq!(
        config.state_backend,
        Some(StateBackendConfig::Local { version: 1 })
    );
    config.validate().unwrap();
}

#[test]
fn state_backend_version_and_kind_are_strict() {
    let wrong_version = Config::from_yaml(&format!(
        "{BASE}\nstate_backend:\n  version: 2\n  kind: local\n"
    ))
    .unwrap();
    assert!(wrong_version.validate().is_err());

    assert!(Config::from_yaml(&format!(
        "{BASE}\nstate_backend:\n  version: 1\n  kind: distributed\n"
    ))
    .is_err());
}
