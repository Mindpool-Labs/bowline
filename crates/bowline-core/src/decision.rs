use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::OwnedCostCatalog;
use crate::policy::{PolicyBundle, WorkloadIdentity};
use crate::supply::{Price, Registry, SupplyClass, SupplyEntry, TaskClass};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityFloors(pub BTreeMap<TaskClass, f32>);

impl Default for QualityFloors {
    fn default() -> Self {
        Self(BTreeMap::from([
            (TaskClass::Mechanical, 0.30),
            (TaskClass::HeavyLifting, 0.55),
            (TaskClass::TasteSensitive, 0.70),
            (TaskClass::Judgment, 0.85),
            (TaskClass::Unclassified, 0.55),
        ]))
    }
}

impl QualityFloors {
    fn floor_for(&self, task_class: TaskClass) -> f32 {
        self.0
            .get(&task_class)
            .copied()
            .or_else(|| QualityFloors::default().0.get(&task_class).copied())
            .unwrap_or(0.55)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Placement {
    pub supply_id: String,
    pub est_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub policy_digest: String,
    pub task_class: TaskClass,
    pub feasible_ids: Vec<String>,
    pub floor: f32,
    pub shadow: Option<Placement>,
}

/// Pure, deterministic shadow allocator for the post-policy feasible set.
// The 8-parameter signature is the plan-normative Phase 1 public surface.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    bundle: &PolicyBundle,
    registry: &Registry,
    floors: &QualityFloors,
    identity: &WorkloadIdentity,
    declared_task_class: Option<TaskClass>,
    est_input_tokens: u64,
    est_output_tokens: u64,
    owned_costs: &OwnedCostCatalog,
) -> Decision {
    let task_class = declared_task_class.unwrap_or_else(|| bundle.task_class_for(identity));
    let floor = floors.floor_for(task_class);
    let feasible = bundle.feasible(identity, registry);
    let feasible_ids = feasible.iter().map(|entry| entry.id.clone()).collect();
    let shadow = choose_shadow(
        &feasible,
        task_class,
        floor,
        est_input_tokens,
        est_output_tokens,
        owned_costs,
    );

    Decision {
        policy_digest: bundle.digest().to_string(),
        task_class,
        feasible_ids,
        floor,
        shadow,
    }
}

pub fn est_cost_usd(price: &Price, input_tokens: u64, output_tokens: u64) -> f64 {
    let input_mtok = input_tokens as f64 / 1_000_000.0;
    let output_mtok = output_tokens as f64 / 1_000_000.0;

    (input_mtok * price.input_per_mtok_usd) + (output_mtok * price.output_per_mtok_usd)
}

fn choose_shadow(
    feasible: &[&SupplyEntry],
    task_class: TaskClass,
    floor: f32,
    est_input_tokens: u64,
    est_output_tokens: u64,
    owned_costs: &OwnedCostCatalog,
) -> Option<Placement> {
    feasible
        .iter()
        .filter(|entry| entry.available != Some(false))
        .filter(|entry| entry.ratings.get(&task_class).copied().unwrap_or(0.0) >= floor)
        .filter_map(|entry| {
            entry_est_cost(entry, est_input_tokens, est_output_tokens, owned_costs)
                .map(|cost| (*entry, cost))
        })
        .min_by(|(left, left_cost), (right, right_cost)| {
            left_cost
                .total_cmp(right_cost)
                .then_with(|| left.id.cmp(&right.id))
        })
        .map(|(entry, est_cost_usd)| Placement {
            supply_id: entry.id.clone(),
            est_cost_usd: Some(est_cost_usd),
        })
}

fn entry_est_cost(
    entry: &SupplyEntry,
    input_tokens: u64,
    output_tokens: u64,
    owned_costs: &OwnedCostCatalog,
) -> Option<f64> {
    entry.price.as_ref().map_or_else(
        || {
            (entry.attributes.class == SupplyClass::Owned).then(|| {
                owned_costs.cost_per_mtok(&entry.id).map(|cost_per_mtok| {
                    let total_mtok = (input_tokens as f64 + output_tokens as f64) / 1_000_000.0;
                    total_mtok * cost_per_mtok
                })
            })?
        },
        |price| Some(est_cost_usd(price, input_tokens, output_tokens)),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn owned_cost(registry: &Registry, cost: f64) -> OwnedCostCatalog {
        let supply_id = registry
            .entries
            .iter()
            .find(|entry| entry.attributes.class == SupplyClass::Owned)
            .expect("test registry has owned supply")
            .id
            .clone();
        OwnedCostCatalog::for_test(BTreeMap::from([(supply_id, cost)]))
    }
    use crate::policy::{PolicyBundle, WorkloadIdentity};
    use crate::supply::{
        Price, Registry, Retention, SupplyAttributes, SupplyClass, SupplyEntry, TaskClass,
    };

    fn identity() -> WorkloadIdentity {
        WorkloadIdentity {
            api_key_digest: None,
            route: "/v1/chat/completions".to_string(),
            app: Some("task-runner".to_string()),
            tags: Vec::new(),
        }
    }

    fn allow_all_policy(task_class: Option<TaskClass>) -> PolicyBundle {
        let task_class_yaml = task_class
            .map(|class| format!("    task_class: {}\n", task_class_yaml(class)))
            .unwrap_or_default();
        let yaml = format!(
            r#"
version: 1
rules:
  - name: default
    default: true
{task_class_yaml}    require:
      supply_class: [owned, vpc-open-weights, vpc-frontier, public-api]
"#
        );

        PolicyBundle::from_yaml(&yaml).expect("policy should parse")
    }

    fn public_only_policy() -> PolicyBundle {
        PolicyBundle::from_yaml(
            r#"
version: 1
rules:
  - name: default
    default: true
    require:
      supply_class: [public-api]
"#,
        )
        .expect("policy should parse")
    }

    fn task_class_yaml(class: TaskClass) -> &'static str {
        match class {
            TaskClass::Mechanical => "mechanical",
            TaskClass::HeavyLifting => "heavy-lifting",
            TaskClass::TasteSensitive => "taste-sensitive",
            TaskClass::Judgment => "judgment",
            TaskClass::Unclassified => "unclassified",
        }
    }

    fn registry(entries: Vec<SupplyEntry>) -> Registry {
        Registry {
            note: None,
            feed_version: "test".to_string(),
            entries,
        }
    }

    fn entry(id: &str, class: SupplyClass, price: Option<Price>, rating: f32) -> SupplyEntry {
        SupplyEntry {
            id: id.to_string(),
            model: id.to_string(),
            aliases: Vec::new(),
            location: "test".to_string(),
            attributes: SupplyAttributes {
                class,
                jurisdiction: "local".to_string(),
                retention: Retention::None,
                training_use: false,
                cloud_act_exposure: false,
            },
            price,
            ratings: BTreeMap::from([
                (TaskClass::Mechanical, rating),
                (TaskClass::HeavyLifting, rating),
                (TaskClass::TasteSensitive, rating),
                (TaskClass::Judgment, rating),
                (TaskClass::Unclassified, rating),
            ]),
            available: Some(true),
        }
    }

    fn price(input_per_mtok_usd: f64, output_per_mtok_usd: f64) -> Price {
        Price {
            input_per_mtok_usd,
            output_per_mtok_usd,
        }
    }

    #[test]
    fn cheapest_clearing_supply_wins() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry(
                "frontier/expensive",
                SupplyClass::PublicApi,
                Some(price(1.0, 2.0)),
                0.9,
            ),
            entry(
                "frontier/cheap",
                SupplyClass::PublicApi,
                Some(price(0.2, 0.4)),
                0.9,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            1_000_000,
            &OwnedCostCatalog::default(),
        );

        let shadow = decision.shadow.expect("a supply should clear");
        assert_eq!(decision.task_class, TaskClass::Mechanical);
        assert_eq!(decision.floor, 0.30);
        assert_eq!(
            decision.feasible_ids,
            vec!["frontier/expensive", "frontier/cheap"]
        );
        assert_eq!(shadow.supply_id, "frontier/cheap");
        assert!(
            (shadow.est_cost_usd.expect("cost should be estimated") - 0.6).abs() < f64::EPSILON
        );
    }

    #[test]
    fn below_floor_supply_excluded() {
        let bundle = allow_all_policy(Some(TaskClass::Judgment));
        let registry = registry(vec![
            entry(
                "frontier/mini",
                SupplyClass::PublicApi,
                Some(price(0.01, 0.01)),
                0.84,
            ),
            entry(
                "frontier/judgment",
                SupplyClass::PublicApi,
                Some(price(1.0, 1.0)),
                0.86,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        assert_eq!(
            decision
                .shadow
                .expect("judgment supply should clear")
                .supply_id,
            "frontier/judgment"
        );
    }

    #[test]
    fn no_feasible_supply_yields_none() {
        let bundle = public_only_policy();
        let registry = registry(vec![entry("local/owned", SupplyClass::Owned, None, 0.99)]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            Some(TaskClass::Mechanical),
            1_000,
            1_000,
            &OwnedCostCatalog::default(),
        );

        assert!(decision.feasible_ids.is_empty());
        assert!(decision.shadow.is_none());
    }

    #[test]
    fn owned_supply_costed_from_tco() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry("local/qwen", SupplyClass::Owned, None, 0.9),
            entry(
                "frontier/api",
                SupplyClass::PublicApi,
                Some(price(2.0, 0.0)),
                0.95,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &owned_cost(&registry, 0.9),
        );

        let shadow = decision.shadow.expect("owned supply should clear");
        assert_eq!(shadow.supply_id, "local/qwen");
        assert_eq!(shadow.est_cost_usd, Some(0.9));
    }

    #[test]
    fn declared_task_class_overrides_rule() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry(
                "frontier/mini",
                SupplyClass::PublicApi,
                Some(price(0.1, 0.0)),
                0.84,
            ),
            entry(
                "frontier/judgment",
                SupplyClass::PublicApi,
                Some(price(1.0, 0.0)),
                0.86,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            Some(TaskClass::Judgment),
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        assert_eq!(decision.task_class, TaskClass::Judgment);
        assert_eq!(decision.floor, 0.85);
        assert_eq!(
            decision
                .shadow
                .expect("judgment supply should clear")
                .supply_id,
            "frontier/judgment"
        );
    }

    #[test]
    fn deterministic_tie_break() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry(
                "supply/b",
                SupplyClass::PublicApi,
                Some(price(1.0, 0.0)),
                0.9,
            ),
            entry(
                "supply/a",
                SupplyClass::PublicApi,
                Some(price(1.0, 0.0)),
                0.9,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        assert_eq!(
            decision
                .shadow
                .expect("one tied supply should win")
                .supply_id,
            "supply/a"
        );
    }

    #[test]
    fn unavailable_supply_excluded() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let mut unavailable = entry(
            "frontier/unavailable",
            SupplyClass::PublicApi,
            Some(price(0.01, 0.0)),
            0.9,
        );
        unavailable.available = Some(false);
        let registry = registry(vec![
            unavailable,
            entry(
                "frontier/available",
                SupplyClass::PublicApi,
                Some(price(1.0, 0.0)),
                0.9,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        assert_eq!(
            decision
                .shadow
                .expect("available supply should clear")
                .supply_id,
            "frontier/available"
        );
    }

    #[test]
    fn quality_floors_default_values_are_exact() {
        let floors = QualityFloors::default();

        assert_eq!(floors.0.get(&TaskClass::Mechanical), Some(&0.30));
        assert_eq!(floors.0.get(&TaskClass::HeavyLifting), Some(&0.55));
        assert_eq!(floors.0.get(&TaskClass::TasteSensitive), Some(&0.70));
        assert_eq!(floors.0.get(&TaskClass::Judgment), Some(&0.85));
        assert_eq!(floors.0.get(&TaskClass::Unclassified), Some(&0.55));
    }

    #[test]
    fn no_declared_header_and_no_rule_task_class_falls_back_to_unclassified() {
        let bundle = allow_all_policy(None);
        let registry = registry(vec![entry(
            "frontier/default",
            SupplyClass::PublicApi,
            Some(price(1.0, 0.0)),
            0.9,
        )]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        assert_eq!(decision.task_class, TaskClass::Unclassified);
        assert_eq!(decision.floor, 0.55);
    }

    #[test]
    fn known_cost_wins_over_priceless_owned_supply_without_tco() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry("local/owned", SupplyClass::Owned, None, 0.9),
            entry(
                "frontier/api",
                SupplyClass::PublicApi,
                Some(price(0.01, 0.0)),
                0.9,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        let shadow = decision.shadow.expect("priced supply should win");
        assert_eq!(shadow.supply_id, "frontier/api");
        assert_eq!(shadow.est_cost_usd, Some(0.01));
    }

    #[test]
    fn all_priceless_supplies_produce_no_cost_optimized_placement() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry("local/owned", SupplyClass::Owned, None, 0.9),
            entry("vpc/open", SupplyClass::VpcOpenWeights, None, 0.9),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::default(),
        );

        assert!(decision.shadow.is_none());
    }

    #[test]
    fn non_owned_priceless_supply_does_not_use_owned_tco_and_cannot_win_cost_optimization() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![
            entry("vpc/open", SupplyClass::VpcOpenWeights, None, 0.9),
            entry(
                "frontier/api",
                SupplyClass::PublicApi,
                Some(price(2.0, 0.0)),
                0.9,
            ),
        ]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            1_000_000,
            0,
            &OwnedCostCatalog::for_test(BTreeMap::from([("unrelated/owned".to_string(), 0.9)])),
        );

        let shadow = decision.shadow.expect("priced supply should win");
        assert_eq!(shadow.supply_id, "frontier/api");
        assert_eq!(shadow.est_cost_usd, Some(2.0));
    }

    #[test]
    fn owned_tco_cost_uses_float_math_for_extreme_token_estimates() {
        let bundle = allow_all_policy(Some(TaskClass::Mechanical));
        let registry = registry(vec![entry("local/owned", SupplyClass::Owned, None, 0.9)]);

        let decision = decide(
            &bundle,
            &registry,
            &QualityFloors::default(),
            &identity(),
            None,
            u64::MAX,
            1,
            &owned_cost(&registry, 0.9),
        );

        let cost = decision
            .shadow
            .expect("owned supply should clear")
            .est_cost_usd
            .expect("owned TCO should estimate cost");
        assert!(cost.is_finite());
        assert!(cost > 0.0);
    }
}
