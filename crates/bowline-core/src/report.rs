use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::OwnedCostCatalog;
use crate::decision::{est_cost_usd, QualityFloors};
use crate::enforcement::{PlanTarget, RouteMode};
use crate::ledger::{
    modeled_delta_applicable, AuthorityRecordV2, CompletionStateV2, DecisionRecord,
    RecoveryOutcome, ValidatedAuthorityDiagnosticRunReadV2, ValidatedAuthorityRunReadV2,
};
use crate::run::RunManifest;
use crate::supply::{Registry, SupplyClass, SupplyEntry, TaskClass};
use crate::traffic::{CoverageStatus, ObservationSource, ProtocolKind};

const UNASSIGNED_DIMENSION: &str = "unassigned";
const AMBIGUOUS_DIMENSION: &str = "ambiguous";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledEnforcementReport {
    pub schema_version: u32,
    pub authority_schema_version: u32,
    pub complete: bool,
    pub run_id: String,
    pub records_digest: String,
    pub totals: ControlledEnforcementTotals,
    pub by_mode: Vec<ControlledEnforcementModeRow>,
    pub shadow_opportunity: Option<ShadowOpportunitySummary>,
    /// Present only when the operator supplies a reprocessing manifest. Absent, the report
    /// serializes exactly as it did before this section existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reprocessing: Option<ReprocessingSection>,
}

pub const REPROCESSING_SCHEMA_VERSION: u32 = 1;
pub const MAX_REPROCESSING_YAML_BYTES: usize = 64 * 1024;
const PPM: u128 = 1_000_000;
const MIN_CACHE_WRITE_PPM: u64 = 1_000_000;
const MAX_CACHE_WRITE_PPM: u64 = 4_000_000;

/// Operator-supplied prices and cache ratios for the modeled context-reprocessing section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReprocessingManifest {
    pub schema_version: u32,
    /// Share of a non-switch step's input that the model reads from its prompt cache.
    pub steady_cache_hit_ppm: u64,
    pub targets: ReprocessingTargets,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReprocessingTargets {
    pub capable: ReprocessingTargetRate,
    pub efficient: ReprocessingTargetRate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReprocessingTargetRate {
    pub input_per_mtok_usd: f64,
    pub output_per_mtok_usd: f64,
    /// Cache-read price as a fraction of the input price.
    pub cache_read_ppm: u64,
    /// Cache-write price as a fraction of the input price.
    pub cache_write_ppm: u64,
}

#[derive(Debug, Error)]
pub enum ReprocessingManifestError {
    #[error("reprocessing manifest exceeds {MAX_REPROCESSING_YAML_BYTES} bytes")]
    InputLimit,
    #[error("failed to parse reprocessing manifest: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid reprocessing manifest")]
    Invalid,
}

impl ReprocessingManifest {
    pub fn from_yaml(input: &str) -> Result<Self, ReprocessingManifestError> {
        if input.len() > MAX_REPROCESSING_YAML_BYTES {
            return Err(ReprocessingManifestError::InputLimit);
        }
        let value: Self = serde_yaml::from_str(input)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ReprocessingManifestError> {
        if self.schema_version != REPROCESSING_SCHEMA_VERSION
            || u128::from(self.steady_cache_hit_ppm) > PPM
            || !self.targets.capable.valid()
            || !self.targets.efficient.valid()
        {
            return Err(ReprocessingManifestError::Invalid);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ReprocessingManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ReprocessingManifestError::Invalid)?;
        Ok(crate::billing::domain_digest(
            b"bowline.report.reprocessing.v1",
            &bytes,
        ))
    }

    fn pricing(
        &self,
        target: crate::routing::RoutingTarget,
    ) -> Result<ReprocessingPricing, ReprocessingManifestError> {
        let rate = match target {
            crate::routing::RoutingTarget::Capable => &self.targets.capable,
            crate::routing::RoutingTarget::Efficient => &self.targets.efficient,
        };
        let hit = u128::from(self.steady_cache_hit_ppm);
        let read = u128::from(rate.cache_read_ppm);
        let write = u128::from(rate.cache_write_ppm);
        let micros = |usd| {
            crate::economics::float_usd_to_micros(usd)
                .map(u128::from)
                .map_err(|_| ReprocessingManifestError::Invalid)
        };
        Ok(ReprocessingPricing {
            input_micros: micros(rate.input_per_mtok_usd)?,
            output_micros: micros(rate.output_per_mtok_usd)?,
            steady_ppm2: hit * read + (PPM - hit) * write,
            miss_ppm2: write * PPM,
        })
    }
}

impl ReprocessingTargetRate {
    fn valid(&self) -> bool {
        [self.input_per_mtok_usd, self.output_per_mtok_usd]
            .into_iter()
            .all(|rate| {
                rate.is_finite()
                    && (0.0..=crate::economics::MAX_COST_RATE_USD_PER_MTOK).contains(&rate)
            })
            && self.cache_read_ppm <= crate::economics::MAX_PPM
            && (MIN_CACHE_WRITE_PPM..=MAX_CACHE_WRITE_PPM).contains(&self.cache_write_ppm)
    }
}

/// Integer prices for one target. Multipliers are in ppm squared (1e12 = 1x) so that the
/// steady mix `h * read + (1 - h) * write` stays exact.
struct ReprocessingPricing {
    input_micros: u128,
    output_micros: u128,
    steady_ppm2: u128,
    miss_ppm2: u128,
}

impl ReprocessingPricing {
    /// Rounds half-up to whole micros once per step, as `CostRateMicros::cost_micros` does.
    fn cost_micros(&self, input: u64, output: u64, multiplier_ppm2: u128) -> Option<u64> {
        let input_term = u128::from(input)
            .checked_mul(self.input_micros)?
            .checked_mul(multiplier_ppm2)?;
        let output_term = u128::from(output)
            .checked_mul(self.output_micros)?
            .checked_mul(PPM * PPM)?;
        let rounded = input_term
            .checked_add(output_term)?
            .checked_add(PPM * PPM * PPM / 2)?
            / (PPM * PPM * PPM);
        u64::try_from(rounded).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReprocessingStatus {
    Available,
    Incomplete,
}

/// Modeled, cache-adjusted pricing of routed tasks. Every switch step is priced as a full cache
/// miss on the target the task switches to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReprocessingSection {
    pub manifest_digest: String,
    pub status: ReprocessingStatus,
    pub tasks: u64,
    pub routed_steps: u64,
    pub cold_steps: u64,
    pub switch_steps: u64,
    pub steady_steps: u64,
    pub switches_to_efficient: u64,
    pub switches_to_capable: u64,
    /// Routed outcomes that never reached a model: rejected before dispatch or fail-closed.
    pub excluded_undispatched_steps: u64,
    pub reprocessing_cost_micros: Option<u64>,
    pub cache_adjusted_enforced_cost_micros: Option<u64>,
    pub cache_adjusted_counterfactual_cost_micros: Option<u64>,
    /// Counterfactual minus enforced.
    #[serde(with = "controlled_optional_i128")]
    pub cache_adjusted_delta_micros: Option<i128>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledEnforcementTotals {
    pub decisions: u64,
    pub candidate_dispatches: u64,
    pub pre_dispatch_rejections: u64,
    pub bypasses: u64,
    pub fail_closed: u64,
    pub failures: u64,
    /// Failures of a candidate dispatch only. Original-path failures remain in `failures`.
    /// Absent, and defaulted to 0, in every schema-v1 report a v1 crate wrote.
    #[serde(default)]
    pub candidate_failures: u64,
    pub cancellations: u64,
    pub incomplete: u64,
    /// Routed decisions are counted by semantic routing result. They are not folded into
    /// authority bypass or candidate-dispatch counts. Absent, and defaulted to 0, in every
    /// schema-v1 report: routing did not exist when schema_version stayed 1.
    #[serde(default)]
    pub routing_capable: u64,
    #[serde(default)]
    pub routing_efficient: u64,
    #[serde(default)]
    pub routing_unavailable: u64,
    pub observed_enforced_cost_micros: Option<u64>,
    #[serde(with = "controlled_optional_i64")]
    pub enforced_modeled_delta_micros: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledEnforcementModeRow {
    pub mode: RouteMode,
    pub totals: ControlledEnforcementTotals,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowOpportunitySummary {
    pub groups: u64,
    #[serde(with = "controlled_optional_i128")]
    pub modeled_delta_micros: Option<i128>,
}

mod controlled_optional_i128 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<i128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|value| value.to_string()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i128>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

mod controlled_optional_i64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|value| value.to_string()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlledEnforcementReportError {
    #[error("controlled-enforcement report metric overflow: {metric}")]
    MetricOverflow { metric: &'static str },
    #[error("invalid reprocessing manifest")]
    InvalidReprocessingManifest,
}

pub fn compute_controlled_enforcement_report(
    run: &ValidatedAuthorityRunReadV2,
) -> Result<ControlledEnforcementReport, ControlledEnforcementReportError> {
    aggregate_controlled_enforcement_report(
        run.complete().run_id(),
        run.complete().records_digest(),
        run.records(),
        true,
    )
}

fn aggregate_controlled_enforcement_report(
    run_id: &str,
    records_digest: &str,
    records: &[AuthorityRecordV2],
    complete: bool,
) -> Result<ControlledEnforcementReport, ControlledEnforcementReportError> {
    let mut by_mode = Vec::<(RouteMode, ControlledAccumulator)>::new();
    let mut totals = ControlledAccumulator::default();
    for record in records {
        let AuthorityRecordV2::Outcome { outcome, .. } = record else {
            continue;
        };
        let index = by_mode
            .iter()
            .position(|(mode, _)| *mode == outcome.mode)
            .unwrap_or_else(|| {
                by_mode.push((outcome.mode, ControlledAccumulator::default()));
                by_mode.len() - 1
            });
        by_mode[index].1.accumulate(outcome)?;
        totals.accumulate(outcome)?;
    }
    by_mode.sort_by_key(|(mode, _)| serde_json::to_string(mode).unwrap_or_default());
    let by_mode = by_mode
        .into_iter()
        .map(|(mode, accumulator)| ControlledEnforcementModeRow {
            mode,
            totals: accumulator.finish(),
        })
        .collect();
    Ok(ControlledEnforcementReport {
        schema_version: 2,
        authority_schema_version: if records.iter().any(|record| record.schema_version() == 3) {
            3
        } else {
            2
        },
        complete,
        run_id: run_id.to_owned(),
        records_digest: records_digest.to_owned(),
        totals: totals.finish(),
        by_mode,
        // Ledger reporting has no opaque validated economics join. Never fabricate an
        // opportunity total.
        shadow_opportunity: None,
        reprocessing: None,
    })
}

/// Computes the modeled reprocessing section for a validated authority run. The caller attaches
/// it to the report; without a manifest the report carries no such section.
pub fn compute_reprocessing_section(
    run: &ValidatedAuthorityDiagnosticRunReadV2,
    manifest: &ReprocessingManifest,
) -> Result<ReprocessingSection, ControlledEnforcementReportError> {
    aggregate_reprocessing_section(run.records(), run.is_complete(), manifest)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepClass {
    Cold,
    Switch,
    Steady,
}

fn aggregate_reprocessing_section(
    records: &[AuthorityRecordV2],
    complete: bool,
    manifest: &ReprocessingManifest,
) -> Result<ReprocessingSection, ControlledEnforcementReportError> {
    use crate::routing::RoutingTarget;

    let overflow =
        |metric: &'static str| ControlledEnforcementReportError::MetricOverflow { metric };
    let invalid = |_| ControlledEnforcementReportError::InvalidReprocessingManifest;
    let manifest_digest = manifest.digest().map_err(invalid)?;
    let capable = manifest.pricing(RoutingTarget::Capable).map_err(invalid)?;
    let efficient = manifest
        .pricing(RoutingTarget::Efficient)
        .map_err(invalid)?;
    let outcomes = records.iter().filter_map(|record| match record {
        AuthorityRecordV2::Outcome { outcome, .. } => Some(outcome),
        AuthorityRecordV2::Decision { .. } => None,
    });
    fn routed_step(outcome: &crate::ledger::AuthorityOutcomeV2) -> Option<(&str, u64)> {
        match outcome.routing.as_ref() {
            Some(crate::ledger::AuthorityRoutingBindingV3::Decision {
                task_reference_digest,
                step_id,
                ..
            }) => Some((task_reference_digest.as_str(), *step_id)),
            _ => None,
        }
    }
    // A replacement dispatch carries no routing binding. Run validation links it exactly once to
    // the candidate it replaced, so it inherits that candidate's (task, step) in any record order.
    let step_by_decision: BTreeMap<&str, (&str, u64)> = outcomes
        .clone()
        .filter_map(|outcome| Some((outcome.decision_id.as_str(), routed_step(outcome)?)))
        .collect();
    let mut excluded_undispatched_steps = 0_u64;
    let mut steps = Vec::new();
    for outcome in outcomes {
        let step = routed_step(outcome).or_else(|| {
            outcome
                .replaces_decision_id
                .as_deref()
                .and_then(|replaced| step_by_decision.get(replaced).copied())
        });
        let Some((task_reference_digest, step_id)) = step else {
            continue;
        };
        // Price the model that served the step, not the semantic target: routing can only force
        // capable, and observe, recommend, and grant loss serve `Original` for an efficient step.
        let served = match (outcome.actual_dispatch, outcome.target) {
            (0, _) | (_, PlanTarget::None) => None,
            (_, PlanTarget::Candidate) => Some(RoutingTarget::Efficient),
            (_, PlanTarget::Original) => Some(RoutingTarget::Capable),
        };
        match served {
            Some(served) => steps.push((task_reference_digest, step_id, served, outcome)),
            // A fail-closed replacement's step is already counted through its rejected candidate.
            None if routed_step(outcome).is_none() => {}
            None => ControlledAccumulator::increment(
                &mut excluded_undispatched_steps,
                "excluded_undispatched_steps",
            )?,
        }
    }
    // Per (task, step): whether a capable model served it, and whether an efficient one did.
    let seen = |target: &RoutingTarget| match target {
        RoutingTarget::Capable => [true, false],
        RoutingTarget::Efficient => [false, true],
    };
    let mut targets_by_step = BTreeMap::<(&str, u64), [bool; 2]>::new();
    for (task, step_id, target, _) in &steps {
        let entry = targets_by_step.entry((*task, *step_id)).or_default();
        let target = seen(target);
        entry[0] |= target[0];
        entry[1] |= target[1];
    }
    let tasks = targets_by_step
        .keys()
        .map(|(task, _)| *task)
        .collect::<BTreeSet<_>>()
        .len();
    let costs_available = complete
        && steps.iter().all(|(_, _, _, outcome)| {
            outcome.input_tokens.is_some() && outcome.output_tokens.is_some()
        });

    let mut section = ReprocessingSection {
        manifest_digest,
        status: if costs_available {
            ReprocessingStatus::Available
        } else {
            ReprocessingStatus::Incomplete
        },
        tasks: u64::try_from(tasks).map_err(|_| overflow("tasks"))?,
        routed_steps: 0,
        cold_steps: 0,
        switch_steps: 0,
        steady_steps: 0,
        switches_to_efficient: 0,
        switches_to_capable: 0,
        excluded_undispatched_steps,
        reprocessing_cost_micros: None,
        cache_adjusted_enforced_cost_micros: None,
        cache_adjusted_counterfactual_cost_micros: None,
        cache_adjusted_delta_micros: None,
    };
    let (mut reprocessing, mut enforced, mut counterfactual) = (0_u64, 0_u64, 0_u64);
    for (task, step_id, target, outcome) in &steps {
        ControlledAccumulator::increment(&mut section.routed_steps, "routed_steps")?;
        // An absent predecessor is priced as a miss: that never overstates the saving.
        let class = if *step_id == 1 {
            StepClass::Cold
        } else if targets_by_step
            .get(&(*task, step_id - 1))
            .is_some_and(|previous| *previous == seen(target))
        {
            StepClass::Steady
        } else {
            StepClass::Switch
        };
        match class {
            StepClass::Cold => {
                ControlledAccumulator::increment(&mut section.cold_steps, "cold_steps")?
            }
            StepClass::Steady => {
                ControlledAccumulator::increment(&mut section.steady_steps, "steady_steps")?
            }
            StepClass::Switch => {
                ControlledAccumulator::increment(&mut section.switch_steps, "switch_steps")?;
                match target {
                    RoutingTarget::Efficient => ControlledAccumulator::increment(
                        &mut section.switches_to_efficient,
                        "switches_to_efficient",
                    )?,
                    RoutingTarget::Capable => ControlledAccumulator::increment(
                        &mut section.switches_to_capable,
                        "switches_to_capable",
                    )?,
                }
            }
        }
        if !costs_available {
            continue;
        }
        let (Some(input), Some(output)) = (outcome.input_tokens, outcome.output_tokens) else {
            continue;
        };
        let pricing = match target {
            RoutingTarget::Capable => &capable,
            RoutingTarget::Efficient => &efficient,
        };
        let enforced_multiplier = match class {
            StepClass::Cold | StepClass::Switch => pricing.miss_ppm2,
            StepClass::Steady => pricing.steady_ppm2,
        };
        let counterfactual_multiplier = match class {
            StepClass::Cold => capable.miss_ppm2,
            StepClass::Switch | StepClass::Steady => capable.steady_ppm2,
        };
        let step_enforced = pricing
            .cost_micros(input, output, enforced_multiplier)
            .ok_or(overflow("cache_adjusted_enforced_cost_micros"))?;
        let step_counterfactual = capable
            .cost_micros(input, output, counterfactual_multiplier)
            .ok_or(overflow("cache_adjusted_counterfactual_cost_micros"))?;
        enforced = enforced
            .checked_add(step_enforced)
            .ok_or(overflow("cache_adjusted_enforced_cost_micros"))?;
        counterfactual = counterfactual
            .checked_add(step_counterfactual)
            .ok_or(overflow("cache_adjusted_counterfactual_cost_micros"))?;
        if class == StepClass::Switch {
            let step_reprocessing = pricing
                .cost_micros(input, 0, pricing.miss_ppm2 - pricing.steady_ppm2)
                .ok_or(overflow("reprocessing_cost_micros"))?;
            reprocessing = reprocessing
                .checked_add(step_reprocessing)
                .ok_or(overflow("reprocessing_cost_micros"))?;
        }
    }
    if costs_available {
        section.reprocessing_cost_micros = Some(reprocessing);
        section.cache_adjusted_enforced_cost_micros = Some(enforced);
        section.cache_adjusted_counterfactual_cost_micros = Some(counterfactual);
        section.cache_adjusted_delta_micros =
            Some(i128::from(counterfactual) - i128::from(enforced));
    }
    Ok(section)
}

pub fn compute_controlled_enforcement_diagnostic_report(
    run: &ValidatedAuthorityDiagnosticRunReadV2,
) -> Result<ControlledEnforcementReport, ControlledEnforcementReportError> {
    let complete = run.is_complete();
    let mut report = aggregate_controlled_enforcement_report(
        run.diagnostics().run_id(),
        run.diagnostics().records_digest(),
        run.records(),
        complete,
    )?;
    report.complete = complete;
    if !complete {
        report.totals.observed_enforced_cost_micros = None;
        report.totals.enforced_modeled_delta_micros = None;
        for row in &mut report.by_mode {
            row.totals.observed_enforced_cost_micros = None;
            row.totals.enforced_modeled_delta_micros = None;
        }
    }
    Ok(report)
}

struct ControlledAccumulator {
    totals: ControlledEnforcementTotals,
    applicable: u64,
    cost_complete: bool,
    delta_complete: bool,
}

impl Default for ControlledAccumulator {
    fn default() -> Self {
        Self {
            totals: ControlledEnforcementTotals::default(),
            applicable: 0,
            cost_complete: true,
            delta_complete: true,
        }
    }
}

impl ControlledAccumulator {
    fn increment(
        value: &mut u64,
        metric: &'static str,
    ) -> Result<(), ControlledEnforcementReportError> {
        *value = value
            .checked_add(1)
            .ok_or(ControlledEnforcementReportError::MetricOverflow { metric })?;
        Ok(())
    }

    fn accumulate(
        &mut self,
        outcome: &crate::ledger::AuthorityOutcomeV2,
    ) -> Result<(), ControlledEnforcementReportError> {
        Self::increment(&mut self.totals.decisions, "decisions")?;
        if outcome.target == PlanTarget::Candidate && outcome.actual_dispatch == 1 {
            Self::increment(
                &mut self.totals.candidate_dispatches,
                "candidate_dispatches",
            )?;
        }
        if outcome.mode.grants_authority() && outcome.target == PlanTarget::Original {
            Self::increment(&mut self.totals.bypasses, "bypasses")?;
        }
        if outcome.mode.grants_authority() && outcome.target == PlanTarget::None {
            Self::increment(&mut self.totals.fail_closed, "fail_closed")?;
        }
        if outcome.candidate_failure.is_some() {
            Self::increment(&mut self.totals.candidate_failures, "candidate_failures")?;
        }
        if let Some(crate::ledger::AuthorityRoutingBindingV3::Decision {
            semantic_target, ..
        }) = outcome.routing.as_ref()
        {
            match semantic_target {
                crate::routing::RoutingTarget::Capable => {
                    Self::increment(&mut self.totals.routing_capable, "routing_capable")?
                }
                crate::routing::RoutingTarget::Efficient => {
                    Self::increment(&mut self.totals.routing_efficient, "routing_efficient")?
                }
            }
        }
        if matches!(
            outcome.routing.as_ref(),
            Some(crate::ledger::AuthorityRoutingBindingV3::Unavailable { .. })
        ) {
            Self::increment(&mut self.totals.routing_unavailable, "routing_unavailable")?;
        }
        match outcome.completion {
            CompletionStateV2::Failed => Self::increment(&mut self.totals.failures, "failures")?,
            CompletionStateV2::Cancelled => {
                Self::increment(&mut self.totals.cancellations, "cancellations")?
            }
            CompletionStateV2::PreDispatchRejected => Self::increment(
                &mut self.totals.pre_dispatch_rejections,
                "pre_dispatch_rejections",
            )?,
            CompletionStateV2::Succeeded | CompletionStateV2::Local => {}
        }
        if outcome.target == PlanTarget::Candidate
            && outcome.completion != CompletionStateV2::PreDispatchRejected
            && (outcome.completion != CompletionStateV2::Succeeded
                || outcome.observed_actual_cost_micros.is_none()
                || outcome.enforced_modeled_delta_micros.is_none())
        {
            Self::increment(&mut self.totals.incomplete, "incomplete")?;
        }
        if modeled_delta_applicable(outcome) {
            Self::increment(&mut self.applicable, "applicable_outcomes")?;
            match outcome.observed_actual_cost_micros {
                Some(cost) if self.cost_complete => {
                    let current = self.totals.observed_enforced_cost_micros.unwrap_or(0);
                    self.totals.observed_enforced_cost_micros =
                        Some(current.checked_add(cost).ok_or(
                            ControlledEnforcementReportError::MetricOverflow {
                                metric: "observed_enforced_cost_micros",
                            },
                        )?);
                }
                Some(_) => {}
                None => {
                    self.cost_complete = false;
                    self.totals.observed_enforced_cost_micros = None;
                }
            }
            match outcome.enforced_modeled_delta_micros {
                Some(delta) if self.delta_complete => {
                    let delta = i64::try_from(delta).map_err(|_| {
                        ControlledEnforcementReportError::MetricOverflow {
                            metric: "enforced_modeled_delta_micros",
                        }
                    })?;
                    let current = self.totals.enforced_modeled_delta_micros.unwrap_or(0);
                    self.totals.enforced_modeled_delta_micros =
                        Some(current.checked_add(delta).ok_or(
                            ControlledEnforcementReportError::MetricOverflow {
                                metric: "enforced_modeled_delta_micros",
                            },
                        )?);
                }
                Some(_) => {}
                None => {
                    self.delta_complete = false;
                    self.totals.enforced_modeled_delta_micros = None;
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> ControlledEnforcementTotals {
        if self.applicable == 0 || !self.cost_complete {
            self.totals.observed_enforced_cost_micros = None;
        }
        if self.applicable == 0 || !self.delta_complete {
            self.totals.enforced_modeled_delta_micros = None;
        }
        self.totals
    }
}

#[cfg(test)]
mod controlled_aggregation_tests {
    use super::*;
    use crate::{
        enforcement::AuthorityProtocol,
        ledger::{
            AuthorityFallbackReasonV2, AuthorityOutcomeV2, AuthoritySelectionFactsV2,
            CandidateFailureClassV2, CircuitStateV2, UsageSource,
        },
        supply::TaskClass,
    };

    pub(super) fn candidate_outcome(
        completion: CompletionStateV2,
        cost: Option<u64>,
        delta: Option<i128>,
    ) -> AuthorityOutcomeV2 {
        let counterfactual = cost.zip(delta).and_then(|(cost, delta)| {
            let value = i128::from(cost).checked_add(delta)?;
            u64::try_from(value).ok()
        });
        AuthorityOutcomeV2 {
            decision_id: "decision".into(),
            replaces_decision_id: None,
            ts_ms: 2,
            route_id: "route".into(),
            mode: RouteMode::Enforce,
            protocol: AuthorityProtocol::ChatCompletions,
            task_class: TaskClass::HeavyLifting,
            workload_identity_digest: Some(format!("sha256:{}", "a".repeat(64))),
            app: Some("support".into()),
            resolved_tags: vec![],
            requested_supply_id: None,
            selection_facts: AuthoritySelectionFactsV2::canonical_candidate(1),
            grant_digest: Some(format!("sha256:{}", "b".repeat(64))),
            grant_expires_at_ms: Some(10),
            model_rewritten: true,
            selected_supply_id: Some("owned/candidate".into()),
            baseline_supply_id: Some("public/baseline".into()),
            actuator_identity_digest: Some(format!("sha256:{}", "c".repeat(64))),
            actuator_config_digest: Some(format!("sha256:{}", "d".repeat(64))),
            enforcement_config_digest: format!("sha256:{}", "e".repeat(64)),
            route_config_digest: format!("sha256:{}", "f".repeat(64)),
            target: PlanTarget::Candidate,
            fallback_reason: None,
            circuit_before: CircuitStateV2::Closed,
            circuit_after: CircuitStateV2::Closed,
            actual_dispatch: 1,
            completion,
            candidate_failure: None,
            status: Some(200),
            input_tokens: cost.map(|_| 1),
            output_tokens: cost.map(|_| 1),
            usage_source: if cost.is_some() {
                UsageSource::Observed
            } else {
                UsageSource::Missing
            },
            observed_actual_cost_micros: cost,
            approved_counterfactual_cost_micros: counterfactual,
            enforced_modeled_delta_micros: delta,
            routing: None,
        }
    }

    #[test]
    fn missing_usage_is_non_applicable_and_does_not_poison_available_totals() {
        let mut accumulator = ControlledAccumulator::default();
        accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(5),
                Some(5),
            ))
            .unwrap();
        accumulator
            .accumulate(&candidate_outcome(CompletionStateV2::Succeeded, None, None))
            .unwrap();
        let totals = accumulator.finish();
        assert_eq!(totals.observed_enforced_cost_micros, Some(5));
        assert_eq!(totals.enforced_modeled_delta_micros, Some(5));
        assert_eq!(totals.incomplete, 1);
    }

    #[test]
    fn known_applicable_values_sum_exactly_and_preserve_delta_sign() {
        let mut accumulator = ControlledAccumulator::default();
        accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(5),
                Some(9),
            ))
            .unwrap();
        accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(7),
                Some(-4),
            ))
            .unwrap();
        let totals = accumulator.finish();
        assert_eq!(totals.observed_enforced_cost_micros, Some(12));
        assert_eq!(totals.enforced_modeled_delta_micros, Some(5));
    }

    #[test]
    fn failed_and_bypassed_outcomes_do_not_manufacture_zero_or_poison_applicable_totals() {
        let mut accumulator = ControlledAccumulator::default();
        accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(5),
                Some(-3),
            ))
            .unwrap();
        let mut failed = candidate_outcome(CompletionStateV2::Failed, None, None);
        failed.candidate_failure = Some(CandidateFailureClassV2::TransportStream);
        failed.validate().unwrap();
        accumulator.accumulate(&failed).unwrap();
        let mut bypass = candidate_outcome(CompletionStateV2::Succeeded, None, None);
        bypass.target = PlanTarget::Original;
        bypass.selection_facts =
            AuthoritySelectionFactsV2::canonical_fallback(AuthorityFallbackReasonV2::KillNotArmed);
        bypass.grant_digest = None;
        bypass.grant_expires_at_ms = None;
        bypass.model_rewritten = false;
        bypass.selected_supply_id = None;
        bypass.baseline_supply_id = None;
        bypass.actuator_identity_digest = None;
        bypass.actuator_config_digest = None;
        bypass.fallback_reason = Some(AuthorityFallbackReasonV2::KillNotArmed);
        bypass.circuit_before = CircuitStateV2::NotApplicable;
        bypass.circuit_after = CircuitStateV2::NotApplicable;
        bypass.validate().unwrap();
        accumulator.accumulate(&bypass).unwrap();
        let totals = accumulator.finish();
        assert_eq!(totals.observed_enforced_cost_micros, Some(5));
        assert_eq!(totals.enforced_modeled_delta_micros, Some(-3));
        assert_eq!(totals.failures, 1);
        assert_eq!(totals.bypasses, 1);
    }

    #[test]
    fn pre_dispatch_rejection_and_linked_bypass_are_counted_without_candidate_delta() {
        let mut rejected = candidate_outcome(CompletionStateV2::PreDispatchRejected, None, None);
        rejected.actual_dispatch = 0;
        rejected.status = None;
        rejected.input_tokens = None;
        rejected.output_tokens = None;
        rejected.usage_source = UsageSource::Missing;
        rejected.validate().unwrap();

        let mut replacement = rejected.clone();
        replacement.decision_id = "replacement".into();
        replacement.replaces_decision_id = Some(rejected.decision_id.clone());
        replacement.selection_facts = AuthoritySelectionFactsV2::canonical_fallback(
            AuthorityFallbackReasonV2::CandidateUnavailable,
        );
        replacement.selection_facts.bucket = Some(1);
        replacement.grant_digest = None;
        replacement.grant_expires_at_ms = None;
        replacement.model_rewritten = false;
        replacement.selected_supply_id = replacement.baseline_supply_id.clone();
        replacement.actuator_identity_digest = None;
        replacement.actuator_config_digest = None;
        replacement.target = PlanTarget::Original;
        replacement.fallback_reason = Some(AuthorityFallbackReasonV2::CandidateUnavailable);
        replacement.actual_dispatch = 1;
        replacement.completion = CompletionStateV2::Succeeded;
        replacement.status = Some(200);
        replacement.validate().unwrap();

        let mut accumulator = ControlledAccumulator::default();
        accumulator.accumulate(&rejected).unwrap();
        accumulator.accumulate(&replacement).unwrap();
        let totals = accumulator.finish();
        assert_eq!(totals.decisions, 2);
        assert_eq!(totals.pre_dispatch_rejections, 1);
        assert_eq!(totals.candidate_dispatches, 0);
        assert_eq!(totals.bypasses, 1);
        assert_eq!(totals.fail_closed, 0);
        assert_eq!(totals.incomplete, 0);
        assert_eq!(totals.observed_enforced_cost_micros, None);
        assert_eq!(totals.enforced_modeled_delta_micros, None);
    }

    #[test]
    fn observed_cost_overflow_is_an_explicit_construction_error() {
        let mut accumulator = ControlledAccumulator::default();
        accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(u64::MAX),
                Some(0),
            ))
            .unwrap();
        let error = accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(1),
                Some(0),
            ))
            .unwrap_err();
        assert_eq!(
            error,
            ControlledEnforcementReportError::MetricOverflow {
                metric: "observed_enforced_cost_micros"
            }
        );
    }

    #[test]
    fn signed_delta_overflow_is_an_explicit_construction_error() {
        let mut accumulator = ControlledAccumulator::default();
        accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(0),
                Some(i128::from(i64::MAX)),
            ))
            .unwrap();
        let error = accumulator
            .accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(0),
                Some(1),
            ))
            .unwrap_err();
        assert_eq!(
            error,
            ControlledEnforcementReportError::MetricOverflow {
                metric: "enforced_modeled_delta_micros"
            }
        );

        let mut out_of_range = ControlledAccumulator::default();
        assert!(matches!(
            out_of_range.accumulate(&candidate_outcome(
                CompletionStateV2::Succeeded,
                Some(0),
                Some(i128::from(i64::MAX) + 1),
            )),
            Err(ControlledEnforcementReportError::MetricOverflow {
                metric: "enforced_modeled_delta_micros"
            })
        ));
    }

    #[test]
    fn mode_and_portfolio_totals_ignore_non_applicable_missing_usage() {
        let mut known = candidate_outcome(CompletionStateV2::Succeeded, Some(5), Some(-2));
        known.decision_id = "known".into();
        let mut missing = candidate_outcome(CompletionStateV2::Succeeded, None, None);
        missing.decision_id = "missing".into();
        missing.mode = RouteMode::CanaryEnforce;
        let records = vec![
            AuthorityRecordV2::outcome(1, known).unwrap(),
            AuthorityRecordV2::outcome(2, missing).unwrap(),
        ];

        let report = aggregate_controlled_enforcement_report(
            "run",
            &format!("sha256:{}", "9".repeat(64)),
            &records,
            true,
        )
        .unwrap();
        assert_eq!(report.totals.observed_enforced_cost_micros, Some(5));
        assert_eq!(report.totals.enforced_modeled_delta_micros, Some(-2));
        let enforce = report
            .by_mode
            .iter()
            .find(|row| row.mode == RouteMode::Enforce)
            .unwrap();
        assert_eq!(enforce.totals.observed_enforced_cost_micros, Some(5));
        assert_eq!(enforce.totals.enforced_modeled_delta_micros, Some(-2));
        let canary = report
            .by_mode
            .iter()
            .find(|row| row.mode == RouteMode::CanaryEnforce)
            .unwrap();
        assert_eq!(canary.totals.observed_enforced_cost_micros, None);
        assert_eq!(canary.totals.enforced_modeled_delta_micros, None);
    }

    #[test]
    fn a_schema_v1_totals_document_loads_with_the_new_routing_counters_defaulted() {
        // Shape of a totals document as it was published before routing_capable,
        // routing_efficient, routing_unavailable, and candidate_failures existed: no such fields,
        // deny_unknown_fields on the struct. A version-1 report written by an old crate must still
        // load under the new one.
        let legacy = serde_json::json!({
            "decisions": 3,
            "candidate_dispatches": 2,
            "pre_dispatch_rejections": 1,
            "bypasses": 0,
            "fail_closed": 0,
            "failures": 0,
            "cancellations": 0,
            "incomplete": 0,
            "observed_enforced_cost_micros": null,
            "enforced_modeled_delta_micros": null,
        });
        let totals: ControlledEnforcementTotals = serde_json::from_value(legacy)
            .expect("a schema-v1 totals document must still deserialize");
        assert_eq!(totals.candidate_failures, 0);
        assert_eq!(totals.routing_capable, 0);
        assert_eq!(totals.routing_efficient, 0);
        assert_eq!(totals.routing_unavailable, 0);
    }

    #[test]
    fn a_new_report_is_stamped_schema_v2() {
        let report = aggregate_controlled_enforcement_report(
            "run",
            &format!("sha256:{}", "9".repeat(64)),
            &[],
            true,
        )
        .unwrap();
        assert_eq!(report.schema_version, 2);
        let round_tripped: ControlledEnforcementReport =
            serde_json::from_value(serde_json::to_value(&report).unwrap()).unwrap();
        assert_eq!(round_tripped, report);
    }

    #[test]
    fn a_report_without_reprocessing_serializes_to_the_pinned_bytes() {
        let report = aggregate_controlled_enforcement_report(
            "run",
            &format!("sha256:{}", "9".repeat(64)),
            &[],
            true,
        )
        .unwrap();
        let pinned = format!(
            r#"{{
  "schema_version": 2,
  "authority_schema_version": 2,
  "complete": true,
  "run_id": "run",
  "records_digest": "sha256:{}",
  "totals": {{
    "decisions": 0,
    "candidate_dispatches": 0,
    "pre_dispatch_rejections": 0,
    "bypasses": 0,
    "fail_closed": 0,
    "failures": 0,
    "candidate_failures": 0,
    "cancellations": 0,
    "incomplete": 0,
    "routing_capable": 0,
    "routing_efficient": 0,
    "routing_unavailable": 0,
    "observed_enforced_cost_micros": null,
    "enforced_modeled_delta_micros": null
  }},
  "by_mode": [],
  "shadow_opportunity": null
}}"#,
            "9".repeat(64)
        );
        let serialized = serde_json::to_string_pretty(&report).unwrap();
        assert_eq!(serialized, pinned);
        let reloaded: ControlledEnforcementReport = serde_json::from_str(&pinned).unwrap();
        assert_eq!(serde_json::to_string_pretty(&reloaded).unwrap(), pinned);
    }
}

#[cfg(test)]
mod reprocessing_tests {
    use super::controlled_aggregation_tests::candidate_outcome;
    use super::*;
    use crate::economics::MAX_EXACT_TOKEN_COUNT;
    use crate::ledger::{AuthorityOutcomeV2, AuthorityRoutingBindingV3, RoutingDecisionSourceV3};
    use crate::routing::{RoutingReason, RoutingTarget};

    const EXAMPLE_MANIFEST: &str = "schema_version: 1
steady_cache_hit_ppm: 950000
targets:
  capable:
    input_per_mtok_usd: 5.0
    output_per_mtok_usd: 25.0
    cache_read_ppm: 100000
    cache_write_ppm: 1250000
  efficient:
    input_per_mtok_usd: 3.0
    output_per_mtok_usd: 15.0
    cache_read_ppm: 100000
    cache_write_ppm: 1250000
";

    fn manifest() -> ReprocessingManifest {
        ReprocessingManifest::from_yaml(EXAMPLE_MANIFEST).unwrap()
    }

    fn task(n: u8) -> String {
        format!("sha256:{}", format!("{n:x}").repeat(64))
    }

    /// A routed step whose served model matches its semantic target: `Candidate` serves
    /// efficient and `Original` serves capable.
    fn step(
        task_reference_digest: &str,
        step_id: u64,
        target: RoutingTarget,
        input: Option<u64>,
        output: Option<u64>,
    ) -> AuthorityRecordV2 {
        let served = match target {
            RoutingTarget::Capable => PlanTarget::Original,
            RoutingTarget::Efficient => PlanTarget::Candidate,
        };
        served_step(
            task_reference_digest,
            step_id,
            target,
            served,
            input,
            output,
        )
    }

    /// A routed step with an explicit served model, which can differ from the semantic target.
    fn served_step(
        task_reference_digest: &str,
        step_id: u64,
        target: RoutingTarget,
        served: PlanTarget,
        input: Option<u64>,
        output: Option<u64>,
    ) -> AuthorityRecordV2 {
        let mut outcome: AuthorityOutcomeV2 =
            candidate_outcome(CompletionStateV2::Succeeded, Some(1), Some(0));
        if served != PlanTarget::Candidate {
            outcome.target = served;
            outcome.model_rewritten = false;
            outcome.grant_digest = None;
            outcome.grant_expires_at_ms = None;
            outcome.actuator_identity_digest = None;
            outcome.actuator_config_digest = None;
            outcome.observed_actual_cost_micros = None;
            outcome.approved_counterfactual_cost_micros = None;
            outcome.enforced_modeled_delta_micros = None;
        }
        if served == PlanTarget::None {
            outcome.actual_dispatch = 0;
            outcome.completion = CompletionStateV2::Local;
            outcome.status = None;
        }
        outcome.input_tokens = input;
        outcome.output_tokens = output;
        outcome.routing = Some(AuthorityRoutingBindingV3::Decision {
            routing_decision_digest: format!("sha256:{}", "1".repeat(64)),
            routing_state_digest: format!("sha256:{}", "2".repeat(64)),
            profile_digest: format!("sha256:{}", "3".repeat(64)),
            task_reference_digest: task_reference_digest.to_owned(),
            step_id,
            semantic_target: target,
            reason: match target {
                RoutingTarget::Capable => RoutingReason::DefaultCapable,
                RoutingTarget::Efficient => RoutingReason::RecentProgress,
            },
            source: RoutingDecisionSourceV3::TrustedImmediatePeer,
        });
        AuthorityRecordV2::Outcome {
            schema_version: 3,
            sequence: step_id,
            outcome,
        }
    }

    fn section(records: &[AuthorityRecordV2], complete: bool) -> ReprocessingSection {
        aggregate_reprocessing_section(records, complete, &manifest()).unwrap()
    }

    /// Golden vector. Rates from `EXAMPLE_MANIFEST`, in micros per Mtok: capable input 5_000_000,
    /// output 25_000_000; efficient input 3_000_000, output 15_000_000. Cache read 0.1x, write
    /// 1.25x, steady hit h = 0.95 for both targets.
    ///
    /// Multipliers: steady s = 0.95 * 0.1 + 0.05 * 1.25 = 0.095 + 0.0625 = 0.1575.
    /// Miss m = 1.25. Reload premium m - s = 1.0925.
    ///
    /// Step 1, capable, cold, I = 100_000, O = 1_000:
    ///   enforced       = 0.1 Mtok * $5 * 1.25 + 0.001 Mtok * $25 = 0.625 + 0.025 = $0.650000
    ///   counterfactual = the same cold price                        = $0.650000
    /// Step 2, efficient, switch (step 1 was capable), I = 120_000, O = 2_000:
    ///   enforced       = 0.12 * $3 * 1.25 + 0.002 * $15   = 0.45 + 0.03    = $0.480000
    ///   counterfactual = 0.12 * $5 * 0.1575 + 0.002 * $25 = 0.0945 + 0.05  = $0.144500
    ///   reprocessing   = 0.12 * $3 * 1.0925                                 = $0.393300
    /// Step 3, capable, switch (step 2 was efficient), I = 140_000, O = 3_000:
    ///   enforced       = 0.14 * $5 * 1.25 + 0.003 * $25   = 0.875 + 0.075  = $0.950000
    ///   counterfactual = 0.14 * $5 * 0.1575 + 0.003 * $25 = 0.11025 + 0.075 = $0.185250
    ///   reprocessing   = 0.14 * $5 * 1.0925                                 = $0.764750
    ///
    /// Totals: enforced 650_000 + 480_000 + 950_000 = 2_080_000 micros.
    /// Counterfactual 650_000 + 144_500 + 185_250 = 979_750 micros.
    /// Reprocessing 393_300 + 764_750 = 1_158_050 micros.
    /// Delta (counterfactual - enforced) = 979_750 - 2_080_000 = -1_100_250 micros.
    /// Counts: 1 task, 3 routed steps, 1 cold, 2 switch, 0 steady, 1 to efficient, 1 to capable.
    #[test]
    fn golden_vector_prices_each_switch_as_a_full_cache_miss() {
        let t = task(7);
        let records = [
            step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            step(&t, 2, RoutingTarget::Efficient, Some(120_000), Some(2_000)),
            step(&t, 3, RoutingTarget::Capable, Some(140_000), Some(3_000)),
        ];
        let result = section(&records, true);
        assert_eq!(
            result,
            ReprocessingSection {
                manifest_digest: manifest().digest().unwrap(),
                status: ReprocessingStatus::Available,
                tasks: 1,
                routed_steps: 3,
                cold_steps: 1,
                switch_steps: 2,
                steady_steps: 0,
                switches_to_efficient: 1,
                switches_to_capable: 1,
                excluded_undispatched_steps: 0,
                reprocessing_cost_micros: Some(1_158_050),
                cache_adjusted_enforced_cost_micros: Some(2_080_000),
                cache_adjusted_counterfactual_cost_micros: Some(979_750),
                cache_adjusted_delta_micros: Some(-1_100_250),
            }
        );
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "available");
        assert_eq!(json["cache_adjusted_delta_micros"], "-1100250");
        assert_eq!(json["reprocessing_cost_micros"], 1_158_050);
        // Record order in the ledger does not change the result.
        let mut reversed = records.to_vec();
        reversed.reverse();
        assert_eq!(section(&reversed, true), result);
    }

    /// All capable, steps 1..=3, I = 100_000, O = 1_000 each. Step 1 is cold on both paths.
    /// Steps 2 and 3 are steady on both paths: 0.1 * $5 * 0.1575 + 0.001 * $25 = $0.103750.
    /// Enforced = counterfactual = 650_000 + 2 * 103_750 = 857_500 micros; delta 0.
    #[test]
    fn a_task_that_never_switches_has_no_reprocessing_and_no_delta() {
        let t = task(8);
        let records: Vec<_> = (1..=3)
            .map(|id| step(&t, id, RoutingTarget::Capable, Some(100_000), Some(1_000)))
            .collect();
        let section = section(&records, true);
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!(
            (
                section.cold_steps,
                section.switch_steps,
                section.steady_steps
            ),
            (1, 0, 2)
        );
        assert_eq!(section.reprocessing_cost_micros, Some(0));
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(857_500));
        assert_eq!(
            section.cache_adjusted_counterfactual_cost_micros,
            Some(857_500)
        );
        assert_eq!(section.cache_adjusted_delta_micros, Some(0));
    }

    /// Steps 1 and 3 only, both capable. Step 3 has no step 2 in the run, so it is a switch:
    ///   enforced       = 0.1 * $5 * 1.25 + 0.001 * $25   = $0.650000
    ///   counterfactual = 0.1 * $5 * 0.1575 + 0.001 * $25 = $0.103750
    ///   reprocessing   = 0.1 * $5 * 1.0925               = $0.546250
    /// Delta = (650_000 + 103_750) - (650_000 + 650_000) = -546_250 micros.
    #[test]
    fn an_absent_predecessor_prices_the_step_as_a_switch() {
        let t = task(9);
        let records = [
            step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            step(&t, 3, RoutingTarget::Capable, Some(100_000), Some(1_000)),
        ];
        let section = section(&records, true);
        assert_eq!(
            (
                section.cold_steps,
                section.switch_steps,
                section.steady_steps
            ),
            (1, 1, 0)
        );
        assert_eq!(section.switches_to_capable, 1);
        assert_eq!(section.switches_to_efficient, 0);
        assert_eq!(section.reprocessing_cost_micros, Some(546_250));
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(1_300_000));
        assert_eq!(
            section.cache_adjusted_counterfactual_cost_micros,
            Some(753_750)
        );
        assert_eq!(section.cache_adjusted_delta_micros, Some(-546_250));
    }

    fn with_outcome(
        mut record: AuthorityRecordV2,
        change: impl FnOnce(&mut AuthorityOutcomeV2),
    ) -> AuthorityRecordV2 {
        if let AuthorityRecordV2::Outcome { outcome, .. } = &mut record {
            change(outcome);
        }
        record
    }

    /// Step 2 is semantically efficient but `Original` served it (for example on grant loss).
    /// It is priced as capable and is steady after capable step 1, on both paths:
    /// 650_000 + (0.1 * $5 * 0.1575 + 0.001 * $25 = 103_750) = 753_750 micros; delta 0.
    #[test]
    fn a_semantic_efficient_step_served_by_the_original_is_priced_as_capable() {
        let t = task(1);
        let records = [
            step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            served_step(
                &t,
                2,
                RoutingTarget::Efficient,
                PlanTarget::Original,
                Some(100_000),
                Some(1_000),
            ),
        ];
        let section = section(&records, true);
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!((section.switch_steps, section.steady_steps), (0, 1));
        assert_eq!(
            (section.switches_to_efficient, section.switches_to_capable),
            (0, 0)
        );
        assert_eq!(section.reprocessing_cost_micros, Some(0));
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(753_750));
        assert_eq!(
            section.cache_adjusted_counterfactual_cost_micros,
            Some(753_750)
        );
        assert_eq!(section.cache_adjusted_delta_micros, Some(0));
    }

    /// Observe mode never dispatches the candidate. Semantic capable, efficient, efficient all
    /// run on `Original`, so the task never switches models.
    #[test]
    fn an_observe_run_has_no_switches_whatever_the_semantic_targets() {
        let t = task(2);
        let records: Vec<_> = [
            RoutingTarget::Capable,
            RoutingTarget::Efficient,
            RoutingTarget::Efficient,
        ]
        .into_iter()
        .zip(1..)
        .map(|(target, id)| {
            with_outcome(
                served_step(
                    &t,
                    id,
                    target,
                    PlanTarget::Original,
                    Some(100_000),
                    Some(1_000),
                ),
                |outcome| outcome.mode = RouteMode::Observe,
            )
        })
        .collect();
        let section = section(&records, true);
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!(
            (
                section.cold_steps,
                section.switch_steps,
                section.steady_steps
            ),
            (1, 0, 2)
        );
        assert_eq!(
            (section.switches_to_efficient, section.switches_to_capable),
            (0, 0)
        );
        assert_eq!(section.reprocessing_cost_micros, Some(0));
        assert_eq!(section.cache_adjusted_delta_micros, Some(0));
    }

    /// Step 2's candidate is rejected before dispatch and has no usage. It is excluded, so step
    /// 3 has no predecessor and is a switch to capable: reprocessing 0.1 * $5 * 1.0925 = 546_250.
    #[test]
    fn a_pre_dispatch_rejected_candidate_is_excluded_without_making_the_section_incomplete() {
        let (first, rejected, _, third) = rejected_candidate_fixture(3);
        let section = section(&[first, rejected, third], true);
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!(section.excluded_undispatched_steps, 1);
        assert_eq!(section.routed_steps, 2);
        assert_eq!((section.switch_steps, section.switches_to_capable), (1, 1));
        assert_eq!(section.reprocessing_cost_micros, Some(546_250));
    }

    /// The shape an enforce run writes: step 1 capable; step 2's efficient candidate rejected
    /// before dispatch; its replacement served by `Original` with `routing: None` and
    /// `replaces_decision_id` set; step 3 capable. Returns (first, rejected, replacement, third).
    fn rejected_candidate_fixture(
        n: u8,
    ) -> (
        AuthorityRecordV2,
        AuthorityRecordV2,
        AuthorityRecordV2,
        AuthorityRecordV2,
    ) {
        let t = task(n);
        let named = |record, id: &'static str| {
            with_outcome(record, |outcome| outcome.decision_id = id.into())
        };
        let first = named(
            step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            "step-1",
        );
        let rejected = with_outcome(
            step(&t, 2, RoutingTarget::Efficient, None, None),
            |outcome| {
                outcome.decision_id = "step-2-candidate".into();
                outcome.completion = CompletionStateV2::PreDispatchRejected;
                outcome.actual_dispatch = 0;
                outcome.status = None;
            },
        );
        let replacement = with_outcome(
            served_step(
                &t,
                2,
                RoutingTarget::Efficient,
                PlanTarget::Original,
                Some(100_000),
                Some(1_000),
            ),
            |outcome| {
                outcome.decision_id = "step-2-replacement".into();
                outcome.replaces_decision_id = Some("step-2-candidate".into());
                outcome.routing = None;
            },
        );
        let third = named(
            step(&t, 3, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            "step-3",
        );
        (first, rejected, replacement, third)
    }

    /// The replacement carries no routing binding. It counts as step 2, served by capable, so
    /// step 3 is steady: 650_000 + 103_750 + 103_750 = 857_500 micros on both paths; delta 0.
    #[test]
    fn a_replacement_dispatch_counts_as_the_step_it_replaced() {
        let (first, rejected, replacement, third) = rejected_candidate_fixture(5);
        let orders = [
            vec![
                first.clone(),
                rejected.clone(),
                replacement.clone(),
                third.clone(),
            ],
            vec![replacement, third, rejected, first],
        ];
        let sections: Vec<_> = orders
            .iter()
            .map(|records| section(records, true))
            .collect();
        for section in &sections {
            assert_eq!(section.status, ReprocessingStatus::Available);
            assert_eq!(section.excluded_undispatched_steps, 1);
            assert_eq!(section.tasks, 1);
            assert_eq!(
                (
                    section.routed_steps,
                    section.cold_steps,
                    section.switch_steps,
                    section.steady_steps
                ),
                (3, 1, 0, 2)
            );
            assert_eq!(
                (section.switches_to_efficient, section.switches_to_capable),
                (0, 0)
            );
            assert_eq!(section.reprocessing_cost_micros, Some(0));
            assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(857_500));
            assert_eq!(section.cache_adjusted_delta_micros, Some(0));
        }
        assert_eq!(sections[0], sections[1]);
    }

    /// A fail-closed replacement (`target: None`) never reached a model either. Its rejected
    /// candidate already counts as the one excluded step, so step 3 has no predecessor.
    #[test]
    fn a_fail_closed_replacement_is_not_counted_as_a_second_excluded_step() {
        let (first, rejected, _, third) = rejected_candidate_fixture(8);
        let t = task(8);
        let replacement = with_outcome(
            served_step(
                &t,
                2,
                RoutingTarget::Efficient,
                PlanTarget::None,
                None,
                None,
            ),
            |outcome| {
                outcome.decision_id = "step-2-replacement".into();
                outcome.replaces_decision_id = Some("step-2-candidate".into());
                outcome.routing = None;
            },
        );
        let section = section(&[first, rejected, replacement, third], true);
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!(section.excluded_undispatched_steps, 1);
        assert_eq!((section.routed_steps, section.switch_steps), (2, 1));
    }

    /// A replacement whose replaced decision is not a routed decision in this run stays out.
    #[test]
    fn a_replacement_of_an_unrouted_decision_stays_outside_the_section() {
        let (first, _, replacement, _) = rejected_candidate_fixture(6);
        let section = section(&[first, replacement], true);
        assert_eq!(section.routed_steps, 1);
        assert_eq!(section.excluded_undispatched_steps, 0);
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(650_000));
    }

    /// A fail-closed step (`target: None`, `completion: Local`) never reached a model.
    #[test]
    fn a_fail_closed_step_is_excluded_without_making_the_section_incomplete() {
        let t = task(4);
        let records = [
            step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            served_step(
                &t,
                2,
                RoutingTarget::Efficient,
                PlanTarget::None,
                None,
                None,
            ),
        ];
        let section = section(&records, true);
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!(section.excluded_undispatched_steps, 1);
        assert_eq!((section.tasks, section.routed_steps), (1, 1));
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(650_000));
        assert_eq!(section.cache_adjusted_delta_micros, Some(0));
    }

    /// Step 1 efficient with zero usage (cost 0). Step 2 efficient steady, I = 200, O = 0:
    ///   enforced       = 200 tokens * 3 micros * 0.1575 = 94.5 micros -> 95 (half-up, not 94)
    ///   counterfactual = 200 tokens * 5 micros * 0.1575 = 157.5 micros -> 158
    #[test]
    fn each_step_rounds_half_up_to_whole_micros() {
        let t = task(6);
        let records = [
            step(&t, 1, RoutingTarget::Efficient, Some(0), Some(0)),
            step(&t, 2, RoutingTarget::Efficient, Some(200), Some(0)),
        ];
        let section = section(&records, true);
        assert_eq!(section.steady_steps, 1);
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(95));
        assert_eq!(section.cache_adjusted_counterfactual_cost_micros, Some(158));
        assert_eq!(section.cache_adjusted_delta_micros, Some(63));
    }

    #[test]
    fn steps_group_by_task_and_other_tasks_never_supply_a_predecessor() {
        let (a, b) = (task(10), task(11));
        let records = [
            step(&a, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            step(&b, 2, RoutingTarget::Capable, Some(100_000), Some(1_000)),
        ];
        let section = section(&records, true);
        assert_eq!(section.tasks, 2);
        assert_eq!((section.cold_steps, section.switch_steps), (1, 1));
    }

    #[test]
    fn missing_usage_on_a_routed_step_makes_the_section_incomplete_without_a_total() {
        let t = task(12);
        for (input, output) in [(None, Some(1_000)), (Some(100_000), None)] {
            let records = [
                step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
                step(&t, 2, RoutingTarget::Efficient, input, output),
            ];
            let section = section(&records, true);
            assert_eq!(section.status, ReprocessingStatus::Incomplete);
            assert_eq!(section.routed_steps, 2);
            assert_eq!(section.switch_steps, 1);
            assert_eq!(section.switches_to_efficient, 1);
            assert_eq!(section.reprocessing_cost_micros, None);
            assert_eq!(section.cache_adjusted_enforced_cost_micros, None);
            assert_eq!(section.cache_adjusted_counterfactual_cost_micros, None);
            assert_eq!(section.cache_adjusted_delta_micros, None);
            assert_eq!(
                serde_json::to_value(&section).unwrap()["status"],
                "incomplete"
            );
        }
    }

    #[test]
    fn an_incomplete_run_makes_the_section_incomplete_without_a_total() {
        let t = task(13);
        let records = [step(&t, 1, RoutingTarget::Capable, Some(1), Some(1))];
        let section = section(&records, false);
        assert_eq!(section.status, ReprocessingStatus::Incomplete);
        assert_eq!(section.routed_steps, 1);
        assert_eq!(section.cache_adjusted_enforced_cost_micros, None);
        assert_eq!(section.cache_adjusted_delta_micros, None);
    }

    #[test]
    fn unrouted_outcomes_are_outside_the_section() {
        let unrouted = AuthorityRecordV2::Outcome {
            schema_version: 2,
            sequence: 1,
            outcome: candidate_outcome(CompletionStateV2::Succeeded, None, None),
        };
        let section = section(&[unrouted], true);
        assert_eq!((section.tasks, section.routed_steps), (0, 0));
        assert_eq!(section.status, ReprocessingStatus::Available);
        assert_eq!(section.cache_adjusted_enforced_cost_micros, Some(0));
    }

    #[test]
    fn the_same_run_and_manifest_produce_identical_bytes() {
        let t = task(14);
        let records = [
            step(&t, 1, RoutingTarget::Capable, Some(100_000), Some(1_000)),
            step(&t, 2, RoutingTarget::Efficient, Some(120_000), Some(2_000)),
        ];
        let first = serde_json::to_vec_pretty(&section(&records, true)).unwrap();
        let second = serde_json::to_vec_pretty(&section(&records, true)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            manifest().digest().unwrap(),
            ReprocessingManifest::from_yaml(EXAMPLE_MANIFEST)
                .unwrap()
                .digest()
                .unwrap()
        );
        assert!(manifest().digest().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn manifest_validation_rejects_each_out_of_range_field_and_unknown_fields() {
        let valid = manifest();
        valid.validate().unwrap();
        let mut invalid = Vec::new();
        let mut value = valid.clone();
        value.schema_version = 2;
        invalid.push(("schema_version", value));
        let mut value = valid.clone();
        value.steady_cache_hit_ppm = 1_000_001;
        invalid.push(("steady_cache_hit_ppm", value));
        for (name, apply) in [
            (
                "input_per_mtok_usd negative",
                (|rate: &mut ReprocessingTargetRate| rate.input_per_mtok_usd = -1.0)
                    as fn(&mut ReprocessingTargetRate),
            ),
            ("input_per_mtok_usd nan", |rate| {
                rate.input_per_mtok_usd = f64::NAN
            }),
            ("input_per_mtok_usd above cap", |rate| {
                rate.input_per_mtok_usd = 1_000_000_001.0
            }),
            ("output_per_mtok_usd negative", |rate| {
                rate.output_per_mtok_usd = -1.0
            }),
            ("output_per_mtok_usd infinite", |rate| {
                rate.output_per_mtok_usd = f64::INFINITY
            }),
            ("cache_read_ppm", |rate| rate.cache_read_ppm = 1_000_001),
            ("cache_write_ppm low", |rate| rate.cache_write_ppm = 999_999),
            ("cache_write_ppm high", |rate| {
                rate.cache_write_ppm = 4_000_001
            }),
        ] {
            let mut capable = valid.clone();
            apply(&mut capable.targets.capable);
            invalid.push((name, capable));
            let mut efficient = valid.clone();
            apply(&mut efficient.targets.efficient);
            invalid.push((name, efficient));
        }
        for (name, value) in invalid {
            assert!(
                matches!(value.validate(), Err(ReprocessingManifestError::Invalid)),
                "{name} must be rejected"
            );
            let yaml = serde_yaml::to_string(&value).unwrap();
            assert!(
                ReprocessingManifest::from_yaml(&yaml).is_err(),
                "{name} must be rejected from YAML"
            );
        }
        let mut boundary = valid.clone();
        boundary.steady_cache_hit_ppm = 1_000_000;
        boundary.targets.capable.cache_read_ppm = 1_000_000;
        boundary.targets.capable.cache_write_ppm = 1_000_000;
        boundary.targets.efficient.cache_write_ppm = 4_000_000;
        boundary.validate().unwrap();

        for unknown in [
            format!("{EXAMPLE_MANIFEST}ttl_seconds: 300\n"),
            EXAMPLE_MANIFEST.replace(
                "    cache_read_ppm: 100000\n    cache_write_ppm: 1250000\n  efficient:",
                "    cache_read_ppm: 100000\n    cache_write_ppm: 1250000\n    ttl: 1\n  efficient:",
            ),
            EXAMPLE_MANIFEST.replace("targets:\n", "targets:\n  frontier: {}\n"),
        ] {
            assert!(
                matches!(
                    ReprocessingManifest::from_yaml(&unknown),
                    Err(ReprocessingManifestError::Parse(_))
                ),
                "unknown field must be rejected: {unknown}"
            );
        }
        let oversized = format!("{EXAMPLE_MANIFEST}#{}\n", "x".repeat(64 * 1024));
        assert!(matches!(
            ReprocessingManifest::from_yaml(&oversized),
            Err(ReprocessingManifestError::InputLimit)
        ));
    }

    #[test]
    fn overflow_at_the_exact_token_limit_is_an_explicit_error() {
        let mut wide = manifest();
        wide.targets.capable.input_per_mtok_usd = 1_000_000_000.0;
        wide.targets.capable.output_per_mtok_usd = 1_000_000_000.0;
        wide.validate().unwrap();
        let t = task(15);
        let records = [step(
            &t,
            1,
            RoutingTarget::Capable,
            Some(MAX_EXACT_TOKEN_COUNT),
            Some(MAX_EXACT_TOKEN_COUNT),
        )];
        assert!(matches!(
            aggregate_reprocessing_section(&records, true, &wide),
            Err(ControlledEnforcementReportError::MetricOverflow { .. })
        ));

        // Each step fits in u64 at the example rates (a capable switch step is about 5.6e16
        // micros), but 1_000 alternating switch steps exceed u64::MAX (about 1.8e19).
        let records: Vec<_> = (1..=1_000)
            .map(|id| {
                let target = if id % 2 == 0 {
                    RoutingTarget::Efficient
                } else {
                    RoutingTarget::Capable
                };
                step(&t, id, target, Some(MAX_EXACT_TOKEN_COUNT), Some(0))
            })
            .collect();
        assert!(matches!(
            aggregate_reprocessing_section(&records, true, &manifest()),
            Err(ControlledEnforcementReportError::MetricOverflow { .. })
        ));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportDimensions {
    pub app: String,
    pub team: String,
    pub environment: String,
    pub cost_center: String,
    pub general_tags: Vec<String>,
    pub complete: bool,
}

impl ReportDimensions {
    /// Derives reporting keys from the identity persisted with the decision. Callers must not
    /// substitute raw request tags: inline and passive recording persist policy-resolved tags.
    pub fn from_resolved_identity(identity: &crate::policy::WorkloadIdentity) -> Self {
        let (team, team_complete) = reserved_dimension(&identity.tags, "team:");
        let (environment, environment_complete) =
            reserved_dimension(&identity.tags, "environment:");
        let (cost_center, cost_center_complete) =
            reserved_dimension(&identity.tags, "cost-center:");
        let mut general_tags = identity
            .tags
            .iter()
            .filter(|tag| {
                !tag.starts_with("team:")
                    && !tag.starts_with("environment:")
                    && !tag.starts_with("cost-center:")
            })
            .cloned()
            .collect::<Vec<_>>();
        general_tags.sort();
        general_tags.dedup();
        Self {
            app: identity
                .app
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(UNASSIGNED_DIMENSION)
                .to_owned(),
            team,
            environment,
            cost_center,
            general_tags,
            complete: team_complete && environment_complete && cost_center_complete,
        }
    }
}

fn reserved_dimension(tags: &[String], prefix: &str) -> (String, bool) {
    let values = tags
        .iter()
        .filter_map(|tag| tag.strip_prefix(prefix))
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    match values.len() {
        0 => (UNASSIGNED_DIMENSION.to_owned(), true),
        1 => (
            values.into_iter().next().unwrap_or_default().to_owned(),
            true,
        ),
        _ => (AMBIGUOUS_DIMENSION.to_owned(), false),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyExposure {
    Compliant,
    Violation,
    Unknown,
}

/// Assesses only the historical feasible set persisted on the decision. It intentionally does not
/// evaluate the current policy bundle or manufacture a matched-rule explanation.
pub fn historical_policy_exposure(
    coverage_status: CoverageStatus,
    actual_supply_id: Option<&str>,
    recorded_feasible_ids: &[String],
) -> PolicyExposure {
    if coverage_status != CoverageStatus::Supported {
        return PolicyExposure::Unknown;
    }
    match actual_supply_id {
        None => PolicyExposure::Unknown,
        Some(actual) if recorded_feasible_ids.iter().any(|id| id == actual) => {
            PolicyExposure::Compliant
        }
        Some(_) => PolicyExposure::Violation,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Observed,
    Declared,
    CanaryVerified,
    Unverified,
}

#[cfg(test)]
mod actionable_economics_exposure_tests {
    use super::{historical_policy_exposure, PolicyExposure, ReportDimensions};
    use crate::policy::WorkloadIdentity;
    use crate::traffic::CoverageStatus;

    #[test]
    fn dimensions_use_resolved_reserved_namespaces_and_disclose_ambiguity() {
        let identity = WorkloadIdentity {
            api_key_digest: Some("sha256:secret-derived".into()),
            route: "/v1/responses".into(),
            app: Some("support".into()),
            tags: vec![
                "z-general".into(),
                "team:ops".into(),
                "environment:prod".into(),
                "team:support".into(),
                "cost-center:cc-14".into(),
                "a-general".into(),
                "a-general".into(),
            ],
        };
        let dimensions = ReportDimensions::from_resolved_identity(&identity);
        assert_eq!(dimensions.app, "support");
        assert_eq!(dimensions.team, "ambiguous");
        assert_eq!(dimensions.environment, "prod");
        assert_eq!(dimensions.cost_center, "cc-14");
        assert_eq!(dimensions.general_tags, vec!["a-general", "z-general"]);
        assert!(!dimensions.complete);
        let encoded = serde_json::to_string(&dimensions).unwrap();
        assert!(!encoded.contains("secret-derived"));
    }

    #[test]
    fn dimensions_use_unassigned_without_inventing_values() {
        let dimensions = ReportDimensions::from_resolved_identity(&WorkloadIdentity {
            api_key_digest: None,
            route: "/v1/chat/completions".into(),
            app: None,
            tags: vec![],
        });
        assert_eq!(dimensions.app, "unassigned");
        assert_eq!(dimensions.team, "unassigned");
        assert_eq!(dimensions.environment, "unassigned");
        assert_eq!(dimensions.cost_center, "unassigned");
        assert!(dimensions.general_tags.is_empty());
        assert!(dimensions.complete);
    }

    #[test]
    fn policy_exposure_uses_only_historical_actual_and_feasible_ids() {
        assert_eq!(
            historical_policy_exposure(
                CoverageStatus::Supported,
                Some("public/east"),
                &["public/east".into()]
            ),
            PolicyExposure::Compliant
        );
        assert_eq!(
            historical_policy_exposure(
                CoverageStatus::Supported,
                Some("public/west"),
                &["public/east".into()]
            ),
            PolicyExposure::Violation
        );
        assert_eq!(
            historical_policy_exposure(CoverageStatus::Supported, None, &["public/east".into()]),
            PolicyExposure::Unknown
        );
        assert_eq!(
            historical_policy_exposure(CoverageStatus::Supported, Some("public/east"), &[]),
            PolicyExposure::Violation
        );
        assert_eq!(
            historical_policy_exposure(
                CoverageStatus::IncompleteObservation,
                Some("public/west"),
                &["public/east".into()]
            ),
            PolicyExposure::Unknown
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct Cell<T: Serialize> {
    pub value: T,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowReport {
    pub complete: bool,
    pub provenance: ReportProvenance,
    pub data_integrity: DataIntegrity,
    pub protocol_coverage: ProtocolCoverage,
    #[serde(default)]
    pub attribution: AttributionSection,
    pub generated_from_records: u64,
    pub ledger_state: String,
    pub window: (u64, u64),
    pub sovereignty: SovereigntySection,
    pub counterfactual: CounterfactualSection,
    pub tier_arbitrage: Vec<ArbitrageRow>,
    pub policy_digests: Vec<String>,
    pub unplaceable: u64,
    pub unmapped_records: u64,
    pub unpriced_records: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportProvenance {
    pub attribution_digest: Option<String>,
    pub owned_cost_digest: Option<String>,
    pub passive_profile_digest: Option<String>,
    pub passive_input_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCoverage {
    pub total_inference_records: u64,
    pub supported_records: u64,
    pub unsupported_records: u64,
    pub complete: bool,
    pub by_protocol: BTreeMap<ProtocolKind, u64>,
    pub by_source: BTreeMap<ObservationSource, u64>,
    pub by_status: BTreeMap<CoverageStatus, u64>,
    #[serde(default)]
    pub by_reason: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributionSection {
    pub by_observation_source: BTreeMap<ObservationSource, AttributionStatusCounts>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AttributionStatusCounts {
    pub static_configured: u64,
    pub attributed: u64,
    pub missing: u64,
    pub unknown_reference: u64,
    pub ambiguous: u64,
    pub model_mismatch: u64,
}

impl AttributionStatusCounts {
    fn increment(&mut self, status: crate::attribution::AttributionStatus) {
        use crate::attribution::AttributionStatus;
        match status {
            AttributionStatus::StaticConfigured => self.static_configured += 1,
            AttributionStatus::Attributed => self.attributed += 1,
            AttributionStatus::Missing => self.missing += 1,
            AttributionStatus::UnknownReference => self.unknown_reference += 1,
            AttributionStatus::Ambiguous => self.ambiguous += 1,
            AttributionStatus::ModelMismatch => self.model_mismatch += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrity {
    pub run_id: Option<String>,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub missing_sequences: u64,
    pub truncated: u64,
    pub unmapped: u64,
    pub unpriceable: u64,
    pub recovery_issues: u64,
    pub clean_shutdown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereigntySection {
    pub actual_by_class: BTreeMap<SupplyClass, Cell<Option<f64>>>,
    pub shadow_by_class: BTreeMap<SupplyClass, Cell<Option<f64>>>,
    pub sovereignty_ratio_actual: Cell<Option<f64>>,
    pub sovereignty_ratio_shadow: Cell<Option<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualSection {
    pub actual_cost_usd: Cell<Option<f64>>,
    pub shadow_cost_usd: Cell<Option<f64>>,
    pub all_frontier_cost_usd: Cell<Option<f64>>,
    pub savings_vs_all_frontier_usd: Cell<Option<f64>>,
    pub quality_parity: Cell<String>,
    /// False when the registry has no frontier reference (e.g. an all-owned fleet) and none
    /// was supplied via `--frontier-reference`. A 100%-owned fleet is a success state, not an
    /// error — the frontier-dependent cells render "n/a — no frontier reference" instead.
    pub has_frontier_reference: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrageRow {
    pub task_class: TaskClass,
    pub records: u64,
    pub actual_cost_usd: Cell<Option<f64>>,
    pub cheapest_clearing_rented_usd: Cell<Option<f64>>,
    pub delta_usd: Cell<Option<f64>>,
}

pub fn compute_report(
    records: &[DecisionRecord],
    recovery: &RecoveryOutcome,
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
    floors: &QualityFloors,
    frontier_reference_id: Option<&str>,
) -> Result<ShadowReport, ReportError> {
    let frontier = frontier_reference_id
        .map(|id| {
            registry
                .by_id(id)
                .ok_or_else(|| ReportError::UnknownSupply(id.to_string()))
        })
        .transpose()?;
    let protocol_coverage = protocol_coverage(records);
    let actual_samples: Vec<CostSample> = records
        .iter()
        .filter(|record| supported_evidence(record))
        .filter_map(|record| actual_cost_sample(record, registry, owned_costs))
        .collect();
    let shadow_samples: Vec<CostSample> = records
        .iter()
        .filter(|record| supported_evidence(record))
        .filter_map(|record| shadow_cost_sample(record, registry, owned_costs))
        .collect();
    let frontier_samples: Vec<CostSample> = frontier
        .map(|frontier| {
            records
                .iter()
                .filter(|record| supported_evidence(record))
                .filter_map(|record| entry_cost_sample(record, frontier, owned_costs))
                .collect()
        })
        .unwrap_or_default();
    let policy_digests = records
        .iter()
        .map(|record| record.decision.policy_digest.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (window_start, window_end) = records.iter().fold((u64::MAX, 0_u64), |acc, record| {
        (acc.0.min(record.ts_ms), acc.1.max(record.ts_ms))
    });
    let window = if records.is_empty() {
        (0, 0)
    } else {
        (window_start, window_end)
    };
    let actual_cost_usd = sum_cell(&actual_samples);
    let shadow_cost_usd = sum_cell(&shadow_samples);
    let all_frontier_cost_usd = sum_cell(&frontier_samples);
    let unplaceable = records
        .iter()
        .filter(|record| supported_evidence(record))
        .filter(|record| record.decision.shadow.is_none())
        .count() as u64;
    let unmapped_records = records
        .iter()
        .filter(|record| supported_evidence(record))
        .filter(|record| has_unmapped_supply(record, registry))
        .count() as u64;
    let unpriced_records = records
        .iter()
        .filter(|record| supported_evidence(record))
        .filter(|record| has_unpriceable_supply(record, registry, owned_costs))
        .count() as u64;
    let has_exclusions =
        unmapped_records > 0 || unpriced_records > 0 || !protocol_coverage.complete;
    let mut sovereignty = SovereigntySection {
        actual_by_class: share_by_class(&actual_samples),
        shadow_by_class: share_by_class(&shadow_samples),
        sovereignty_ratio_actual: owned_ratio(&actual_samples),
        sovereignty_ratio_shadow: owned_ratio(&shadow_samples),
    };
    let mut counterfactual = CounterfactualSection {
        actual_cost_usd,
        shadow_cost_usd: shadow_cost_usd.clone(),
        all_frontier_cost_usd: all_frontier_cost_usd.clone(),
        savings_vs_all_frontier_usd: Cell {
            value: all_frontier_cost_usd
                .value
                .zip(shadow_cost_usd.value)
                .map(|(all_frontier, shadow)| all_frontier - shadow),
            confidence: Confidence::Unverified,
        },
        quality_parity: Cell {
            value: "not measured — no parity canary evidence for this report".to_string(),
            confidence: Confidence::Unverified,
        },
        has_frontier_reference: frontier.is_some(),
    };
    let mut tier_arbitrage = tier_arbitrage(records, registry, owned_costs, floors);

    if has_exclusions {
        degrade_sovereignty(&mut sovereignty);
        degrade_counterfactual(&mut counterfactual);
        degrade_arbitrage(&mut tier_arbitrage);
    }

    let recovery_issues = u64::from(!matches!(recovery, RecoveryOutcome::Clean { .. }));
    let truncated = records
        .iter()
        .filter(|record| record.accounting_truncated)
        .count() as u64;
    let complete = recovery_issues == 0
        && truncated == 0
        && unmapped_records == 0
        && unpriced_records == 0
        && protocol_coverage.complete;
    Ok(ShadowReport {
        complete,
        provenance: ReportProvenance::default(),
        data_integrity: DataIntegrity {
            run_id: None,
            accepted: records.len() as u64,
            recorded: records.len() as u64,
            dropped: 0,
            missing_sequences: 0,
            truncated,
            unmapped: unmapped_records,
            unpriceable: unpriced_records,
            recovery_issues,
            clean_shutdown: true,
        },
        protocol_coverage,
        attribution: attribution_section(records),
        generated_from_records: records.len() as u64,
        ledger_state: ledger_state(recovery),
        window,
        sovereignty,
        counterfactual,
        tier_arbitrage,
        policy_digests,
        unplaceable,
        unmapped_records,
        unpriced_records,
    })
}

pub fn compute_run_report(
    records: &[DecisionRecord],
    recoveries: &[RecoveryOutcome],
    manifest: &RunManifest,
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
    floors: &QualityFloors,
    frontier_reference_id: Option<&str>,
) -> Result<ShadowReport, ReportError> {
    let representative_recovery = recoveries
        .iter()
        .find(|outcome| !matches!(outcome, RecoveryOutcome::Clean { .. }))
        .cloned()
        .unwrap_or(RecoveryOutcome::Clean {
            records: records.len() as u64,
        });
    let mut report = compute_report(
        records,
        &representative_recovery,
        registry,
        owned_costs,
        floors,
        frontier_reference_id,
    )?;
    let sequences = records
        .iter()
        .filter_map(|record| record.sequence)
        .filter(|sequence| *sequence > 0 && *sequence <= manifest.accepted)
        .collect::<BTreeSet<_>>();
    let sequence_gaps = manifest.accepted.saturating_sub(sequences.len() as u64);
    let missing_sequences = sequence_gaps.saturating_sub(manifest.dropped);
    let truncated = manifest.truncated.max(
        records
            .iter()
            .filter(|record| record.accounting_truncated)
            .count() as u64,
    );
    let recovery_issues = recoveries
        .iter()
        .filter(|outcome| !matches!(outcome, RecoveryOutcome::Clean { .. }))
        .count() as u64;
    let unmapped = manifest.unmapped.max(report.unmapped_records);
    let unpriceable = manifest.unpriceable.max(report.unpriced_records);
    let integrity_complete = manifest.clean_shutdown
        && manifest.writer_healthy
        && manifest.dropped == 0
        && missing_sequences == 0
        && truncated == 0
        && unmapped == 0
        && unpriceable == 0
        && recovery_issues == 0
        && manifest.recorded == records.len() as u64;
    report.complete = integrity_complete && report.protocol_coverage.complete;
    report.provenance = ReportProvenance {
        attribution_digest: safe_digest(manifest.attribution_digest.as_deref()),
        owned_cost_digest: safe_digest(manifest.owned_cost_digest.as_deref()),
        passive_profile_digest: safe_digest(manifest.passive_profile_digest.as_deref()),
        passive_input_digest: safe_digest(manifest.passive_input_digest.as_deref()),
    };
    report.data_integrity = DataIntegrity {
        run_id: Some(manifest.run_id.clone()),
        accepted: manifest.accepted,
        recorded: manifest.recorded,
        dropped: manifest.dropped,
        missing_sequences,
        truncated,
        unmapped,
        unpriceable,
        recovery_issues,
        clean_shutdown: manifest.clean_shutdown,
    };
    if !report.complete {
        degrade_sovereignty(&mut report.sovereignty);
        degrade_counterfactual(&mut report.counterfactual);
        degrade_arbitrage(&mut report.tier_arbitrage);
    }
    Ok(report)
}

pub fn render_markdown(r: &ShadowReport) -> String {
    let mut out = String::new();
    if r.ledger_state != "clean" {
        out.push_str(&format!(
            "> **Warning:** ledger state is {} (observed). Records after recovery may be incomplete.\n\n",
            r.ledger_state
        ));
    }
    if r.unmapped_records > 0 {
        out.push_str(&format!(
            "> **Warning:** {} records could not be mapped to a supply entry and are excluded from cost cells.\n\n",
            r.unmapped_records
        ));
    }
    if r.unpriced_records > 0 {
        out.push_str(&format!(
            "> **Warning:** {} records referenced unpriceable supply entries and are excluded from cost cells.\n\n",
            r.unpriced_records
        ));
    }

    out.push_str("# Bowline Shadow Report\n\n");
    out.push_str(&format!(
        "Traffic accounted: {}\n\n",
        format_count(r.generated_from_records, Confidence::Observed)
    ));
    out.push_str(&format!(
        "Window: {} to {}\n\n",
        format_count(r.window.0, Confidence::Observed),
        format_count(r.window.1, Confidence::Observed)
    ));
    out.push_str(&format!(
        "Unplaceable shadow decisions: {}\n\n",
        format_count(r.unplaceable, Confidence::Observed)
    ));

    out.push_str("## Data Integrity\n\n");
    out.push_str(&format!("- Complete: {}\n", r.complete));
    out.push_str(&format!(
        "- Run ID: {}\n",
        r.data_integrity.run_id.as_deref().unwrap_or("legacy")
    ));
    out.push_str(&format!("- Accepted: {}\n", r.data_integrity.accepted));
    out.push_str(&format!("- Recorded: {}\n", r.data_integrity.recorded));
    out.push_str(&format!("- Dropped: {}\n", r.data_integrity.dropped));
    out.push_str(&format!(
        "- Missing sequences: {}\n",
        r.data_integrity.missing_sequences
    ));
    out.push_str(&format!("- Truncated: {}\n", r.data_integrity.truncated));
    out.push_str(&format!("- Unmapped: {}\n", r.data_integrity.unmapped));
    out.push_str(&format!(
        "- Unpriceable: {}\n",
        r.data_integrity.unpriceable
    ));
    out.push_str(&format!(
        "- Recovery issues: {}\n",
        r.data_integrity.recovery_issues
    ));
    out.push_str(&format!(
        "- Clean shutdown: {}\n\n",
        r.data_integrity.clean_shutdown
    ));

    out.push_str("## Protocol Coverage\n\n");
    out.push_str(&format!(
        "- Supported inference records: {}\n",
        r.protocol_coverage.supported_records
    ));
    out.push_str(&format!(
        "- Unsupported inference records: {}\n",
        r.protocol_coverage.unsupported_records
    ));
    out.push_str("- By protocol:\n");
    for (protocol, label) in [
        (ProtocolKind::ChatCompletions, "chat-completions"),
        (ProtocolKind::Responses, "responses"),
        (ProtocolKind::Embeddings, "embeddings"),
        (ProtocolKind::Unsupported, "unsupported"),
    ] {
        out.push_str(&format!(
            "  - {label}: {}\n",
            r.protocol_coverage
                .by_protocol
                .get(&protocol)
                .copied()
                .unwrap_or_default()
        ));
    }
    out.push_str("- By observation source:\n");
    for (source, label) in [
        (ObservationSource::Inline, "inline"),
        (ObservationSource::Passive, "passive"),
    ] {
        out.push_str(&format!(
            "  - {label}: {}\n",
            r.protocol_coverage
                .by_source
                .get(&source)
                .copied()
                .unwrap_or_default()
        ));
    }
    out.push_str("- By coverage status:\n");
    for (status, label) in [
        (CoverageStatus::Supported, "supported"),
        (
            CoverageStatus::IncompleteObservation,
            "incomplete-observation",
        ),
        (CoverageStatus::UnsupportedProtocol, "unsupported-protocol"),
        (CoverageStatus::UnsupportedShape, "unsupported-shape"),
    ] {
        out.push_str(&format!(
            "  - {label}: {}\n",
            r.protocol_coverage
                .by_status
                .get(&status)
                .copied()
                .unwrap_or_default()
        ));
    }
    if !r.protocol_coverage.by_reason.is_empty() {
        out.push_str("- By coverage reason:\n");
        for (reason, count) in &r.protocol_coverage.by_reason {
            out.push_str(&format!("  - {reason}: {count}\n"));
        }
    }
    out.push_str(&format!(
        "- Coverage complete: {}\n\n",
        if r.protocol_coverage.complete {
            "yes"
        } else {
            "no"
        }
    ));
    out.push_str(
        "Unsupported inference traffic is forwarded unchanged but excluded from placement and financial conclusions.\n\n",
    );

    out.push_str("## Attribution\n\n");
    for (source, label) in [
        (ObservationSource::Inline, "Inline"),
        (ObservationSource::Passive, "Passive"),
    ] {
        let counts = r
            .attribution
            .by_observation_source
            .get(&source)
            .copied()
            .unwrap_or_default();
        out.push_str(&format!("### {label}\n\n"));
        for (status, count) in [
            ("static-configured", counts.static_configured),
            ("attributed", counts.attributed),
            ("missing", counts.missing),
            ("unknown-reference", counts.unknown_reference),
            ("ambiguous", counts.ambiguous),
            ("model-mismatch", counts.model_mismatch),
        ] {
            out.push_str(&format!("- {status}: {count}\n"));
        }
        out.push('\n');
    }

    out.push_str("## Provenance\n\n");
    out.push_str(&format!(
        "- Attribution configuration: {}\n",
        display_digest(r.provenance.attribution_digest.as_deref())
    ));
    out.push_str(&format!(
        "- Owned-cost catalog: {}\n",
        display_digest(r.provenance.owned_cost_digest.as_deref())
    ));
    out.push_str(&format!(
        "- Passive profile/source contract: {}\n",
        display_digest(r.provenance.passive_profile_digest.as_deref())
    ));
    out.push_str(&format!(
        "- Passive input: {}\n\n",
        display_digest(r.provenance.passive_input_digest.as_deref())
    ));

    out.push_str("## Sovereignty\n\n");
    out.push_str(&format!(
        "- Actual owned ratio: {}\n",
        format_ratio_cell(&r.sovereignty.sovereignty_ratio_actual)
    ));
    out.push_str(&format!(
        "- Shadow owned ratio: {}\n",
        format_ratio_cell(&r.sovereignty.sovereignty_ratio_shadow)
    ));
    out.push_str("- Actual cost-share by class:\n");
    push_share_lines(&mut out, &r.sovereignty.actual_by_class);
    out.push_str("- Shadow cost-share by class:\n");
    push_share_lines(&mut out, &r.sovereignty.shadow_by_class);

    out.push_str("\n## Counterfactual\n\n");
    out.push_str(&format!(
        "- Actual cost: {}\n",
        format_money_cell(&r.counterfactual.actual_cost_usd)
    ));
    out.push_str(&format!(
        "- Shadow cost: {}\n",
        format_money_cell(&r.counterfactual.shadow_cost_usd)
    ));
    out.push_str(&format!(
        "- All-frontier reference cost: {}\n",
        format_frontier_cell(
            r.counterfactual.has_frontier_reference,
            &r.counterfactual.all_frontier_cost_usd
        )
    ));
    out.push_str(&format!(
        "- Savings vs all-frontier: {}\n",
        format_frontier_cell(
            r.counterfactual.has_frontier_reference,
            &r.counterfactual.savings_vs_all_frontier_usd
        )
    ));
    out.push_str(&format!(
        "- Quality parity: {} ({})\n",
        r.counterfactual.quality_parity.value,
        confidence_label(r.counterfactual.quality_parity.confidence)
    ));

    out.push_str("\n## Tier Arbitrage\n\n");
    if r.tier_arbitrage.is_empty() {
        out.push_str("No rented tier arbitrage rows were available.\n");
    } else {
        out.push_str("| Task class | Records | Actual cost | Cheapest clearing rented | Delta |\n");
        out.push_str("| --- | ---: | ---: | ---: | ---: |\n");
        for row in &r.tier_arbitrage {
            out.push_str(&format!(
                "| {:?} | {} | {} | {} | {} |\n",
                row.task_class,
                format_count(row.records, Confidence::Observed),
                format_money_cell(&row.actual_cost_usd),
                format_money_cell(&row.cheapest_clearing_rented_usd),
                format_money_cell(&row.delta_usd)
            ));
        }
    }

    out.push_str("\n## Policy Digests\n\n");
    for digest in &r.policy_digests {
        out.push_str(&format!("- `{digest}`\n"));
    }

    out.push_str("\n## Confidence Legend\n\n");
    out.push_str("- observed: from observed usage or list-price inputs\n");
    out.push_str("- declared: from declared TCO or estimated usage inputs\n");
    out.push_str("- canary-verified: backed by parity canaries\n");
    out.push_str("- unverified: missing usage or parity not proven\n\n");
    out.push_str(
        "Diagnostic counts in warning blocks are raw counts, not labeled metric cells.\n\n",
    );
    out.push_str(
        "Bowline observes and accounts; it changed no routing in this window (shadow mode).",
    );
    out
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("unknown supply id: {0}")]
    UnknownSupply(String),
    #[error("authority run is not valid schema-v2 report evidence")]
    InvalidAuthorityRun,
}

#[derive(Debug, Clone)]
struct CostSample {
    class: SupplyClass,
    amount: f64,
    confidence: Confidence,
}

fn supported_evidence(record: &DecisionRecord) -> bool {
    record.coverage_status == CoverageStatus::Supported && record.protocol.is_supported()
}

fn protocol_coverage(records: &[DecisionRecord]) -> ProtocolCoverage {
    let mut by_protocol = BTreeMap::new();
    let mut by_source = BTreeMap::new();
    let mut by_status = BTreeMap::new();
    let mut by_reason = BTreeMap::new();
    let mut supported_records = 0_u64;

    for record in records {
        *by_protocol.entry(record.protocol).or_default() += 1;
        *by_source.entry(record.observation_source).or_default() += 1;
        *by_status.entry(record.coverage_status).or_default() += 1;
        if let Some(reason) = &record.coverage_reason {
            *by_reason.entry(reason.clone()).or_default() += 1;
        }
        supported_records += u64::from(supported_evidence(record));
    }

    let total_inference_records = records.len() as u64;
    let unsupported_records = total_inference_records.saturating_sub(supported_records);
    ProtocolCoverage {
        total_inference_records,
        supported_records,
        unsupported_records,
        complete: unsupported_records == 0,
        by_protocol,
        by_source,
        by_status,
        by_reason,
    }
}

fn attribution_section(records: &[DecisionRecord]) -> AttributionSection {
    let mut by_observation_source = BTreeMap::new();
    for record in records {
        by_observation_source
            .entry(record.observation_source)
            .or_insert_with(AttributionStatusCounts::default)
            .increment(record.actual.attribution_status);
    }
    AttributionSection {
        by_observation_source,
    }
}

fn safe_digest(digest: Option<&str>) -> Option<String> {
    digest
        .filter(|value| {
            value.len() == 71
                && value.starts_with("sha256:")
                && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map(str::to_string)
}

fn display_digest(digest: Option<&str>) -> String {
    digest
        .map(|value| format!("`{value}`"))
        .unwrap_or_else(|| "absent".to_string())
}

fn ledger_state(recovery: &RecoveryOutcome) -> String {
    match recovery {
        RecoveryOutcome::Absent => "absent".to_string(),
        RecoveryOutcome::Clean { .. } => "clean".to_string(),
        RecoveryOutcome::TornTail {
            discarded_bytes, ..
        } => format!("torn-tail ({discarded_bytes} bytes discarded)"),
        RecoveryOutcome::Corrupt { at_offset, .. } => {
            format!("corrupt at offset {at_offset} — records after that point are missing")
        }
        RecoveryOutcome::Undecodable { at_offset, .. } => format!(
            "undecodable record at offset {at_offset} — records after that point are excluded (schema drift, not disk damage)"
        ),
    }
}

fn actual_cost_sample(
    record: &DecisionRecord,
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
) -> Option<CostSample> {
    if record.accounting_truncated {
        return None;
    }
    let entry = actual_entry(record, registry)?;
    let confidence = if entry.price.is_none() && entry.attributes.class == SupplyClass::Owned {
        weakest(usage_confidence(record), Confidence::Declared)
    } else {
        usage_confidence(record)
    };
    let amount = if entry.price.is_some() {
        record.actual.est_cost_usd.unwrap_or(entry_cost_amount(
            entry,
            record.actual.input_tokens,
            record.actual.output_tokens,
            owned_costs,
        )?)
    } else {
        entry_cost_amount(
            entry,
            record.actual.input_tokens,
            record.actual.output_tokens,
            owned_costs,
        )?
    };

    Some(CostSample {
        class: entry.attributes.class,
        amount,
        confidence,
    })
}

fn shadow_cost_sample(
    record: &DecisionRecord,
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
) -> Option<CostSample> {
    let placement = record.decision.shadow.as_ref()?;
    let entry = registry.by_id(&placement.supply_id)?;
    entry_cost_sample(record, entry, owned_costs)
}

fn entry_cost_sample(
    record: &DecisionRecord,
    entry: &SupplyEntry,
    owned_costs: &OwnedCostCatalog,
) -> Option<CostSample> {
    if record.accounting_truncated {
        return None;
    }
    let amount = entry_cost_amount(
        entry,
        record.actual.input_tokens,
        record.actual.output_tokens,
        owned_costs,
    )?;
    let confidence = if entry.price.is_none() && entry.attributes.class == SupplyClass::Owned {
        if owned_costs.cost_per_mtok(&entry.id).is_some() {
            weakest(usage_confidence(record), Confidence::Declared)
        } else {
            Confidence::Unverified
        }
    } else {
        usage_confidence(record)
    };

    Some(CostSample {
        class: entry.attributes.class,
        amount,
        confidence,
    })
}

fn entry_cost_amount(
    entry: &SupplyEntry,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    owned_costs: &OwnedCostCatalog,
) -> Option<f64> {
    let input_tokens = input_tokens.unwrap_or(0);
    let output_tokens = output_tokens.unwrap_or(0);
    if let Some(price) = &entry.price {
        Some(est_cost_usd(price, input_tokens, output_tokens))
    } else if entry.attributes.class == SupplyClass::Owned {
        owned_costs
            .cost_per_mtok(&entry.id)
            .map(|cost| ((input_tokens + output_tokens) as f64 / 1_000_000.0) * cost)
    } else {
        None
    }
}

fn has_unmapped_supply(record: &DecisionRecord, registry: &Registry) -> bool {
    let actual_unmapped = actual_entry(record, registry).is_none();
    let shadow_unmapped = record
        .decision
        .shadow
        .as_ref()
        .is_some_and(|placement| registry.by_id(&placement.supply_id).is_none());

    actual_unmapped || shadow_unmapped
}

fn has_unpriceable_supply(
    record: &DecisionRecord,
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
) -> bool {
    let actual_unpriceable = record
        .actual
        .model
        .as_ref()
        .and_then(|_| actual_entry(record, registry))
        .is_some_and(|entry| !is_priceable(entry, owned_costs));
    let shadow_unpriceable = record
        .decision
        .shadow
        .as_ref()
        .and_then(|placement| registry.by_id(&placement.supply_id))
        .is_some_and(|entry| !is_priceable(entry, owned_costs));

    actual_unpriceable || shadow_unpriceable
}

fn is_priceable(entry: &SupplyEntry, owned_costs: &OwnedCostCatalog) -> bool {
    entry.price.is_some()
        || (entry.attributes.class == SupplyClass::Owned
            && owned_costs.cost_per_mtok(&entry.id).is_some())
}

fn usage_confidence(record: &DecisionRecord) -> Confidence {
    if record.accounting_truncated {
        return Confidence::Unverified;
    }
    match record.actual.usage_source {
        crate::ledger::UsageSource::Observed => Confidence::Observed,
        crate::ledger::UsageSource::Estimated => Confidence::Declared,
        crate::ledger::UsageSource::Missing => Confidence::Unverified,
    }
}

fn actual_entry<'a>(record: &DecisionRecord, registry: &'a Registry) -> Option<&'a SupplyEntry> {
    let model = record.actual.model.as_deref()?;
    match record.actual.supply_id.as_deref() {
        Some(supply_id) => registry.resolve_model(supply_id, model),
        None if record.actual.attribution_status
            == crate::attribution::AttributionStatus::StaticConfigured
            && record.actual.attribution_source
                == crate::attribution::AttributionSource::LegacyConfigured =>
        {
            registry.resolve_unique_model(model)
        }
        None => None,
    }
}

fn share_by_class(samples: &[CostSample]) -> BTreeMap<SupplyClass, Cell<Option<f64>>> {
    let total: f64 = samples.iter().map(|sample| sample.amount).sum();
    let confidence = samples_confidence(samples);
    let mut sums: BTreeMap<SupplyClass, f64> = BTreeMap::new();
    for sample in samples {
        *sums.entry(sample.class).or_default() += sample.amount;
    }

    sums.into_iter()
        .map(|(class, amount)| {
            (
                class,
                Cell {
                    value: if samples.is_empty() {
                        None
                    } else if total == 0.0 {
                        Some(0.0)
                    } else {
                        Some(amount / total)
                    },
                    confidence,
                },
            )
        })
        .collect()
}

fn owned_ratio(samples: &[CostSample]) -> Cell<Option<f64>> {
    let total: f64 = samples.iter().map(|sample| sample.amount).sum();
    let owned: f64 = samples
        .iter()
        .filter(|sample| sample.class == SupplyClass::Owned)
        .map(|sample| sample.amount)
        .sum();

    Cell {
        value: if samples.is_empty() {
            None
        } else if total == 0.0 {
            Some(0.0)
        } else {
            Some(owned / total)
        },
        confidence: samples_confidence(samples),
    }
}

fn sum_cell(samples: &[CostSample]) -> Cell<Option<f64>> {
    Cell {
        value: if samples.is_empty() {
            None
        } else {
            Some(samples.iter().map(|sample| sample.amount).sum())
        },
        confidence: samples_confidence(samples),
    }
}

fn samples_confidence(samples: &[CostSample]) -> Confidence {
    if samples.is_empty() {
        return Confidence::Unverified;
    }

    samples
        .iter()
        .map(|sample| sample.confidence)
        .fold(Confidence::Observed, weakest)
}

fn tier_arbitrage(
    records: &[DecisionRecord],
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
    floors: &QualityFloors,
) -> Vec<ArbitrageRow> {
    let mut by_task: BTreeMap<TaskClass, (u64, Vec<CostSample>, Vec<CostSample>)> = BTreeMap::new();

    for record in records {
        if !supported_evidence(record) {
            continue;
        }
        let floor = floor_for(floors, record);
        let cheapest = cheapest_clearing_rented(record, registry, owned_costs, floor);
        if let (Some(actual), Some(cheapest)) =
            (actual_cost_sample(record, registry, owned_costs), cheapest)
        {
            let row = by_task
                .entry(record.decision.task_class)
                .or_insert_with(|| (0, Vec::new(), Vec::new()));
            row.0 += 1;
            row.1.push(actual);
            row.2.push(cheapest);
        }
    }

    by_task
        .into_iter()
        .map(
            |(task_class, (records, actual_samples, cheapest_samples))| {
                let actual_cost_usd = sum_cell(&actual_samples);
                let cheapest_clearing_rented_usd = sum_cell(&cheapest_samples);
                ArbitrageRow {
                    task_class,
                    records,
                    delta_usd: Cell {
                        value: actual_cost_usd
                            .value
                            .zip(cheapest_clearing_rented_usd.value)
                            .map(|(actual, cheapest)| actual - cheapest),
                        confidence: Confidence::Unverified,
                    },
                    actual_cost_usd,
                    cheapest_clearing_rented_usd,
                }
            },
        )
        .collect()
}

fn floor_for(floors: &QualityFloors, record: &DecisionRecord) -> f32 {
    floors
        .0
        .get(&record.decision.task_class)
        .copied()
        .unwrap_or(record.decision.floor)
}

fn cheapest_clearing_rented(
    record: &DecisionRecord,
    registry: &Registry,
    owned_costs: &OwnedCostCatalog,
    floor: f32,
) -> Option<CostSample> {
    record
        .decision
        .feasible_ids
        .iter()
        .filter_map(|supply_id| registry.by_id(supply_id))
        .filter(|entry| entry.attributes.class != SupplyClass::Owned)
        .filter(|entry| entry.available != Some(false))
        .filter(|entry| {
            entry
                .ratings
                .get(&record.decision.task_class)
                .copied()
                .unwrap_or(0.0)
                >= floor
        })
        .filter_map(|entry| entry_cost_sample(record, entry, owned_costs))
        .min_by(|left, right| left.amount.total_cmp(&right.amount))
}

fn degrade_sovereignty(sovereignty: &mut SovereigntySection) {
    for cell in sovereignty.actual_by_class.values_mut() {
        cell.confidence = Confidence::Unverified;
    }
    for cell in sovereignty.shadow_by_class.values_mut() {
        cell.confidence = Confidence::Unverified;
    }
    sovereignty.sovereignty_ratio_actual.confidence = Confidence::Unverified;
    sovereignty.sovereignty_ratio_shadow.confidence = Confidence::Unverified;
}

fn degrade_counterfactual(counterfactual: &mut CounterfactualSection) {
    counterfactual.actual_cost_usd.confidence = Confidence::Unverified;
    counterfactual.shadow_cost_usd.confidence = Confidence::Unverified;
    counterfactual.all_frontier_cost_usd.confidence = Confidence::Unverified;
    counterfactual.savings_vs_all_frontier_usd.confidence = Confidence::Unverified;
}

fn degrade_arbitrage(rows: &mut [ArbitrageRow]) {
    for row in rows {
        row.actual_cost_usd.confidence = Confidence::Unverified;
        row.cheapest_clearing_rented_usd.confidence = Confidence::Unverified;
        row.delta_usd.confidence = Confidence::Unverified;
    }
}

fn weakest(left: Confidence, right: Confidence) -> Confidence {
    if confidence_rank(left) <= confidence_rank(right) {
        left
    } else {
        right
    }
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Unverified => 0,
        Confidence::Declared => 1,
        Confidence::CanaryVerified => 2,
        Confidence::Observed => 3,
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Observed => "observed",
        Confidence::Declared => "declared",
        Confidence::CanaryVerified => "canary-verified",
        Confidence::Unverified => "unverified",
    }
}

fn format_money_cell(cell: &Cell<Option<f64>>) -> String {
    match cell.value {
        // `+ 0.0` normalizes negative zero so empty shares never render as "$-0.00".
        Some(value) => format!(
            "${:.2} ({})",
            value + 0.0,
            confidence_label(cell.confidence)
        ),
        None => no_priceable_records_label().to_string(),
    }
}

fn format_ratio_cell(cell: &Cell<Option<f64>>) -> String {
    match cell.value {
        // `+ 0.0` normalizes negative zero so empty shares never render as "-0.0%".
        Some(value) => format!(
            "{:.1}% ({})",
            value * 100.0 + 0.0,
            confidence_label(cell.confidence)
        ),
        None => no_priceable_records_label().to_string(),
    }
}

fn format_count(value: u64, confidence: Confidence) -> String {
    format!("{value} ({})", confidence_label(confidence))
}

fn push_share_lines(out: &mut String, shares: &BTreeMap<SupplyClass, Cell<Option<f64>>>) {
    if shares.is_empty() {
        out.push_str(&format!("  - None: {}\n", no_priceable_records_label()));
        return;
    }

    for (class, share) in shares {
        out.push_str(&format!("  - {:?}: {}\n", class, format_ratio_cell(share)));
    }
}

fn no_priceable_records_label() -> &'static str {
    "n/a — no priceable records (unverified)"
}

/// Frontier-dependent cells (all-frontier cost, savings vs all-frontier) render this instead of
/// the generic no-priceable-records label when the registry has no frontier reference at all —
/// e.g. a 100%-owned fleet, which is a success state, not an error (design D-7).
fn format_frontier_cell(has_frontier_reference: bool, cell: &Cell<Option<f64>>) -> String {
    if !has_frontier_reference {
        return no_frontier_reference_label().to_string();
    }
    format_money_cell(cell)
}

fn no_frontier_reference_label() -> &'static str {
    "n/a — no frontier reference"
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::load_owned_cost_catalog;
    use crate::decision::{Decision, Placement};
    use crate::ledger::{ActualOutcome, UsageSource};
    use crate::policy::WorkloadIdentity;
    use crate::run::RunManifest;
    use crate::supply::{Price, Retention, SupplyAttributes, SupplyEntry};
    use crate::traffic::{CoverageStatus, ObservationSource, ProtocolKind};

    fn registry() -> Registry {
        Registry {
            note: None,
            feed_version: "test".to_string(),
            entries: vec![
                entry("local/qwen", "qwen", SupplyClass::Owned, None, 0.90),
                entry(
                    "anthropic/haiku",
                    "haiku",
                    SupplyClass::VpcOpenWeights,
                    Some(price(1.0, 1.0)),
                    0.72,
                ),
                entry(
                    "openai/gpt-frontier",
                    "gpt-frontier",
                    SupplyClass::PublicApi,
                    Some(price(4.0, 6.0)),
                    0.95,
                ),
                entry(
                    "openai/gpt-mini",
                    "gpt-mini",
                    SupplyClass::PublicApi,
                    Some(price(2.0, 2.0)),
                    0.60,
                ),
            ],
        }
    }

    fn registry_with(mut entries: Vec<SupplyEntry>) -> Registry {
        let mut registry = registry();
        registry.entries.append(&mut entries);
        registry
    }

    fn entry(
        id: &str,
        model: &str,
        class: SupplyClass,
        price: Option<Price>,
        rating: f32,
    ) -> SupplyEntry {
        SupplyEntry {
            id: id.to_string(),
            model: model.to_string(),
            aliases: Vec::new(),
            location: "test".to_string(),
            attributes: SupplyAttributes {
                class,
                jurisdiction: "test".to_string(),
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

    fn tco() -> OwnedCostCatalog {
        crate::config::load_owned_cost_catalog(
            Some("monthly_amortization_usd: 600\nmonthly_power_usd: 200\nmonthly_ops_usd: 200\nmonthly_capacity_mtok: 1000\n"),
            Some("local/qwen"),
            &registry(),
        ).expect("test catalog")
    }

    fn cheap_tco() -> OwnedCostCatalog {
        crate::config::load_owned_cost_catalog(
            Some("monthly_amortization_usd: 25\nmonthly_power_usd: 25\nmonthly_ops_usd: 0\nmonthly_capacity_mtok: 1000\n"),
            Some("local/qwen"),
            &registry(),
        ).expect("test catalog")
    }

    fn record(
        id: &str,
        ts_ms: u64,
        task_class: TaskClass,
        actual_model: &str,
        usage_source: UsageSource,
        shadow_supply_id: Option<&str>,
    ) -> DecisionRecord {
        let input_tokens = Some(1_000_000);
        let output_tokens = Some(1_000_000);
        DecisionRecord {
            id: id.to_string(),
            ts_ms,
            run_id: None,
            sequence: None,
            accounting_truncated: false,
            protocol: ProtocolKind::ChatCompletions,
            observation_source: ObservationSource::Inline,
            coverage_status: CoverageStatus::Supported,
            coverage_reason: None,
            identity: WorkloadIdentity {
                api_key_digest: Some("digest".to_string()),
                route: "/v1/chat/completions".to_string(),
                app: Some("report-tests".to_string()),
                tags: Vec::new(),
            },
            decision: Decision {
                policy_digest: format!("policy-{id}"),
                task_class,
                feasible_ids: vec![
                    "local/qwen".to_string(),
                    "anthropic/haiku".to_string(),
                    "openai/gpt-frontier".to_string(),
                    "openai/gpt-mini".to_string(),
                ],
                floor: 0.70,
                shadow: shadow_supply_id.map(|supply_id| Placement {
                    supply_id: supply_id.to_string(),
                    est_cost_usd: None,
                }),
            },
            actual: ActualOutcome {
                upstream: "https://api.example.test".to_string(),
                supply_id: None,
                model: Some(actual_model.to_string()),
                status: 200,
                streamed: false,
                latency_ms: 123,
                input_tokens,
                output_tokens,
                usage_source,
                est_cost_usd: None,
                attribution_status: crate::attribution::AttributionStatus::StaticConfigured,
                attribution_source: crate::attribution::AttributionSource::LegacyConfigured,
                attribution_reference: None,
                attribution_reason: None,
            },
        }
    }

    fn report_with(
        records: &[DecisionRecord],
        registry: &Registry,
        owned_costs: &OwnedCostCatalog,
        floors: &QualityFloors,
    ) -> ShadowReport {
        compute_report(
            records,
            &RecoveryOutcome::Clean {
                records: records.len() as u64,
            },
            registry,
            owned_costs,
            floors,
            Some("openai/gpt-frontier"),
        )
        .expect("report computes")
    }

    fn report(records: &[DecisionRecord]) -> ShadowReport {
        compute_report(
            records,
            &RecoveryOutcome::Clean {
                records: records.len() as u64,
            },
            &registry(),
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("report computes")
    }

    #[test]
    fn report_discloses_protocol_coverage_and_excludes_unsupported_economics() {
        let mut chat = record(
            "chat",
            10,
            TaskClass::HeavyLifting,
            "gpt-frontier",
            UsageSource::Observed,
            Some("local/qwen"),
        );
        chat.protocol = ProtocolKind::ChatCompletions;

        let mut responses = chat.clone();
        responses.id = "responses".to_string();
        responses.protocol = ProtocolKind::Responses;

        let mut embeddings = chat.clone();
        embeddings.id = "embeddings".to_string();
        embeddings.protocol = ProtocolKind::Embeddings;

        let mut unsupported = record(
            "unsupported",
            20,
            TaskClass::HeavyLifting,
            "qwen",
            UsageSource::Observed,
            Some("openai/gpt-mini"),
        );
        unsupported.actual.est_cost_usd = Some(0.001);
        unsupported
            .decision
            .shadow
            .as_mut()
            .expect("apparent placement exists")
            .est_cost_usd = Some(0.001);
        unsupported.protocol = ProtocolKind::Unsupported;
        unsupported.coverage_status = CoverageStatus::UnsupportedProtocol;
        unsupported.coverage_reason = Some("protocol is not supported".to_string());

        let report = report(&[chat, responses, embeddings, unsupported]);

        assert_eq!(report.protocol_coverage.total_inference_records, 4);
        assert_eq!(report.protocol_coverage.supported_records, 3);
        assert_eq!(report.protocol_coverage.unsupported_records, 1);
        assert_eq!(
            report.protocol_coverage.by_protocol[&ProtocolKind::ChatCompletions],
            1
        );
        assert_eq!(
            report.protocol_coverage.by_protocol[&ProtocolKind::Responses],
            1
        );
        assert_eq!(
            report.protocol_coverage.by_protocol[&ProtocolKind::Embeddings],
            1
        );
        assert_eq!(
            report.protocol_coverage.by_protocol[&ProtocolKind::Unsupported],
            1
        );
        assert_eq!(
            report.protocol_coverage.by_source[&ObservationSource::Inline],
            4
        );
        assert_eq!(
            report.protocol_coverage.by_status[&CoverageStatus::Supported],
            3
        );
        assert_eq!(
            report.protocol_coverage.by_status[&CoverageStatus::UnsupportedProtocol],
            1
        );
        assert!(!report.protocol_coverage.complete);
        assert!(!report.complete);
        assert_eq!(report.unplaceable, 0);
        assert_eq!(report.unmapped_records, 0);
        assert_eq!(report.unpriced_records, 0);
        assert_eq!(report.counterfactual.actual_cost_usd.value, Some(30.0));
        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(report.counterfactual.shadow_cost_usd.value, Some(6.0));
        assert_eq!(report.sovereignty.sovereignty_ratio_actual.value, Some(0.0));
        assert_eq!(report.sovereignty.sovereignty_ratio_shadow.value, Some(1.0));
    }

    #[test]
    fn incomplete_observation_is_coverage_only() {
        let mut incomplete = record(
            "incomplete",
            10,
            TaskClass::HeavyLifting,
            "gpt-frontier",
            UsageSource::Observed,
            Some("local/qwen"),
        );
        incomplete.coverage_status = CoverageStatus::IncompleteObservation;
        incomplete.coverage_reason = Some("missing-attribution".to_string());
        incomplete.actual.est_cost_usd = Some(42.0);
        incomplete.actual.supply_id = Some("openai/gpt-frontier".to_string());

        let report = report(&[incomplete]);

        assert_eq!(report.protocol_coverage.total_inference_records, 1);
        assert_eq!(report.protocol_coverage.supported_records, 0);
        assert_eq!(
            report.protocol_coverage.by_status[&CoverageStatus::IncompleteObservation],
            1
        );
        assert_eq!(report.unplaceable, 0);
        assert_eq!(report.unmapped_records, 0);
        assert_eq!(report.unpriced_records, 0);
        assert!(report.tier_arbitrage.is_empty());
        assert_eq!(report.counterfactual.actual_cost_usd.value, None);
        assert_eq!(report.counterfactual.shadow_cost_usd.value, None);
        assert_eq!(report.sovereignty.sovereignty_ratio_actual.value, None);
        assert_eq!(report.sovereignty.sovereignty_ratio_shadow.value, None);
    }

    #[test]
    fn passive_incomplete_never_affects_report_conclusions() {
        let registry = registry_with(vec![entry(
            "unpriced/passive",
            "unpriced-passive",
            SupplyClass::PublicApi,
            None,
            0.99,
        )]);
        let mut unplaceable = record(
            "passive-unplaceable",
            10,
            TaskClass::Mechanical,
            "gpt-frontier",
            UsageSource::Observed,
            None,
        );
        unplaceable.actual.supply_id = Some("openai/gpt-frontier".to_string());
        let mut unmapped = unplaceable.clone();
        unmapped.id = "passive-unmapped".to_string();
        unmapped.actual.supply_id = Some("missing/supply".to_string());
        let mut unpriceable = unplaceable.clone();
        unpriceable.id = "passive-unpriceable".to_string();
        unpriceable.actual.model = Some("unpriced-passive".to_string());
        unpriceable.actual.supply_id = Some("unpriced/passive".to_string());

        for incomplete in [&mut unplaceable, &mut unmapped, &mut unpriceable] {
            incomplete.observation_source = ObservationSource::Passive;
            incomplete.coverage_status = CoverageStatus::IncompleteObservation;
            incomplete.coverage_reason = Some("missing-app".to_string());
            incomplete.actual.est_cost_usd = Some(42.0);
            incomplete.actual.attribution_status = crate::attribution::AttributionStatus::Missing;
            incomplete.actual.attribution_source =
                crate::attribution::AttributionSource::PassiveEvent;
        }

        let report = report_with(
            &[unplaceable, unmapped, unpriceable],
            &registry,
            &tco(),
            &QualityFloors::default(),
        );
        let markdown = render_markdown(&report);

        assert_eq!(
            report.protocol_coverage.by_source[&ObservationSource::Passive],
            3
        );
        assert_eq!(
            report.protocol_coverage.by_status[&CoverageStatus::IncompleteObservation],
            3
        );
        assert_eq!(report.unplaceable, 0);
        assert_eq!(report.unmapped_records, 0);
        assert_eq!(report.unpriced_records, 0);
        assert_eq!(report.counterfactual.actual_cost_usd.value, None);
        assert_eq!(report.counterfactual.shadow_cost_usd.value, None);
        assert_eq!(report.counterfactual.all_frontier_cost_usd.value, None);
        assert_eq!(
            report.counterfactual.savings_vs_all_frontier_usd.value,
            None
        );
        assert!(report.sovereignty.actual_by_class.is_empty());
        assert!(report.sovereignty.shadow_by_class.is_empty());
        assert_eq!(report.sovereignty.sovereignty_ratio_actual.value, None);
        assert_eq!(report.sovereignty.sovereignty_ratio_shadow.value, None);
        assert!(report.tier_arbitrage.is_empty());
        assert!(markdown.contains("passive"));
        assert!(markdown.contains("incomplete-observation"));
        assert!(markdown.contains("missing-app"));
    }

    #[test]
    fn attribution_counts_are_reported_by_observation_source() {
        let cases = [
            (
                ObservationSource::Inline,
                crate::attribution::AttributionStatus::StaticConfigured,
                crate::attribution::AttributionSource::LegacyConfigured,
            ),
            (
                ObservationSource::Inline,
                crate::attribution::AttributionStatus::Attributed,
                crate::attribution::AttributionSource::InlineResponseHeader,
            ),
            (
                ObservationSource::Passive,
                crate::attribution::AttributionStatus::Missing,
                crate::attribution::AttributionSource::PassiveEvent,
            ),
            (
                ObservationSource::Passive,
                crate::attribution::AttributionStatus::UnknownReference,
                crate::attribution::AttributionSource::PassiveEvent,
            ),
            (
                ObservationSource::Passive,
                crate::attribution::AttributionStatus::Ambiguous,
                crate::attribution::AttributionSource::PassiveEvent,
            ),
            (
                ObservationSource::Passive,
                crate::attribution::AttributionStatus::ModelMismatch,
                crate::attribution::AttributionSource::PassiveEvent,
            ),
        ];
        let records = cases
            .into_iter()
            .enumerate()
            .map(|(index, (observation_source, status, source))| {
                let mut record = record(
                    &format!("attribution-{index}"),
                    index as u64,
                    TaskClass::Mechanical,
                    "gpt-mini",
                    UsageSource::Observed,
                    Some("openai/gpt-mini"),
                );
                record.observation_source = observation_source;
                record.actual.attribution_status = status;
                record.actual.attribution_source = source;
                record
            })
            .collect::<Vec<_>>();

        let report = report(&records);
        let json = serde_json::to_value(&report).expect("report serializes");
        for (pointer, expected) in [
            (
                "/attribution/by_observation_source/inline/static_configured",
                1,
            ),
            ("/attribution/by_observation_source/inline/attributed", 1),
            ("/attribution/by_observation_source/inline/missing", 0),
            ("/attribution/by_observation_source/passive/missing", 1),
            (
                "/attribution/by_observation_source/passive/unknown_reference",
                1,
            ),
            ("/attribution/by_observation_source/passive/ambiguous", 1),
            (
                "/attribution/by_observation_source/passive/model_mismatch",
                1,
            ),
        ] {
            assert_eq!(
                json.pointer(pointer).and_then(serde_json::Value::as_u64),
                Some(expected)
            );
        }

        let markdown = render_markdown(&report);
        assert!(markdown.contains("## Attribution"));
        for expected in [
            "### Inline",
            "### Passive",
            "static-configured: 1",
            "attributed: 1",
            "missing: 1",
            "unknown-reference: 1",
            "ambiguous: 1",
            "model-mismatch: 1",
        ] {
            assert!(
                markdown.contains(expected),
                "missing {expected}\n{markdown}"
            );
        }
    }

    #[test]
    fn provenance_discloses_only_digest_presence_and_values() {
        let mut record = record(
            "safe-provenance",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Observed,
            Some("openai/gpt-mini"),
        );
        record.run_id = Some("run-integrity".to_string());
        record.sequence = Some(1);
        record.actual.attribution_reference = Some(crate::attribution::AttributionRef {
            namespace: "must-not-leak-namespace".to_string(),
            value: "must-not-leak-value".to_string(),
        });
        let mut manifest = manifest(1, 1, 0, true);
        let attribution_digest = format!("sha256:{}", "a".repeat(64));
        let profile_digest = format!("sha256:{}", "b".repeat(64));
        manifest.attribution_digest = Some(attribution_digest.clone());
        manifest.owned_cost_digest = Some("must-not-leak-invalid-digest".to_string());
        manifest.passive_profile_digest = Some(profile_digest.clone());

        let report = compute_run_report(
            &[record],
            &[RecoveryOutcome::Clean { records: 1 }],
            &manifest,
            &registry(),
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("report computes");
        let json = serde_json::to_string(&report).expect("report serializes");
        let markdown = render_markdown(&report);

        assert!(json.contains(&attribution_digest));
        assert!(json.contains(&profile_digest));
        assert!(json.contains("\"owned_cost_digest\":null"));
        assert!(json.contains("\"passive_input_digest\":null"));
        for output in [&json, &markdown] {
            assert!(!output.contains("must-not-leak-namespace"));
            assert!(!output.contains("must-not-leak-value"));
            assert!(!output.contains("must-not-leak-invalid-digest"));
        }
        for expected in [
            "## Provenance",
            &format!("Attribution configuration: `{attribution_digest}`"),
            "Owned-cost catalog: absent",
            &format!("Passive profile/source contract: `{profile_digest}`"),
            "Passive input: absent",
        ] {
            assert!(
                markdown.contains(expected),
                "missing {expected}\n{markdown}"
            );
        }
    }

    #[test]
    fn two_owned_locations_use_distinct_keyed_costs() {
        let registry = registry_with(vec![
            entry("owned/a", "owned-a", SupplyClass::Owned, None, 0.95),
            entry("owned/b", "owned-b", SupplyClass::Owned, None, 0.95),
        ]);
        let catalog = load_owned_cost_catalog(
            Some(
                r#"version: 2
supplies:
  owned/a: {monthly_amortization_usd: 100, monthly_power_usd: 0, monthly_ops_usd: 0, monthly_capacity_mtok: 100}
  owned/b: {monthly_amortization_usd: 300, monthly_power_usd: 0, monthly_ops_usd: 0, monthly_capacity_mtok: 100}
"#,
            ),
            None,
            &registry,
        )
        .expect("catalog loads");
        let mut a = record(
            "a",
            10,
            TaskClass::HeavyLifting,
            "owned-a",
            UsageSource::Observed,
            Some("owned/a"),
        );
        a.actual.supply_id = Some("owned/a".to_string());
        let mut b = record(
            "b",
            20,
            TaskClass::HeavyLifting,
            "owned-b",
            UsageSource::Observed,
            Some("owned/b"),
        );
        b.actual.supply_id = Some("owned/b".to_string());

        let a_report = compute_report(
            &[a],
            &RecoveryOutcome::Clean { records: 1 },
            &registry,
            &catalog,
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("a report computes");
        let b_report = compute_report(
            &[b],
            &RecoveryOutcome::Clean { records: 1 },
            &registry,
            &catalog,
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("b report computes");

        assert_eq!(a_report.counterfactual.actual_cost_usd.value, Some(2.0));
        assert_eq!(a_report.counterfactual.shadow_cost_usd.value, Some(2.0));
        assert_eq!(b_report.counterfactual.actual_cost_usd.value, Some(6.0));
        assert_eq!(b_report.counterfactual.shadow_cost_usd.value, Some(6.0));
    }

    #[test]
    fn coverage_exclusions_require_both_supported_protocol_and_supported_status() {
        let registry = registry_with(vec![entry(
            "unpriced/vendor",
            "unpriced",
            SupplyClass::PublicApi,
            None,
            0.99,
        )]);

        let mut unsupported_shape = record(
            "unsupported-shape",
            10,
            TaskClass::HeavyLifting,
            "unknown-model",
            UsageSource::Observed,
            None,
        );
        unsupported_shape.protocol = ProtocolKind::ChatCompletions;
        unsupported_shape.coverage_status = CoverageStatus::UnsupportedShape;

        let mut unsupported_protocol = record(
            "unsupported-protocol",
            20,
            TaskClass::HeavyLifting,
            "unpriced",
            UsageSource::Observed,
            Some("unpriced/vendor"),
        );
        unsupported_protocol.protocol = ProtocolKind::Unsupported;
        unsupported_protocol.coverage_status = CoverageStatus::Supported;
        unsupported_protocol.decision.feasible_ids = vec!["unpriced/vendor".to_string()];

        let report = report_with(
            &[unsupported_shape, unsupported_protocol],
            &registry,
            &tco(),
            &QualityFloors::default(),
        );
        let markdown = render_markdown(&report);

        assert_eq!(report.protocol_coverage.supported_records, 0);
        assert_eq!(report.protocol_coverage.unsupported_records, 2);
        assert_eq!(
            report.protocol_coverage.by_status[&CoverageStatus::Supported],
            1
        );
        assert_eq!(
            report.protocol_coverage.by_status[&CoverageStatus::UnsupportedShape],
            1
        );
        assert_eq!(report.protocol_coverage.by_status.values().sum::<u64>(), 2);
        let supported = markdown
            .find("\n  - supported: 1\n")
            .expect("supported status is rendered");
        let unsupported_protocol = markdown
            .find("\n  - unsupported-protocol: 0\n")
            .expect("unsupported-protocol status is rendered");
        let unsupported_shape = markdown
            .find("\n  - unsupported-shape: 1\n")
            .expect("unsupported-shape status is rendered");
        assert!(supported < unsupported_protocol);
        assert!(unsupported_protocol < unsupported_shape);
        assert_eq!(report.unplaceable, 0);
        assert_eq!(report.unmapped_records, 0);
        assert_eq!(report.unpriced_records, 0);
        assert!(report.tier_arbitrage.is_empty());
        assert_eq!(report.counterfactual.actual_cost_usd.value, None);
        assert_eq!(report.counterfactual.shadow_cost_usd.value, None);
        assert_eq!(report.sovereignty.sovereignty_ratio_actual.value, None);
        assert_eq!(report.sovereignty.sovereignty_ratio_shadow.value, None);
    }

    #[test]
    fn run_report_remains_incomplete_when_protocol_coverage_is_incomplete() {
        let registry = registry();
        let mut unsupported = record(
            "unsupported",
            10,
            TaskClass::HeavyLifting,
            "gpt-frontier",
            UsageSource::Observed,
            Some("local/qwen"),
        );
        unsupported.run_id = Some("run-integrity".to_string());
        unsupported.sequence = Some(1);
        unsupported.actual.supply_id = Some("openai/gpt-frontier".to_string());
        unsupported.protocol = ProtocolKind::Unsupported;
        unsupported.coverage_status = CoverageStatus::UnsupportedProtocol;

        let report = compute_run_report(
            &[unsupported],
            &[RecoveryOutcome::Clean { records: 1 }],
            &manifest(1, 1, 0, true),
            &registry,
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("report computes");

        assert!(!report.protocol_coverage.complete);
        assert!(!report.complete);
        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
    }

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 0.000_001,
            "expected {expected}, got {actual}"
        );
    }

    fn contains_word_meter_case_insensitive(markdown: &str) -> bool {
        let needle = "meter";
        let lower = markdown.to_ascii_lowercase();
        lower.match_indices(needle).any(|(idx, _)| {
            idx == 0
                || lower[..idx]
                    .chars()
                    .next_back()
                    .is_some_and(|ch| !ch.is_ascii_alphanumeric() && ch != '_')
        })
    }

    #[test]
    fn sovereignty_ratio_from_mixed_records() {
        let records = vec![
            record(
                "a",
                10,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("local/qwen"),
            ),
            record(
                "b",
                20,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
            record(
                "c",
                30,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
        ];

        let report = report(&records);

        assert_close(
            report
                .sovereignty
                .sovereignty_ratio_actual
                .value
                .expect("actual sovereignty ratio is priceable"),
            0.0,
        );
        assert_eq!(
            report.sovereignty.sovereignty_ratio_actual.confidence,
            Confidence::Observed
        );
        assert_close(
            report
                .sovereignty
                .sovereignty_ratio_shadow
                .value
                .expect("shadow sovereignty ratio is priceable"),
            0.2,
        );
        assert_eq!(
            report.sovereignty.sovereignty_ratio_shadow.confidence,
            Confidence::Declared
        );
    }

    #[test]
    fn savings_cell_is_always_unverified_in_phase1() {
        let report = report(&[record(
            "a",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Observed,
            Some("local/qwen"),
        )]);

        assert_eq!(
            report.counterfactual.savings_vs_all_frontier_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(
            report.counterfactual.quality_parity.confidence,
            Confidence::Unverified
        );
    }

    #[test]
    fn missing_usage_degrades_confidence() {
        let report = report(&[record(
            "a",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Missing,
            Some("openai/gpt-mini"),
        )]);

        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(
            report.sovereignty.sovereignty_ratio_actual.confidence,
            Confidence::Unverified
        );
    }

    #[test]
    fn corrupt_recovery_surfaces_warning() {
        let records = vec![record(
            "a",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Observed,
            Some("openai/gpt-mini"),
        )];
        let report = compute_report(
            &records,
            &RecoveryOutcome::Corrupt {
                records: 1,
                at_offset: 42,
            },
            &registry(),
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("report computes");
        let markdown = render_markdown(&report);

        assert!(report.ledger_state.contains("corrupt"));
        assert!(markdown.contains("> **Warning:**"));
    }

    #[test]
    fn undecodable_recovery_surfaces_warning_distinct_from_corrupt() {
        let records = vec![record(
            "a",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Observed,
            Some("openai/gpt-mini"),
        )];
        let report = compute_report(
            &records,
            &RecoveryOutcome::Undecodable {
                records: 1,
                at_offset: 42,
            },
            &registry(),
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("report computes");
        let markdown = render_markdown(&report);

        assert!(report.ledger_state.contains("undecodable"));
        assert!(!report.ledger_state.contains("corrupt"));
        assert!(markdown.contains("> **Warning:**"));
    }

    #[test]
    fn arbitrage_row_math() {
        let report = report(&[record(
            "a",
            10,
            TaskClass::HeavyLifting,
            "gpt-frontier",
            UsageSource::Observed,
            Some("local/qwen"),
        )]);
        let row = report
            .tier_arbitrage
            .iter()
            .find(|row| row.task_class == TaskClass::HeavyLifting)
            .expect("heavy-lifting row exists");

        assert_eq!(row.records, 1);
        assert_close(row.actual_cost_usd.value.expect("actual cost"), 10.0);
        assert_close(
            row.cheapest_clearing_rented_usd
                .value
                .expect("cheapest clearing rented cost"),
            2.0,
        );
        assert_close(row.delta_usd.value.expect("delta cost"), 8.0);
        assert_eq!(row.delta_usd.confidence, Confidence::Unverified);
    }

    #[test]
    fn arbitrage_excludes_below_floor_even_when_cheaper() {
        let mut registry = registry();
        registry
            .entries
            .iter_mut()
            .find(|entry| entry.id == "openai/gpt-mini")
            .expect("gpt-mini exists")
            .price = Some(price(0.01, 0.01));
        let floors = QualityFloors(BTreeMap::from([(TaskClass::HeavyLifting, 0.70)]));
        let report = report_with(
            &[record(
                "a",
                10,
                TaskClass::HeavyLifting,
                "gpt-frontier",
                UsageSource::Observed,
                Some("local/qwen"),
            )],
            &registry,
            &tco(),
            &floors,
        );
        let row = report
            .tier_arbitrage
            .iter()
            .find(|row| row.task_class == TaskClass::HeavyLifting)
            .expect("heavy-lifting row exists");

        assert_close(
            row.cheapest_clearing_rented_usd
                .value
                .expect("cheapest clearing rented cost"),
            2.0,
        );
    }

    #[test]
    fn arbitrage_excludes_owned_candidates_even_when_cheapest() {
        let registry = registry();
        let tco = cheap_tco();
        let report = report_with(
            &[record(
                "a",
                10,
                TaskClass::HeavyLifting,
                "gpt-frontier",
                UsageSource::Observed,
                Some("local/qwen"),
            )],
            &registry,
            &tco,
            &QualityFloors::default(),
        );
        let row = report
            .tier_arbitrage
            .iter()
            .find(|row| row.task_class == TaskClass::HeavyLifting)
            .expect("heavy-lifting row exists");

        assert_close(
            row.cheapest_clearing_rented_usd
                .value
                .expect("cheapest clearing rented cost"),
            2.0,
        );
    }

    #[test]
    fn markdown_locks_footer_legend_and_metric_labels() {
        let markdown = render_markdown(&report(&[record(
            "a",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Observed,
            Some("openai/gpt-mini"),
        )]));

        assert!(markdown.contains("accounted"));
        assert!(!contains_word_meter_case_insensitive(&markdown));
        assert!(markdown.ends_with(
            "Bowline observes and accounts; it changed no routing in this window (shadow mode)."
        ));
        assert!(markdown.contains("- observed:"));
        assert!(markdown.contains("- declared:"));
        assert!(markdown.contains("- canary-verified:"));
        assert!(markdown.contains("- unverified:"));
        assert!(markdown.contains("- Actual cost: $4.00 (observed)"));
        assert!(markdown.contains("Traffic accounted: 1 (observed)"));
    }

    #[test]
    fn markdown_reports_protocol_coverage() {
        let mut chat = record(
            "chat",
            10,
            TaskClass::Mechanical,
            "gpt-mini",
            UsageSource::Observed,
            Some("openai/gpt-mini"),
        );
        chat.protocol = ProtocolKind::ChatCompletions;

        let mut responses = chat.clone();
        responses.id = "responses".to_string();
        responses.protocol = ProtocolKind::Responses;

        let mut embeddings = chat.clone();
        embeddings.id = "embeddings".to_string();
        embeddings.protocol = ProtocolKind::Embeddings;

        let mut unsupported_protocol = chat.clone();
        unsupported_protocol.id = "unsupported-protocol".to_string();
        unsupported_protocol.protocol = ProtocolKind::Unsupported;
        unsupported_protocol.coverage_status = CoverageStatus::UnsupportedProtocol;

        let mut unsupported_shape = chat.clone();
        unsupported_shape.id = "unsupported-shape".to_string();
        unsupported_shape.coverage_status = CoverageStatus::UnsupportedShape;

        let markdown = render_markdown(&report(&[
            chat,
            responses,
            embeddings,
            unsupported_protocol,
            unsupported_shape,
        ]));

        for expected in [
            "## Protocol Coverage",
            "Supported inference records: 3",
            "Unsupported inference records: 2",
            "chat-completions: 2",
            "responses: 1",
            "embeddings: 1",
            "unsupported: 1",
            "unsupported-protocol: 1",
            "unsupported-shape: 1",
            "Coverage complete: no",
        ] {
            assert!(
                markdown.contains(expected),
                "missing protocol coverage line: {expected}\n\n{markdown}"
            );
        }
    }

    #[test]
    fn unplaceable_counted() {
        let report = report(&[
            record(
                "a",
                10,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                None,
            ),
            record(
                "b",
                20,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
        ]);

        assert_eq!(report.unplaceable, 1);
    }

    #[test]
    fn window_uses_min_and_max_timestamps_across_records() {
        let report = report(&[
            record(
                "a",
                50,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
            record(
                "b",
                10,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
            record(
                "c",
                70,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
        ]);

        assert_eq!(report.window, (10, 70));
    }

    #[test]
    fn unmapped_records_are_disclosed_and_degrade_cost_cells() {
        let report = report(&[
            record(
                "a",
                10,
                TaskClass::Mechanical,
                "unknown-model",
                UsageSource::Observed,
                Some("openai/gpt-mini"),
            ),
            record(
                "b",
                20,
                TaskClass::Mechanical,
                "gpt-mini",
                UsageSource::Observed,
                Some("missing/supply"),
            ),
        ]);
        let markdown = render_markdown(&report);

        assert_eq!(report.unmapped_records, 2);
        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(
            report.counterfactual.shadow_cost_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(
            report.sovereignty.sovereignty_ratio_actual.confidence,
            Confidence::Unverified
        );
        assert!(markdown.contains(
            "2 records could not be mapped to a supply entry and are excluded from cost cells"
        ));
    }

    #[test]
    fn priceless_rented_entries_are_excluded_from_arbitrage_and_cost_sums() {
        let registry = registry_with(vec![entry(
            "freeish/vendor",
            "freeish",
            SupplyClass::PublicApi,
            None,
            0.99,
        )]);
        let mut record = record(
            "a",
            10,
            TaskClass::HeavyLifting,
            "gpt-frontier",
            UsageSource::Observed,
            Some("freeish/vendor"),
        );
        record.decision.feasible_ids = vec![
            "freeish/vendor".to_string(),
            "anthropic/haiku".to_string(),
            "openai/gpt-frontier".to_string(),
        ];

        let report = report_with(&[record], &registry, &tco(), &QualityFloors::default());
        let markdown = render_markdown(&report);
        let row = report
            .tier_arbitrage
            .iter()
            .find(|row| row.task_class == TaskClass::HeavyLifting)
            .expect("heavy-lifting row exists");

        assert_close(
            row.cheapest_clearing_rented_usd
                .value
                .expect("cheapest clearing rented cost"),
            2.0,
        );
        assert_eq!(
            report.counterfactual.shadow_cost_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(report.counterfactual.shadow_cost_usd.value, None);
        assert_eq!(
            report.counterfactual.savings_vs_all_frontier_usd.value,
            None
        );
        assert_eq!(
            report.counterfactual.savings_vs_all_frontier_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(
            serde_json::to_value(&report)
                .expect("report serializes")
                .pointer("/counterfactual/shadow_cost_usd/value"),
            Some(&serde_json::Value::Null)
        );
        assert!(markdown.contains("n/a — no priceable records (unverified)"));
        assert!(!markdown.contains("- Shadow cost: $0.00"));
    }

    #[test]
    fn all_owned_registry_degrades_counterfactual_to_na_instead_of_erroring() {
        let registry = Registry {
            note: None,
            feed_version: "test".to_string(),
            entries: vec![entry("local/qwen", "qwen", SupplyClass::Owned, None, 0.90)],
        };
        let mut record = record(
            "a",
            10,
            TaskClass::Mechanical,
            "qwen",
            UsageSource::Observed,
            Some("local/qwen"),
        );
        record.decision.feasible_ids = vec!["local/qwen".to_string()];

        let report = compute_report(
            &[record],
            &RecoveryOutcome::Clean { records: 1 },
            &registry,
            &tco(),
            &QualityFloors::default(),
            None,
        )
        .expect("all-owned registry must not error — a 100%-owned fleet is a success state");
        let markdown = render_markdown(&report);

        assert!(!report.counterfactual.has_frontier_reference);
        assert_eq!(report.counterfactual.all_frontier_cost_usd.value, None);
        assert_eq!(
            report.counterfactual.savings_vs_all_frontier_usd.value,
            None
        );
        assert!(markdown.contains("- All-frontier reference cost: n/a — no frontier reference"));
        assert!(markdown.contains("- Savings vs all-frontier: n/a — no frontier reference"));
        assert_eq!(
            serde_json::to_value(&report)
                .expect("report serializes")
                .pointer("/counterfactual/all_frontier_cost_usd/value"),
            Some(&serde_json::Value::Null)
        );

        // Every other section still renders normally for a 100%-owned fleet.
        assert_close(
            report
                .sovereignty
                .sovereignty_ratio_actual
                .value
                .expect("sovereignty ratio is priceable"),
            1.0,
        );
    }

    #[test]
    fn explicit_unresolvable_frontier_reference_still_errors() {
        let registry = Registry {
            note: None,
            feed_version: "test".to_string(),
            entries: vec![entry("local/qwen", "qwen", SupplyClass::Owned, None, 0.90)],
        };
        let err = compute_report(
            &[],
            &RecoveryOutcome::Clean { records: 0 },
            &registry,
            &tco(),
            &QualityFloors::default(),
            Some("openai/no-such-entry"),
        )
        .expect_err("an explicitly supplied but unresolvable frontier reference must error");
        assert!(matches!(err, ReportError::UnknownSupply(id) if id == "openai/no-such-entry"));
    }

    #[test]
    fn owned_without_tco_is_excluded_not_declared_zero() {
        let registry = registry();
        let report = report_with(
            &[record(
                "a",
                10,
                TaskClass::HeavyLifting,
                "qwen",
                UsageSource::Observed,
                Some("local/qwen"),
            )],
            &registry,
            &OwnedCostCatalog::default(),
            &QualityFloors::default(),
        );
        let markdown = render_markdown(&report);

        assert_eq!(report.counterfactual.actual_cost_usd.value, None);
        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
        assert_eq!(report.counterfactual.shadow_cost_usd.value, None);
        assert_eq!(
            report.counterfactual.shadow_cost_usd.confidence,
            Confidence::Unverified
        );
        assert!(!report
            .sovereignty
            .actual_by_class
            .contains_key(&SupplyClass::Owned));
        assert!(markdown.contains("- Actual owned ratio: n/a — no priceable records (unverified)"));
        assert!(markdown.contains("- Shadow owned ratio: n/a — no priceable records (unverified)"));
        assert!(!markdown.contains("- Actual owned ratio: 0.0%"));
        assert!(!markdown.contains("- Shadow owned ratio: 0.0%"));
    }

    #[test]
    fn drops_and_sequence_gaps_make_report_incomplete_and_unverified() {
        let registry = registry();
        let mut records = (1..=8)
            .map(|sequence| {
                let mut record = record(
                    &sequence.to_string(),
                    10 + sequence,
                    TaskClass::HeavyLifting,
                    "gpt-frontier",
                    UsageSource::Observed,
                    Some("local/qwen"),
                );
                record.run_id = Some("run-integrity".to_string());
                record.sequence = Some(sequence);
                record.actual.supply_id = Some("openai/gpt-frontier".to_string());
                record
            })
            .collect::<Vec<_>>();
        records.remove(2);
        let report = compute_run_report(
            &records,
            &[RecoveryOutcome::Clean {
                records: records.len() as u64,
            }],
            &manifest(10, 7, 2, false),
            &registry,
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("incomplete report still renders");

        assert!(!report.complete);
        assert_eq!(report.data_integrity.dropped, 2);
        assert_eq!(report.data_integrity.missing_sequences, 1);
        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
        assert!(render_markdown(&report).contains("## Data Integrity"));
    }

    #[test]
    fn accounting_truncation_never_substitutes_zero_output_cost() {
        let registry = registry();
        let mut truncated = record(
            "truncated",
            10,
            TaskClass::HeavyLifting,
            "gpt-frontier",
            UsageSource::Estimated,
            Some("local/qwen"),
        );
        truncated.run_id = Some("run-integrity".to_string());
        truncated.sequence = Some(1);
        truncated.accounting_truncated = true;
        truncated.actual.supply_id = Some("openai/gpt-frontier".to_string());
        truncated.actual.output_tokens = None;
        truncated.actual.est_cost_usd = None;

        let report = compute_run_report(
            &[truncated],
            &[RecoveryOutcome::Clean { records: 1 }],
            &manifest(1, 1, 0, true),
            &registry,
            &tco(),
            &QualityFloors::default(),
            Some("openai/gpt-frontier"),
        )
        .expect("truncated report renders");

        assert!(!report.complete);
        assert_eq!(report.data_integrity.truncated, 1);
        assert_eq!(report.counterfactual.actual_cost_usd.value, None);
        assert_eq!(
            report.counterfactual.actual_cost_usd.confidence,
            Confidence::Unverified
        );
    }

    fn manifest(accepted: u64, recorded: u64, dropped: u64, clean_shutdown: bool) -> RunManifest {
        RunManifest {
            schema_version: 1,
            run_id: "run-integrity".to_string(),
            started_at_ms: 1,
            ended_at_ms: clean_shutdown.then_some(2),
            clean_shutdown,
            policy_digest: "sha256:policy".to_string(),
            registry_digest: "sha256:registry".to_string(),
            attribution_digest: None,
            owned_cost_digest: None,
            passive_profile_digest: None,
            passive_input_digest: None,
            accepted,
            recorded,
            dropped,
            truncated: 0,
            unmapped: 0,
            unpriceable: 0,
            untrusted_identity_headers: 0,
            next_sequence: accepted + 1,
            writer_healthy: true,
            writer_error: None,
            last_flush_at_ms: Some(2),
            segment_bytes: 1024,
            max_segments: 4,
            segments: vec!["segment.bwl".to_string()],
            segment_inventory: vec![],
            records_digest: None,
        }
    }
}
