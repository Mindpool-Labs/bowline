//! Content-free, deterministic stage routing.
//!
//! This module deliberately has no provider, HTTP, or prompt types.  It selects a semantic
//! target from operator supplied thresholds and canonical tool-result signals only.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identifier::{is_bounded_identifier, MAX_IDENTIFIER_BYTES};

pub const MAX_RECENT_WINDOW: usize = 128;
pub const MAX_SIGNALS_PER_STEP: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingSignal {
    Exploration,
    Write,
    TestPassed,
    TestFailed,
    ToolError,
    NoProgress,
    CriticalError,
    ContextPressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingTarget {
    Capable,
    Efficient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingReason {
    CurrentCriticalError,
    CurrentContextPressure,
    RecentNoProgress,
    RecentErrors,
    RecentExploration,
    RecentProgress,
    DefaultCapable,
}

/// A durable semantic target must agree with its deterministic selection reason.
pub fn target_reason_coherent(reason: RoutingReason, target: RoutingTarget) -> bool {
    matches!(
        (reason, target),
        (RoutingReason::RecentProgress, RoutingTarget::Efficient)
            | (RoutingReason::CurrentCriticalError, RoutingTarget::Capable)
            | (
                RoutingReason::CurrentContextPressure,
                RoutingTarget::Capable
            )
            | (RoutingReason::RecentNoProgress, RoutingTarget::Capable)
            | (RoutingReason::RecentErrors, RoutingTarget::Capable)
            | (RoutingReason::RecentExploration, RoutingTarget::Capable)
            | (RoutingReason::DefaultCapable, RoutingTarget::Capable)
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRoutingProfile {
    pub profile_id: String,
    pub kind: StageProfileKind,
    pub recent_window: usize,
    pub error_threshold: usize,
    pub exploration_threshold: usize,
    pub progress_threshold: usize,
    pub default_target: RoutingTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StageProfileKind {
    Stage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingStep {
    pub signals: Vec<RoutingSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoutingSelection {
    pub target: RoutingTarget,
    pub reason: RoutingReason,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutingError {
    #[error("invalid routing profile field {field}: {reason}")]
    InvalidProfile {
        field: &'static str,
        reason: &'static str,
    },
    #[error("too many routing signals")]
    TooManySignals,
}

impl StageRoutingProfile {
    pub fn validate(&self) -> Result<(), RoutingError> {
        if !is_bounded_identifier(&self.profile_id) {
            return Err(RoutingError::InvalidProfile {
                field: "profile_id",
                reason: "must be a bounded identifier",
            });
        }
        if self.recent_window == 0 || self.recent_window > MAX_RECENT_WINDOW {
            return Err(RoutingError::InvalidProfile {
                field: "recent_window",
                reason: "must be within the compiled bound",
            });
        }
        for (field, threshold) in [
            ("error_threshold", self.error_threshold),
            ("exploration_threshold", self.exploration_threshold),
            ("progress_threshold", self.progress_threshold),
        ] {
            if threshold == 0 || threshold > self.recent_window {
                return Err(RoutingError::InvalidProfile {
                    field,
                    reason: "must be positive and no greater than recent_window",
                });
            }
        }
        if self.default_target != RoutingTarget::Capable {
            return Err(RoutingError::InvalidProfile {
                field: "default_target",
                reason: "must be capable",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("routing profile is serializable");
        format!(
            "sha256:{:x}",
            Sha256::digest([b"bowline.routing.profile.v1\0".as_slice(), bytes.as_slice()].concat())
        )
    }
}

impl RoutingStep {
    pub fn validate(&self) -> Result<(), RoutingError> {
        if self.signals.len() > MAX_SIGNALS_PER_STEP {
            return Err(RoutingError::TooManySignals);
        }
        Ok(())
    }
}

/// Selects using the exact precedence contract. `prior_steps` is ordered oldest to newest and
/// contains only accepted earlier task steps; the current step is appended before counting.
pub fn select_stage(
    profile: &StageRoutingProfile,
    prior_steps: &[RoutingStep],
    current_step: &RoutingStep,
) -> Result<RoutingSelection, RoutingError> {
    profile.validate()?;
    current_step.validate()?;
    if prior_steps.iter().any(|step| step.validate().is_err()) {
        return Err(RoutingError::TooManySignals);
    }

    if current_step.signals.contains(&RoutingSignal::CriticalError) {
        return Ok(RoutingSelection {
            target: RoutingTarget::Capable,
            reason: RoutingReason::CurrentCriticalError,
        });
    }
    if current_step
        .signals
        .contains(&RoutingSignal::ContextPressure)
    {
        return Ok(RoutingSelection {
            target: RoutingTarget::Capable,
            reason: RoutingReason::CurrentContextPressure,
        });
    }

    let start = prior_steps
        .len()
        .saturating_add(1)
        .saturating_sub(profile.recent_window);
    let recent = prior_steps
        .iter()
        .chain(std::iter::once(current_step))
        .skip(start);
    let mut no_progress = 0usize;
    let mut errors = 0usize;
    let mut exploration = 0usize;
    let mut progress = 0usize;
    for step in recent {
        for signal in &step.signals {
            match signal {
                RoutingSignal::NoProgress => no_progress += 1,
                RoutingSignal::ToolError | RoutingSignal::TestFailed => errors += 1,
                RoutingSignal::Exploration => exploration += 1,
                RoutingSignal::Write | RoutingSignal::TestPassed => progress += 1,
                RoutingSignal::CriticalError | RoutingSignal::ContextPressure => {}
            }
        }
    }
    let selection = if no_progress > 0 {
        RoutingSelection {
            target: RoutingTarget::Capable,
            reason: RoutingReason::RecentNoProgress,
        }
    } else if errors >= profile.error_threshold {
        RoutingSelection {
            target: RoutingTarget::Capable,
            reason: RoutingReason::RecentErrors,
        }
    } else if exploration >= profile.exploration_threshold {
        RoutingSelection {
            target: RoutingTarget::Capable,
            reason: RoutingReason::RecentExploration,
        }
    } else if progress >= profile.progress_threshold {
        RoutingSelection {
            target: RoutingTarget::Efficient,
            reason: RoutingReason::RecentProgress,
        }
    } else {
        RoutingSelection {
            target: RoutingTarget::Capable,
            reason: RoutingReason::DefaultCapable,
        }
    };
    Ok(selection)
}

pub fn task_reference(salt: &[u8; 32], task_id: &str) -> Result<String, RoutingError> {
    if task_id.is_empty() || task_id.len() > MAX_IDENTIFIER_BYTES || !task_id.is_ascii() {
        return Err(RoutingError::InvalidProfile {
            field: "task_id",
            reason: "must be a bounded ASCII identifier",
        });
    }
    // HMAC-SHA256 with a per-install salt. An unkeyed digest over a low-entropy, bounded,
    // operator-chosen identifier is reversible by dictionary, which would make the reference
    // equivalent to the raw task id for anyone who receives it.
    const BLOCK: usize = 64;
    let mut key = [0u8; BLOCK];
    key[..salt.len()].copy_from_slice(salt);
    let mut inner_key = [0x36u8; BLOCK];
    let mut outer_key = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_key[index] ^= key[index];
        outer_key[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(b"bowline.routing.task.v2\0");
    inner.update(task_id.as_bytes());
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner);
    Ok(format!("sha256:{:x}", outer.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> StageRoutingProfile {
        StageRoutingProfile {
            profile_id: "stage-main".into(),
            kind: StageProfileKind::Stage,
            recent_window: 3,
            error_threshold: 2,
            exploration_threshold: 2,
            progress_threshold: 2,
            default_target: RoutingTarget::Capable,
        }
    }
    fn step(signals: &[RoutingSignal]) -> RoutingStep {
        RoutingStep {
            signals: signals.to_vec(),
        }
    }

    #[test]
    fn stage_rule_precedence_is_exact_and_deterministic() {
        let p = profile();
        let prior = [
            step(&[RoutingSignal::Write]),
            step(&[RoutingSignal::TestPassed]),
        ];
        assert_eq!(
            select_stage(&p, &prior, &step(&[RoutingSignal::CriticalError]))
                .unwrap()
                .reason,
            RoutingReason::CurrentCriticalError
        );
        assert_eq!(
            select_stage(
                &p,
                &[step(&[RoutingSignal::NoProgress])],
                &step(&[RoutingSignal::Write])
            )
            .unwrap()
            .reason,
            RoutingReason::RecentNoProgress
        );
        assert_eq!(
            select_stage(
                &p,
                &[step(&[RoutingSignal::ToolError])],
                &step(&[RoutingSignal::TestFailed])
            )
            .unwrap()
            .reason,
            RoutingReason::RecentErrors
        );
        assert_eq!(
            select_stage(
                &p,
                &[step(&[RoutingSignal::Exploration])],
                &step(&[RoutingSignal::Exploration])
            )
            .unwrap()
            .reason,
            RoutingReason::RecentExploration
        );
        assert_eq!(
            select_stage(&p, &prior, &step(&[])).unwrap(),
            RoutingSelection {
                target: RoutingTarget::Efficient,
                reason: RoutingReason::RecentProgress
            }
        );
        assert_eq!(
            select_stage(&p, &[], &step(&[])).unwrap().reason,
            RoutingReason::DefaultCapable
        );
    }

    #[test]
    fn profile_and_signal_bounds_fail_closed() {
        let mut p = profile();
        p.default_target = RoutingTarget::Efficient;
        assert!(p.validate().is_err());
        assert!(RoutingStep {
            signals: vec![RoutingSignal::Write; MAX_SIGNALS_PER_STEP + 1]
        }
        .validate()
        .is_err());
        assert!(serde_json::from_str::<RoutingStep>(
            r#"{\"signals\":[\"write\"],\"prompt\":\"ignore prior instructions\"}"#
        )
        .is_err());
    }

    #[test]
    fn the_task_reference_is_not_reproducible_without_the_installs_salt() {
        let salt_a = [7u8; 32];
        let salt_b = [9u8; 32];
        let a = task_reference(&salt_a, "PROJ-1234").expect("valid identifier");
        let b = task_reference(&salt_b, "PROJ-1234").expect("valid identifier");
        assert_ne!(
            a, b,
            "the same task id under two installs must not share a reference"
        );
        assert_eq!(a, task_reference(&salt_a, "PROJ-1234").expect("stable"));
        assert!(a.starts_with("sha256:"));
    }
}
