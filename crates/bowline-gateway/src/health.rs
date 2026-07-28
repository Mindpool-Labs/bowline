use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use bowline_core::enforcement::KillReadResult;
use bowline_core::run::RunStore;
use serde::Serialize;

#[derive(Clone)]
pub struct GatewayHealth {
    run: Arc<RunStore>,
    queue_depth: Arc<AtomicUsize>,
    queue_capacity: usize,
    shutting_down: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
    pub mode: &'static str,
    pub ready: bool,
    pub run_id: String,
    pub policy_digest: String,
    pub registry_digest: String,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub truncated: u64,
    pub unmapped: u64,
    pub unpriceable: u64,
    pub untrusted_identity_headers: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub writer_healthy: bool,
    pub writer_error: Option<String>,
    pub clean_shutdown: bool,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub last_flush_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlledHealthSnapshot {
    pub mode: &'static str,
    pub ready: bool,
    pub degraded: bool,
    pub accepted: u64,
    pub recorded: u64,
    pub dropped: u64,
    pub truncated: u64,
    pub unmapped: u64,
    pub unpriceable: u64,
    pub untrusted_identity_headers: u64,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub writer_healthy: bool,
    pub clean_shutdown: bool,
    pub enforcement: PublicEnforcementHealth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicEnforcementHealth {
    pub config_valid: bool,
    pub evidence_valid: bool,
    pub kill_state: KillReadResult,
    pub route_modes: RouteModeCounts,
    pub circuits: CircuitCounts,
    pub grant_freshness: GrantFreshnessCounts,
    pub candidate_admission: CandidateAdmissionHealth,
    pub active_fail_closed_routes_on_unavailable_actuators: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RouteModeCounts {
    pub observe: usize,
    pub recommend: usize,
    pub canary_enforce: usize,
    pub enforce: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CircuitCounts {
    pub closed: usize,
    pub open: usize,
    pub half_open: usize,
}

/// `unverified` counts every authority route with no usable promotion grant for any reason: no
/// evidence configured at all, a rejected `authority_signing` signature, or a rejected
/// `promotion_approval` artifact (missing, invalid, unbound, or expired). This snapshot never
/// distinguishes which of those applied; it only reports that the route currently carries no
/// authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GrantFreshnessCounts {
    pub fresh: usize,
    pub stale: usize,
    pub unverified: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CandidateAdmissionHealth {
    pub in_flight: usize,
    pub capacity: usize,
    pub saturation_count: usize,
}

impl GatewayHealth {
    pub fn new(run: Arc<RunStore>, queue_capacity: usize) -> Self {
        Self {
            run,
            queue_depth: Arc::new(AtomicUsize::new(0)),
            queue_capacity,
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let manifest = self.run.snapshot();
        let shutting_down = self.shutting_down.load(Ordering::Acquire);
        HealthSnapshot {
            mode: "shadow",
            ready: manifest.writer_healthy && manifest.dropped == 0 && !shutting_down,
            run_id: manifest.run_id,
            policy_digest: manifest.policy_digest,
            registry_digest: manifest.registry_digest,
            accepted: manifest.accepted,
            recorded: manifest.recorded,
            dropped: manifest.dropped,
            truncated: manifest.truncated,
            unmapped: manifest.unmapped,
            unpriceable: manifest.unpriceable,
            untrusted_identity_headers: manifest.untrusted_identity_headers,
            queue_depth: self.queue_depth.load(Ordering::Acquire),
            queue_capacity: self.queue_capacity,
            writer_healthy: manifest.writer_healthy,
            writer_error: manifest.writer_error,
            clean_shutdown: manifest.clean_shutdown,
            started_at_ms: manifest.started_at_ms,
            ended_at_ms: manifest.ended_at_ms,
            last_flush_at_ms: manifest.last_flush_at_ms,
        }
    }

    pub fn controlled_snapshot(
        &self,
        enforcement: &PublicEnforcementHealth,
    ) -> ControlledHealthSnapshot {
        let manifest = self.run.snapshot();
        let shutting_down = self.shutting_down.load(Ordering::Acquire);
        let writer_ready = manifest.writer_healthy && manifest.dropped == 0 && !shutting_down;
        let enforcement_ready = enforcement.config_valid
            && enforcement.evidence_valid
            && enforcement.grant_freshness.stale == 0
            && enforcement.grant_freshness.unverified == 0
            && enforcement.active_fail_closed_routes_on_unavailable_actuators == 0;
        let degraded = enforcement.kill_state != KillReadResult::Armed
            || enforcement.circuits.open > 0
            || enforcement.circuits.half_open > 0
            || enforcement.grant_freshness.stale > 0
            || enforcement.grant_freshness.unverified > 0
            || enforcement.candidate_admission.saturation_count > 0;
        ControlledHealthSnapshot {
            mode: "controlled",
            ready: writer_ready && enforcement_ready,
            degraded,
            accepted: manifest.accepted,
            recorded: manifest.recorded,
            dropped: manifest.dropped,
            truncated: manifest.truncated,
            unmapped: manifest.unmapped,
            unpriceable: manifest.unpriceable,
            untrusted_identity_headers: manifest.untrusted_identity_headers,
            queue_depth: self.queue_depth.load(Ordering::Acquire),
            queue_capacity: self.queue_capacity,
            writer_healthy: manifest.writer_healthy,
            clean_shutdown: manifest.clean_shutdown,
            enforcement: enforcement.clone(),
        }
    }

    pub(crate) fn increment_queue_depth(&self) {
        self.queue_depth.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn decrement_queue_depth(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(1))
            });
    }

    #[cfg(test)]
    pub(crate) fn set_queue_depth(&self, value: usize) {
        self.queue_depth.store(value, Ordering::Release);
    }

    pub(crate) fn begin_shutdown(&self) -> bool {
        !self.shutting_down.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    pub(crate) fn run(&self) -> &Arc<RunStore> {
        &self.run
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bowline_core::run::{RunDigests, RunLimits, RunStore};
    use tempfile::tempdir;

    use super::*;
    use bowline_core::enforcement::KillReadResult;

    #[test]
    fn shadow_status_preserves_the_exact_legacy_serialization_contract() {
        let temp = tempdir().expect("temporary run directory");
        let run = Arc::new(
            RunStore::create(
                temp.path(),
                RunDigests {
                    policy: "sha256:policy".to_string(),
                    registry: "sha256:registry".to_string(),
                    attribution: None,
                    owned_cost: None,
                    passive_profile: None,
                    passive_input: None,
                },
                RunLimits {
                    segment_bytes: 1024,
                    max_segments: 4,
                },
            )
            .expect("run starts"),
        );
        let health = GatewayHealth::new(run, 16);
        health.set_queue_depth(3);
        let snapshot = health.snapshot();
        let json = serde_json::to_string(&snapshot).expect("snapshot serializes");

        assert!(snapshot.ready);
        assert_eq!(snapshot.queue_depth, 3);
        assert_eq!(snapshot.queue_capacity, 16);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                "accepted",
                "clean_shutdown",
                "dropped",
                "ended_at_ms",
                "last_flush_at_ms",
                "mode",
                "policy_digest",
                "queue_capacity",
                "queue_depth",
                "ready",
                "recorded",
                "registry_digest",
                "run_id",
                "started_at_ms",
                "truncated",
                "unmapped",
                "unpriceable",
                "untrusted_identity_headers",
                "writer_error",
                "writer_healthy",
            ]
        );
        assert!(json.contains("sha256:policy"));
        assert!(json.contains("run_id"));
        assert!(json.contains("writer_error"));
        assert!(!json.contains("authorization"));
        assert!(!json.contains("prompt"));
        assert!(!json.contains("response"));
    }

    #[test]
    fn controlled_public_health_is_aggregate_and_route_safe() {
        let temp = tempdir().expect("temporary run directory");
        let run = Arc::new(
            RunStore::create(
                temp.path(),
                RunDigests {
                    policy: "sha256:policy".to_string(),
                    registry: "sha256:registry".to_string(),
                    attribution: None,
                    owned_cost: None,
                    passive_profile: None,
                    passive_input: None,
                },
                RunLimits {
                    segment_bytes: 1024,
                    max_segments: 4,
                },
            )
            .unwrap(),
        );
        let health = GatewayHealth::new(run, 16);
        let enforcement = PublicEnforcementHealth {
            config_valid: true,
            evidence_valid: true,
            kill_state: KillReadResult::Armed,
            route_modes: RouteModeCounts {
                observe: 1,
                recommend: 2,
                canary_enforce: 3,
                enforce: 4,
            },
            circuits: CircuitCounts {
                closed: 1,
                open: 1,
                half_open: 0,
            },
            grant_freshness: GrantFreshnessCounts {
                fresh: 2,
                stale: 0,
                unverified: 0,
            },
            candidate_admission: CandidateAdmissionHealth {
                in_flight: 2,
                capacity: 8,
                saturation_count: 1,
            },
            active_fail_closed_routes_on_unavailable_actuators: 0,
        };
        let snapshot = health.controlled_snapshot(&enforcement);
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(snapshot.ready);
        assert!(snapshot.degraded);
        for forbidden in [
            "\"run_id\"",
            "\"policy_digest\"",
            "\"registry_digest\"",
            "\"route_id\"",
            "\"app\"",
            "\"tags\"",
            "\"supply_id\"",
            "\"model_id\"",
            "\"endpoint\"",
            "\"authorization_env\"",
            "\"writer_error\"",
        ] {
            assert!(!json.contains(forbidden), "leaked {forbidden}: {json}");
        }

        let mut unsafe_route = enforcement;
        unsafe_route.active_fail_closed_routes_on_unavailable_actuators = 1;
        assert!(!health.controlled_snapshot(&unsafe_route).ready);
    }
}
