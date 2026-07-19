use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bowline_core::enforcement::ActuatorConfig;
use bowline_gateway::{
    actuator::{CandidateFailure, CircuitSnapshot},
    state_backend::{LocalStateBackend, StateBackend},
};

fn actuator(supply_id: &str, concurrency: u32) -> ActuatorConfig {
    ActuatorConfig {
        supply_id: supply_id.into(),
        base_url: "http://127.0.0.1:3000".into(),
        authorization_env: "BOWLINE_TEST_TOKEN".into(),
        health_path: Some("/v1/models".into()),
        remote_acknowledged: false,
        connect_timeout_ms: 100,
        response_header_timeout_ms: 100,
        stream_idle_timeout_ms: 100,
        concurrency,
        probe_timeout_ms: 100,
        probe_max_bytes: 1024,
        breaker_consecutive_failures: 2,
        breaker_cooldown_ms: 100,
    }
}

#[tokio::test]
async fn local_backend_preserves_semantics() {
    let backend: Arc<dyn StateBackend> =
        Arc::new(LocalStateBackend::new(1, [actuator("candidate", 1)]).unwrap());
    let started = Instant::now();

    assert_eq!(backend.circuit("candidate").unwrap(), CircuitSnapshot::Open);
    assert!(!backend.try_begin_probe("candidate", started).unwrap());
    assert!(backend
        .try_begin_probe("candidate", started + Duration::from_millis(100))
        .unwrap());
    assert_eq!(
        backend.circuit("candidate").unwrap(),
        CircuitSnapshot::HalfOpen
    );

    backend.finish_probe("candidate", true, started + Duration::from_millis(101));
    assert_eq!(
        backend.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );

    backend.record_candidate(
        "candidate",
        Some(CandidateFailure::Connect),
        started + Duration::from_millis(102),
    );
    assert_eq!(
        backend.circuit("candidate").unwrap(),
        CircuitSnapshot::ClosedWithFailures(1)
    );
    backend.record_candidate("candidate", None, started + Duration::from_millis(103));
    assert_eq!(
        backend.circuit("candidate").unwrap(),
        CircuitSnapshot::Closed
    );

    let permit = backend
        .try_acquire("candidate", Duration::from_millis(10))
        .await
        .unwrap();
    assert_eq!(backend.in_flight(), (1, 1));
    drop(permit);
    assert_eq!(backend.in_flight(), (0, 0));

    backend.record_candidate(
        "candidate",
        Some(CandidateFailure::HeaderTimeout),
        started + Duration::from_millis(104),
    );
    backend.record_candidate(
        "candidate",
        Some(CandidateFailure::StreamIdleTimeout),
        started + Duration::from_millis(105),
    );
    assert_eq!(backend.circuit("candidate").unwrap(), CircuitSnapshot::Open);

    let snapshot = backend.snapshot();
    assert_eq!(snapshot.closed, 0);
    assert_eq!(snapshot.open, 1);
    assert_eq!(snapshot.half_open, 0);
    assert_eq!(snapshot.global_candidate_in_flight, 0);
    assert_eq!(snapshot.global_candidate_capacity, 1);
    assert_eq!(snapshot.saturation_count, 0);
}
