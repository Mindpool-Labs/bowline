use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use bowline_core::enforcement::ActuatorConfig;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::actuator::{
    ActuatorError, ActuatorSnapshot, CandidateFailure, CircuitSnapshot, CircuitState,
};

pub trait AdmissionLease: Send {}

pub type AdmissionLeaseHandle = Box<dyn AdmissionLease>;
pub type AdmissionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AdmissionLeaseHandle, ActuatorError>> + Send + 'a>>;

pub trait StateBackend: Send + Sync {
    fn try_acquire<'a>(&'a self, supply_id: &'a str, wait: Duration) -> AdmissionFuture<'a>;

    fn in_flight(&self) -> (usize, usize);

    fn candidate_acquisition_count(&self) -> usize;

    fn snapshot(&self) -> ActuatorSnapshot;

    fn circuit(&self, supply_id: &str) -> Result<CircuitSnapshot, ActuatorError>;

    fn try_begin_probe(&self, supply_id: &str, now: Instant) -> Result<bool, ActuatorError>;

    fn try_begin_startup_probe(&self, supply_id: &str, now: Instant)
        -> Result<bool, ActuatorError>;

    fn finish_probe(&self, supply_id: &str, success: bool, now: Instant);

    fn record_candidate(&self, supply_id: &str, failure: Option<CandidateFailure>, now: Instant);
}

#[derive(Clone)]
pub struct LocalStateBackend {
    global: Arc<Semaphore>,
    global_capacity: usize,
    global_in_flight: Arc<AtomicUsize>,
    candidate_acquisition_count: Arc<AtomicUsize>,
    saturation_count: Arc<AtomicUsize>,
    actuators: Arc<BTreeMap<String, Arc<LocalActuatorState>>>,
}

struct LocalActuatorState {
    semaphore: Arc<Semaphore>,
    in_flight: Arc<AtomicUsize>,
    breaker_consecutive_failures: u32,
    breaker_cooldown: Duration,
    circuit: Mutex<CircuitData>,
}

struct CircuitData {
    state: CircuitState,
    consecutive_failures: u32,
    opened_at: Instant,
    probe_in_flight: bool,
}

struct LocalAdmissionLease {
    _actuator: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    actuator_in_flight: Arc<AtomicUsize>,
    global_in_flight: Arc<AtomicUsize>,
}

impl AdmissionLease for LocalAdmissionLease {}

impl Drop for LocalAdmissionLease {
    fn drop(&mut self) {
        self.actuator_in_flight.fetch_sub(1, Ordering::AcqRel);
        self.global_in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl LocalStateBackend {
    pub fn new(
        global_candidate_in_flight: u32,
        configs: impl IntoIterator<Item = ActuatorConfig>,
    ) -> Result<Self, ActuatorError> {
        if global_candidate_in_flight == 0 {
            return Err(ActuatorError::InvalidConfiguration);
        }
        let mut actuators = BTreeMap::new();
        for config in configs {
            if config.concurrency == 0 || actuators.contains_key(&config.supply_id) {
                return Err(ActuatorError::InvalidConfiguration);
            }
            actuators.insert(
                config.supply_id,
                Arc::new(LocalActuatorState {
                    semaphore: Arc::new(Semaphore::new(config.concurrency as usize)),
                    in_flight: Arc::new(AtomicUsize::new(0)),
                    breaker_consecutive_failures: config.breaker_consecutive_failures,
                    breaker_cooldown: Duration::from_millis(config.breaker_cooldown_ms),
                    circuit: Mutex::new(CircuitData {
                        state: CircuitState::Open,
                        consecutive_failures: 0,
                        opened_at: Instant::now(),
                        probe_in_flight: false,
                    }),
                }),
            );
        }
        Ok(Self {
            global: Arc::new(Semaphore::new(global_candidate_in_flight as usize)),
            global_capacity: global_candidate_in_flight as usize,
            global_in_flight: Arc::new(AtomicUsize::new(0)),
            candidate_acquisition_count: Arc::new(AtomicUsize::new(0)),
            saturation_count: Arc::new(AtomicUsize::new(0)),
            actuators: Arc::new(actuators),
        })
    }

    fn begin_probe(
        &self,
        supply_id: &str,
        now: Instant,
        startup: bool,
    ) -> Result<bool, ActuatorError> {
        let actuator = self
            .actuators
            .get(supply_id)
            .ok_or(ActuatorError::UnknownActuator)?;
        let mut state = actuator
            .circuit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.state != CircuitState::Open
            || state.probe_in_flight
            || (!startup
                && now.saturating_duration_since(state.opened_at) < actuator.breaker_cooldown)
        {
            return Ok(false);
        }
        state.state = CircuitState::HalfOpen;
        state.probe_in_flight = true;
        Ok(true)
    }
}

impl StateBackend for LocalStateBackend {
    fn try_acquire<'a>(&'a self, supply_id: &'a str, wait: Duration) -> AdmissionFuture<'a> {
        Box::pin(async move {
            let actuator = self
                .actuators
                .get(supply_id)
                .ok_or(ActuatorError::UnknownActuator)?;
            if actuator
                .circuit
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .state
                != CircuitState::Closed
            {
                return Err(ActuatorError::CircuitUnavailable);
            }
            let deadline = tokio::time::Instant::now() + wait;
            let global =
                match tokio::time::timeout_at(deadline, Arc::clone(&self.global).acquire_owned())
                    .await
                {
                    Ok(Ok(permit)) => permit,
                    _ => {
                        self.saturation_count.fetch_add(1, Ordering::AcqRel);
                        return Err(ActuatorError::Saturated);
                    }
                };
            let actuator_permit = match tokio::time::timeout_at(
                deadline,
                Arc::clone(&actuator.semaphore).acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => permit,
                _ => {
                    self.saturation_count.fetch_add(1, Ordering::AcqRel);
                    return Err(ActuatorError::Saturated);
                }
            };
            if actuator
                .circuit
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .state
                != CircuitState::Closed
            {
                return Err(ActuatorError::CircuitUnavailable);
            }
            self.global_in_flight.fetch_add(1, Ordering::AcqRel);
            actuator.in_flight.fetch_add(1, Ordering::AcqRel);
            self.candidate_acquisition_count
                .fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(LocalAdmissionLease {
                _actuator: actuator_permit,
                _global: global,
                actuator_in_flight: Arc::clone(&actuator.in_flight),
                global_in_flight: Arc::clone(&self.global_in_flight),
            }) as AdmissionLeaseHandle)
        })
    }

    fn in_flight(&self) -> (usize, usize) {
        let actuator = self
            .actuators
            .values()
            .map(|entry| entry.in_flight.load(Ordering::Acquire))
            .sum();
        (self.global_in_flight.load(Ordering::Acquire), actuator)
    }

    fn candidate_acquisition_count(&self) -> usize {
        self.candidate_acquisition_count.load(Ordering::Acquire)
    }

    fn snapshot(&self) -> ActuatorSnapshot {
        let mut closed = 0;
        let mut open = 0;
        let mut half_open = 0;
        for actuator in self.actuators.values() {
            match actuator
                .circuit
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .state
            {
                CircuitState::Closed => closed += 1,
                CircuitState::Open => open += 1,
                CircuitState::HalfOpen => half_open += 1,
            }
        }
        ActuatorSnapshot {
            closed,
            open,
            half_open,
            global_candidate_in_flight: self.global_in_flight.load(Ordering::Acquire),
            global_candidate_capacity: self.global_capacity,
            saturation_count: self.saturation_count.load(Ordering::Acquire),
        }
    }

    fn circuit(&self, supply_id: &str) -> Result<CircuitSnapshot, ActuatorError> {
        let actuator = self
            .actuators
            .get(supply_id)
            .ok_or(ActuatorError::UnknownActuator)?;
        let state = actuator
            .circuit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(match state.state {
            CircuitState::Closed if state.consecutive_failures == 0 => CircuitSnapshot::Closed,
            CircuitState::Closed => CircuitSnapshot::ClosedWithFailures(state.consecutive_failures),
            CircuitState::Open => CircuitSnapshot::Open,
            CircuitState::HalfOpen => CircuitSnapshot::HalfOpen,
        })
    }

    fn try_begin_probe(&self, supply_id: &str, now: Instant) -> Result<bool, ActuatorError> {
        self.begin_probe(supply_id, now, false)
    }

    fn try_begin_startup_probe(
        &self,
        supply_id: &str,
        now: Instant,
    ) -> Result<bool, ActuatorError> {
        self.begin_probe(supply_id, now, true)
    }

    fn finish_probe(&self, supply_id: &str, success: bool, now: Instant) {
        let Some(actuator) = self.actuators.get(supply_id) else {
            return;
        };
        let mut state = actuator
            .circuit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.probe_in_flight = false;
        if success {
            state.state = CircuitState::Closed;
            state.consecutive_failures = 0;
        } else {
            state.state = CircuitState::Open;
            state.opened_at = now;
        }
    }

    fn record_candidate(&self, supply_id: &str, failure: Option<CandidateFailure>, now: Instant) {
        let Some(actuator) = self.actuators.get(supply_id) else {
            return;
        };
        let mut state = actuator
            .circuit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.state != CircuitState::Closed {
            return;
        }
        match failure {
            None => {
                state.state = CircuitState::Closed;
                state.consecutive_failures = 0;
            }
            Some(_) => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                if state.consecutive_failures >= actuator.breaker_consecutive_failures {
                    state.state = CircuitState::Open;
                    state.opened_at = now;
                }
            }
        }
    }
}
