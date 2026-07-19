use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Context;
use axum::Router;
use bowline_core::config::Config;

use crate::{serving_lease::ServingLease, GatewayDeps, GatewayState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSummary {
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingState {
    Standby,
    Activating,
    Active,
    Draining,
}

impl ServingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standby => "standby",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Draining => "draining",
        }
    }

    pub fn rejection_reason(self) -> &'static str {
        match self {
            Self::Standby => "standby-no-lease",
            Self::Activating => "activation-in-progress",
            Self::Active => "runtime-unready",
            Self::Draining => "draining",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingStatusSnapshot {
    pub state: ServingState,
    pub last_activation_reason: Option<&'static str>,
}

#[derive(Clone)]
pub(crate) struct ServingStatus {
    inner: Arc<RwLock<ServingStatusSnapshot>>,
}

impl ServingStatus {
    pub(crate) fn standby() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ServingStatusSnapshot {
                state: ServingState::Standby,
                last_activation_reason: None,
            })),
        }
    }

    pub(crate) fn snapshot(&self) -> ServingStatusSnapshot {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set_state(&self, state: ServingState) {
        let mut status = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        status.state = state;
        if state == ServingState::Active {
            status.last_activation_reason = None;
        }
    }

    pub(crate) fn activation_failed(&self) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ServingStatusSnapshot {
            state: ServingState::Standby,
            last_activation_reason: Some("activation-failed"),
        };
    }
}

pub struct GatewaySupervisor<L> {
    config: Config,
    state: GatewayState,
    lease: L,
}

impl<L> GatewaySupervisor<L>
where
    L: ServingLease,
{
    pub fn new(config: Config, lease: L) -> anyhow::Result<Self> {
        let state = GatewayState::standby(&config)?;
        Ok(Self {
            config,
            state,
            lease,
        })
    }

    pub fn router(&self) -> Router {
        self.state.clone().router()
    }

    pub fn is_active(&self) -> bool {
        self.state.has_active_runtime()
    }

    pub async fn activate<F>(&mut self, factory: &mut F) -> anyhow::Result<ActivationSummary>
    where
        F: FnMut() -> anyhow::Result<GatewayDeps>,
    {
        if self.state.has_active_runtime() {
            self.state.set_serving_state(ServingState::Active);
            return Ok(ActivationSummary {
                run_id: self.state.active_run_id(),
            });
        }
        if !self
            .lease
            .try_acquire()
            .context("failed to acquire serving lease")?
            || !self.lease.may_admit()
        {
            anyhow::bail!("serving lease is unavailable");
        }
        self.state.set_serving_state(ServingState::Activating);
        let deps = match factory() {
            Ok(deps) => deps,
            Err(error) => {
                self.state.activation_failed();
                self.lease.release()?;
                return Err(error);
            }
        };
        if let Err(error) = self.state.activate_runtime(&self.config, deps).await {
            self.state.activation_failed();
            self.lease.release()?;
            return Err(error);
        }
        self.state.set_serving_state(ServingState::Active);
        Ok(ActivationSummary {
            run_id: self.state.active_run_id(),
        })
    }

    pub async fn reconcile<F>(&mut self, factory: &mut F, grace: Duration) -> anyhow::Result<()>
    where
        F: FnMut() -> anyhow::Result<GatewayDeps>,
    {
        if self.state.has_active_runtime() {
            if self.lease.may_admit() {
                self.state.set_serving_state(ServingState::Active);
                return Ok(());
            }
            self.state.set_serving_state(ServingState::Draining);
            self.state.deactivate_runtime(grace).await?;
            self.lease.release()?;
            self.state.set_serving_state(ServingState::Standby);
        }
        if !self.lease.try_acquire()? {
            self.state.set_serving_state(ServingState::Standby);
            return Ok(());
        }
        self.activate(factory).await?;
        Ok(())
    }

    pub async fn deactivate(&mut self, grace: Duration) -> anyhow::Result<()> {
        if self.state.has_active_runtime() {
            self.state.set_serving_state(ServingState::Draining);
        }
        self.state.deactivate_runtime(grace).await?;
        let result = self
            .lease
            .release()
            .context("failed to release serving lease");
        if result.is_ok() {
            self.state.set_serving_state(ServingState::Standby);
        }
        result
    }
}
