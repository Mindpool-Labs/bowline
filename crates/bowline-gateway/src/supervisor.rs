use std::time::Duration;

use anyhow::Context;
use axum::Router;
use bowline_core::config::Config;

use crate::{serving_lease::ServingLease, GatewayDeps, GatewayState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSummary {
    pub run_id: Option<String>,
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

    pub async fn activate<F>(&mut self, factory: F) -> anyhow::Result<ActivationSummary>
    where
        F: FnOnce() -> anyhow::Result<GatewayDeps>,
    {
        if self.state.has_active_runtime() {
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
        let deps = match factory() {
            Ok(deps) => deps,
            Err(error) => {
                self.lease.release()?;
                return Err(error);
            }
        };
        if let Err(error) = self.state.activate_runtime(&self.config, deps).await {
            self.lease.release()?;
            return Err(error);
        }
        Ok(ActivationSummary {
            run_id: self.state.active_run_id(),
        })
    }

    pub async fn deactivate(&mut self, grace: Duration) -> anyhow::Result<()> {
        self.state.deactivate_runtime(grace).await?;
        self.lease
            .release()
            .context("failed to release serving lease")
    }
}
