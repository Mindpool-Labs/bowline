use std::{
    collections::BTreeMap,
    env, fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, HeaderName, Method, Request, Response, StatusCode, Uri},
    routing::{any, get},
    Router,
};
use bowline_core::{
    attribution::{
        resolve_actual_supply, AttributionInput, AttributionResolver, AttributionSource,
    },
    config::{
        endpoint_identity, load_owned_cost_catalog, Config, InlineAttributionConfig,
        OwnedCostCatalog, RuntimeConfig, StateBackendConfig,
    },
    decision::{decide, Decision, QualityFloors},
    enforcement::{
        operator_safe_route_id, rewrite_top_level_model, ActiveRuntimeProvenance,
        AuthorityProtocol, CandidateAvailability, EnforcementConfigV1, EnforcementPlan,
        FallbackMode, KillReadResult, PlanTarget, RewriteLimits, SelectionReason,
        SelectionRequestFacts, ValidatedEnforcement,
    },
    ledger::{
        CandidateFailureClassV2, CircuitStateV2, CompletionStateV2, DecisionRecord, UsageSource,
    },
    policy::{PolicyBundle, WorkloadIdentity},
    supply::Registry,
    traffic::{CoverageStatus, ObservationSource, ProtocolKind},
};
use futures_util::{stream::Stream, StreamExt};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::health::{
    CandidateAdmissionHealth, CircuitCounts, GatewayHealth, GrantFreshnessCounts,
    PublicEnforcementHealth, RouteModeCounts,
};
use crate::{
    accounting::{
        parse_request, parse_response_model, parse_response_usage, parse_sse_model,
        parse_sse_usage, RequestFacts, UsageFacts,
    },
    actuator::{
        build_redirect_free_client, send_authorized_candidate, ActuatorError, ActuatorRegistry,
        AuthorizedCandidateRequest, CandidateFailure, CandidatePermit, CandidateResponseStream,
        CircuitSnapshot, RedirectFreeClient,
    },
    enforcement_loader::{
        load_verified_promotion_grant_with_approval, load_verified_recommendation_evidence,
        select_enforcement_target, select_enforcement_target_with_grant_rejection,
        select_enforcement_target_without_grant, select_recommendation_target,
        BoundedKillStateReader, KillStateReader, PromotionGrantLoad, VerifiedPromotionGrant,
        VerifiedRecommendationEvidence,
    },
    identity::{extract_identity, resolve_request_context, ResolvedRequestContext},
    observation::{
        actual_cost, apply_attribution_coverage, build_decision_record,
        prepare_candidate_authority_decision_v2, prepare_zero_authority_decision_v2,
        ActualObservation, AuthorityDecisionContextV2, CandidatePreparationV2, RecordEnvelope,
    },
    writer::{
        open_writer_if_recording_enabled, spawn_managed_authority_writer, AuthorityTerminalV2,
        AuthorityWriterOptions, CandidateDecisionReservation, CandidateDispatchReservation,
        FinalDispatchAuthorization, LedgerWriter, ManagedAuthorityWriter, ManagedWriter,
        RecordContext,
    },
};

#[cfg(test)]
use crate::protocol::INFERENCE_PROTOCOL_CATALOG;
#[cfg(test)]
use bowline_core::enforcement::route_workload_digest;

const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct GatewayDeps {
    recording: Option<Arc<RecordingDeps>>,
    enforcement: Option<Arc<EnforcementRuntime>>,
}

impl GatewayDeps {
    pub fn recording(
        policy: PolicyBundle,
        registry: Registry,
        floors: QualityFloors,
        owned_costs: OwnedCostCatalog,
        writer: LedgerWriter,
    ) -> Self {
        Self::recording_inner(
            policy,
            registry,
            floors,
            owned_costs,
            RecordingWriter::Legacy(writer),
            None,
        )
    }

    pub fn managed(
        policy: PolicyBundle,
        registry: Registry,
        floors: QualityFloors,
        owned_costs: OwnedCostCatalog,
        writer: ManagedWriter,
    ) -> Self {
        Self::managed_inner(policy, registry, floors, owned_costs, writer, None)
    }

    pub fn managed_with_provenance(
        policy: PolicyBundle,
        registry_source: &str,
        floors: QualityFloors,
        owned_costs: OwnedCostCatalog,
        writer: ManagedWriter,
    ) -> anyhow::Result<Self> {
        let registry = Registry::from_json(registry_source)
            .context("failed to parse active registry source")?;
        let provenance =
            ActiveRuntimeProvenance::from_loaded(&policy, registry_source, &owned_costs);
        Ok(Self::managed_inner(
            policy,
            registry,
            floors,
            owned_costs,
            writer,
            Some(provenance),
        ))
    }

    fn managed_inner(
        policy: PolicyBundle,
        registry: Registry,
        floors: QualityFloors,
        owned_costs: OwnedCostCatalog,
        writer: ManagedWriter,
        provenance: Option<ActiveRuntimeProvenance>,
    ) -> Self {
        Self::recording_inner(
            policy,
            registry,
            floors,
            owned_costs,
            RecordingWriter::Managed(writer),
            provenance,
        )
    }

    fn recording_inner(
        policy: PolicyBundle,
        registry: Registry,
        floors: QualityFloors,
        owned_costs: OwnedCostCatalog,
        writer: RecordingWriter,
        provenance: Option<ActiveRuntimeProvenance>,
    ) -> Self {
        Self {
            recording: Some(Arc::new(RecordingDeps {
                policy,
                registry,
                floors,
                owned_costs,
                writer,
                provenance,
            })),
            enforcement: None,
        }
    }
}

#[derive(Clone)]
pub struct GatewayState {
    client: reqwest::Client,
    upstream_base: String,
    upstream_identity: String,
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    response_header_timeout: std::time::Duration,
    stream_idle_timeout: std::time::Duration,
    accounting_limit_bytes: usize,
    controlled_configured: bool,
    serving_status: Option<crate::supervisor::ServingStatus>,
    runtime: Arc<RwLock<Option<Arc<GatewayRuntime>>>>,
}

struct GatewayRuntime {
    recording: Option<Arc<RecordingDeps>>,
    health: Option<GatewayHealth>,
    attribution_resolver: Option<Arc<AttributionResolver>>,
    attribution_header: Option<HeaderName>,
    attribution_namespace: Option<String>,
    enforcement: Option<Arc<EnforcementRuntime>>,
    admission: Arc<RuntimeAdmission>,
}

#[derive(Default)]
struct RuntimeAdmission {
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    idle: tokio::sync::Notify,
}

struct RuntimeAdmissionGuard {
    admission: Arc<RuntimeAdmission>,
}

struct AdmissionStream<S> {
    inner: Pin<Box<S>>,
    _guard: RuntimeAdmissionGuard,
}

impl<S> Stream for AdmissionStream<S>
where
    S: Stream,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(cx)
    }
}

impl RuntimeAdmission {
    fn active() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            idle: tokio::sync::Notify::new(),
        }
    }

    fn try_admit(self: &Arc<Self>) -> Option<RuntimeAdmissionGuard> {
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        if !self.accepting.load(Ordering::Acquire) {
            if self.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.idle.notify_waiters();
            }
            return None;
        }
        Some(RuntimeAdmissionGuard {
            admission: Arc::clone(self),
        })
    }

    fn stop(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    async fn wait_idle(&self) {
        loop {
            if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = self.idle.notified();
            if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for RuntimeAdmissionGuard {
    fn drop(&mut self) {
        if self.admission.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.admission.idle.notify_waiters();
        }
    }
}

struct EnforcementRuntime {
    validated: ValidatedEnforcement,
    route_ids: Vec<String>,
    grants: BTreeMap<String, VerifiedPromotionGrant>,
    /// Routes whose promotion grant was rejected wholesale — a missing or invalid
    /// `authority_signing` signature, or a missing, invalid, unbound, or expired
    /// `promotion_approval` artifact. Disjoint from `grants`; populated only when the route
    /// otherwise has no verified grant. Never populated when neither `authority_signing` nor
    /// `promotion_approval` is configured.
    grant_rejections: BTreeMap<String, SelectionReason>,
    recommendations: BTreeMap<String, VerifiedRecommendationEvidence>,
    kill_reader: BoundedKillStateReader,
    actuators: ActuatorRegistry,
    targets: BTreeMap<String, ActuatorTarget>,
    writer: ManagedAuthorityWriter,
    terminal_tracker: Arc<AuthorityTerminalTracker>,
    last_kill_state: Mutex<KillReadResult>,
}

#[derive(Default)]
struct AuthorityTerminalTracker {
    outstanding: AtomicUsize,
    idle: tokio::sync::Notify,
}

struct AuthorityTerminalGuard {
    tracker: Arc<AuthorityTerminalTracker>,
}

impl AuthorityTerminalTracker {
    fn start(self: &Arc<Self>) -> AuthorityTerminalGuard {
        self.outstanding.fetch_add(1, Ordering::AcqRel);
        AuthorityTerminalGuard {
            tracker: Arc::clone(self),
        }
    }

    async fn wait_idle(&self) {
        loop {
            if self.outstanding.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = self.idle.notified();
            if self.outstanding.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for AuthorityTerminalGuard {
    fn drop(&mut self) {
        if self.tracker.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.idle.notify_waiters();
        }
    }
}

struct ActuatorTarget {
    client: RedirectFreeClient,
    base_url: String,
    authorization: reqwest::header::HeaderValue,
    canonical_model: String,
    response_header_timeout: Duration,
    stream_idle_timeout: Duration,
}

#[derive(Clone)]
struct RecordingDeps {
    policy: PolicyBundle,
    registry: Registry,
    floors: QualityFloors,
    owned_costs: OwnedCostCatalog,
    writer: RecordingWriter,
    provenance: Option<ActiveRuntimeProvenance>,
}

#[derive(Clone)]
enum RecordingWriter {
    Legacy(LedgerWriter),
    Managed(ManagedWriter),
}

fn managed_recording_writer(deps: &GatewayDeps) -> Option<ManagedWriter> {
    deps.recording
        .as_ref()
        .and_then(|recording| match &recording.writer {
            RecordingWriter::Managed(writer) => Some(writer.clone()),
            RecordingWriter::Legacy(_) => None,
        })
}

async fn cleanup_failed_activation(
    writer: Option<ManagedWriter>,
    grace: Duration,
) -> anyhow::Result<()> {
    let Some(writer) = writer else {
        return Ok(());
    };
    let run = writer.health().run().clone();
    run.set_writer_error("activation-failed");
    let flush_result = run.flush();
    let shutdown_result = writer.shutdown(grace).await;
    flush_result.context("failed to persist activation failure")?;
    shutdown_result.context("failed to close partial activation writer")
}

impl GatewayState {
    pub fn new(upstream_base: impl Into<String>, deps: GatewayDeps) -> Self {
        let runtime = RuntimeConfig::default();
        let trusted_proxy_cidrs = vec![
            ipnet::IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ipnet::IpNet::from(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];
        let state = Self::build_base(
            upstream_base.into(),
            trusted_proxy_cidrs,
            &runtime,
            false,
            false,
        )
        .expect("default reqwest client configuration is valid");
        let active = GatewayRuntime::build(None, None, deps)
            .expect("default gateway dependencies are valid");
        state.replace_runtime(Some(Arc::new(active)));
        state
    }

    pub fn from_config(config: &Config, deps: GatewayDeps) -> anyhow::Result<Self> {
        let state = Self::build_base(
            config.upstream.clone(),
            config.trusted_proxy_cidrs.clone(),
            &config.runtime,
            config.enforcement.is_some(),
            matches!(
                config.state_backend.as_ref(),
                Some(StateBackendConfig::FileLease { .. })
            ),
        )?;
        let active = GatewayRuntime::build(
            Some(config.actual_supply_id.clone()),
            config.attribution.clone(),
            deps,
        )?;
        state.replace_runtime(Some(Arc::new(active)));
        Ok(state)
    }

    pub fn standby(config: &Config) -> anyhow::Result<Self> {
        Self::build_base(
            config.upstream.clone(),
            config.trusted_proxy_cidrs.clone(),
            &config.runtime,
            config.enforcement.is_some(),
            matches!(
                config.state_backend.as_ref(),
                Some(StateBackendConfig::FileLease { .. })
            ),
        )
    }

    fn build_base(
        upstream_base: String,
        trusted_proxy_cidrs: Vec<ipnet::IpNet>,
        runtime: &RuntimeConfig,
        controlled_configured: bool,
        file_lease_mode: bool,
    ) -> anyhow::Result<Self> {
        let upstream_identity = endpoint_identity(&upstream_base);
        Ok(Self {
            // Invariant: reqwest has no compression features, so bytes pass through verbatim; do not add gzip/brotli features.
            client: reqwest::Client::builder()
                .connect_timeout(runtime.connect_timeout())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("failed to build upstream HTTP client")?,
            upstream_base: upstream_base.trim_end_matches('/').to_string(),
            upstream_identity,
            trusted_proxy_cidrs,
            response_header_timeout: runtime.response_header_timeout(),
            stream_idle_timeout: runtime.stream_idle_timeout(),
            accounting_limit_bytes: runtime.accounting_limit_bytes,
            controlled_configured,
            serving_status: file_lease_mode.then(crate::supervisor::ServingStatus::standby),
            runtime: Arc::new(RwLock::new(None)),
        })
    }

    fn replace_runtime(&self, runtime: Option<Arc<GatewayRuntime>>) {
        *self
            .runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = runtime;
    }

    fn active_runtime(&self) -> Option<Arc<GatewayRuntime>> {
        self.runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn has_active_runtime(&self) -> bool {
        self.runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    pub(crate) fn active_run_id(&self) -> Option<String> {
        self.active_runtime().and_then(|runtime| runtime.run_id())
    }

    pub(crate) fn set_serving_state(&self, state: crate::supervisor::ServingState) {
        if let Some(status) = &self.serving_status {
            status.set_state(state);
        }
    }

    pub(crate) fn activation_failed(&self) {
        if let Some(status) = &self.serving_status {
            status.activation_failed();
        }
    }

    fn serving_status_snapshot(&self) -> Option<crate::supervisor::ServingStatusSnapshot> {
        self.serving_status
            .as_ref()
            .map(crate::supervisor::ServingStatus::snapshot)
    }

    #[cfg(test)]
    fn set_health_for_test(&self, health: GatewayHealth) {
        let mut runtime = self
            .runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::get_mut(runtime.as_mut().expect("test runtime is active"))
            .expect("test runtime is not shared")
            .health = Some(health);
    }

    pub(crate) async fn activate_runtime(
        &self,
        config: &Config,
        deps: GatewayDeps,
    ) -> anyhow::Result<()> {
        if self.has_active_runtime() {
            anyhow::bail!("gateway runtime is already active");
        }
        let cleanup_writer = managed_recording_writer(&deps);
        let deps = match prepare_runtime_deps(config, deps) {
            Ok(deps) => deps,
            Err(error) => {
                cleanup_failed_activation(cleanup_writer, config.runtime.shutdown_grace())
                    .await
                    .with_context(|| format!("activation cleanup failed after: {error}"))?;
                return Err(error);
            }
        };
        let cleanup_writer = cleanup_writer.or_else(|| managed_recording_writer(&deps));
        let runtime = match GatewayRuntime::build(
            Some(config.actual_supply_id.clone()),
            config.attribution.clone(),
            deps,
        ) {
            Ok(runtime) => Arc::new(runtime),
            Err(error) => {
                cleanup_failed_activation(cleanup_writer, config.runtime.shutdown_grace())
                    .await
                    .with_context(|| format!("activation cleanup failed after: {error}"))?;
                return Err(error);
            }
        };
        if let Some(enforcement) = runtime.enforcement.as_deref() {
            run_startup_authority_probes(enforcement).await;
        }
        self.replace_runtime(Some(runtime));
        Ok(())
    }

    pub(crate) async fn deactivate_runtime(&self, grace: Duration) -> anyhow::Result<()> {
        let runtime = self
            .runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(runtime) = runtime {
            runtime.shutdown(grace).await?;
        }
        Ok(())
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/health/live", get(health_live))
            .route("/health/ready", get(health_ready))
            .route("/health/status", get(health_status))
            .fallback(any(proxy_handler))
            .with_state(self)
    }
}

impl GatewayRuntime {
    fn build(
        actual_supply_id: Option<String>,
        attribution_config: Option<InlineAttributionConfig>,
        deps: GatewayDeps,
    ) -> anyhow::Result<Self> {
        let attribution_header = attribution_config
            .as_ref()
            .map(|config| HeaderName::from_bytes(config.response_header.as_bytes()))
            .transpose()
            .context("invalid attribution response header")?;
        let attribution_namespace = attribution_config
            .as_ref()
            .map(|config| config.namespace.clone());
        let attribution_resolver = deps
            .recording
            .as_ref()
            .map(|recording| {
                let rules = attribution_config
                    .as_ref()
                    .map(InlineAttributionConfig::rules)
                    .unwrap_or_default();
                let legacy = actual_supply_id
                    .as_ref()
                    .filter(|value| !value.trim().is_empty())
                    .cloned();
                AttributionResolver::new(rules, legacy, &recording.registry)
                    .context("invalid configured supply attribution")
                    .map(Arc::new)
            })
            .transpose()?;
        let health = deps
            .recording
            .as_ref()
            .and_then(|recording| match &recording.writer {
                RecordingWriter::Managed(writer) => Some(writer.health()),
                RecordingWriter::Legacy(_) => None,
            });
        Ok(Self {
            recording: deps.recording,
            health,
            attribution_resolver,
            attribution_header,
            attribution_namespace,
            enforcement: deps.enforcement,
            admission: Arc::new(RuntimeAdmission::active()),
        })
    }

    fn run_id(&self) -> Option<String> {
        self.health.as_ref().map(|health| health.snapshot().run_id)
    }

    fn try_admit(&self) -> Option<RuntimeAdmissionGuard> {
        self.admission.try_admit()
    }

    async fn shutdown(&self, grace: Duration) -> anyhow::Result<()> {
        self.admission.stop();
        tokio::time::timeout(grace, self.admission.wait_idle())
            .await
            .context("gateway request drain exceeded shutdown grace")?;
        if let Some(enforcement) = self.enforcement.as_deref() {
            enforcement.kill_reader.shutdown();
            tokio::time::timeout(grace, enforcement.terminal_tracker.wait_idle())
                .await
                .context("authority terminal drain exceeded shutdown grace")?;
            enforcement
                .writer
                .shutdown(grace)
                .await
                .context("failed to close authority evidence writer")?;
        }
        if let Some(RecordingWriter::Managed(writer)) =
            self.recording.as_ref().map(|recording| &recording.writer)
        {
            writer
                .shutdown(grace)
                .await
                .context("failed to drain managed ledger writer")?;
        }
        Ok(())
    }
}

async fn health_live(State(state): State<GatewayState>) -> Response<Body> {
    let runtime = state.active_runtime();
    let mode = if runtime
        .as_ref()
        .is_some_and(|runtime| runtime.enforcement.is_some())
        || state.controlled_configured
    {
        "controlled"
    } else {
        "shadow"
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({ "mode": mode, "live": true }),
    )
}

async fn health_ready(State(state): State<GatewayState>) -> Response<Body> {
    let runtime = state.active_runtime();
    let enforcement = match runtime
        .as_ref()
        .and_then(|runtime| runtime.enforcement.as_deref())
    {
        Some(runtime) => Some(public_enforcement_health(runtime).await),
        None => None,
    };
    let ready = runtime
        .as_ref()
        .and_then(|runtime| runtime.health.as_ref())
        .is_some_and(|health| match &enforcement {
            Some(enforcement) => health.controlled_snapshot(enforcement).ready,
            None => health.snapshot().ready,
        });
    let mode = if enforcement.is_some() || state.controlled_configured {
        "controlled"
    } else {
        "shadow"
    };
    let mut value = serde_json::json!({ "mode": mode, "ready": ready });
    if let Some(serving) = state.serving_status_snapshot() {
        if !ready {
            value["reason"] =
                serde_json::Value::String(serving.state.rejection_reason().to_string());
        }
    }
    json_response(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        value,
    )
}

async fn health_status(State(state): State<GatewayState>) -> Response<Body> {
    let runtime = state.active_runtime();
    let enforcement = match runtime
        .as_ref()
        .and_then(|runtime| runtime.enforcement.as_deref())
    {
        Some(runtime) => Some(public_enforcement_health(runtime).await),
        None => None,
    };
    let mut value = match runtime.and_then(|runtime| runtime.health.clone()) {
        Some(health) => match &enforcement {
            Some(enforcement) => serde_json::to_value(health.controlled_snapshot(enforcement)),
            None => serde_json::to_value(health.snapshot()),
        }
        .unwrap_or_else(|_| serde_json::json!({ "mode": "shadow", "ready": false })),
        None => serde_json::json!({
            "mode": if state.controlled_configured { "controlled" } else { "shadow" },
            "ready": false,
            "reason": "durable recording is not configured"
        }),
    };
    if let Some(serving) = state.serving_status_snapshot() {
        value["serving_state"] = serde_json::Value::String(serving.state.as_str().to_string());
        if let Some(reason) = serving.last_activation_reason {
            value["last_activation_reason"] = serde_json::Value::String(reason.to_string());
        }
    }
    json_response(StatusCode::OK, value)
}

async fn public_enforcement_health(runtime: &EnforcementRuntime) -> PublicEnforcementHealth {
    let mut route_modes = RouteModeCounts::default();
    for route in runtime.validated.routes() {
        match route.mode {
            bowline_core::enforcement::RouteMode::Observe => route_modes.observe += 1,
            bowline_core::enforcement::RouteMode::Recommend => route_modes.recommend += 1,
            bowline_core::enforcement::RouteMode::CanaryEnforce => route_modes.canary_enforce += 1,
            bowline_core::enforcement::RouteMode::Enforce => route_modes.enforce += 1,
        }
    }
    let actuator = runtime.actuators.snapshot();
    let now = now_ms();
    let kill_state = runtime.kill_reader.read_kill_state().await;
    *runtime
        .last_kill_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = kill_state;
    let mut grant_freshness = GrantFreshnessCounts::default();
    let mut fail_closed_unavailable = 0;
    for route in runtime.validated.authority_routes() {
        match runtime.grants.get(&route.route_id) {
            Some(grant) if grant.is_fresh_at(now) => grant_freshness.fresh += 1,
            Some(_) => grant_freshness.stale += 1,
            None => grant_freshness.unverified += 1,
        }
        if route.fallback == Some(FallbackMode::FailClosed)
            && (kill_state != KillReadResult::Armed
                || route.promoted_supply_id.as_deref().is_none_or(|supply_id| {
                    !matches!(
                        runtime.actuators.circuit(supply_id),
                        Ok(CircuitSnapshot::Closed | CircuitSnapshot::ClosedWithFailures(_))
                    )
                }))
        {
            fail_closed_unavailable += 1;
        }
    }
    let authority_manifest = runtime.writer.manifest_snapshot();
    PublicEnforcementHealth {
        config_valid: true,
        evidence_valid: authority_manifest.writer_healthy && authority_manifest.dropped == 0,
        kill_state,
        route_modes,
        circuits: CircuitCounts {
            closed: actuator.closed,
            open: actuator.open,
            half_open: actuator.half_open,
        },
        grant_freshness,
        candidate_admission: CandidateAdmissionHealth {
            in_flight: actuator.global_candidate_in_flight,
            capacity: actuator.global_candidate_capacity,
            saturation_count: actuator.saturation_count,
        },
        active_fail_closed_routes_on_unavailable_actuators: fail_closed_unavailable,
    }
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR))
}

pub async fn serve(config: Config, deps: GatewayDeps) -> anyhow::Result<()> {
    serve_with_shutdown(config, deps, std::future::pending()).await
}

pub async fn serve_with_shutdown<F>(
    config: Config,
    deps: GatewayDeps,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut deps = Some(deps);
    serve_with_runtime_factory(
        config,
        move || {
            deps.take()
                .context("injected gateway dependencies cannot be reactivated")
        },
        shutdown,
    )
    .await
}

pub async fn serve_with_runtime_factory<D, F>(
    config: Config,
    factory: D,
    shutdown: F,
) -> anyhow::Result<()>
where
    D: FnMut() -> anyhow::Result<GatewayDeps> + Send,
    F: Future<Output = ()> + Send + 'static,
{
    match config.state_backend.clone() {
        Some(StateBackendConfig::FileLease {
            path,
            poll_interval_ms,
            takeover_timeout_ms,
            ..
        }) => {
            let lease = crate::serving_lease::FileServingLease::open(&path)?;
            serve_with_file_lease(
                config,
                factory,
                shutdown,
                lease,
                Duration::from_millis(poll_interval_ms),
                Duration::from_millis(takeover_timeout_ms),
            )
            .await
        }
        None | Some(StateBackendConfig::Local { .. }) => {
            serve_with_local_lease(config, factory, shutdown).await
        }
    }
}

async fn serve_with_local_lease<D, F>(
    config: Config,
    mut factory: D,
    shutdown: F,
) -> anyhow::Result<()>
where
    D: FnMut() -> anyhow::Result<GatewayDeps> + Send,
    F: Future<Output = ()> + Send + 'static,
{
    let shutdown_grace = config.runtime.shutdown_grace();
    let mut supervisor = crate::supervisor::GatewaySupervisor::new(
        config.clone(),
        crate::serving_lease::LocalServingLease,
    )?;
    supervisor.activate(&mut factory).await?;
    let listener = match TcpListener::bind(&config.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            supervisor.deactivate(shutdown_grace).await?;
            return Err(error)
                .with_context(|| format!("failed to bind gateway listener {}", config.listen));
        }
    };
    let serve_result = axum::serve(
        listener,
        supervisor
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("gateway server failed");
    supervisor.deactivate(shutdown_grace).await?;
    serve_result
}

async fn serve_with_file_lease<D, F>(
    config: Config,
    mut factory: D,
    shutdown: F,
    lease: crate::serving_lease::FileServingLease,
    poll_interval: Duration,
    takeover_timeout: Duration,
) -> anyhow::Result<()>
where
    D: FnMut() -> anyhow::Result<GatewayDeps> + Send,
    F: Future<Output = ()> + Send + 'static,
{
    let shutdown_grace = config.runtime.shutdown_grace();
    let mut supervisor = crate::supervisor::GatewaySupervisor::new(config.clone(), lease)?;
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("failed to bind gateway listener {}", config.listen))?;
    let router = supervisor.router();
    let (server_started_tx, server_started_rx) = tokio::sync::oneshot::channel();
    let mut server = tokio::spawn(async move {
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown);
        let _ = server_started_tx.send(());
        server.await.context("gateway server failed")
    });
    server_started_rx
        .await
        .context("gateway server task exited before startup")?;
    let mut standby_since = tokio::time::Instant::now();
    let mut takeover_alerted = false;
    if let Err(error) = supervisor.reconcile(&mut factory, shutdown_grace).await {
        tracing::warn!(error = %error, "gateway activation failed; remaining in standby");
    }

    loop {
        tokio::select! {
            result = &mut server => {
                let server_result = match result {
                    Ok(result) => result,
                    Err(error) => Err(anyhow::Error::from(error)
                        .context("gateway server task failed")),
                };
                supervisor.deactivate(shutdown_grace).await?;
                return server_result;
            }
            _ = tokio::time::sleep(poll_interval) => {
                let was_active = supervisor.is_active();
                if let Err(error) = supervisor.reconcile(&mut factory, shutdown_grace).await {
                    if was_active {
                        return Err(error).context("gateway deactivation failed after serving lease loss");
                    }
                    tracing::warn!(error = %error, "gateway activation failed; remaining in standby");
                }
                if supervisor.is_active() {
                    standby_since = tokio::time::Instant::now();
                    takeover_alerted = false;
                } else if !takeover_alerted && standby_since.elapsed() >= takeover_timeout {
                    tracing::warn!(
                        timeout_ms = takeover_timeout.as_millis(),
                        "serving lease has remained unavailable beyond the takeover alert boundary"
                    );
                    takeover_alerted = true;
                }
            }
        }
    }
}

fn prepare_runtime_deps(config: &Config, deps: GatewayDeps) -> anyhow::Result<GatewayDeps> {
    let mut deps = if deps.recording.is_some() {
        deps
    } else {
        deps_from_config(config)?
    };
    if deps.enforcement.is_none() {
        if let Some(path) = config.enforcement.as_deref() {
            let (_, recovery) = bowline_core::ledger::Ledger::read_all(&config.ledger_dir)
                .context("failed to inspect legacy observation evidence")?;
            if recovery.blocks_append() {
                anyhow::bail!(
                    "configured enforcement requires a writable legacy observation ledger; recovery found corrupt or undecodable evidence"
                );
            }
            let registry = deps
                .recording
                .as_ref()
                .context("configured enforcement requires recording dependencies")?
                .registry
                .clone();
            let active = deps
                .recording
                .as_ref()
                .and_then(|recording| recording.provenance.as_ref())
                .context(
                    "configured enforcement requires active provenance from the exact loaded policy, registry source, and owned costs",
                )?;
            deps.enforcement = Some(Arc::new(load_enforcement_runtime(
                config, path, &registry, active,
            )?));
        }
    }
    Ok(deps)
}

async fn proxy_handler(
    State(state): State<GatewayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let Some(runtime) = state.active_runtime() else {
        return serving_unavailable_response(&state);
    };
    let Some(admission) = runtime.try_admit() else {
        return serving_unavailable_response(&state);
    };
    let response =
        proxy_admitted_handler(state, runtime, peer, method, uri, headers, request).await;
    hold_admission_until_body_complete(response, admission)
}

async fn proxy_admitted_handler(
    state: GatewayState,
    runtime: Arc<GatewayRuntime>,
    peer: SocketAddr,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    let started_at = Instant::now();
    let path = uri.path().to_string();
    let protocol = classify_inference_protocol(&method, &path);
    let body = match to_bytes(request.into_body(), MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return status_response(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let trusted_peer = state
        .trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(&peer.ip()));
    let resolved_context = protocol
        .and_then(authority_protocol)
        .and_then(|authority_protocol| {
            runtime.recording.as_ref().map(|recording| {
                resolve_request_context(
                    &recording.policy,
                    &headers,
                    trusted_peer,
                    &path,
                    authority_protocol,
                )
            })
        });
    let mut pending_shadow = protocol.and_then(|protocol| {
        prepare_shadow(
            &state,
            &runtime,
            Some(peer.ip()),
            &headers,
            &path,
            &body,
            started_at,
            protocol,
            resolved_context.as_ref(),
        )
    });

    if let Some(response) = controlled_enforcement_response(
        &state,
        &runtime,
        &method,
        &uri,
        &headers,
        &body,
        protocol,
        resolved_context.as_ref(),
        &mut pending_shadow,
    )
    .await
    {
        return response;
    }

    let upstream_url = upstream_url(&state.upstream_base, &uri);
    let upstream_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return status_response(StatusCode::METHOD_NOT_ALLOWED),
    };
    let mut upstream_request = state
        .client
        .request(upstream_method, upstream_url)
        .body(body);

    for (name, value) in headers.iter() {
        if should_forward_header(name) {
            upstream_request = upstream_request.header(name, value);
        }
    }

    let upstream_response =
        match tokio::time::timeout(state.response_header_timeout, upstream_request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let status = if error.is_timeout() {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                };
                tracing::warn!(error = %error, %status, "upstream request failed");
                finalize_failed_shadow(pending_shadow, status, error.to_string());
                return status_response(status);
            }
            Err(_) => {
                let status = StatusCode::GATEWAY_TIMEOUT;
                tracing::warn!(%status, "upstream response header timeout");
                finalize_failed_shadow(
                    pending_shadow,
                    status,
                    "upstream response header timeout".to_string(),
                );
                return status_response(status);
            }
        };

    response_from_upstream(upstream_response, pending_shadow, state.stream_idle_timeout)
}

fn hold_admission_until_body_complete(
    response: Response<Body>,
    guard: RuntimeAdmissionGuard,
) -> Response<Body> {
    let (parts, body) = response.into_parts();
    let stream = AdmissionStream {
        inner: Box::pin(body.into_data_stream()),
        _guard: guard,
    };
    Response::from_parts(parts, Body::from_stream(stream))
}

#[allow(clippy::too_many_arguments)]
async fn controlled_enforcement_response(
    state: &GatewayState,
    gateway_runtime: &Arc<GatewayRuntime>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
    protocol: Option<ProtocolKind>,
    request_context: Option<&ResolvedRequestContext>,
    pending_shadow: &mut Option<PendingShadow>,
) -> Option<Response<Body>> {
    let runtime = Arc::clone(gateway_runtime.enforcement.as_ref()?);
    let protocol = authority_protocol(protocol?)?;
    let route = runtime
        .validated
        .routes()
        .find(|route| {
            route.method == method.as_str()
                && route.path == uri.path()
                && route.protocol == protocol
                && runtime.route_ids.iter().any(|id| id == &route.route_id)
        })?
        .clone();
    let recording = gateway_runtime.recording.as_ref()?;
    let request_context = request_context?;
    let request_facts = parse_request(protocol_to_traffic(protocol), body);
    let request_body_digest: [u8; 32] = Sha256::digest(body).into();
    let requested_supply_id = request_facts.model.as_deref().and_then(|model| {
        recording
            .registry
            .resolve_unique_model(model)
            .map(|entry| entry.id.clone())
    });
    let kill = runtime.kill_reader.read_kill_state().await;
    *runtime
        .last_kill_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = kill;
    let mut candidate_availability = CandidateAvailability::Available;
    if route.mode.grants_authority() {
        let supply_id = route.promoted_supply_id.as_deref().unwrap_or_default();
        match runtime.actuators.circuit(supply_id) {
            Ok(CircuitSnapshot::Closed | CircuitSnapshot::ClosedWithFailures(_)) => {
                candidate_availability = CandidateAvailability::Available;
            }
            Ok(CircuitSnapshot::Open | CircuitSnapshot::HalfOpen) => {
                candidate_availability = CandidateAvailability::CircuitOpen;
                if let Some(target) = runtime.targets.get(supply_id) {
                    let registry = runtime.actuators.clone();
                    let supply_id = supply_id.to_owned();
                    let canonical_model = target.canonical_model.clone();
                    let authorization = target.authorization.clone();
                    tokio::spawn(async move {
                        let _ = registry
                            .run_probe(
                                &supply_id,
                                &canonical_model,
                                Some(authorization),
                                Instant::now(),
                            )
                            .await;
                    });
                }
            }
            Err(_) => candidate_availability = CandidateAvailability::Unavailable,
        }
    }
    let mut facts = SelectionRequestFacts {
        method: method.as_str().to_owned(),
        path: uri.path().to_owned(),
        protocol,
        identity_trusted: request_context.identity_trusted,
        authority_metadata_valid: request_context.authority_metadata_valid,
        shape_supported: request_facts.shape_supported,
        task_class: request_context.task_class,
        app: request_context.app.clone(),
        resolved_tags: request_context.resolved_tags.clone(),
        workload_identity_digest: request_context.workload_identity_digest.clone(),
        request_body_digest,
        requested_supply_id,
        kill,
        now_ms: now_ms(),
        candidate_availability,
        actuator_available: route
            .promoted_supply_id
            .as_deref()
            .is_none_or(|supply| runtime.targets.contains_key(supply)),
    };
    let mut prepared_candidate_body = None;
    if route.mode.grants_authority()
        && route.model_authority
            == Some(bowline_core::enforcement::ModelAuthority::RewriteToCanonical)
    {
        let rewrite = route
            .promoted_supply_id
            .as_deref()
            .and_then(|supply| runtime.targets.get(supply))
            .ok_or(())
            .and_then(|target| {
                rewrite_top_level_model(
                    body,
                    &target.canonical_model,
                    RewriteLimits {
                        max_bytes: MAX_REQUEST_BODY_BYTES,
                        max_depth: 128,
                        max_nodes: 1_000_000,
                    },
                )
                .map(|rewritten| Bytes::copy_from_slice(rewritten.as_ref()))
                .map_err(|_| ())
            });
        match rewrite {
            Ok(rewritten) => prepared_candidate_body = Some(rewritten),
            Err(()) => facts.shape_supported = false,
        }
    }
    let gateway_plan = match (
        runtime.grants.get(&route.route_id),
        runtime.recommendations.get(&route.route_id),
        runtime.grant_rejections.get(&route.route_id),
    ) {
        (Some(grant), _, _) => {
            select_enforcement_target(&runtime.validated, &route.route_id, &facts, grant)
        }
        (None, Some(evidence), _) => {
            select_recommendation_target(&runtime.validated, &route.route_id, &facts, evidence)
        }
        (None, None, Some(reason)) => select_enforcement_target_with_grant_rejection(
            &runtime.validated,
            &route.route_id,
            &facts,
            *reason,
        ),
        (None, None, None) => {
            select_enforcement_target_without_grant(&runtime.validated, &route.route_id, &facts)
        }
    };
    let gateway_plan = match gateway_plan {
        Ok(plan) => plan,
        Err(error) => {
            tracing::error!(error = %error, "controlled enforcement selection failed");
            return Some(evidence_unavailable_response());
        }
    };
    let original_body = body.clone();
    if gateway_plan.target() != PlanTarget::Candidate {
        let context = zero_authority_context(&route, &facts, kill, now_ms());
        let prepared = match prepare_zero_authority_decision_v2(gateway_plan.plan(), context) {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::error!(error = %error, "failed to prepare zero-authority decision");
                return Some(evidence_unavailable_response());
            }
        };
        let handle = match runtime.writer.reserve_and_flush_decision(prepared).await {
            Ok(handle) => handle,
            Err(error) => {
                tracing::error!(error = %error, "zero-authority decision was not durable");
                return Some(evidence_unavailable_response());
            }
        };
        return Some(
            dispatch_authorized_target(
                state,
                &runtime,
                handle,
                &facts,
                uri,
                headers,
                original_body,
                None,
                pending_shadow.take(),
                request_facts,
            )
            .await,
        );
    }

    let grant = runtime.grants.get(&route.route_id)?.clone();
    let candidate_body = if gateway_plan.plan().model_rewritten {
        match prepared_candidate_body {
            Some(body) => body,
            None => {
                return Some(evidence_unavailable_response());
            }
        }
    } else {
        original_body.clone()
    };
    let candidate = match prepare_candidate_authority_decision_v2(
        &runtime.validated,
        gateway_plan,
        grant.clone(),
        Uuid::new_v4().to_string(),
        &runtime.kill_reader,
    )
    .await
    {
        Ok(candidate) => candidate,
        Err(error) => {
            tracing::error!(error = %error, "failed to prepare candidate authority decision");
            return Some(evidence_unavailable_response());
        }
    };
    match candidate {
        CandidatePreparationV2::Fallback(prepared) => {
            let handle = match runtime.writer.reserve_and_flush_decision(prepared).await {
                Ok(handle) => handle,
                Err(_) => return Some(evidence_unavailable_response()),
            };
            Some(
                dispatch_authorized_target(
                    state,
                    &runtime,
                    handle,
                    &facts,
                    uri,
                    headers,
                    original_body,
                    None,
                    pending_shadow.take(),
                    request_facts,
                )
                .await,
            )
        }
        CandidatePreparationV2::Candidate(prepared) => {
            let supply_id = prepared
                .decision()
                .selected_supply_id
                .as_deref()
                .unwrap_or_default();
            let candidate_permit = match runtime
                .actuators
                .try_acquire(supply_id, Duration::from_millis(10))
                .await
            {
                Ok(permit) => permit,
                Err(error) => {
                    facts.kill = KillReadResult::Armed;
                    facts.candidate_availability = match error {
                        ActuatorError::Saturated => CandidateAvailability::AdmissionSaturated,
                        ActuatorError::CircuitUnavailable => CandidateAvailability::CircuitOpen,
                        ActuatorError::UnknownActuator | ActuatorError::InvalidConfiguration => {
                            CandidateAvailability::Unavailable
                        }
                    };
                    let fallback_plan = match select_enforcement_target(
                        &runtime.validated,
                        &route.route_id,
                        &facts,
                        &grant,
                    ) {
                        Ok(plan) if plan.target() != PlanTarget::Candidate => plan,
                        _ => return Some(evidence_unavailable_response()),
                    };
                    let context = zero_authority_context(&route, &facts, facts.kill, now_ms());
                    let fallback =
                        match prepare_zero_authority_decision_v2(fallback_plan.plan(), context) {
                            Ok(fallback) => fallback,
                            Err(_) => return Some(evidence_unavailable_response()),
                        };
                    let handle = match runtime.writer.reserve_and_flush_decision(fallback).await {
                        Ok(handle) => handle,
                        Err(_) => return Some(evidence_unavailable_response()),
                    };
                    return Some(
                        dispatch_authorized_target(
                            state,
                            &runtime,
                            handle,
                            &facts,
                            uri,
                            headers,
                            original_body,
                            None,
                            pending_shadow.take(),
                            request_facts,
                        )
                        .await,
                    );
                }
            };
            let replacement = match candidate_replacement(
                &runtime.validated,
                &route,
                prepared.decision(),
                &facts,
            ) {
                Ok(replacement) => replacement,
                Err(_) => {
                    drop(candidate_permit);
                    return Some(evidence_unavailable_response());
                }
            };
            match runtime
                .writer
                .reserve_candidate_decision_or_recovery(&runtime.validated, prepared, replacement)
                .await
            {
                CandidateDecisionReservation::Flushed(reservation) => Some(
                    dispatch_candidate_reservation(
                        state,
                        &runtime,
                        *reservation,
                        &facts,
                        uri,
                        headers,
                        original_body,
                        candidate_body,
                        candidate_permit,
                        pending_shadow.take(),
                        request_facts,
                    )
                    .await,
                ),
                CandidateDecisionReservation::Recoverable { recovery, .. } => {
                    drop(candidate_permit);
                    let handle = match recovery.reserve_and_flush_replacement().await {
                        Ok(handle) => handle,
                        Err(_) => return Some(evidence_unavailable_response()),
                    };
                    Some(
                        dispatch_authorized_target(
                            state,
                            &runtime,
                            handle,
                            &facts,
                            uri,
                            headers,
                            original_body,
                            None,
                            pending_shadow.take(),
                            request_facts,
                        )
                        .await,
                    )
                }
                CandidateDecisionReservation::Rejected(error) => {
                    tracing::error!(error = %error, "candidate authority decision was rejected");
                    drop(candidate_permit);
                    Some(evidence_unavailable_response())
                }
            }
        }
    }
}

fn authority_protocol(protocol: ProtocolKind) -> Option<AuthorityProtocol> {
    match protocol {
        ProtocolKind::ChatCompletions => Some(AuthorityProtocol::ChatCompletions),
        ProtocolKind::Responses => Some(AuthorityProtocol::Responses),
        ProtocolKind::Embeddings => Some(AuthorityProtocol::Embeddings),
        ProtocolKind::Unsupported => None,
    }
}

fn protocol_to_traffic(protocol: AuthorityProtocol) -> ProtocolKind {
    match protocol {
        AuthorityProtocol::ChatCompletions => ProtocolKind::ChatCompletions,
        AuthorityProtocol::Responses => ProtocolKind::Responses,
        AuthorityProtocol::Embeddings => ProtocolKind::Embeddings,
    }
}

fn zero_authority_context(
    route: &bowline_core::enforcement::EnforcementRoute,
    facts: &SelectionRequestFacts,
    kill: KillReadResult,
    ts_ms: u64,
) -> AuthorityDecisionContextV2 {
    AuthorityDecisionContextV2 {
        decision_id: Uuid::new_v4().to_string(),
        ts_ms,
        route_id: route.route_id.clone(),
        protocol: route.protocol,
        task_class: facts.task_class,
        workload_identity_digest: facts.workload_identity_digest.clone(),
        kill_state: kill,
        method: facts.method.clone(),
        path: facts.path.clone(),
        app: facts.app.clone(),
        resolved_tags: facts.resolved_tags.clone(),
        request_body_digest: facts.request_body_digest,
        requested_supply_id: facts.requested_supply_id.clone(),
    }
}

fn candidate_replacement(
    validated: &ValidatedEnforcement,
    route: &bowline_core::enforcement::EnforcementRoute,
    candidate: &bowline_core::ledger::AuthorityDecisionV2,
    facts: &SelectionRequestFacts,
) -> Result<
    crate::observation::PreparedAuthorityDecisionV2,
    bowline_core::ledger::AuthorityRecordError,
> {
    let target = match route.fallback {
        Some(FallbackMode::Bypass) => PlanTarget::Original,
        _ => PlanTarget::None,
    };
    let plan = EnforcementPlan {
        target,
        mode: candidate.mode,
        reason: SelectionReason::CandidateUnavailable,
        evidence_state: bowline_core::enforcement::EvidenceState::Unverified,
        bucket: candidate.selection_facts.bucket,
        selected_supply_id: (target == PlanTarget::Original)
            .then(|| candidate.baseline_supply_id.clone())
            .flatten(),
        baseline_supply_id: candidate.baseline_supply_id.clone(),
        actuator_digest: None,
        config_digest: Some(validated.normalized_digest().to_owned()),
        route_digest: Some(candidate.route_config_digest.clone()),
        model_rewritten: false,
        grant_digest: None,
        dispatch_count: u8::from(target == PlanTarget::Original),
    };
    let mut context = zero_authority_context(route, facts, facts.kill, candidate.ts_ms);
    context.decision_id = Uuid::new_v4().to_string();
    prepare_zero_authority_decision_v2(&plan, context)
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_candidate_reservation(
    state: &GatewayState,
    runtime: &Arc<EnforcementRuntime>,
    reservation: CandidateDispatchReservation,
    facts: &SelectionRequestFacts,
    uri: &Uri,
    headers: &HeaderMap,
    original_body: Bytes,
    candidate_body: Bytes,
    candidate_permit: CandidatePermit,
    pending_shadow: Option<PendingShadow>,
    request_facts: RequestFacts,
) -> Response<Body> {
    let selected_supply_id = reservation.decision().selected_supply_id.clone();
    let circuit_before = reservation.decision().selection_facts.circuit_before;
    match reservation.authorize_final_bound_dispatch().await {
        FinalDispatchAuthorization::Authorized(authority) => {
            dispatch_pre_authorized_target(
                state,
                runtime,
                PlanTarget::Candidate,
                selected_supply_id,
                circuit_before,
                authority,
                facts,
                uri,
                headers,
                candidate_body,
                Some(candidate_permit),
                pending_shadow,
                request_facts,
            )
            .await
        }
        FinalDispatchAuthorization::Fallback(recovery) => {
            drop(candidate_permit);
            let handle = match recovery.reserve_and_flush_replacement().await {
                Ok(handle) => handle,
                Err(error) => {
                    tracing::error!(error = %error, "final fallback decision persistence failed");
                    return evidence_unavailable_response();
                }
            };
            dispatch_authorized_target(
                state,
                runtime,
                handle,
                facts,
                uri,
                headers,
                original_body,
                None,
                pending_shadow,
                request_facts,
            )
            .await
        }
        FinalDispatchAuthorization::Fatal(error) => {
            tracing::error!(error = %error, "final candidate authorization evidence unavailable");
            drop(candidate_permit);
            evidence_unavailable_response()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_authorized_target(
    state: &GatewayState,
    runtime: &Arc<EnforcementRuntime>,
    handle: crate::writer::DecisionHandle,
    facts: &SelectionRequestFacts,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    candidate_permit: Option<CandidatePermit>,
    pending_shadow: Option<PendingShadow>,
    request_facts: RequestFacts,
) -> Response<Body> {
    let target = handle.decision().target;
    if !candidate_protocol_may_dispatch(target, handle.decision().protocol) {
        tracing::error!("Embeddings candidate authority reached the dispatch boundary");
        drop(candidate_permit);
        return evidence_unavailable_response();
    }
    let selected_supply_id = handle.decision().selected_supply_id.clone();
    let circuit_before = handle.decision().selection_facts.circuit_before;
    let authority = match handle.authorize_bound_dispatch().await {
        Ok(authority) => authority,
        Err(error) => {
            tracing::error!(error = %error, "current authority revalidation rejected dispatch");
            drop(candidate_permit);
            return evidence_unavailable_response();
        }
    };
    dispatch_pre_authorized_target(
        state,
        runtime,
        target,
        selected_supply_id,
        circuit_before,
        authority,
        facts,
        uri,
        headers,
        body,
        candidate_permit,
        pending_shadow,
        request_facts,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_pre_authorized_target(
    state: &GatewayState,
    runtime: &Arc<EnforcementRuntime>,
    target: PlanTarget,
    selected_supply_id: Option<String>,
    circuit_before: CircuitStateV2,
    authority: crate::writer::AuthorizedDispatchHandle,
    facts: &SelectionRequestFacts,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    candidate_permit: Option<CandidatePermit>,
    pending_shadow: Option<PendingShadow>,
    request_facts: RequestFacts,
) -> Response<Body> {
    match target {
        PlanTarget::None => {
            drop(candidate_permit);
            let terminal = AuthorityTerminalV2 {
                ts_ms: now_ms(),
                circuit_after: circuit_before,
                completion: CompletionStateV2::Local,
                candidate_failure: None,
                status: None,
                input_tokens: None,
                output_tokens: None,
                usage_source: UsageSource::Missing,
            };
            if persist_immediate_terminal(&runtime.writer, authority, terminal)
                .await
                .is_err()
            {
                return evidence_unavailable_response();
            }
            fail_closed_response()
        }
        PlanTarget::Original => {
            drop(candidate_permit);
            let upstream_url = upstream_url(&state.upstream_base, uri);
            let upstream_method = match reqwest::Method::from_bytes(facts.method.as_bytes()) {
                Ok(method) => method,
                Err(_) => return evidence_unavailable_response(),
            };
            let mut request = state
                .client
                .request(upstream_method, upstream_url)
                .body(body);
            for (name, value) in headers {
                if should_forward_header(name) {
                    request = request.header(name, value);
                }
            }
            let response = match tokio::time::timeout(state.response_header_timeout, request.send())
                .await
            {
                Ok(Ok(response)) => response,
                result => {
                    let timeout =
                        result.is_err() || matches!(&result, Ok(Err(error)) if error.is_timeout());
                    let terminal = AuthorityTerminalV2 {
                        ts_ms: now_ms(),
                        circuit_after: circuit_before,
                        completion: CompletionStateV2::Failed,
                        candidate_failure: None,
                        status: None,
                        input_tokens: None,
                        output_tokens: None,
                        usage_source: UsageSource::Missing,
                    };
                    let _ = persist_immediate_terminal(&runtime.writer, authority, terminal).await;
                    return status_response(if timeout {
                        StatusCode::GATEWAY_TIMEOUT
                    } else {
                        StatusCode::BAD_GATEWAY
                    });
                }
            };
            response_from_authorized(
                response,
                pending_shadow,
                state.stream_idle_timeout,
                PendingAuthorityTerminal {
                    writer: runtime.writer.clone(),
                    handle: authority,
                    protocol: protocol_to_traffic(facts.protocol),
                    request_facts,
                    status: 0,
                    candidate_supply_id: None,
                    actuators: None,
                    expected_response_bytes: None,
                    terminal_tracker: Arc::clone(&runtime.terminal_tracker),
                    circuit_before,
                },
            )
        }
        PlanTarget::Candidate => {
            let supply_id = match selected_supply_id {
                Some(supply_id) => supply_id,
                None => return evidence_unavailable_response(),
            };
            let Some(target) = runtime.targets.get(&supply_id) else {
                return evidence_unavailable_response();
            };
            let Some(permit) = candidate_permit else {
                return evidence_unavailable_response();
            };
            let url = format!(
                "{}{}",
                target.base_url,
                uri.path_and_query().map_or("/", |v| v.as_str())
            );
            let method = match reqwest::Method::from_bytes(facts.method.as_bytes()) {
                Ok(method) => method,
                Err(_) => return evidence_unavailable_response(),
            };
            let sent = send_authorized_candidate(
                &target.client,
                authority,
                permit,
                AuthorizedCandidateRequest {
                    method,
                    url: &url,
                    incoming_headers: headers,
                    authorization: target.authorization.clone(),
                    body,
                    response_header_timeout: target.response_header_timeout,
                },
            )
            .await;
            match sent {
                Ok(sent) => {
                    let status = sent.response.status();
                    let expected_response_bytes = sent.response.content_length();
                    let mut builder = Response::builder().status(status);
                    for (name, value) in sent.response.headers() {
                        if should_forward_header(name) {
                            builder = builder.header(name, value);
                        }
                    }
                    let raw = sent
                        .response
                        .bytes_stream()
                        .map(|result| {
                            result.map_err(|_| {
                                ProxyStreamError::Candidate(
                                    crate::actuator::CandidateTransportError::Transport,
                                )
                            })
                        })
                        .boxed();
                    let idle =
                        IdleTimeoutStream::new(raw, target.stream_idle_timeout).map(|result| {
                            result.map_err(|error| match error {
                                ProxyStreamError::IdleTimeout => ProxyStreamError::Candidate(
                                    crate::actuator::CandidateTransportError::IdleTimeout,
                                ),
                                other => other,
                            })
                        });
                    let candidate = CandidateResponseStream::new(
                        idle.map(|result| {
                            result.map_err(|error| match error {
                                ProxyStreamError::Candidate(error) => error,
                                _ => crate::actuator::CandidateTransportError::Transport,
                            })
                        }),
                        sent.permit,
                        facts.protocol,
                        request_facts.stream,
                        state.accounting_limit_bytes,
                    )
                    .map(|result| result.map_err(ProxyStreamError::Candidate))
                    .boxed();
                    let mut shadow = pending_shadow;
                    if let Some(shadow) = shadow.as_mut() {
                        shadow.response_status = status.as_u16();
                    }
                    let stream = TeeStream::new(candidate, shadow).with_authority(
                        PendingAuthorityTerminal {
                            writer: runtime.writer.clone(),
                            handle: sent.authority,
                            protocol: protocol_to_traffic(facts.protocol),
                            request_facts,
                            status: status.as_u16(),
                            candidate_supply_id: Some(supply_id),
                            actuators: Some(runtime.actuators.clone()),
                            expected_response_bytes,
                            terminal_tracker: Arc::clone(&runtime.terminal_tracker),
                            circuit_before,
                        },
                    );
                    builder
                        .body(Body::from_stream(stream))
                        .unwrap_or_else(|_| status_response(StatusCode::BAD_GATEWAY))
                }
                Err(failure) => {
                    let class = candidate_failure_class(failure.failure);
                    let after = runtime
                        .actuators
                        .circuit(&supply_id)
                        .map(circuit_state_v2)
                        .unwrap_or(CircuitStateV2::Open);
                    drop(failure.permit);
                    let terminal = AuthorityTerminalV2 {
                        ts_ms: now_ms(),
                        circuit_after: after,
                        completion: CompletionStateV2::Failed,
                        candidate_failure: Some(class),
                        status: None,
                        input_tokens: None,
                        output_tokens: None,
                        usage_source: UsageSource::Missing,
                    };
                    let _ =
                        persist_immediate_terminal(&runtime.writer, failure.authority, terminal)
                            .await;
                    status_response(match failure.failure {
                        CandidateFailure::HeaderTimeout => StatusCode::GATEWAY_TIMEOUT,
                        _ => StatusCode::BAD_GATEWAY,
                    })
                }
            }
        }
    }
}

fn candidate_protocol_may_dispatch(target: PlanTarget, protocol: AuthorityProtocol) -> bool {
    target != PlanTarget::Candidate || protocol != AuthorityProtocol::Embeddings
}

async fn persist_immediate_terminal(
    writer: &ManagedAuthorityWriter,
    handle: crate::writer::AuthorizedDispatchHandle,
    terminal: AuthorityTerminalV2,
) -> Result<(), crate::writer::ManagedWriterError> {
    let outcome = handle.build_outcome(terminal)?;
    writer.append_and_flush_outcome(handle, outcome).await?;
    Ok(())
}

fn response_from_authorized(
    upstream_response: reqwest::Response,
    mut pending_shadow: Option<PendingShadow>,
    stream_idle_timeout: Duration,
    mut authority: PendingAuthorityTerminal,
) -> Response<Body> {
    let status = upstream_response.status();
    initialize_original_shadow_response(&upstream_response, &mut pending_shadow);
    authority.status = status.as_u16();
    authority.expected_response_bytes = upstream_response.content_length();
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_response.headers() {
        if should_forward_header(name) {
            builder = builder.header(name, value);
        }
    }
    let stream = upstream_response
        .bytes_stream()
        .map(|result| result.map_err(|error| ProxyStreamError::Upstream(error.to_string())))
        .boxed();
    let stream = Box::pin(IdleTimeoutStream::new(stream, stream_idle_timeout));
    let stream = TeeStream::new(stream, pending_shadow).with_authority(authority);
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| status_response(StatusCode::BAD_GATEWAY))
}

fn candidate_failure_class(failure: CandidateFailure) -> CandidateFailureClassV2 {
    match failure {
        CandidateFailure::Connect => CandidateFailureClassV2::Connect,
        CandidateFailure::HeaderTimeout => CandidateFailureClassV2::ResponseHeaderTimeout,
        CandidateFailure::StreamIdleTimeout => CandidateFailureClassV2::StreamIdleTimeout,
        CandidateFailure::TransportStream => CandidateFailureClassV2::TransportStream,
        CandidateFailure::ProtocolIncomplete => CandidateFailureClassV2::ProtocolIncomplete,
        CandidateFailure::Authentication => CandidateFailureClassV2::Authentication,
        CandidateFailure::Server => CandidateFailureClassV2::Server,
    }
}

fn evidence_unavailable_response() -> Response<Body> {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({"error": {"code": "evidence-unavailable"}}),
    )
}

fn serving_unavailable_response(state: &GatewayState) -> Response<Body> {
    match state.serving_status_snapshot() {
        Some(serving) => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error": {"code": serving.state.rejection_reason()}}),
        ),
        None => status_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn fail_closed_response() -> Response<Body> {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({"error": {"code": "enforcement-fail-closed"}}),
    )
}

fn classify_inference_protocol(method: &Method, path: &str) -> Option<ProtocolKind> {
    crate::protocol::classify_inference_protocol(method.as_str(), path)
}

fn coverage_for(
    protocol: ProtocolKind,
    request_facts: &RequestFacts,
) -> (CoverageStatus, Option<String>) {
    if !protocol.is_supported() {
        return (
            CoverageStatus::UnsupportedProtocol,
            Some("unsupported-protocol".to_string()),
        );
    }
    if !request_facts.shape_supported {
        return (
            CoverageStatus::UnsupportedShape,
            request_facts.unsupported_reason.clone(),
        );
    }
    (CoverageStatus::Supported, None)
}

fn finalize_failed_shadow(
    pending_shadow: Option<PendingShadow>,
    status: StatusCode,
    error: String,
) {
    if let Some(mut pending) = pending_shadow {
        pending.response_status = status.as_u16();
        tokio::spawn(record_shadow(pending, Vec::new(), Some(error), true));
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_shadow(
    state: &GatewayState,
    runtime: &GatewayRuntime,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    path: &str,
    request_body: &[u8],
    started_at: Instant,
    protocol: ProtocolKind,
    resolved_context: Option<&ResolvedRequestContext>,
) -> Option<PendingShadow> {
    let recording = Arc::clone(runtime.recording.as_ref()?);
    let trusted = peer_ip.is_some_and(|ip| {
        state
            .trusted_proxy_cidrs
            .iter()
            .any(|network| network.contains(&ip))
    });
    let mut trusted_headers = headers.clone();
    let untrusted_identity_headers = !trusted
        && (headers.contains_key("x-bowline-app") || headers.contains_key("x-bowline-task-class"));
    if !trusted {
        trusted_headers.remove("x-bowline-app");
        trusted_headers.remove("x-bowline-task-class");
    }
    if untrusted_identity_headers {
        if let RecordingWriter::Managed(writer) = &recording.writer {
            let _ = writer.health().run().increment_untrusted_identity_headers();
        }
    }
    let (identity, declared_task) = if let Some(context) = resolved_context {
        (context.identity.clone(), Some(context.task_class))
    } else {
        let mut identity = extract_identity(&trusted_headers, path);
        identity.tags = recording.policy.resolve_tags(&identity);
        (identity, None)
    };
    let request_facts = parse_request(protocol, request_body);
    let (coverage_status, coverage_reason) = coverage_for(protocol, &request_facts);
    let mut decision = decide(
        &recording.policy,
        &recording.registry,
        &recording.floors,
        &identity,
        declared_task,
        request_facts.est_input_tokens,
        0,
        &recording.owned_costs,
    );
    if coverage_status != CoverageStatus::Supported {
        decision.shadow = None;
    }

    let record_context = match &recording.writer {
        RecordingWriter::Managed(writer) => match writer.accept_request() {
            Ok(context) => Some(context),
            Err(error) => {
                tracing::error!(error = %error, "failed to allocate accounting sequence");
                None
            }
        },
        RecordingWriter::Legacy(_) => None,
    };

    Some(PendingShadow {
        recording,
        identity,
        request_facts,
        decision,
        protocol,
        coverage_status,
        coverage_reason,
        started_at,
        response_status: 0,
        upstream: state.upstream_identity.clone(),
        attribution_resolver: runtime.attribution_resolver.clone(),
        attribution_header: runtime.attribution_header.clone(),
        attribution_namespace: runtime.attribution_namespace.clone(),
        attribution_input: AttributionInput::Absent,
        record_context,
        accounting_limit_bytes: state.accounting_limit_bytes,
    })
}

fn read_response_reference(
    headers: &HeaderMap,
    header: Option<&HeaderName>,
    namespace: Option<&str>,
) -> AttributionInput {
    let (Some(header), Some(namespace)) = (header, namespace) else {
        return AttributionInput::Absent;
    };
    let mut values = headers.get_all(header).iter();
    let Some(value) = values.next() else {
        return AttributionInput::Absent;
    };
    if values.next().is_some() {
        return AttributionInput::Ambiguous;
    }
    let Some(value) = value.to_str().ok().filter(|value| value.len() <= 256) else {
        // An oversized or non-UTF8 header value is treated the same as no header at all, so the
        // legacy static-attribution fallback still applies instead of a spurious UnknownReference.
        return AttributionInput::Absent;
    };
    AttributionInput::Single(bowline_core::attribution::AttributionRef {
        namespace: namespace.to_string(),
        value: value.to_string(),
    })
}

fn response_from_upstream(
    upstream_response: reqwest::Response,
    mut pending_shadow: Option<PendingShadow>,
    stream_idle_timeout: Duration,
) -> Response<Body> {
    let status = upstream_response.status();
    initialize_original_shadow_response(&upstream_response, &mut pending_shadow);
    let mut builder = Response::builder().status(status);

    for (name, value) in upstream_response.headers().iter() {
        if should_forward_header(name) {
            builder = builder.header(name, value);
        }
    }

    let stream = upstream_response
        .bytes_stream()
        .map(|result| result.map_err(|error| ProxyStreamError::Upstream(error.to_string())))
        .boxed();
    let stream = Box::pin(IdleTimeoutStream::new(stream, stream_idle_timeout));
    let stream = TeeStream::new(stream, pending_shadow);

    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| status_response(StatusCode::BAD_GATEWAY))
}

fn initialize_original_shadow_response(
    upstream_response: &reqwest::Response,
    pending_shadow: &mut Option<PendingShadow>,
) {
    let Some(shadow) = pending_shadow.as_mut() else {
        return;
    };
    shadow.response_status = upstream_response.status().as_u16();
    if shadow.coverage_status == CoverageStatus::Supported {
        shadow.attribution_input = read_response_reference(
            upstream_response.headers(),
            shadow.attribution_header.as_ref(),
            shadow.attribution_namespace.as_deref(),
        );
    }
}

struct PendingShadow {
    recording: Arc<RecordingDeps>,
    identity: WorkloadIdentity,
    request_facts: RequestFacts,
    decision: Decision,
    protocol: ProtocolKind,
    coverage_status: CoverageStatus,
    coverage_reason: Option<String>,
    started_at: Instant,
    response_status: u16,
    upstream: String,
    attribution_resolver: Option<Arc<AttributionResolver>>,
    attribution_header: Option<HeaderName>,
    attribution_namespace: Option<String>,
    attribution_input: AttributionInput,
    record_context: Option<RecordContext>,
    accounting_limit_bytes: usize,
}

struct FinalObservation {
    decision: Decision,
    coverage_status: CoverageStatus,
    coverage_reason: Option<String>,
    model: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    usage_source: UsageSource,
    est_cost_usd: Option<f64>,
    attribution: bowline_core::attribution::AttributionResult,
    accounting_truncated: bool,
}

#[derive(Debug, Error)]
enum ProxyStreamError {
    #[error("upstream response stream failed: {0}")]
    Upstream(String),
    #[error("upstream response stream exceeded idle timeout")]
    IdleTimeout,
    #[error(transparent)]
    Candidate(#[from] crate::actuator::CandidateTransportError),
}

type UpstreamStream = Pin<Box<dyn Stream<Item = Result<Bytes, ProxyStreamError>> + Send>>;

struct IdleTimeoutStream {
    inner: UpstreamStream,
    timeout: Duration,
    timer: Pin<Box<tokio::time::Sleep>>,
    timed_out: bool,
}

impl IdleTimeoutStream {
    fn new(inner: UpstreamStream, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            timer: Box::pin(tokio::time::sleep(timeout)),
            timed_out: false,
        }
    }
}

impl Stream for IdleTimeoutStream {
    type Item = Result<Bytes, ProxyStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        if self.timed_out {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(item) => {
                if item.is_some() {
                    let deadline = tokio::time::Instant::now() + self.timeout;
                    self.timer.as_mut().reset(deadline);
                }
                Poll::Ready(item)
            }
            Poll::Pending => match self.timer.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.timed_out = true;
                    Poll::Ready(Some(Err(ProxyStreamError::IdleTimeout)))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

struct TeeStream {
    inner: UpstreamStream,
    pending_shadow: Option<PendingShadow>,
    collected: Vec<u8>,
    error: Option<String>,
    truncated: bool,
    accounting_limit_bytes: usize,
    authority: Option<PendingAuthorityTerminal>,
    reached_eof: bool,
    authority_failure: Option<CandidateFailureClassV2>,
    delivered_bytes: u64,
}

struct PendingAuthorityTerminal {
    writer: ManagedAuthorityWriter,
    handle: crate::writer::AuthorizedDispatchHandle,
    protocol: ProtocolKind,
    request_facts: RequestFacts,
    status: u16,
    candidate_supply_id: Option<String>,
    actuators: Option<ActuatorRegistry>,
    expected_response_bytes: Option<u64>,
    terminal_tracker: Arc<AuthorityTerminalTracker>,
    circuit_before: CircuitStateV2,
}

impl TeeStream {
    fn new(inner: UpstreamStream, pending_shadow: Option<PendingShadow>) -> Self {
        let accounting_limit_bytes = pending_shadow
            .as_ref()
            .map_or(0, |shadow| shadow.accounting_limit_bytes);
        Self {
            inner,
            pending_shadow,
            collected: Vec::new(),
            error: None,
            truncated: false,
            accounting_limit_bytes,
            authority: None,
            reached_eof: false,
            authority_failure: None,
            delivered_bytes: 0,
        }
    }

    fn with_authority(mut self, authority: PendingAuthorityTerminal) -> Self {
        if self.accounting_limit_bytes == 0 {
            self.accounting_limit_bytes = MAX_REQUEST_BODY_BYTES;
        }
        self.authority = Some(authority);
        self
    }

    fn collect_chunk(&mut self, bytes: &Bytes) {
        self.delivered_bytes = self
            .delivered_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let remaining = self
            .accounting_limit_bytes
            .saturating_sub(self.collected.len());
        if remaining == 0 {
            if !bytes.is_empty() {
                self.truncated = true;
            }
            return;
        }

        let take = remaining.min(bytes.len());
        self.collected.extend_from_slice(&bytes[..take]);
        if take < bytes.len() {
            self.truncated = true;
        }
    }

    fn finish(&mut self) {
        let collected = std::mem::take(&mut self.collected);
        let error = self.error.take();
        if let Some(pending_shadow) = self.pending_shadow.take() {
            let shadow_collected = collected.clone();
            let shadow_error = error.clone();
            let incomplete = self.truncated || shadow_error.is_some();
            tokio::spawn(async move {
                record_shadow(pending_shadow, shadow_collected, shadow_error, incomplete).await;
            });
        }
        if let Some(authority) = self.authority.take() {
            let terminal_guard = authority.terminal_tracker.start();
            let cancelled = !self.reached_eof
                && error.is_none()
                && authority
                    .expected_response_bytes
                    .is_none_or(|expected| self.delivered_bytes < expected);
            let truncated = self.truncated;
            let authority_failure = self.authority_failure.take();
            tokio::spawn(async move {
                append_authority_terminal(
                    authority,
                    collected,
                    error,
                    authority_failure,
                    truncated,
                    cancelled,
                )
                .await;
                drop(terminal_guard);
            });
        }
    }
}

impl Stream for TeeStream {
    type Item = Result<Bytes, ProxyStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.collect_chunk(&bytes);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(err))) => {
                self.authority_failure = match &err {
                    ProxyStreamError::Candidate(
                        crate::actuator::CandidateTransportError::Transport,
                    ) => Some(CandidateFailureClassV2::TransportStream),
                    ProxyStreamError::Candidate(
                        crate::actuator::CandidateTransportError::IdleTimeout,
                    ) => Some(CandidateFailureClassV2::StreamIdleTimeout),
                    ProxyStreamError::Candidate(
                        crate::actuator::CandidateTransportError::ProtocolIncomplete,
                    ) => Some(CandidateFailureClassV2::ProtocolIncomplete),
                    _ => None,
                };
                self.error = Some(err.to_string());
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                self.reached_eof = true;
                self.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for TeeStream {
    fn drop(&mut self) {
        self.finish();
    }
}

async fn append_authority_terminal(
    pending: PendingAuthorityTerminal,
    collected: Vec<u8>,
    error: Option<String>,
    stream_failure: Option<CandidateFailureClassV2>,
    truncated: bool,
    cancelled: bool,
) {
    let candidate = pending.candidate_supply_id.is_some();
    let (completion, candidate_failure) = classify_authority_terminal(
        candidate,
        pending.status,
        stream_failure,
        error.as_deref(),
        cancelled,
    );
    let usage = if completion == CompletionStateV2::Succeeded && !truncated {
        if pending.request_facts.stream {
            parse_sse_usage(pending.protocol, &collected)
        } else {
            parse_response_usage(pending.protocol, &collected)
        }
    } else {
        UsageFacts {
            input_tokens: None,
            output_tokens: None,
            source: UsageSource::Missing,
        }
    };
    let (input_tokens, output_tokens, usage_source) = if usage.source == UsageSource::Observed {
        (usage.input_tokens, usage.output_tokens, usage.source)
    } else {
        (None, None, UsageSource::Missing)
    };
    let circuit_after = if candidate_failure.is_some() {
        pending
            .actuators
            .as_ref()
            .and_then(|registry| {
                registry
                    .circuit(pending.candidate_supply_id.as_deref()?)
                    .ok()
            })
            .map(circuit_state_v2)
            .unwrap_or(CircuitStateV2::Open)
    } else if cancelled {
        if candidate {
            CircuitStateV2::Closed
        } else {
            pending.circuit_before
        }
    } else if candidate {
        CircuitStateV2::Closed
    } else {
        pending.circuit_before
    };
    let terminal = AuthorityTerminalV2 {
        ts_ms: now_ms(),
        circuit_after,
        completion,
        candidate_failure,
        status: Some(pending.status),
        input_tokens,
        output_tokens,
        usage_source,
    };
    let outcome = match pending.handle.build_outcome(terminal) {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(error = %error, "failed to construct exact authority terminal");
            return;
        }
    };
    if let Err(error) = pending
        .writer
        .append_and_flush_outcome(pending.handle, outcome)
        .await
    {
        tracing::error!(error = %error, "failed to persist authority terminal");
    }
}

fn classify_authority_terminal(
    candidate: bool,
    status: u16,
    stream_failure: Option<CandidateFailureClassV2>,
    error: Option<&str>,
    cancelled: bool,
) -> (CompletionStateV2, Option<CandidateFailureClassV2>) {
    let status_failure = if candidate {
        match status {
            401 | 403 => Some(CandidateFailureClassV2::Authentication),
            500..=599 => Some(CandidateFailureClassV2::Server),
            _ => None,
        }
    } else {
        None
    };
    let candidate_failure = status_failure.or(stream_failure);
    let completion = if candidate_failure.is_some() || error.is_some() {
        CompletionStateV2::Failed
    } else if cancelled {
        CompletionStateV2::Cancelled
    } else {
        CompletionStateV2::Succeeded
    };
    (completion, candidate_failure)
}

fn circuit_state_v2(snapshot: CircuitSnapshot) -> CircuitStateV2 {
    match snapshot {
        CircuitSnapshot::Closed | CircuitSnapshot::ClosedWithFailures(_) => CircuitStateV2::Closed,
        CircuitSnapshot::Open => CircuitStateV2::Open,
        CircuitSnapshot::HalfOpen => CircuitStateV2::HalfOpen,
    }
}

async fn record_shadow(
    pending: PendingShadow,
    collected: Vec<u8>,
    error: Option<String>,
    accounting_truncated: bool,
) {
    if let Some(error) = error {
        tracing::warn!(
            error,
            "upstream response stream failed before shadow accounting completed"
        );
    }

    let usage = if pending.request_facts.stream {
        parse_sse_usage(pending.protocol, &collected)
    } else {
        parse_response_usage(pending.protocol, &collected)
    };
    let (input_tokens, output_tokens, usage_source) = actual_usage(&pending.request_facts, usage);
    let model = if pending.request_facts.stream {
        parse_sse_model(pending.protocol, &collected)
            .or_else(|| pending.request_facts.model.clone())
    } else {
        parse_response_model(pending.protocol, &collected)
            .or_else(|| pending.request_facts.model.clone())
    };
    let mut decision = pending.decision.clone();
    let (mut coverage_status, mut coverage_reason) =
        (pending.coverage_status, pending.coverage_reason.clone());
    let attribution = if coverage_status == CoverageStatus::Supported {
        let resolver = pending
            .attribution_resolver
            .as_deref()
            .expect("recording gateway has a validated attribution resolver");
        let attribution = resolve_actual_supply(
            resolver,
            &pending.recording.registry,
            pending.attribution_input.clone(),
            model.as_deref(),
            AttributionSource::InlineResponseHeader,
        );
        (coverage_status, coverage_reason) = apply_attribution_coverage(
            coverage_status,
            coverage_reason,
            &attribution,
            pending.attribution_header.is_some(),
        );
        if coverage_status != CoverageStatus::Supported {
            decision.shadow = None;
        }
        attribution
    } else {
        bowline_core::attribution::AttributionResult {
            status: bowline_core::attribution::AttributionStatus::Missing,
            source: AttributionSource::InlineResponseHeader,
            reference: None,
            supply_id: None,
            reason: Some("attribution-not-attempted-for-unsupported-observation".to_string()),
        }
    };
    let supported_evidence =
        coverage_status == CoverageStatus::Supported && pending.protocol.is_supported();
    let est_cost_usd = if accounting_truncated || !supported_evidence {
        None
    } else {
        actual_cost(
            &pending.recording.registry,
            attribution.supply_id.as_deref(),
            model.as_deref(),
            input_tokens,
            output_tokens,
            &pending.recording.owned_costs,
        )
    };
    if accounting_truncated {
        if let RecordingWriter::Managed(writer) = &pending.recording.writer {
            let _ = writer.health().run().increment_truncated();
        }
    }
    if supported_evidence {
        if let RecordingWriter::Managed(writer) = &pending.recording.writer {
            let run = writer.health();
            let entry = model.as_deref().and_then(|model| {
                pending
                    .recording
                    .registry
                    .resolve_actual_entry(attribution.supply_id.as_deref(), model)
            });
            if entry.is_none() {
                let _ = run.run().increment_unmapped();
            } else if !accounting_truncated && est_cost_usd.is_none() {
                let _ = run.run().increment_unpriceable();
            }
        }
    }
    let record = build_final_record(
        &pending,
        FinalObservation {
            decision,
            coverage_status,
            coverage_reason,
            model,
            input_tokens,
            output_tokens,
            usage_source,
            est_cost_usd,
            attribution,
            accounting_truncated,
        },
    );

    match &pending.recording.writer {
        RecordingWriter::Legacy(writer) => {
            if let Err(error) = writer.tx.try_send(record) {
                tracing::warn!(error = %error, "decision ledger writer queue full; dropping record");
            }
        }
        RecordingWriter::Managed(writer) => {
            if record.sequence.is_some() {
                if let Err(error) = writer.try_record(record) {
                    tracing::warn!(error = %error, "managed decision record was not queued");
                }
            }
        }
    }
}

fn build_final_record(
    pending: &PendingShadow,
    final_observation: FinalObservation,
) -> DecisionRecord {
    build_decision_record(
        RecordEnvelope {
            id: Uuid::new_v4().to_string(),
            ts_ms: now_ms(),
            run_id: pending
                .record_context
                .as_ref()
                .map(|context| context.run_id.clone()),
            sequence: pending
                .record_context
                .as_ref()
                .map(|context| context.sequence),
            accounting_truncated: final_observation.accounting_truncated,
            protocol: pending.protocol,
            observation_source: ObservationSource::Inline,
            coverage_status: final_observation.coverage_status,
            coverage_reason: final_observation.coverage_reason,
            identity: pending.identity.clone(),
            decision: final_observation.decision,
        },
        ActualObservation {
            upstream: pending.upstream.clone(),
            model: final_observation.model,
            status: pending.response_status,
            streamed: pending.request_facts.stream,
            latency_ms: pending
                .started_at
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            input_tokens: final_observation.input_tokens,
            output_tokens: final_observation.output_tokens,
            usage_source: final_observation.usage_source,
            est_cost_usd: final_observation.est_cost_usd,
            attribution: final_observation.attribution,
        },
    )
}

fn actual_usage(
    request_facts: &RequestFacts,
    usage: UsageFacts,
) -> (Option<u64>, Option<u64>, UsageSource) {
    if usage.source == UsageSource::Missing {
        (
            Some(request_facts.est_input_tokens),
            None,
            UsageSource::Estimated,
        )
    } else {
        (usage.input_tokens, usage.output_tokens, usage.source)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn deps_from_config(config: &Config) -> anyhow::Result<GatewayDeps> {
    let policy_source = fs::read_to_string(&config.policy_bundle).with_context(|| {
        format!(
            "failed to read policy bundle {}",
            config.policy_bundle.display()
        )
    })?;
    let registry_source = fs::read_to_string(&config.registry_feed).with_context(|| {
        format!(
            "failed to read registry feed {}",
            config.registry_feed.display()
        )
    })?;
    let policy =
        PolicyBundle::from_yaml(&policy_source).context("failed to parse policy bundle")?;
    let registry =
        Registry::from_json(&registry_source).context("failed to parse registry feed")?;
    let tco_source = config
        .tco
        .as_ref()
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read TCO inputs {}", path.display()))
        })
        .transpose()?;
    let owned_costs = load_owned_cost_catalog(
        tco_source.as_deref(),
        Some(&config.actual_supply_id),
        &registry,
    )
    .context("failed to load owned-cost catalog")?;
    let provenance = ActiveRuntimeProvenance::from_loaded(&policy, &registry_source, &owned_costs);
    let (writer, recovery) = open_writer_if_recording_enabled(config.ledger_dir.clone())?;

    if recovery.blocks_append() {
        if config.enforcement.is_some() {
            anyhow::bail!(
                "configured enforcement requires a writable legacy observation ledger; recovery found corrupt or undecodable evidence"
            );
        }
        tracing::error!(
            recovery = ?recovery,
            ledger_dir = %config.ledger_dir.display(),
            "decision ledger cannot accept further appends (corrupt or undecodable); proxying continues with shadow recording disabled"
        );
        return Ok(GatewayDeps::default());
    }

    let enforcement = config
        .enforcement
        .as_ref()
        .map(|path| load_enforcement_runtime(config, path, &registry, &provenance))
        .transpose()?
        .map(Arc::new);
    let mut deps = GatewayDeps::recording_inner(
        policy,
        registry,
        config.floors.clone().unwrap_or_default(),
        owned_costs,
        RecordingWriter::Legacy(writer.expect("non-corrupt ledger recovery returns a writer")),
        Some(provenance),
    );
    deps.enforcement = enforcement;
    Ok(deps)
}

fn load_enforcement_runtime(
    config: &Config,
    path: &std::path::Path,
    registry: &Registry,
    active: &ActiveRuntimeProvenance,
) -> anyhow::Result<EnforcementRuntime> {
    use std::os::unix::fs::PermissionsExt;

    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read enforcement bundle {}", path.display()))?;
    let raw =
        EnforcementConfigV1::from_yaml(&source).context("failed to parse enforcement bundle")?;
    let route_ids = raw
        .routes
        .iter()
        .map(|route| route.route_id.clone())
        .collect::<Vec<_>>();
    let validated = raw
        .validate()
        .context("failed to validate enforcement bundle")?;
    let evidence_root = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut grants = BTreeMap::new();
    let mut grant_rejections = BTreeMap::new();
    for route in validated.authority_routes() {
        let outcome = load_verified_promotion_grant_with_approval(
            &validated,
            &route.route_id,
            evidence_root,
            active,
            now_ms(),
            config.authority_signing.as_ref(),
            config.promotion_approval.as_ref(),
        )
        .with_context(|| {
            format!(
                "failed to verify promotion grant for {}",
                operator_safe_route_id(&route.route_id)
            )
        })?;
        match outcome {
            PromotionGrantLoad::Verified(grant) => {
                grants.insert(route.route_id.clone(), *grant);
            }
            PromotionGrantLoad::SignatureMissing => {
                grant_rejections.insert(route.route_id.clone(), SelectionReason::SignatureMissing);
            }
            PromotionGrantLoad::SignatureInvalid => {
                grant_rejections.insert(route.route_id.clone(), SelectionReason::SignatureInvalid);
            }
            PromotionGrantLoad::ApprovalMissing => {
                grant_rejections.insert(route.route_id.clone(), SelectionReason::ApprovalMissing);
            }
            PromotionGrantLoad::ApprovalSignatureInvalid => {
                grant_rejections.insert(
                    route.route_id.clone(),
                    SelectionReason::ApprovalSignatureInvalid,
                );
            }
            PromotionGrantLoad::ApprovalUnbound => {
                grant_rejections.insert(route.route_id.clone(), SelectionReason::ApprovalUnbound);
            }
            PromotionGrantLoad::ApprovalExpired => {
                grant_rejections.insert(route.route_id.clone(), SelectionReason::ApprovalExpired);
            }
        }
    }
    let mut recommendations = BTreeMap::new();
    for route in validated.routes().filter(|route| {
        route.mode == bowline_core::enforcement::RouteMode::Recommend && route.promotion.is_some()
    }) {
        let evidence = optional_recommendation_evidence(
            &route.route_id,
            load_verified_recommendation_evidence(
                &validated,
                &route.route_id,
                evidence_root,
                active,
                now_ms(),
            )
            .with_context(|| {
                format!(
                    "failed to verify recommendation evidence for {}",
                    operator_safe_route_id(&route.route_id)
                )
            }),
        );
        if let Some(evidence) = evidence {
            recommendations.insert(route.route_id.clone(), evidence);
        }
    }
    let kill = &raw.kill_switch;
    let kill_reader = BoundedKillStateReader::new(
        KillStateReader::open(std::path::Path::new(&kill.trust_root), &kill.relative_path)
            .context("failed to open enforcement kill switch")?,
        config.runtime.writer_queue_capacity.max(1),
    );
    let actuators = ActuatorRegistry::new(
        raw.global_candidate_in_flight,
        raw.actuators.iter().cloned(),
    )
    .context("failed to initialize actuator registry")?;
    let mut targets = BTreeMap::new();
    for actuator in &raw.actuators {
        let secret = env::var(&actuator.authorization_env).with_context(|| {
            format!(
                "missing actuator authorization environment variable {}",
                actuator.authorization_env
            )
        })?;
        let authorization = reqwest::header::HeaderValue::from_str(&secret)
            .context("actuator authorization is not a valid HTTP header value")?;
        let canonical_model = registry
            .by_id(&actuator.supply_id)
            .map(|entry| entry.model.clone())
            .with_context(|| {
                format!(
                    "actuator supply {} is absent from the registry",
                    actuator.supply_id
                )
            })?;
        targets.insert(
            actuator.supply_id.clone(),
            ActuatorTarget {
                client: build_redirect_free_client(Duration::from_millis(
                    actuator.connect_timeout_ms,
                ))
                .context("failed to build redirect-free actuator client")?,
                base_url: actuator.base_url.trim_end_matches('/').to_owned(),
                authorization,
                canonical_model,
                response_header_timeout: Duration::from_millis(actuator.response_header_timeout_ms),
                stream_idle_timeout: Duration::from_millis(actuator.stream_idle_timeout_ms),
            },
        );
    }
    let authority_directory = config
        .ledger_dir
        .join("authority-v2")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&authority_directory).with_context(|| {
        format!(
            "failed to create authority evidence directory {}",
            authority_directory.display()
        )
    })?;
    fs::set_permissions(&authority_directory, fs::Permissions::from_mode(0o700))?;
    let actuator_digests = raw
        .actuators
        .iter()
        .filter_map(|actuator| validated.actuator_digest(&actuator.supply_id))
        .collect();
    let grant_digests = grants
        .values()
        .map(|grant| grant.grant_digest().to_owned())
        .collect();
    let writer = spawn_managed_authority_writer(AuthorityWriterOptions {
        directory: authority_directory,
        enforcement_digest: validated.normalized_digest().to_owned(),
        actuator_digests,
        grant_digests,
        queue_capacity: config.runtime.writer_queue_capacity,
        max_records_bytes: config.runtime.ledger_segment_bytes,
    })
    .context("failed to start authority evidence writer")?;
    Ok(EnforcementRuntime {
        validated,
        route_ids,
        grants,
        grant_rejections,
        recommendations,
        kill_reader,
        actuators,
        targets,
        writer,
        terminal_tracker: Arc::new(AuthorityTerminalTracker::default()),
        last_kill_state: Mutex::new(KillReadResult::Unreadable),
    })
}

fn optional_recommendation_evidence(
    route_id: &str,
    result: anyhow::Result<VerifiedRecommendationEvidence>,
) -> Option<VerifiedRecommendationEvidence> {
    match result {
        Ok(evidence) => Some(evidence),
        Err(error) => {
            let route_id = operator_safe_route_id(route_id);
            tracing::warn!(%route_id, error = %error, "recommendation evidence is unverified");
            None
        }
    }
}

async fn run_startup_authority_probes(runtime: &EnforcementRuntime) {
    let kill = runtime.kill_reader.read_kill_state().await;
    *runtime
        .last_kill_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = kill;
    let mut supply_ids = runtime
        .validated
        .authority_routes()
        .filter_map(|route| route.promoted_supply_id.as_deref())
        .collect::<Vec<_>>();
    supply_ids.sort_unstable();
    supply_ids.dedup();
    for supply_id in supply_ids {
        let Some(target) = runtime.targets.get(supply_id) else {
            continue;
        };
        match runtime
            .actuators
            .run_startup_probe(
                supply_id,
                &target.canonical_model,
                Some(target.authorization.clone()),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(%supply_id, "authority actuator startup probe failed; circuit remains open")
            }
            Err(error) => {
                tracing::warn!(%supply_id, error = %error, "authority actuator startup probe failed; circuit remains open")
            }
        }
    }
}

fn upstream_url(upstream_base: &str, uri: &Uri) -> String {
    let path_and_query = uri.path_and_query().map_or("/", |value| value.as_str());
    format!("{upstream_base}{path_and_query}")
}

fn should_forward_header(name: &HeaderName) -> bool {
    !is_hop_by_hop_header(name) && !name.as_str().starts_with("x-bowline-")
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

fn status_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
#[path = "proxy_controlled_matrix_tests.rs"]
pub(crate) mod proxy_controlled_matrix_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_enforcement_with_corrupt_legacy_observation_evidence_refuses_startup() {
        let root = tempfile::tempdir().unwrap();
        let policy_path = root.path().join("policy.yaml");
        fs::write(
            &policy_path,
            r#"
version: 1
identities: []
rules:
  - name: default
    default: true
    require: { supply_class: [public-api] }
"#,
        )
        .unwrap();
        let registry_path = root.path().join("registry.json");
        fs::write(
            &registry_path,
            r#"{"feed_version":"test","entries":[{"id":"baseline","model":"baseline-model","location":"public","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0},"ratings":{"heavy-lifting":0.9}}]}"#,
        )
        .unwrap();
        let ledger_dir = root.path().join("ledger");
        fs::create_dir(&ledger_dir).unwrap();
        let mut corrupt = b"BWL1\n".to_vec();
        corrupt.extend_from_slice(&2_u32.to_le_bytes());
        corrupt.extend_from_slice(&0_u32.to_le_bytes());
        corrupt.extend_from_slice(b"{}");
        fs::write(ledger_dir.join("decisions.bwl"), corrupt).unwrap();
        let config = Config {
            listen: "127.0.0.1:0".into(),
            upstream: "http://127.0.0.1:9".into(),
            actual_supply_id: "baseline".into(),
            policy_bundle: policy_path,
            registry_feed: registry_path,
            local_endpoints: Vec::new(),
            ledger_dir,
            tco: None,
            attribution: None,
            floors: None,
            enforcement: Some(root.path().join("enforcement.yaml")),
            authority_signing: None,
            promotion_approval: None,
            state_backend: None,
            trusted_proxy_cidrs: vec![],
            runtime: RuntimeConfig::default(),
        };

        let error = match deps_from_config(&config) {
            Ok(_) => panic!("enforcement must not disappear"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("configured enforcement requires"));
    }

    #[test]
    fn malformed_or_stale_recommendation_evidence_is_optional() {
        let evidence = optional_recommendation_evidence(
            "recommend-route",
            Err(anyhow::anyhow!("stale recommendation")),
        );
        assert!(evidence.is_none());
    }

    #[test]
    fn status_failure_precedes_downstream_cancellation() {
        for (status, expected) in [
            (401, CandidateFailureClassV2::Authentication),
            (403, CandidateFailureClassV2::Authentication),
            (500, CandidateFailureClassV2::Server),
            (599, CandidateFailureClassV2::Server),
        ] {
            let (completion, failure) = classify_authority_terminal(true, status, None, None, true);
            assert_eq!(completion, CompletionStateV2::Failed);
            assert_eq!(failure, Some(expected));
        }
        let (completion, failure) = classify_authority_terminal(true, 200, None, None, true);
        assert_eq!(completion, CompletionStateV2::Cancelled);
        assert_eq!(failure, None);
    }

    #[tokio::test]
    async fn controlled_handler_observe_and_fail_closed_are_exactly_zero_or_one_dispatch() {
        use std::{
            os::unix::fs::PermissionsExt,
            sync::atomic::{AtomicUsize, Ordering},
        };

        let root = tempfile::tempdir().unwrap();
        let kill_root = root.path().join("kill");
        fs::create_dir(&kill_root).unwrap();
        fs::set_permissions(&kill_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(kill_root.join("state"), b"bypass\n").unwrap();
        fs::set_permissions(kill_root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
        let policy = PolicyBundle::from_yaml(
            "version: 1\nidentities: []\nrules:\n  - name: default\n    default: true\n    task_class: heavy-lifting\n",
        )
        .unwrap();
        let active = ActiveRuntimeProvenance::from_loaded(
            &policy,
            "controlled handler registry source\n",
            &OwnedCostCatalog::default(),
        );
        let source = format!(
            r#"
version: 1
global_candidate_in_flight: 1
kill_switch: {{trust_root: {}, relative_path: state}}
actuators:
  - supply_id: candidate
    base_url: http://127.0.0.1:9
    authorization_env: TEST_CANDIDATE_TOKEN
    health_path: /v1/models
    connect_timeout_ms: 100
    response_header_timeout_ms: 100
    stream_idle_timeout_ms: 100
    concurrency: 1
    probe_timeout_ms: 100
    probe_max_bytes: 1024
    breaker_consecutive_failures: 1
    breaker_cooldown_ms: 100
routes:
  - route_id: chat-observe
    method: POST
    path: /v1/chat/completions
    protocol: chat-completions
    mode: observe
    rollout_ppm: 0
  - route_id: responses-closed
    method: POST
    path: /v1/responses
    protocol: responses
    workload: {{app: support, resolved_tags: [production]}}
    mode: enforce
    rollout_ppm: 0
    promoted_supply_id: candidate
    actual_supply_id: baseline
    task_class: heavy-lifting
    model_authority: rewrite-to-canonical
    fallback: fail-closed
    promotion:
      economics_bundle_path: economics
      economics_report_digest: sha256:{a}
      opportunity_digest: sha256:{b}
      quality_run_path: quality
      authorization_path: authorization/responses-closed.json
      quality_run_id: quality-1
      quality_report_digest: sha256:{c}
      policy_digest: sha256:{d}
      registry_digest: sha256:{e}
      owned_cost_digest: sha256:{f}
      max_economics_age_ms: 100000
      expires_at_ms: 2000000000000
"#,
            kill_root.display(),
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64),
            d = active.policy_digest().strip_prefix("sha256:").unwrap(),
            e = active.registry_digest().strip_prefix("sha256:").unwrap(),
            f = active.owned_cost_digest().strip_prefix("sha256:").unwrap(),
        );
        let raw = EnforcementConfigV1::from_yaml(&source).unwrap();
        let route_ids = raw
            .routes
            .iter()
            .map(|route| route.route_id.clone())
            .collect();
        let validated = raw.validate().unwrap();
        let route = validated.route("responses-closed").unwrap();
        let workload =
            route_workload_digest(route.protocol, route.workload.as_ref().unwrap()).unwrap();
        let digest = |ch: char| format!("sha256:{}", ch.to_string().repeat(64));
        let mut artifact_digests = BTreeMap::new();
        for name in [
            "dimensions.csv",
            "opportunities.csv",
            "reconciliation.csv",
            "report.html",
            "report.json",
            "report.md",
        ] {
            artifact_digests.insert(
                name.to_owned(),
                if name == "report.json" {
                    digest('a')
                } else {
                    digest('1')
                },
            );
        }
        let evidence_now = now_ms();
        let economics = bowline_core::enforcement::EconomicsPromotionSource {
            schema_version: 1,
            as_of_ms: evidence_now,
            window_end_ms: evidence_now,
            complete: true,
            report_digest: digest('a'),
            bundle_digest: digest('1'),
            artifact_digests,
            selected_traffic_digest: digest('1'),
            selected_billing_digest: Some(digest('1')),
            selected_quality_digests: vec![digest('c')],
            opportunity: bowline_core::enforcement::PromotionOpportunityEvidence {
                digest: digest('b'),
                workload_identity_digest: workload.clone(),
                task_class: bowline_core::supply::TaskClass::HeavyLifting,
                protocol: AuthorityProtocol::Responses,
                actual_supply_id: "baseline".into(),
                candidate_supply_id: "candidate".into(),
                eligible: true,
                policy_feasible: true,
                capacity_available: true,
                actual_cost_micros: Some(10),
                candidate_cost_micros: Some(5),
                actual_rate_micros: Some(bowline_core::economics::CostRateMicros {
                    input_per_mtok_micros: 2_000_000,
                    output_per_mtok_micros: 2_000_000,
                }),
                candidate_rate_micros: Some(bowline_core::economics::CostRateMicros {
                    input_per_mtok_micros: 1_000_000,
                    output_per_mtok_micros: 1_000_000,
                }),
            },
            policy_digest: active.policy_digest().into(),
            registry_digest: active.registry_digest().into(),
            owned_cost_digest: active.owned_cost_digest().into(),
        };
        let quality = bowline_core::enforcement::QualityPromotionSource {
            schema_version: 2,
            run_id: "quality-1".into(),
            completed_at_ms: evidence_now.saturating_sub(10),
            valid_until_ms: 2_000_000_000_000,
            workload_identity_digest: workload,
            task_class: bowline_core::supply::TaskClass::HeavyLifting,
            protocol: AuthorityProtocol::Responses,
            candidate_supply_id: "candidate".into(),
            effective_verdict: bowline_core::quality::PromotionVerdict::Eligible,
            manifest_digest: digest('1'),
            outcomes_digest: digest('1'),
            report_digest: digest('c'),
            manifest_valid: true,
            outcomes_valid: true,
            report_valid: true,
            policy_digest: active.policy_digest().into(),
            registry_digest: active.registry_digest().into(),
            owned_cost_digest: active.owned_cost_digest().into(),
        };
        let authorization = bowline_core::enforcement::seal_promotion_authorization(
            &validated,
            "responses-closed",
            &economics,
            &quality,
            &active,
            evidence_now,
        )
        .unwrap();
        let validation = bowline_core::enforcement::validate_promotion_documents(
            &validated,
            "responses-closed",
            &economics,
            &quality,
            &authorization,
            &active,
            evidence_now,
        )
        .unwrap();
        let grant = crate::enforcement_loader::test_verified_promotion_grant(validation);
        let grant_digest = grant.grant_digest().to_owned();

        let candidate_count = Arc::new(AtomicUsize::new(0));
        let candidate_seen = Arc::new(std::sync::Mutex::new(None));
        let candidate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let candidate_addr = candidate_listener.local_addr().unwrap();
        let candidate_app = Router::new()
            .route(
                "/v1/models",
                get(|| async { r#"{"data":[{"id":"candidate-model"}]}"# }),
            )
            .fallback(any({
                let count = Arc::clone(&candidate_count);
                let seen = Arc::clone(&candidate_seen);
                move |headers: HeaderMap, body: Bytes| {
                    let count = Arc::clone(&count);
                    let seen = Arc::clone(&seen);
                    async move {
                        count.fetch_add(1, Ordering::AcqRel);
                        *seen.lock().unwrap() = Some((headers, body));
                        (
                            StatusCode::OK,
                            r#"{"model":"candidate-model","usage":{"input_tokens":3,"output_tokens":4},"output":[]}"#,
                        )
                    }
                }
            }));
        let candidate_task = tokio::spawn(async move {
            axum::serve(candidate_listener, candidate_app)
                .await
                .unwrap()
        });
        let authority_dir = root.path().join("authority");
        fs::create_dir(&authority_dir).unwrap();
        fs::set_permissions(&authority_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let authority_writer = crate::writer::spawn_transient_faulting_authority_writer(
            AuthorityWriterOptions {
                directory: authority_dir,
                enforcement_digest: validated.normalized_digest().to_owned(),
                actuator_digests: vec![validated.actuator_digest("candidate").unwrap()],
                grant_digests: vec![grant_digest],
                queue_capacity: 8,
                max_records_bytes: 1024 * 1024,
            },
            7,
        )
        .unwrap();
        let mut actuator_configs = raw.actuators;
        actuator_configs[0].base_url = format!("http://{candidate_addr}");
        let actuators = ActuatorRegistry::new(1, actuator_configs).unwrap();
        let mut targets = BTreeMap::new();
        targets.insert(
            "candidate".to_owned(),
            ActuatorTarget {
                client: build_redirect_free_client(Duration::from_millis(100)).unwrap(),
                base_url: format!("http://{candidate_addr}"),
                authorization: reqwest::header::HeaderValue::from_static("Bearer candidate-secret"),
                canonical_model: "candidate-model".into(),
                response_header_timeout: Duration::from_millis(100),
                stream_idle_timeout: Duration::from_millis(100),
            },
        );
        let runtime = Arc::new(EnforcementRuntime {
            validated,
            route_ids,
            grants: BTreeMap::from([("responses-closed".to_owned(), grant)]),
            grant_rejections: BTreeMap::new(),
            recommendations: BTreeMap::new(),
            kill_reader: BoundedKillStateReader::new(
                KillStateReader::open(&kill_root.canonicalize().unwrap(), "state").unwrap(),
                8,
            ),
            actuators,
            targets,
            writer: authority_writer.clone(),
            terminal_tracker: Arc::new(AuthorityTerminalTracker::default()),
            last_kill_state: Mutex::new(KillReadResult::Unreadable),
        });
        let startup_open = public_enforcement_health(&runtime).await;
        assert_eq!(
            startup_open.active_fail_closed_routes_on_unavailable_actuators,
            1
        );
        run_startup_authority_probes(&runtime).await;
        assert_eq!(
            runtime.actuators.circuit("candidate").unwrap(),
            CircuitSnapshot::Closed
        );

        let upstream_count = Arc::new(AtomicUsize::new(0));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_app = Router::new().fallback(any({
            let count = Arc::clone(&upstream_count);
            move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::AcqRel);
                    (StatusCode::OK, r#"{"model":"baseline-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#)
                }
            }
        }));
        let upstream_task =
            tokio::spawn(
                async move { axum::serve(upstream_listener, upstream_app).await.unwrap() },
            );
        let ledger_dir = root.path().join("shadow");
        let (legacy_writer, _) = crate::writer::spawn_writer(ledger_dir).unwrap();
        let policy = PolicyBundle::from_yaml(
            r#"
version: 1
identities:
  - match: { app: support }
    tags: [production]
rules:
  - name: default
    default: true
    task_class: heavy-lifting
    require: { supply_class: [public-api, owned] }
"#,
        )
        .unwrap();
        let registry = Registry::from_json(
            r#"{
  "feed_version":"test",
  "entries":[
    {"id":"baseline","model":"baseline-model","location":"public","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0},"ratings":{"heavy-lifting":0.9}},
    {"id":"candidate","model":"candidate-model","location":"local","attributes":{"class":"owned","jurisdiction":"local","retention":"none","training_use":false,"cloud_act_exposure":false},"price":null,"ratings":{"heavy-lifting":0.9}}
  ]
}"#,
        )
        .unwrap();
        let owned = load_owned_cost_catalog(None, Some("baseline"), &registry).unwrap();
        let mut deps = GatewayDeps::recording(
            policy,
            registry,
            QualityFloors::default(),
            owned,
            legacy_writer,
        );
        deps.enforcement = Some(Arc::clone(&runtime));
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway_listener.local_addr().unwrap();
        let health_run = Arc::new(
            bowline_core::run::RunStore::create(
                &root.path().join("health-run"),
                bowline_core::run::RunDigests {
                    policy: digest('d'),
                    registry: digest('e'),
                    attribution: None,
                    owned_cost: None,
                    passive_profile: None,
                    passive_input: None,
                },
                bowline_core::run::RunLimits {
                    segment_bytes: 1024,
                    max_segments: 2,
                },
            )
            .unwrap(),
        );
        let gateway_state = GatewayState::new(format!("http://{upstream_addr}"), deps);
        gateway_state.set_health_for_test(GatewayHealth::new(health_run, 8));
        let gateway = gateway_state.router();
        let gateway_task = tokio::spawn(async move {
            axum::serve(
                gateway_listener,
                gateway.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let client = build_redirect_free_client(Duration::from_secs(1)).unwrap();
        let controlled_live = client
            .get(format!("http://{gateway_addr}/health/live"))
            .send()
            .await
            .unwrap();
        assert_eq!(controlled_live.status(), StatusCode::OK);
        assert_eq!(
            controlled_live.text().await.unwrap(),
            r#"{"live":true,"mode":"controlled"}"#
        );
        let public_health = client
            .get(format!("http://{gateway_addr}/health/status"))
            .send()
            .await
            .unwrap();
        assert_eq!(public_health.status(), StatusCode::OK);
        let public_health = public_health.text().await.unwrap();
        assert!(public_health.contains("\"mode\":\"controlled\""));
        assert!(public_health.contains("\"ready\":false"));
        for forbidden in [
            "responses-closed",
            "support",
            "production",
            "candidate-model",
            "candidate-secret",
            "authorization_env",
        ] {
            assert!(!public_health.contains(forbidden));
        }
        // Health independently re-reads the descriptor-anchored kill file while traffic is idle.
        fs::write(kill_root.join("state"), b"armed\n").unwrap();
        let idle_armed = client
            .get(format!("http://{gateway_addr}/health/ready"))
            .send()
            .await
            .unwrap();
        assert_eq!(idle_armed.status(), StatusCode::OK);
        assert_eq!(
            idle_armed.json::<serde_json::Value>().await.unwrap()["mode"],
            "controlled"
        );
        fs::write(kill_root.join("state"), b"bypass\n").unwrap();
        assert_eq!(
            client
                .get(format!("http://{gateway_addr}/health/ready"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        fs::write(kill_root.join("state"), b"malformed\n").unwrap();
        let malformed = client
            .get(format!("http://{gateway_addr}/health/status"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(malformed["enforcement"]["kill_state"], "malformed");
        assert_eq!(malformed["ready"], false);
        fs::remove_file(kill_root.join("state")).unwrap();
        let missing = client
            .get(format!("http://{gateway_addr}/health/status"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(missing["enforcement"]["kill_state"], "missing");
        assert_eq!(missing["ready"], false);
        fs::write(kill_root.join("state"), b"armed\n").unwrap();
        fs::set_permissions(kill_root.join("state"), fs::Permissions::from_mode(0o644)).unwrap();
        let unsafe_state = client
            .get(format!("http://{gateway_addr}/health/status"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(unsafe_state["enforcement"]["kill_state"], "unsafe");
        assert_eq!(unsafe_state["ready"], false);
        fs::set_permissions(kill_root.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(kill_root.join("state"), b"bypass\n").unwrap();
        let observed = client
            .post(format!("http://{gateway_addr}/v1/chat/completions"))
            .header("x-bowline-app", "support")
            .body(r#"{"model":"baseline-model","messages":[]}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(observed.status(), StatusCode::OK);
        let observed_bytes = observed.bytes().await.unwrap();
        assert!(observed_bytes.starts_with(b"{\"model\":\"baseline-model\""));
        let first_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while authority_writer.manifest_snapshot().accepted < 2 {
            assert!(tokio::time::Instant::now() < first_deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            authority_writer.manifest_snapshot().writer_healthy,
            "observe terminal poisoned authority: {:?}",
            authority_writer.manifest_snapshot()
        );
        let closed = client
            .post(format!("http://{gateway_addr}/v1/responses"))
            .header("x-bowline-app", "support")
            .body(r#"{"model":"baseline-model","input":"hello"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(closed.status(), StatusCode::SERVICE_UNAVAILABLE);
        let closed_body = closed.json::<serde_json::Value>().await.unwrap();
        assert_eq!(
            closed_body["error"]["code"],
            "enforcement-fail-closed",
            "authority manifest: {:?}",
            authority_writer.manifest_snapshot()
        );
        fs::write(kill_root.join("state"), b"armed\n").unwrap();
        let candidate = client
            .post(format!("http://{gateway_addr}/v1/responses"))
            .header("x-bowline-app", "support")
            .header("authorization", "Bearer customer-secret")
            .header("connection", "x-private-hop, keep-alive")
            .header("x-private-hop", "must-not-cross")
            .body(r#"{"model":"baseline-model","input":"hello"}"#)
            .send()
            .await
            .unwrap();
        let candidate_status = candidate.status();
        let candidate_bytes = candidate.bytes().await.unwrap();
        assert_eq!(
            candidate_status,
            StatusCode::OK,
            "candidate body: {}",
            String::from_utf8_lossy(&candidate_bytes)
        );
        assert!(candidate_bytes.starts_with(b"{\"model\":\"candidate-model\""));
        let armed_health = client
            .get(format!("http://{gateway_addr}/health/status"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(armed_health.contains("\"ready\":true"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while authority_writer.manifest_snapshot().accepted < 6 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(upstream_count.load(Ordering::Acquire), 1);
        assert_eq!(candidate_count.load(Ordering::Acquire), 1);
        {
            let seen = candidate_seen.lock().unwrap();
            let (seen_headers, seen_body) = seen.as_ref().unwrap();
            assert_eq!(
                seen_headers.get("authorization").unwrap(),
                "Bearer candidate-secret"
            );
            assert!(!seen_headers.contains_key("x-bowline-app"));
            assert!(!seen_headers.contains_key("x-private-hop"));
            assert_eq!(
                seen_body.as_ref(),
                br#"{"model":"candidate-model","input":"hello"}"#
            );
        }
        let recovered = client
            .post(format!("http://{gateway_addr}/v1/responses"))
            .header("x-bowline-app", "support")
            .body(r#"{"model":"baseline-model","input":"recovery"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            recovered.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "enforcement-fail-closed",
            "recovery manifest: {:?}",
            authority_writer.manifest_snapshot()
        );
        let failure_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while authority_writer.manifest_snapshot().accepted < 9 {
            assert!(tokio::time::Instant::now() < failure_deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(upstream_count.load(Ordering::Acquire), 1);
        assert_eq!(candidate_count.load(Ordering::Acquire), 1);
        assert_eq!(
            runtime.actuators.circuit("candidate").unwrap(),
            CircuitSnapshot::Closed
        );
        runtime.kill_reader.shutdown();
        let queue_unavailable = client
            .get(format!("http://{gateway_addr}/health/status"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(
            queue_unavailable["enforcement"]["kill_state"],
            "queue-unavailable"
        );
        assert_eq!(queue_unavailable["ready"], false);
        gateway_task.abort();
        upstream_task.abort();
        candidate_task.abort();
        authority_writer
            .shutdown(Duration::from_secs(2))
            .await
            .unwrap();
        let manifest = authority_writer.manifest_snapshot();
        assert_eq!(
            (manifest.accepted, manifest.recorded, manifest.dropped),
            (9, 8, 1)
        );
        assert!(!manifest.clean_shutdown);
    }

    #[tokio::test]
    async fn tee_stream_yields_input_byte_item_boundaries_unchanged() {
        let input = vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"-"),
            Bytes::from_static(b"third-item"),
        ];
        let inner: UpstreamStream = Box::pin(futures_util::stream::iter(
            input.clone().into_iter().map(Ok),
        ));
        let output = TeeStream::new(inner, None)
            .collect::<Vec<Result<Bytes, ProxyStreamError>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("tee stream remains successful");

        assert_eq!(output, input);
    }

    #[test]
    fn exact_catalog_classifies_all_twelve_inference_routes() {
        let expected = [
            ("/v1/chat/completions", ProtocolKind::ChatCompletions),
            ("/v1/responses", ProtocolKind::Responses),
            ("/v1/embeddings", ProtocolKind::Embeddings),
            ("/v1/completions", ProtocolKind::Unsupported),
            ("/v1/audio/transcriptions", ProtocolKind::Unsupported),
            ("/v1/audio/translations", ProtocolKind::Unsupported),
            ("/v1/audio/speech", ProtocolKind::Unsupported),
            ("/v1/images/generations", ProtocolKind::Unsupported),
            ("/v1/images/edits", ProtocolKind::Unsupported),
            ("/v1/images/variations", ProtocolKind::Unsupported),
            ("/v1/moderations", ProtocolKind::Unsupported),
            ("/v1/rerank", ProtocolKind::Unsupported),
        ];

        assert_eq!(INFERENCE_PROTOCOL_CATALOG, expected);
        for (path, protocol) in expected {
            assert_eq!(
                classify_inference_protocol(&Method::POST, path),
                Some(protocol),
                "wrong classification for POST {path}"
            );
        }
        assert_eq!(
            classify_inference_protocol(&Method::GET, "/v1/models"),
            None
        );
        assert_eq!(
            classify_inference_protocol(&Method::POST, "/v1/files"),
            None
        );
        assert_eq!(
            classify_inference_protocol(&Method::POST, "/v1/batches"),
            None
        );
        assert_eq!(
            classify_inference_protocol(&Method::POST, "/internal/health"),
            None
        );
    }

    #[test]
    fn architecture_documents_every_catalog_method_and_route() {
        let architecture = include_str!("../../../docs/architecture.md");

        for (path, _) in INFERENCE_PROTOCOL_CATALOG {
            let row_prefix = format!("| `POST` | `{path}` |");
            assert!(
                architecture.contains(&row_prefix),
                "architecture route table is missing {row_prefix}"
            );
        }
    }

    #[test]
    fn gateway_state_separates_transport_url_from_evidence_identity() {
        let source = r#"
listen: 127.0.0.1:8080
upstream: https://example.test/v1?api-version=2025-01-01&region=us#deployment
actual_supply_id: public/example
policy_bundle: policy.yaml
registry_feed: registry.json
ledger_dir: ledger
"#;
        let config = Config::from_yaml(source).expect("config parses");
        let state = GatewayState::from_config(&config, GatewayDeps::default())
            .expect("gateway state builds");

        assert_eq!(
            state.upstream_base,
            "https://example.test/v1?api-version=2025-01-01&region=us#deployment",
        );
        assert_eq!(state.upstream_identity, "https://example.test/v1");
    }

    #[test]
    fn read_response_reference_treats_oversized_and_non_utf8_as_absent() {
        let header = HeaderName::from_static("x-bowline-attribution");

        let mut oversized = HeaderMap::new();
        oversized.insert(header.clone(), "x".repeat(257).parse().unwrap());
        assert_eq!(
            read_response_reference(&oversized, Some(&header), Some("ns")),
            AttributionInput::Absent
        );

        let mut non_utf8 = HeaderMap::new();
        non_utf8.insert(
            header.clone(),
            axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert_eq!(
            read_response_reference(&non_utf8, Some(&header), Some("ns")),
            AttributionInput::Absent
        );

        let mut well_formed = HeaderMap::new();
        well_formed.insert(header.clone(), "candidate-a".parse().unwrap());
        assert_eq!(
            read_response_reference(&well_formed, Some(&header), Some("ns")),
            AttributionInput::Single(bowline_core::attribution::AttributionRef {
                namespace: "ns".into(),
                value: "candidate-a".into(),
            })
        );
    }

    #[test]
    fn absent_inline_attribution_falls_back_to_legacy_static_attribution() {
        let registry = Registry::from_json(
            r#"{"feed_version":"test","entries":[{"id":"baseline","model":"baseline-model","location":"public","attributes":{"class":"public-api","jurisdiction":"us","retention":"none","training_use":false,"cloud_act_exposure":false},"price":{"input_per_mtok_usd":1.0,"output_per_mtok_usd":1.0},"ratings":{"heavy-lifting":0.9}}]}"#,
        )
        .unwrap();
        let resolver =
            AttributionResolver::new(Vec::new(), Some("baseline".into()), &registry).unwrap();

        // An oversized/non-UTF8 header collapses to Absent (see the test above), which must still
        // reach the same legacy static-attribution fallback as a request with no header at all.
        let result = resolve_actual_supply(
            &resolver,
            &registry,
            AttributionInput::Absent,
            Some("baseline-model"),
            AttributionSource::InlineResponseHeader,
        );
        assert_eq!(
            result.status,
            bowline_core::attribution::AttributionStatus::StaticConfigured
        );
        assert_eq!(result.supply_id.as_deref(), Some("baseline"));
    }
}
