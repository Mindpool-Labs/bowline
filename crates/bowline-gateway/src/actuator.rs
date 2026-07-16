use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use bowline_core::enforcement::ActuatorConfig;
use bowline_core::enforcement::AuthorityProtocol;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::{
    state_backend::{AdmissionLeaseHandle, LocalStateBackend, StateBackend},
    writer::AuthorizedDispatchHandle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitSnapshot {
    Closed,
    ClosedWithFailures(u32),
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateFailure {
    Connect,
    HeaderTimeout,
    StreamIdleTimeout,
    TransportStream,
    ProtocolIncomplete,
    Authentication,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CandidateTransportError {
    #[error("candidate response transport stream failed")]
    Transport,
    #[error("candidate response stream exceeded its idle timeout")]
    IdleTimeout,
    #[error("candidate protocol ended before a required completion marker")]
    ProtocolIncomplete,
}

#[derive(Debug, Error)]
pub enum ActuatorError {
    #[error("candidate actuator is not configured")]
    UnknownActuator,
    #[error("candidate admission wait expired")]
    Saturated,
    #[error("candidate circuit is not closed")]
    CircuitUnavailable,
    #[error("candidate registry configuration is invalid")]
    InvalidConfiguration,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeDocument {
    data: Vec<ProbeModel>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeModel {
    id: String,
}

#[derive(Clone)]
pub struct RedirectFreeClient(reqwest::Client);

impl RedirectFreeClient {
    pub fn get(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.0.get(url)
    }

    pub fn post(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.0.post(url)
    }
}

pub fn build_redirect_free_client(timeout: Duration) -> Result<RedirectFreeClient, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .build()
        .map(RedirectFreeClient)
}

pub fn validate_probe_response(
    status: u16,
    body: &[u8],
    canonical_model_id: &str,
    max_bytes: usize,
) -> Result<(), ActuatorError> {
    if status != 200 || body.len() > max_bytes || body.is_empty() {
        return Err(ActuatorError::InvalidConfiguration);
    }
    let document: ProbeDocument =
        serde_json::from_slice(body).map_err(|_| ActuatorError::InvalidConfiguration)?;
    if !document
        .data
        .iter()
        .any(|model| model.id == canonical_model_id)
    {
        return Err(ActuatorError::InvalidConfiguration);
    }
    Ok(())
}

#[derive(Clone)]
pub struct ActuatorRegistry {
    state_backend: Arc<dyn StateBackend>,
    actuators: Arc<BTreeMap<String, Arc<Actuator>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActuatorSnapshot {
    pub closed: usize,
    pub open: usize,
    pub half_open: usize,
    pub global_candidate_in_flight: usize,
    pub global_candidate_capacity: usize,
    pub saturation_count: usize,
}

struct Actuator {
    config: ActuatorConfig,
    probe_semaphore: Arc<Semaphore>,
}

pub struct CandidatePermit {
    _admission: AdmissionLeaseHandle,
    state_backend: Arc<dyn StateBackend>,
    supply_id: String,
    breaker_failure_recorded: bool,
}

pub struct AuthorizedCandidateResponse {
    pub response: reqwest::Response,
    pub authority: AuthorizedDispatchHandle,
    pub permit: CandidatePermit,
}

pub struct AuthorizedCandidateFailure {
    pub failure: CandidateFailure,
    pub authority: AuthorizedDispatchHandle,
    pub permit: CandidatePermit,
}

pub struct AuthorizedCandidateRequest<'a> {
    pub method: reqwest::Method,
    pub url: &'a str,
    pub incoming_headers: &'a reqwest::header::HeaderMap,
    pub authorization: reqwest::header::HeaderValue,
    pub body: Bytes,
    pub response_header_timeout: Duration,
}

pub async fn send_authorized_candidate(
    client: &RedirectFreeClient,
    authority: AuthorizedDispatchHandle,
    mut permit: CandidatePermit,
    request: AuthorizedCandidateRequest<'_>,
) -> Result<AuthorizedCandidateResponse, AuthorizedCandidateFailure> {
    let headers = sanitize_candidate_headers(request.incoming_headers, request.authorization);
    let send = client
        .0
        .request(request.method, request.url)
        .headers(headers)
        .body(request.body)
        .send();
    match tokio::time::timeout(request.response_header_timeout, send).await {
        Ok(Ok(response)) => {
            if let Some(failure) = classify_candidate_result(Some(response.status().as_u16()), None)
            {
                permit.record_failure_once(failure);
            }
            Ok(AuthorizedCandidateResponse {
                response,
                authority,
                permit,
            })
        }
        Ok(Err(error)) => {
            let failure = if error.is_connect() {
                CandidateFailure::Connect
            } else if error.is_timeout() {
                CandidateFailure::HeaderTimeout
            } else {
                CandidateFailure::TransportStream
            };
            permit.record_failure_once(failure);
            Err(AuthorizedCandidateFailure {
                failure,
                authority,
                permit,
            })
        }
        Err(_) => {
            let failure = CandidateFailure::HeaderTimeout;
            permit.record_failure_once(failure);
            Err(AuthorizedCandidateFailure {
                failure,
                authority,
                permit,
            })
        }
    }
}

pub fn sanitize_candidate_headers(
    incoming: &reqwest::header::HeaderMap,
    authorization: reqwest::header::HeaderValue,
) -> reqwest::header::HeaderMap {
    let nominated = incoming
        .get_all(reqwest::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| reqwest::header::HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect::<HashSet<_>>();
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in incoming {
        if candidate_header_is_forwardable(name) && !nominated.contains(name) {
            headers.append(name, value.clone());
        }
    }
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    headers
}

fn candidate_header_is_forwardable(name: &reqwest::header::HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "authorization"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    ) && !name.as_str().starts_with("x-bowline-")
}

pub struct CandidateResponseStream<S> {
    inner: S,
    permit: Option<CandidatePermit>,
    protocol: AuthorityProtocol,
    streaming: bool,
    collected: Vec<u8>,
    limit: usize,
    over_limit: bool,
    terminal: bool,
}

impl<S> CandidateResponseStream<S> {
    pub fn new(
        inner: S,
        permit: CandidatePermit,
        protocol: AuthorityProtocol,
        streaming: bool,
        accounting_limit: usize,
    ) -> Self {
        Self {
            inner,
            permit: Some(permit),
            protocol,
            streaming,
            collected: Vec::new(),
            limit: accounting_limit,
            over_limit: false,
            terminal: false,
        }
    }

    fn collect_chunk(&mut self, bytes: &Bytes) {
        let remaining = self.limit.saturating_sub(self.collected.len());
        let take = remaining.min(bytes.len());
        self.collected.extend_from_slice(&bytes[..take]);
        self.over_limit |= take != bytes.len();
    }

    fn finish(&mut self, failure: Option<CandidateFailure>) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        if let Some(failure) = failure {
            if let Some(permit) = self.permit.as_mut() {
                permit.record_failure_once(failure);
            }
        } else if self.over_limit
            || response_is_provably_complete(self.protocol, self.streaming, &self.collected)
        {
            if let Some(permit) = self
                .permit
                .as_ref()
                .filter(|permit| !permit.breaker_failure_recorded)
            {
                permit
                    .state_backend
                    .record_candidate(&permit.supply_id, None, Instant::now());
            }
        }
        self.permit.take();
    }
}

impl<S> Stream for CandidateResponseStream<S>
where
    S: Stream<Item = Result<Bytes, CandidateTransportError>> + Unpin,
{
    type Item = Result<Bytes, CandidateTransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminal {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.collect_chunk(&bytes);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(error))) => {
                let failure = match error {
                    CandidateTransportError::Transport => CandidateFailure::TransportStream,
                    CandidateTransportError::IdleTimeout => CandidateFailure::StreamIdleTimeout,
                    CandidateTransportError::ProtocolIncomplete => {
                        CandidateFailure::ProtocolIncomplete
                    }
                };
                self.finish(Some(failure));
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if !self.over_limit
                    && !response_is_provably_complete(
                        self.protocol,
                        self.streaming,
                        &self.collected,
                    )
                {
                    self.finish(Some(CandidateFailure::ProtocolIncomplete));
                    Poll::Ready(Some(Err(CandidateTransportError::ProtocolIncomplete)))
                } else {
                    self.finish(None);
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Drop for CandidateResponseStream<S> {
    fn drop(&mut self) {
        // Dropping before a terminal poll is downstream cancellation. It releases admission but
        // cannot establish an actuator failure, so it leaves the breaker unchanged.
        self.permit.take();
    }
}

fn response_is_provably_complete(
    protocol: AuthorityProtocol,
    streaming: bool,
    bytes: &[u8],
) -> bool {
    if !streaming {
        return serde_json::from_slice::<serde_json::Value>(bytes).is_ok();
    }
    match protocol {
        AuthorityProtocol::ChatCompletions => bytes
            .split(|byte| *byte == b'\n')
            .any(|line| sse_data_field(line.trim_ascii()) == Some(&b"[DONE]"[..])),
        AuthorityProtocol::Responses => responses_sse_has_valid_completion(bytes),
        AuthorityProtocol::Embeddings => false,
    }
}

/// Parses an SSE `data:` field per the WHATWG field-parsing rule, where the single space
/// after the colon is optional (`data: value` and `data:value` are both legal).
fn sse_data_field(line: &[u8]) -> Option<&[u8]> {
    let rest = line.strip_prefix(b"data:")?;
    Some(rest.strip_prefix(b" ").unwrap_or(rest))
}

fn responses_sse_has_valid_completion(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let normalized = text.replace("\r\n", "\n");
    normalized.split("\n\n").any(|event| {
        let mut event_name = None;
        let mut data = None;
        for line in event.lines() {
            if let Some(value) = line.strip_prefix("event: ") {
                if event_name.replace(value).is_some() {
                    return false;
                }
            } else if let Some(value) = line.strip_prefix("data: ") {
                if data.replace(value).is_some() {
                    return false;
                }
            }
        }
        if event_name != Some("response.completed") {
            return false;
        }
        let Some(data) = data else {
            return false;
        };
        serde_json::from_str::<serde_json::Value>(data)
            .ok()
            .and_then(|value| {
                value
                    .as_object()
                    .and_then(|object| object.get("type"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("response.completed")
    })
}

impl CandidatePermit {
    fn record_failure_once(&mut self, failure: CandidateFailure) {
        if !self.breaker_failure_recorded {
            self.state_backend
                .record_candidate(&self.supply_id, Some(failure), Instant::now());
            self.breaker_failure_recorded = true;
        }
    }
}

impl ActuatorRegistry {
    pub fn new(
        global_candidate_in_flight: u32,
        configs: impl IntoIterator<Item = ActuatorConfig>,
    ) -> Result<Self, ActuatorError> {
        let configs = configs.into_iter().collect::<Vec<_>>();
        let state_backend = Arc::new(LocalStateBackend::new(
            global_candidate_in_flight,
            configs.iter().cloned(),
        )?);
        Self::with_state_backend(configs, state_backend)
    }

    pub fn with_state_backend(
        configs: impl IntoIterator<Item = ActuatorConfig>,
        state_backend: Arc<dyn StateBackend>,
    ) -> Result<Self, ActuatorError> {
        let mut actuators = BTreeMap::new();
        for config in configs {
            if config.concurrency == 0 || actuators.contains_key(&config.supply_id) {
                return Err(ActuatorError::InvalidConfiguration);
            }
            let entry = Arc::new(Actuator {
                probe_semaphore: Arc::new(Semaphore::new(1)),
                config,
            });
            actuators.insert(entry.config.supply_id.clone(), entry);
        }
        Ok(Self {
            state_backend,
            actuators: Arc::new(actuators),
        })
    }

    pub async fn try_acquire(
        &self,
        supply_id: &str,
        wait: Duration,
    ) -> Result<CandidatePermit, ActuatorError> {
        let admission = self.state_backend.try_acquire(supply_id, wait).await?;
        Ok(CandidatePermit {
            _admission: admission,
            state_backend: Arc::clone(&self.state_backend),
            supply_id: supply_id.to_owned(),
            breaker_failure_recorded: false,
        })
    }

    pub fn in_flight(&self) -> (usize, usize) {
        self.state_backend.in_flight()
    }

    pub fn candidate_acquisition_count(&self) -> usize {
        self.state_backend.candidate_acquisition_count()
    }

    pub fn snapshot(&self) -> ActuatorSnapshot {
        self.state_backend.snapshot()
    }

    pub fn circuit(&self, supply_id: &str) -> Result<CircuitSnapshot, ActuatorError> {
        self.state_backend.circuit(supply_id)
    }

    pub fn try_begin_probe(&self, supply_id: &str, now: Instant) -> Result<bool, ActuatorError> {
        self.state_backend.try_begin_probe(supply_id, now)
    }

    pub async fn run_startup_probe(
        &self,
        supply_id: &str,
        canonical_model_id: &str,
        authorization: Option<reqwest::header::HeaderValue>,
    ) -> Result<bool, ActuatorError> {
        self.run_probe_inner(
            supply_id,
            canonical_model_id,
            authorization,
            Instant::now(),
            true,
        )
        .await
    }

    pub fn finish_probe(&self, supply_id: &str, success: bool, now: Instant) {
        self.state_backend.finish_probe(supply_id, success, now);
    }

    pub async fn run_probe(
        &self,
        supply_id: &str,
        canonical_model_id: &str,
        authorization: Option<reqwest::header::HeaderValue>,
        now: Instant,
    ) -> Result<bool, ActuatorError> {
        self.run_probe_inner(supply_id, canonical_model_id, authorization, now, false)
            .await
    }

    async fn run_probe_inner(
        &self,
        supply_id: &str,
        canonical_model_id: &str,
        authorization: Option<reqwest::header::HeaderValue>,
        now: Instant,
        startup: bool,
    ) -> Result<bool, ActuatorError> {
        let began = if startup {
            self.state_backend.try_begin_startup_probe(supply_id, now)?
        } else {
            self.state_backend.try_begin_probe(supply_id, now)?
        };
        if !began {
            return Ok(false);
        }
        let actuator = self
            .actuators
            .get(supply_id)
            .ok_or(ActuatorError::UnknownActuator)?;
        let timeout = Duration::from_millis(actuator.config.probe_timeout_ms);
        let probe_permit = match tokio::time::timeout(
            timeout,
            Arc::clone(&actuator.probe_semaphore).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            _ => {
                self.state_backend
                    .finish_probe(supply_id, false, Instant::now());
                return Ok(false);
            }
        };
        let result = async {
            let health_path = actuator
                .config
                .health_path
                .as_deref()
                .ok_or(ActuatorError::InvalidConfiguration)?;
            let url = format!(
                "{}{}",
                actuator.config.base_url.trim_end_matches('/'),
                health_path
            );
            let client = build_redirect_free_client(Duration::from_millis(
                actuator.config.connect_timeout_ms,
            ))
            .map_err(|_| ActuatorError::InvalidConfiguration)?;
            let mut request = client.get(url);
            if let Some(authorization) = authorization {
                request = request.header(reqwest::header::AUTHORIZATION, authorization);
            }
            let response = request
                .send()
                .await
                .map_err(|_| ActuatorError::InvalidConfiguration)?;
            let status = response.status().as_u16();
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| ActuatorError::InvalidConfiguration)?;
                if body.len().saturating_add(chunk.len()) > actuator.config.probe_max_bytes {
                    return Err(ActuatorError::InvalidConfiguration);
                }
                body.extend_from_slice(&chunk);
            }
            validate_probe_response(
                status,
                &body,
                canonical_model_id,
                actuator.config.probe_max_bytes,
            )
        };
        let success = matches!(tokio::time::timeout(timeout, result).await, Ok(Ok(())));
        drop(probe_permit);
        self.state_backend
            .finish_probe(supply_id, success, Instant::now());
        Ok(success)
    }

    pub fn record_candidate(
        &self,
        supply_id: &str,
        failure: Option<CandidateFailure>,
        now: Instant,
    ) {
        self.state_backend.record_candidate(supply_id, failure, now);
    }
}

pub fn classify_candidate_result(
    status: Option<u16>,
    transport: Option<CandidateFailure>,
) -> Option<CandidateFailure> {
    if transport.is_some() {
        return transport;
    }
    match status {
        Some(401 | 403) => Some(CandidateFailure::Authentication),
        Some(500..=599) => Some(CandidateFailure::Server),
        _ => None,
    }
}
