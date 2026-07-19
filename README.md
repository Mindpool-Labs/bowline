# Bowline

Bowline is the intelligence layer for enterprise AI. It turns task distribution into an evidenced
decision: which class of work runs on which supply, at what modeled cost, with what measured
quality.

**Routers move requests. Bowline decides where work belongs.**

The unit is the task, not the request. Bowline evaluates where each workload should run across
owned, VPC-hosted, and public supply using workload identity, policy, quality, economics,
sovereignty, and integrity-bound evidence.

Bowline can observe inline through its OpenAI-compatible listener or off the request path through
bounded, content-free observations imported from existing routers. Existing control planes,
schedulers, gateways, and model routers enact any decision or narrowly scoped authority they
receive.

Bowline v0.1 can deploy as a local OpenAI-compatible observation and evidence point. Without an
enforcement bundle it forwards requests to the configured upstream in shadow mode. Optional
controlled enforcement is limited to exact allowlisted Chat Completions and Responses workloads
with a fresh verified promotion grant. Startup never arms authority automatically or rewrites an
existing valid kill state.

## Status

v0.1.0-dev, licensed Apache-2.0. Repository verification covers the runtime, bounded evidence path,
integrity-aware report, and single-replica deployment. Shadow remains the
default; optional controlled enforcement is
explicit, evidence-bound, and limited to exact Chat/Responses routes. Missing, invalid, or
`bypass` kill state removes authority; each route then applies its configured pre-dispatch
`bypass` or `fail-closed` fallback. External
operational acceptance is not represented by repository tests.

The separate `bowline canary` workflow validates and runs bounded offline customer-quality cases
and renders integrity-bound advisory evidence. It does not share the serving request path or change
routing.

## Default shadow behavior

Without an `enforcement` bundle, Bowline v0.1 observes, accounts, and changes nothing. It forwards the request to the configured
upstream, records the policy and allocation decision it would have made, and renders a report from
the local ledger.

## Quickstart

Run the self-cleaning Docker smoke or point Bowline at your own OpenAI-compatible upstream:

```sh
./scripts/docker-smoke.sh
```

Full setup: [`docs/quickstart.md`](docs/quickstart.md).

## Command guide

### Decision evidence

| Command | Use it to |
| --- | --- |
| `bowline preflight` | Validate the local configuration before serving. |
| `bowline serve` | Start the v0.1 observation point in shadow mode or with an explicit enforcement bundle. |
| `bowline health` | Check the v0.1 serving component's local health endpoints. |
| `bowline report` | Render a report from local evidence. |
| `bowline import observations` | Import reviewed, content-free passive observations. |
| `bowline policy validate` | Validate a policy file and print its digest. |
| `bowline registry show` | Inspect the configured supply registry. |
| `bowline registry probe` | Probe configured local endpoints against the registry. |

See the [quickstart](docs/quickstart.md), [policy reference](docs/policy.md),
[registry reference](docs/registry.md), and [reporting contract](docs/reporting.md) for commands,
inputs, and expected output.

### Customer-quality canaries

| Command | Use it to |
| --- | --- |
| `bowline canary validate` | Validate the quality inputs without creating a run or calling an endpoint. |
| `bowline canary run` | Run an approved, bounded offline quality canary. |
| `bowline canary report` | Render or verify the resulting private quality report. |

See [customer quality evidence](docs/customer-quality.md) for the input, egress, and approval
requirements. This workflow does not share the serving request path.

### Actionable economics

| Command | Use it to |
| --- | --- |
| `bowline billing validate` | Validate canonical or mapped billing input locally. |
| `bowline billing import` | Import validated billing input into private local evidence. |
| `bowline economics validate` | Validate an analysis manifest and its named local evidence. |
| `bowline economics report` | Render a private, static economics analysis bundle. |

These commands operate on explicit local inputs and runs; they do not contact provider billing
systems. See [actionable economics](docs/actionable-economics.md).

### Controlled enforcement

| Command | Use it to |
| --- | --- |
| `bowline promotion seal` | Create the private local authorization sidecar from exact economics and quality evidence. |
| `bowline kill bypass` | Remove candidate authority before or during an incident. |
| `bowline kill arm` | Explicitly arm an eligible sealed authorization sidecar. |

Startup never arms authority automatically. `bowline promotion seal` does not arm the kill state,
start serving, or contact an actuator. See [controlled enforcement](docs/controlled-enforcement.md)
for the exact authority, fallback, and safe-start contract.

## Docs

- [`docs/quickstart.md`](docs/quickstart.md) - Docker smoke, real deployment, and offline import.
- [`docs/architecture.md`](docs/architecture.md) - logical stack placement and the current v0.1
  request, decision, writer, and evidence flows.
- [`docs/production-pov.md`](docs/production-pov.md) - execution and acceptance runbook.
- [`docs/configuration.md`](docs/configuration.md) - every configuration field and default.
- [`docs/policy.md`](docs/policy.md) and [`docs/registry.md`](docs/registry.md) - decision inputs.
- [`docs/reporting.md`](docs/reporting.md) - integrity and confidence contract.
- [`docs/operations.md`](docs/operations.md) - health, backup, restore, upgrade, bypass, rollback.
- [`docs/security.md`](docs/security.md), [`docs/threat-model.md`](docs/threat-model.md), and
  [`docs/limitations.md`](docs/limitations.md) - trust boundary and non-claims.
- [`docs/positioning.md`](docs/positioning.md) - layer ownership, system boundaries, current
  behavior, and supply neutrality.
- [`docs/neutrality-charter.md`](docs/neutrality-charter.md) - the binding neutrality commitments
  and how to verify them.
- [`docs/methodology.md`](docs/methodology.md) - floors, ratings provenance, confidence labels, TCO, sovereignty ratio.
- [`docs/customer-quality.md`](docs/customer-quality.md) - strict canary inputs, evaluators,
  content flow, bounds, statistics, verdicts, and non-claims.
- [`docs/actionable-economics.md`](docs/actionable-economics.md) - canonical billing input,
  reconciliation, opportunity arithmetic, static bundles, and financial non-claims.
- [`docs/controlled-enforcement.md`](docs/controlled-enforcement.md) - exact authority, fallback,
  kill, circuit, evidence, health, and failure contracts.
- [`examples/enforcement/validate-offline.sh`](examples/enforcement/validate-offline.sh) - offline
  structural validation of the synthetic killed example without endpoint contact.
- [`docs/bench.md`](docs/bench.md) - latency bench method and current localhost result.
- [`examples/ollama/`](examples/ollama/) - shadow-run against a local Ollama server (native and Docker).

## Behavior boundaries

Bowline evaluates workload-identity policy and records the resulting shadow decision. In shadow
mode it does not hold routing enforcement authority. It is not DLP. Policy binds to what a workload
*is* (key, route, app, tags), never to what a prompt *says*.

Inline attribution trusts only an explicitly configured response header from the configured
upstream and exact operator-reviewed `(namespace, value)` mappings. Offline passive import accepts
bounded, content-free JSONL through reviewed profiles and writes the same managed evidence format.
Passive import stays off the request path and has no routing authority. It is file import, not a
listener, collector, log tailer, or provider-native schema detector.

Quality evidence is similarly advisory. Operators explicitly choose the local input files,
configured candidate and optional judge endpoints, egress acknowledgments, bounds, and acceptance
criteria. Bowline persists content-free outcomes and a bound report, not the customer-controlled
case, expected, response, evaluator, or rubric content.

Controlled enforcement is a separate explicit route mode. It accepts authority only for one exact
allowlisted workload and fresh verified economics/quality grant. The grant must match the exact
active policy, registry source, owned-cost catalog, runtime task, application identity, and
canonical tags, and each request dispatches zero or one target.
Bowline never follows redirects, retries a completion, or falls back after a candidate attempt. One
deployment is one enterprise security domain.
