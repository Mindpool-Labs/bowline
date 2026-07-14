# Bowline Quickstart

Bowline v0.1 defaults to shadow observation. It receives OpenAI-compatible traffic, forwards it to
the configured upstream, accounts the request in a local ledger, and renders a report. Optional
controlled enforcement is configured separately after verified evidence and explicit arming.

This quickstart has four tracks:

- Track A: Docker Compose example loop with the built-in echo upstream.
- Track B: Real deployment pointed at your provider, LiteLLM, or local OpenAI-compatible gateway.
- Track C: Offline import of reviewed, content-free LiteLLM or Envoy JSONL.
- Track D: Offline validation of the synthetic quality canary contract.

For offline structural validation of the synthetic killed enforcement contract, use the
[shipped validator](../examples/enforcement/README.md) and review the
[controlled-enforcement contract](controlled-enforcement.md).

Controlled enforcement is not activated by configuration or startup. Its order is kill bypass ->
produce evidence -> promotion seal -> preflight -> organizational approval -> kill arm. After the
exact economics and quality evidence exists and every promoted route has a bounded relative
`authorization_path`, create the private local seal with:

```sh
cargo run -p bowline -- promotion seal \
  --config bowline.prod.yaml \
  --route support-chat
```

The command refuses stale or mismatched evidence and an existing sidecar. It does not probe or send
traffic. Run `bowline preflight` after sealing, and keep the kill state at `bypass` until the
deployment's separate approval is complete.

## Track A: Verified container loop

Prerequisites: Docker with Compose v2.

The production smoke builds the pinned minimal images, runs preflight, sends normal, identified, and
streaming traffic, drains with SIGTERM, renders an integrity-complete report, verifies zero drops,
and removes its volume:

```sh
./scripts/check-deployment.sh
./scripts/docker-smoke.sh
# deployment contract: PASS
# docker smoke: PASS (3 accepted, 3 recorded, 0 dropped)
```

For an inspectable long-running example, use `docker-compose.production.yml`, but run
`bowline preflight` before `bowline serve`; preflight intentionally refuses an evidence directory
already locked by the production writer.

## Track B: Real Deployment

Prerequisites:

- A provider, LiteLLM, local model server, or other OpenAI-compatible upstream.
- A policy bundle that maps workload identity to allowed supply.
- A registry feed with the supply entries and prices you want reports to use.
- Optional TCO inputs for owned supply.

Create a deployment config:

```sh
cp bowline.example.yaml bowline.prod.yaml
```

Edit `bowline.prod.yaml`:

```yaml
listen: 0.0.0.0:8080
upstream: http://127.0.0.1:4000
actual_supply_id: company/upstream-model-location
policy_bundle: policies/default.yaml
registry_feed: registry/feed.json
ledger_dir: ./ledger-prod
tco: tco.example.yaml
```

Validate the policy:

```sh
cargo run -p bowline -- policy validate policies/default.yaml
```

Show the registry the report will use:

```sh
cargo run -p bowline -- registry show --config bowline.prod.yaml
```

Probe configured local endpoints, if you add `local_endpoints` to the config:

```sh
cargo run -p bowline -- registry probe --config bowline.prod.yaml
```

Run the bounded production preflight. If the upstream needs credentials for `/v1/models`, set the
environment variable only for this command:

```sh
BOWLINE_PREFLIGHT_AUTHORIZATION='Bearer ...' \
  cargo run -p bowline -- preflight --config bowline.prod.yaml --json
```

Run Bowline in shadow mode:

```sh
cargo run -p bowline -- serve --config bowline.prod.yaml
```

From another terminal:

```sh
cargo run -p bowline -- health --url http://127.0.0.1:8080/health/ready
# ready
```

Point one route at Bowline and keep the upstream unchanged. For the first week, keep Bowline in
front of low-risk traffic and compare the report to your provider invoice and application logs.

Generate a Markdown report:

```sh
cargo run -p bowline -- report --config bowline.prod.yaml --out bowline-report.md
```

Generate a JSON report:

```sh
cargo run -p bowline -- report --config bowline.prod.yaml --json --out bowline-report.json
```

Choose the all-frontier reference explicitly when your registry has several public API entries:

```sh
cargo run -p bowline -- report \
  --config bowline.prod.yaml \
  --frontier-reference openai/gpt-5.5 \
  --out bowline-report.md
```

For production cutover, keep policy subjects on workload identity: API key digest, route, app, and
tags. Do not write policy that depends on prompt or response text; Bowline v0.1 does not inspect
content for policy decisions.

Follow the complete [production PoV runbook](production-pov.md) for traffic shift, integrity
acceptance, archive, bypass, and reviewer sign-off.

## Track C: Offline passive import

Passive import stays off the request path and has no routing authority. First configure exact
attribution rules in `bowline.prod.yaml`; the namespace must match the reviewed profile:

```yaml
attribution:
  version: 1
  response_header: x-upstream-deployment
  namespace: deployment
  mappings:
    - value: deployment-a
      supply_id: company/model-a-region
```

Generate JSONL only with the reviewed contracts under `integrations/`. For LiteLLM, wire
`integrations/litellm/bowline_callback.py` as an operator callback and write its serialized output;
it is not a parser for arbitrary LiteLLM logs. For Envoy, install the exact typed-JSON formatter and
explicitly populate the documented dynamic metadata; Envoy does not derive LLM usage itself.

Import a regular file after inspecting it for content or secrets:

```sh
cargo run -p bowline -- import observations \
  --config bowline.prod.yaml \
  --profile integrations/litellm/profile.yaml \
  --input /reviewed/litellm-observations.jsonl

cargo run -p bowline -- import observations \
  --config bowline.prod.yaml \
  --profile integrations/envoy/profile.yaml \
  --input /reviewed/envoy-observations.jsonl \
  --json
```

The command prevalidates the bounded profile and entire bounded input before creating a run. Source
line order determines ledger sequence; timestamps are preserved. Duplicate event IDs within the
file fail atomically. Cross-run duplicate suppression is not performed.

## Track D: Synthetic quality validation

The tracked `examples/canary/` files are synthetic contract examples, not production evidence. The
candidate is loopback and the optional judge is an illustrative OpenAI-compatible HTTPS endpoint.
Validation requires placeholder Authorization header values but performs no network call and creates
no run:

```sh
BOWLINE_CANARY_AUTHORIZATION='Bearer synthetic-candidate' \
BOWLINE_JUDGE_AUTHORIZATION='Bearer synthetic-judge' \
cargo run -p bowline -- canary validate \
  --config bowline.example.yaml \
  --dataset examples/canary/dataset.yaml \
  --evaluators examples/canary/evaluators.yaml \
  --canary examples/canary/canary.yaml
```

Do not run the example against a real endpoint as an acceptance test. For reviewed operator-owned
files, use `bowline canary run` only after content-egress, retention, representativeness, spend, and
acceptance approvals. Render with `bowline canary report --config bowline.prod.yaml --run-id UUID`;
add all three input flags for offline provenance verification. See
[customer quality evidence](customer-quality.md).

## Synthetic billing validation

The tracked canonical JSONL and mapped CSV are synthetic and validate offline without creating a
run:

```sh
cargo run -p bowline -- billing validate --config bowline.example.yaml \
  --billing examples/billing/canonical.jsonl
cargo run -p bowline -- billing validate --config bowline.example.yaml \
  --billing examples/billing/mapped.csv --mapping examples/billing/mapping.yaml
```

Import reviewed private input with `bowline billing import`, then replace the explicit synthetic
run IDs in `examples/economics/analysis.yaml` with completed local runs. Run
`bowline economics validate --config bowline.prod.yaml --analysis analysis.yaml` before
`bowline economics report --config bowline.prod.yaml --analysis analysis.yaml --out-dir PATH`.
The output path must not exist. See [actionable economics](actionable-economics.md).
