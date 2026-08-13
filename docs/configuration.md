# Configuration reference

## Routing and observe-only proposal configuration

`routing` configures a loopback-only advisory decision listener, named authorization environment reference, and bounded durable-state limits. `switchyard_observe` is optional and strict: version, decision API URL, profile ID, named authorization environment reference, 25 ms default timeout, exact capable/efficient backend IDs, bounded queue, and `remote_acknowledged`. Loopback HTTP is permitted; remote use requires HTTPS and acknowledgement. Neither section grants external allocation authority.

Bowline parses YAML with unknown fields denied. Relative paths resolve from the configuration file
directory. Run `bowline preflight --config PATH --json` before starting the production writer.

## Top-level fields

| Field | Required/default | Meaning and validation |
| --- | --- | --- |
| `listen` | required | IP socket address. A non-loopback address requires at least one trusted proxy CIDR. |
| `upstream` | required | Base HTTP or HTTPS URL for the unchanged serving path. URL userinfo and credential-bearing query parameters are rejected. |
| `actual_supply_id` | required, non-empty | Exact registry entry representing the upstream model and location. Serve and preflight require it to exist. |
| `policy_bundle` | required | Policy YAML path. |
| `registry_feed` | required | Registry JSON path. |
| `local_endpoints` | `[]` | Optional list of `{supply_id, url}` probes. Each `url` must expose `/v1/models`; `supply_id` identifies the intended registry entry. |
| `ledger_dir` | required | Writable evidence directory. Only one writer may hold it. |
| `tco` | absent | Optional owned-supply TCO YAML path. |
| `attribution` | absent | Optional strict version-1 exact-reference mapping for inline and passive attribution. |
| `enforcement` | absent | Optional path to a strict version-1 controlled-enforcement bundle. Absent means observe. |
| `floors` | built-in defaults | Optional map of task-class names to finite values from 0.0 through 1.0. |
| `trusted_proxy_cidrs` | loopback v4/v6 | Immediate peer CIDRs allowed to assert `x-bowline-app` and related identity headers. |
| `runtime` | defaults below | Bounded runtime and evidence settings. |

## Runtime fields

Every runtime value must be greater than zero.

| Field | Default | Meaning |
| --- | ---: | --- |
| `connect_timeout_ms` | 2000 | Upstream TCP/TLS connection timeout. |
| `response_header_timeout_ms` | 300000 | Maximum wait for upstream response headers; expiry returns 504. |
| `stream_idle_timeout_ms` | 300000 | Maximum gap between response body chunks. |
| `shutdown_grace_ms` | 30000 | Total managed-writer drain grace after HTTP shutdown. |
| `writer_queue_capacity` | 1024 | Bounded off-path decision-record queue. |
| `accounting_limit_bytes` | 2097152 | Maximum response bytes retained for accounting only; forwarding is not truncated. |
| `ledger_segment_bytes` | 67108864 | Target maximum bytes per segment, with complete-frame rotation. |
| `ledger_max_segments` | 32 | Maximum run segments; capacity exhaustion is disclosed and readiness fails. |

## TCO and floors

TCO fields are `monthly_amortization_usd`, `monthly_power_usd`, `monthly_ops_usd`, and
`monthly_capacity_mtok`. Costs must be finite and non-negative; capacity must be finite and positive.
See [methodology](methodology.md) for the formula and default quality floors.

Version-2 TCO keys each owned supply independently:

```yaml
version: 2
supplies:
  local/model-a:
    monthly_amortization_usd: 1200
    monthly_power_usd: 300
    monthly_ops_usd: 500
    monthly_capacity_mtok: 2000
```

The legacy unversioned shape prices only the exact configured `actual_supply_id` when it is owned.
It does not price other owned supplies reached through attribution.

## Attribution

`attribution.version` must be `1`. When the optional `attribution` block is present,
`response_header` is its required exact non-sensitive upstream response header used only for inline
evidence. `namespace` and each mapping `value` form an exact
operator-reviewed key; each `supply_id` must exist in the registry. Duplicate keys, unknown supply
IDs, empty/boundedness violations, and malformed header names fail configuration. An absent inline
header may use `actual_supply_id`; a present invalid, repeated, unknown, or model-mismatched value
never falls back. Passive events never use the legacy fallback.

## Example

```yaml
listen: 0.0.0.0:8080
upstream: https://gateway.example/v1
actual_supply_id: company/gpt-5-mini-us
policy_bundle: policies/production.yaml
registry_feed: registry/production.json
ledger_dir: /var/lib/bowline
trusted_proxy_cidrs: [10.0.0.0/8]
runtime:
  writer_queue_capacity: 4096
  ledger_segment_bytes: 67108864
  ledger_max_segments: 32
```

Never place credentials in `upstream`. Supply upstream credentials through the deployment's secret
mechanism rather than embedding them in a URL. Pass normal client authorization through Bowline.
Optional preflight authorization comes only from `BOWLINE_PREFLIGHT_AUTHORIZATION` and is never
printed.

## Canary configuration

Customer-quality configuration is a separate strict `canary.yaml`, not a top-level serving config
block. It contains `version`, one or more exact registry `candidates`, `runner`, `promotion`, and an
optional `judge`. Candidate and judge entries use `supply_id`, `/v1` `base_url`, and
`authorization_env`; secrets are full Authorization header values in the environment, never YAML.

Runner fields are `send_customer_content`, `concurrency`, `per_candidate_concurrency`,
`max_requests`, `max_wall_time_ms`, `request_timeout_ms`, `shutdown_grace_ms`,
`max_response_bytes`, `max_observed_tokens`, `max_observed_cost_usd`, and
`writer_queue_capacity`. Promotion fields are `min_samples`, `min_pass_rate`,
`min_wilson_lower_95`, `max_error_rate`, `max_p95_latency_ms`, and `max_age_ms`. Judge adds
`rubric_file`, `required`, its own `send_customer_content`, `score_threshold`, `concurrency`,
`request_timeout_ms`, and `max_response_bytes`.

All fields are required unless documented as optional, unknown fields fail, and operator values
must fit compiled maxima. See the fully synthetic [canary example](../examples/canary/canary.yaml)
and [customer-quality contract](customer-quality.md).

## Economics analysis manifest

Economics uses a separate strict analysis YAML. It names `traffic_run_id`, a forbidden/required
`billing_run_id` according to `mode`, explicit `quality_run_ids`, `as_of_ms`, one half-open window,
required request/token-count flags, ppm tolerances and coverage gates, maximum charge variance,
minimum duration and records, `annualize`, and `representative_window_acknowledged`. Ppm values are
integers from 0 through 1,000,000; at most 256 quality runs may be named; YAML is at most 64 KiB and
the window cannot exceed 31,556,952,000 ms. Unknown fields, duplicate run IDs, future evidence, and
inconsistent mode fields fail. See [actionable economics](actionable-economics.md).

## Enforcement bundle

The strict enforcement YAML contains `version`, `global_candidate_in_flight`, `kill_switch`,
`actuators`, and non-overlapping `routes`. The kill switch names an absolute bounded private
`trust_root` without control characters plus a bounded relative path. Each actuator names
`supply_id`, `base_url`,
`authorization_env`, authority-required `health_path`, connect/header/stream/probe timeouts,
concurrency, probe byte bound, consecutive-failure threshold, and cooldown. Remote URLs require
HTTPS; loopback HTTP is accepted. A non-loopback HTTPS `base_url` additionally requires the
optional `remote_acknowledged: true` field as an explicit operator opt-in; it defaults to `false`,
so a config that omits it fails closed instead of silently trusting a remote actuator. Authorization
values remain outside YAML.

Routes name exact `route_id`, method, path, protocol, optional workload, mode, `rollout_ppm`, and
authority-only actual/promoted supply, task class, `model_authority`, `fallback`, and `promotion`.
Promotion binds economics bundle/report/opportunity, quality run/report, policy, registry,
owned-cost, age, and expiry. Authority routes require exactly one workload selector and support
only Chat Completions or Responses. See the [full contract](controlled-enforcement.md) and the
[synthetic killed example](../examples/enforcement/README.md).

## Advisory routing and Switchyard

Enforcement version 1 has no routing fields and rejects them. Version 2 adds non-empty
`routing_profiles` (at most 64) and an optional `routing_profile_id` on Chat Completions or
Responses routes. Routing does not add an actuator, promotion, or authority. In `observe` and
`recommend`, the original target remains the dispatch target. In `enforce` or `canary-enforce`,
only already-valid promotion authority can permit an efficient dispatch.

`routing` starts a separate loopback-only decision listener only while the serving runtime is
active. Its complete version-1 fields are `version`, `listen`, `authorization_env`,
`max_active_tasks`, `segment_bytes`, and `max_segments`. `max_active_tasks` is `1..=16384`;
without a `routing` section its default is 1024. `segment_bytes` and `max_segments` are positive
and cannot exceed compiled ledger limits; their no-section defaults are normal runtime limits
(1048576 bytes and 16 segments). Routing state is a private, exclusive-writer, CRC-checked durable
prefix under the ledger directory. It survives activation and takeover. It is not a distributed
coordinator or a volatile cache. A listener stops before lease-loss state drain; a standby does not
bind or write routing state.

The decision API accepts only `POST /v1/routing/decision`, exactly one `Authorization` header
whose byte value equals the value named by `authorization_env`, and JSON no larger than 65536 bytes.
Its grammar is `schema_version: 1`, bounded `route_id`, bounded `task_id`, unsigned decimal
`step_id`, and `signals`, an array of enumerated routing signals. A successful response names the
version, opaque decision ID, route and profile digest bindings, task-reference digest, step,
target, selected supply ID, deterministic reason, state digest, and `authority`. Errors are 400
`invalid_request`, 401 `unauthorized`, 404 `unknown_route`, 409 `step_conflict`, 413
`body_too_large`, and 503 `routing_unavailable`. A 503 retains a typed cause:
`missing-metadata`, `untrusted-metadata`, `malformed-metadata`, `step-conflict`,
`capacity-exhausted`, `state-corrupt`, `writer-failure`, or `startup-unavailable`.

Trusted inference metadata is one `x-bowline-task-id`, one decimal `x-bowline-step-id`, and one
`x-bowline-agent-signals` value. Task IDs use the bounded identifier grammar; signals are a JSON
array of the same enumerated routing signals accepted by the decision API. These
headers are accepted only from a configured trusted immediate peer and are stripped before upstream
forwarding. Missing, untrusted, malformed, conflicting, capacity-exhausted, corrupt, writer-failed,
or unavailable routing retains the capable/original target. Schema-v3 authority decision and
outcome evidence binds either the durable routing decision or that unavailable cause and source.

`switchyard_observe` is optional. Its complete version-1 fields are `version`,
`decision_api_url`, `profile_id`, `authorization_env`, `timeout_ms`, `capable_backend_id`,
`efficient_backend_id`, `observation_queue_capacity`, and `remote_acknowledged`. Backend and
profile IDs are bounded and the backend IDs differ. `timeout_ms` defaults to 25 and is
`1..=1000`; `observation_queue_capacity` is `1..=1024`; `remote_acknowledged` defaults to
`false`. HTTP is valid only for a loopback IP literal; a remote endpoint needs HTTPS and
`remote_acknowledged: true`. For a committed routed decision only, the outbound JSON has exactly
`schema_version`, routing `task_ref` digest, `protocol`, `step_id`, and enumerated `signals`.
The native target and the adapter version, profile version, and configuration digest are local
telemetry only. The public health
record never includes a profile ID or profile digest. The adapter disables redirects, bounds a successful response
before parsing, and emits bounded local adapter version, profile version, configuration digest,
targets/agreement/latency/error aggregates. It does not retain a profile-ID digest, request content,
credentials, endpoint text, or raw routing identifiers in telemetry. Switchyard is observe-only: it cannot change
plan, authority, target, dispatch, fallback, kill state, or the native request result.
