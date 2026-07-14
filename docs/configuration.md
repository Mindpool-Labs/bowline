# Configuration reference

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
