# Customer quality evidence

Bowline v0.1 can run a bounded, operator-started canary over synthetic or customer-owned cases and
produce content-free evidence for one exact candidate supply. Quality canaries are an offline
foreground process and do not mirror or replay live traffic. They share no request path with
`bowline serve`.

Quality overlays are advisory evidence for one exact supply and do not mutate registry ratings,
rank candidates, promote, route, or enforce. Dataset representativeness, spend authorization,
governance approval, and quality acceptance remain external gates.

## Input files and strict schemas

`bowline canary validate`, `bowline canary run`, and verification-mode `bowline canary report`
consume a Bowline config plus three quality inputs. Bowline-owned manifest, request, evaluator, and
configuration structs deny unknown fields. Customer/domain-defined keys remain permitted inside
their bounded containers, including expected maps, embedded JSON Schema documents, function-tool
parameter schemas, and expected JSON values. Files must be regular non-symlink files, are read
through byte bounds, and are fully validated before a quality run is created.

`dataset.yaml` has exactly `version: 1`, `dataset_id`, `protocol`, `cases_file`, `task_class`, and
`policy_identity`. The protocol is `chat` or `responses`; `policy_identity` has `app` and optional
ordered `tags`. `cases_file` is one safe relative filename. Cases are JSONL in source order, each
with exactly `case_id`, `request`, and an `expected` map.

Dataset IDs, case IDs, evaluator IDs, expected-map keys, and function names use safe opaque ASCII
identifiers: 1 through 128 characters from `[A-Za-z0-9._-]`. Required IDs are unique. Candidate and
judge supply IDs are separate exact registry identifiers: the existing canary supply-ID validator
also permits `/`, and the ID must resolve to one registry entry. Do not put prompts, answers, people,
account numbers, or other customer content in identifiers; identifiers are persisted.

The dataset protocol selects one exact request schema:

- Chat accepts ordered `system|developer|user|assistant` messages with string content, optional
  function tools/choice, response format, finite temperature/top-p, positive completion-token cap,
  seed, and up to four stop strings.
- Responses accepts a string or ordered text-only input messages, optional instructions, function
  tools/choice, text format, `low|medium|high` reasoning effort, finite temperature/top-p, and a
  positive output-token cap.

Case requests cannot select a URL, headers, authorization, model, stream mode, cost, placement,
decision, or evidence. Image, audio, file, refusal, arbitrary content parts, provider extensions,
SSE, multimodal input, and Embeddings canaries are rejected or deferred. Bowline injects the exact
registry model and `stream:false`, and calls only OpenAI-compatible
`POST /v1/chat/completions` or `POST /v1/responses`. Provider-specific request bodies are not a v1
contract.

`evaluators.yaml` has exactly `version: 1` and an `evaluators` array. The strict variants are:

| Kind | Required fields | Result |
| --- | --- | --- |
| `exact-match` | `id`, `expected_key`, `required` | Exact Unicode string equality. |
| `normalized-match` | `id`, `expected_key`, `required` | NFKC, CRLF to LF, trim, and Unicode whitespace collapsed to one ASCII space; no case folding. |
| `regex` | `id`, `expected_key`, `required` | Bounded Rust Unicode regex; no look-around or backreferences. |
| `json-schema` | `id`, `expected_key`, `required` | Draft 2020-12 inline local schema; every `$ref` key is rejected. |
| `field` | `id`, `pointer`, `expected_key`, `required` | JSON Pointer existence and structural equality. |
| `tool-call` | `id`, `call_index`, two expected keys, optional `require_total_calls`, `required` | Ordered function name and parsed argument-object equality. |
| `latency-ceiling` | `id`, `max_ms`, `required` | Inclusive observed latency ceiling. |
| `cost-ceiling` | `id`, `max_usd`, `required` | Inclusive observed cost ceiling; unknown cost stays unknown. |

Text/regex evaluators require string expected values. JSON Schema requires an object. Field accepts
any bounded JSON value. Tool call requires a string name and object arguments. Missing candidate
text, invalid assistant JSON, missing pointer, malformed tool arguments, missing call, or comparison
mismatch is a quality failure. An evaluator engine failure is an error. Optional evaluator errors
are disclosed but non-gating; every required evaluator must execute and pass for the case to pass.
JSON object key order is ignored and array order is preserved.

`canary.yaml` has exactly `version: 1`, `candidates`, `runner`, `promotion`, and optional `judge`.
Each candidate has `supply_id`, an OpenAI-compatible `/v1` `base_url`, and
`authorization_env`. `runner` contains the explicit content acknowledgment, concurrency/request/
deadline/body/observed-token/observed-cost bounds, shutdown grace, and writer queue capacity.
`promotion` contains minimum sample/pass/Wilson floors, maximum error/p95 limits, and evidence age.

The optional judge has `supply_id`, `base_url`, `authorization_env`, safe relative `rubric_file`,
`required`, `send_customer_content: true`, score threshold, concurrency, timeout, and response-byte
bound. Its fixed prompt requires one assistant JSON object containing only a finite `score` from
0.0 through 1.0. Usage is required. A subjective judge is an explicitly configured model opinion,
not ground truth or cryptographic attestation.

## Content flow, endpoint egress, and retention

Candidate and judge endpoints receive transient customer-controlled content only when configured by
the operator. Candidate endpoints receive the selected case request. A judge endpoint receives the
case request, expected map, normalized candidate text, ordered normalized candidate tool calls, the
operator rubric, and a fixed system instruction. These values exist transiently in bounded process
memory and in the configured endpoints' security domains. Endpoint providers and surrounding
network/logging controls may retain them under their own policies.

Remote candidate egress requires `runner.send_customer_content: true`; loopback HTTP may use false.
Every judge requires its separate explicit `send_customer_content: true`. These flags acknowledge
egress; they are not governance approval, data-processing approval, representativeness review, or
spend authorization. Base URLs reject credentials and credential-like path/query material, remote
URLs require HTTPS, redirects are disabled, and authorization is read only from the named
environment variable. Environment values are bounded, CR/LF-rejected, sent as the complete
Authorization header, and excluded from normalized digests and output.

Persisted quality evidence contains no raw prompt, response, expected value, schema, regex, tool
arguments, rubric, or judge prose. It contains opaque IDs, exact supply/model/protocol/task class,
safe status/error codes, latency/token/cost measurements, evaluator/judge pass/fail/error facts, and
content/config digests. Content digests can expose low-entropy values through guessing, so manifests,
outcome ledgers, and reports remain private operator artifacts and must not be published casually.
Candidate normalized-config provenance and the separate judge model, rubric, template, normalized-
config, endpoint, and authorization-reference provenance use distinct versioned domain labels with
an ordered field count and length-prefixed fields. Authorization values are never digest inputs.

## Bounds and execution behavior

Compiled maxima include 64 KiB manifests and rubrics, 1 MiB evaluator/canary files and individual
cases, 16 MiB case files, 10,000 cases, 256 evaluators, 64 candidates, 128 messages, 64 tools,
512 KiB request/expected objects, 256 KiB text, 16 KiB regex, JSON depth 64, 10,000 JSON nodes,
4 MiB responses, concurrency 64, 10,000 planned candidate-plus-judge requests, one-hour wall time,
five-minute request timeout, and one-minute shutdown grace. Operator values can lower runner bounds.

Each candidate/case request and judge evaluation is dispatched at most once; Bowline does not retry.
Candidate and judge work form one in-flight chain under global, per-candidate, and judge semaphores.
The full candidate-plus-judge request count is reserved before execution. A candidate completion that
crosses a continuation threshold prevents new chains, while its already reserved judge may still
run. Requests already in flight can finish after a threshold is crossed.

Observed token and cost ceilings are continuation limits, not hard pre-dispatch currency
reservations. Exact response tokens and charges are unknown before execution. Known candidate and
judge usage/cost are accounted separately and together; unknown price or required usage produces an
unknown cost gate rather than zero. Wall expiry, cancellation, writer queue/append failure, missing
records, gaps, unhealthy writer, or an unclean manifest produces incomplete evidence and a nonzero
run result where applicable.

## Metrics, gates, and verdicts

Capacity uses every dispatched attempt for the exact candidate. Candidate-attributable timeout,
transport, disconnect, HTTP, oversized, or invalid-response outcomes enter the error numerator.
Only normalized responses with latency enter nearest-rank p95: sort ascending and select rank
`ceil(0.95 * n)`. Quality samples include cases with complete required evaluator/judge execution;
required failures are samples with zero pass, while required execution errors are insufficient
evidence. Pass rate is `passes / samples`.

The Wilson lower 95% bound uses `z = 1.959963984540054` over the observed pass count and sample
count. It is a binomial uncertainty bound for this exact dataset/candidate run, not proof that the
dataset covers production traffic. Minimum samples, pass-rate floor, Wilson floor, candidate error
ceiling, and p95 ceiling are operator criteria.

| Cost evidence | Cost gate |
| --- | --- |
| Every dispatched normalized candidate and configured judge has known usage/price or applicable owned TCO, and required cost evaluators pass | `pass` |
| A required cost evaluator exceeds its ceiling | `fail` |
| Any dispatched candidate or judge cost is unknown | `unknown` |

Completion verdict precedence is exact: policy failure, capacity failure, insufficient evidence,
unknown cost, quality/cost failure, then eligible. All blockers remain disclosed even when a higher
precedence verdict wins. The completion verdict is immutable. At report time, evidence older than
`max_age_ms` changes an otherwise eligible, quality-failed, or cost-unknown effective verdict to
insufficient evidence; it does not rewrite the completion verdict.

Freshness starts at completion. `valid_until_ms` is the checked sum of `completed_at_ms` and the
configured `max_age_ms`; evidence is fresh exactly at that boundary and stale only when the report's
`as_of_ms` is greater.

`quality-report.json` is a private mode-0600 completion artifact. Its domain-separated digest and a
domain-separated, sequence-sorted outcomes digest are bound once into the atomic run manifest.
Stored reporting recomputes both bindings before applying a requested current time. Verification
mode additionally requires current config, policy, registry, owned-cost, dataset, evaluator,
candidate, and judge provenance to match; it does not call an endpoint or rerun a canary.

## Commands and operator gates

Validate all local files without creating a run or calling an endpoint:

```sh
BOWLINE_CANARY_AUTHORIZATION='Bearer ...' \
BOWLINE_JUDGE_AUTHORIZATION='Bearer ...' \
bowline canary validate --config bowline.prod.yaml \
  --dataset examples/canary/dataset.yaml \
  --evaluators examples/canary/evaluators.yaml \
  --canary examples/canary/canary.yaml
```

After independent approval of content egress and spend, run in the foreground and render the bound
report:

```sh
bowline canary run --config bowline.prod.yaml \
  --dataset /reviewed/dataset.yaml --evaluators /reviewed/evaluators.yaml \
  --canary /reviewed/canary.yaml --json

bowline canary report --config bowline.prod.yaml --run-id UUID --json

bowline canary report --config bowline.prod.yaml --run-id UUID \
  --dataset /reviewed/dataset.yaml --evaluators /reviewed/evaluators.yaml \
  --canary /reviewed/canary.yaml
```

Before a real run, an operator must independently approve dataset ownership and representativeness,
endpoint data processing and retention, authorization handling, policy/registry/TCO effective dates,
maximum planned requests and possible in-flight overshoot, spend, operational window, acceptance
criteria, reviewers, and archive/retention. Repository tests and synthetic examples prove the
implementation contract, not those external decisions.
