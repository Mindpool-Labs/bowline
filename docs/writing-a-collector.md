# Writing a passive-event collector

Passive import stays off the request path and has no routing authority. It is bounded, offline
file import only: an operator (or a small script) writes a JSONL file and runs
`bowline import observations` against it. This document is for whoever writes that file — a
LiteLLM callback, an Envoy access-log formatter, or any other producer — and wants to check it
against the contract before wiring it into a real import run.

## The contract, in one sentence

Every line is one JSON object matching the canonical passive-event schema at
[`schemas/passive-event-v1.schema.json`](../schemas/passive-event-v1.schema.json); a **profile**
(`crates/bowline-gateway/src/profile.rs`) is an optional declarative map from your own JSON shape
onto that canonical schema, so you rarely have to emit the canonical shape directly.

## Two ways to validate offline

`bowline conformance` runs the exact same validation the real importer runs — the identical Rust
functions in `bowline-gateway`, not a reimplementation — and never writes anything (no config, no
policy, no registry, no ledger). It prints one JSON result to stdout and exits nonzero on the first
rejection.

**If your producer already emits the canonical schema directly:**

```sh
bowline conformance canonical --input canonical.jsonl
```

**If your producer emits its own shape and you have a profile mapping it:**

```sh
bowline conformance collector --profile profile.yaml --input producer.jsonl
```

Both print the same versioned result shape:

```json
{"result_version": 1, "accepted": 3, "error": null}
```

or, on the first rejection:

```json
{
  "result_version": 1,
  "accepted": null,
  "error": {
    "reason_code": "duplicate-event-id",
    "line": 4,
    "message": "producer.jsonl:4: duplicate event_id first seen at line 1, duplicated at line 4"
  }
}
```

`reason_code` is one of a fixed v1 vocabulary: `unsafe-input-path`, `unsafe-profile-path`,
`invalid-utf8-input`, `invalid-utf8-profile`, `input-too-large`, `profile-too-large`,
`line-too-large`, `event-count-exceeded`, `malformed-profile`, `forbidden-profile-pointer`,
`missing-required-target`, `duplicate-event-id`, and `invalid-event` (a malformed JSON line, or a
canonical-schema type/bounds violation). `line` is the 1-based source line for a per-event
violation, or absent for a whole-file violation (an oversized or unsafe input/profile path, or a
malformed profile). A passing result means this exact file would clear import's prevalidation
today, nothing more or less.

## Writing a profile

A profile is a small YAML document that never sees or forwards prompt, message, header,
credential, or body content — only the scalar fields it names:

```yaml
version: 1
kind: my-producer-v1
source_contract: my-producer-contract-v1
attribution_namespace: deployment
timestamp_unit: milliseconds
fields:
  event_id: /request_id
  observed_at_ms: /started_at_ms
  route: /route
  model: /model
  actual_supply_value: /deployment
  status: /status_code
  latency_ms: /latency_ms
  input_tokens: /usage/prompt_tokens
  output_tokens: /usage/completion_tokens
  dimensions.app: /metadata/app
constants:
  method: POST
  streamed: false
```

`fields` maps a canonical target to a JSON Pointer into your producer's own object shape;
`constants` sets a target to a fixed value instead, for producers that don't vary it per event
(most HTTP-only producers can hardcode `method: POST`). A target may appear in `fields` or
`constants`, never both. `timestamp_unit` (`milliseconds`, `seconds`, `microseconds`, or
`nanoseconds`) converts your producer's `observed_at_ms` source value to milliseconds; an overflow
during that conversion fails at profile load, before any event is read.

`event_id`, `observed_at_ms`, `method`, `route`, `status`, `streamed`, and `latency_ms` are
required: every profile must map or constant-fill all seven, or it fails to load
(`missing-required-target`). `model`, `actual_supply_value`, `input_tokens`, `output_tokens`, and
the `dimensions.*` targets are optional; when a mapped field is absent or null for a specific
event, the event still validates — coverage of that event is instead reduced downstream during
normalization (see [limitations](limitations.md)), which is a different, later concern from
contract validation.

`route` (whether mapped, constant, or produced by canonical input directly) must be an exact,
catalogued inference path with `method: POST`; there is no wildcard or prefix matching.
`actual_supply_value` requires `attribution_namespace` to be set, since the two together form the
canonical `actual_supply_ref`.

### Forbidden pointers

A field pointer may not target — by exact name or a normalized (case- and punctuation-stripped)
match — any prompt, message, content, tool-argument, request/response body, header,
authorization, token, API key, secret, cookie, password, raw URL, or credential-shaped segment,
anywhere in the pointer path. This is a static, structural check at profile-load time, not content
inspection: it cannot detect a secret or content value deliberately aliased under an innocuous
field name, so keeping the producer's own metadata fields free of secrets or content remains the
collector author's responsibility. The one exception is `input_tokens`/`output_tokens`, which may
point at fields literally named for token counts (for example `/usage/prompt_tokens` or
`/completion_tokens`) without tripping the generic `tokens` denylist entry.

## Bounds

The same compiled bounds apply to canonical input and profile-mapped input alike, and are shared
by import and `bowline conformance`:

| Bound | Limit |
|---|---|
| Whole input file | 16 MiB |
| Profile file | 256 KiB |
| Single JSONL line | 16 KiB |
| Events per file | 100,000 |
| `event_id` | 1–256 bytes |
| `method` | 1–16 bytes |
| `route` | 1–1,024 bytes |
| `model`, attribution namespace/value, each `dimensions.*` string | ≤256 bytes |

A file exceeding any of these is rejected as a whole-file or per-line violation before any event
is normalized or written; there is no partial or truncated acceptance.

## Duplicate semantics

`event_id` must be unique within one input file; the second occurrence is the rejection, reported
at its own line, naming the line the first occurrence appeared at. Cross-run deduplication is not
performed — running the same file, or an overlapping file, through import twice produces two
separate accepted runs. This is deliberate: passive import has no concept of an idempotency key
beyond one file's own contents.

## Atomicity

Both conformance modes and import's prevalidation are all-or-nothing over the whole input file:
the first rejection anywhere in the file is the only result reported, and nothing is written for a
rejected file. Import itself extends this further — even after prevalidation succeeds, a run that
cannot fully drain to the ledger is reported as incomplete rather than partially committed (see
[operations](operations.md)). Neither conformance mode writes anything at all, ever; they exist
purely to let a collector author check a file before handing it to import.

## Reference integrations

`integrations/litellm/` and `integrations/envoy/` each ship a profile and a synthetic fixture that
validate with `bowline conformance collector`. As their own READMEs state, the LiteLLM serializer
is tested only against Bowline synthetic callback objects, and Envoy verification covers
formatter, fixture, and profile key/type parity — neither is a live LiteLLM or Envoy integration
test, and neither is a universal or provider-native log schema.
