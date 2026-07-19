# Controlled enforcement

Controlled enforcement is an optional serving mode for narrowly scoped, operator-approved
allocation. Observe is the default when `enforcement` is absent. Observe and recommend routes send
the original request and body to the configured upstream; recommend may attach verified advisory
evidence but cannot select an actuator.

Allocation authority requires an exact allowlisted workload, rollout bucket, and fresh verified
promotion grant. Allocation authority is limited to OpenAI-compatible Chat Completions and
Responses. Embeddings remain observe/recommend-only with zero allocation authority. Authority never
transfers between protocols, tasks, workloads, routes, actual supplies, or promoted supplies.

## Route modes

Each strict version-1 enforcement route has one mode:

| Mode | Behavior |
| --- | --- |
| `observe` | Send the original request to the configured upstream and record the shadow decision. |
| `recommend` | Send the original request upstream and record a non-authoritative recommendation. |
| `canary-enforce` | Select the promoted actuator only for an exact eligible workload whose deterministic bucket is below `rollout_ppm`. |
| `enforce` | Select the promoted actuator for every exact eligible allowlisted request. |

`rollout_ppm` is an integer from 0 through 1,000,000. The canary bucket is a stable SHA-256 function
of the route ID, canonical workload identity digest, and request-body digest. `enforce` uses the
full 1,000,000 ppm. Selector tags are canonicalized, and missing, extra, duplicated, reserved, or
mismatched tags do not broaden authority.

## Promotion grant

An authority route names one promoted supply and binds one exact economics bundle/report and
opportunity, one quality run/report, and the current policy, registry, owned-cost, enforcement,
actuator, and route digests. Startup and preflight descriptor-safely verify those private inputs.
The eligible opportunity and quality evidence must match the workload, task, protocol, actual
supply, and promoted supply. Unknown cost, ineligible policy, unavailable capacity, stale or future
evidence, missing artifacts, digest mismatch, incomplete runs, or schema-v1 quality evidence make
the grant unavailable. Evidence does not renew or promote itself.

Every promoted Chat or Responses route names a bounded relative `authorization_path`. After the
economics and quality evidence has been produced, the operator seals the route while the kill state
is still `bypass`:

```sh
bowline promotion seal --config /etc/bowline/bowline.yaml --route support-chat
```

Run `bowline promotion seal --config <config> --route <route-id>` only after evidence generation and
while the kill state is `bypass`.
The command descriptor-safely reads the exact private inputs and exclusively creates the configured
mode-0600 sidecar beneath the effective-user-owned mode-0700 evidence root. It rejects an existing
output, unsafe path, symlink, wrong owner or mode, unsupported route, stale evidence, or any binding
mismatch. It does not arm the kill switch, probe an actuator, or start serving. Re-sealing requires
keeping `bypass`, deliberately removing the obsolete sidecar, and running the command again.

The authorization sidecar is a local descriptor-protected provenance seal, not a signature or
organizational approval.
It binds the exact normalized enforcement, route, actuator, workload, evidence, task, protocol, and
supply facts. Configuration without this independently loaded sidecar has no promotion authority,
and any bound semantic change invalidates an unchanged sidecar.

Preflight and serve independently load the sidecar, economics bundle, and quality run. Authority
requires exact equality with the active policy bundle, registry-source bytes, and normalized
owned-cost catalog.
They refuse authority when those active inputs differ from the sealed evidence, including a
semantically equivalent registry document whose source bytes differ.

Candidate selection requires exact runtime task, application identity, and canonical tag binding to
the route and verified grant.
Bowline resolves trusted identity, tags, and task once for both shadow and controlled selection.
An unresolved or invalid application identity has zero allocation authority and uses the configured
pre-dispatch fallback.
Reordered equivalent tags are canonicalized; duplicate, missing, extra, or reserved tags fail
closed. A trusted declared task overrides the current policy task only when it still exactly matches
the route and grant.

## Optional authority signing

The authorization sidecar can optionally require a standard, bring-your-own-key
[Minisign](https://jedisct1.github.io/minisign/) signature. This is off by default and does not
change the sidecar's binding semantics above; it adds one more precondition before a route's
promotion grant is trusted.

Configure it in the gateway config, never in the enforcement bundle:

```yaml
authority_signing:
  version: 1
  required: true
  verify_keys:
    - |
      untrusted comment: minisign public key <KEY-ID>
      <standard minisign public key, base64>
```

`verify_keys` names one or more standard minisign public keys in their usual two-line
`minisign.pub` format. Bowline never generates or holds a secret signing key; produce the
signature with the standard `minisign` tool (or any implementation of the format) as part of your
own promotion pipeline, after `bowline promotion seal` writes the authorization file:

```sh
minisign -Sm /etc/bowline/authorization/support-chat.json -s /path/to/signing.key
```

The resulting envelope is a small JSON document at the deterministic sidecar path
`<authorization_path>.signature.json` (for example
`authorization/support-chat.json.signature.json`), containing the envelope version, algorithm,
signing key id, a SHA-256 digest of the exact authorization bytes, and the complete `.minisig`
text:

```json
{
  "envelope_version": 1,
  "algorithm": "minisign-ed25519",
  "key_id": "<minisign-key-id>",
  "payload_sha256": "sha256:...",
  "minisign_signature": "<complete .minisig text>"
}
```

Verification recomputes the digest over the exact authorization bytes, decodes the standard
Minisign signature, and checks it against the configured `verify_keys` only; no key or key
identifier the envelope itself supplies is ever trusted. The envelope file is subject to the same
private-regular-file, no-symlink, and byte-bound safety checks as every other piece of evidence,
so an unsafe, oversized, or wrong-permission envelope retains ordinary startup refusal. Only two
outcomes are soft (the gateway keeps running and the route falls to its configured pre-dispatch
fallback with zero allocation authority, durably recorded): the envelope is absent when
`required: true`, or the envelope is present but does not verify (tampered payload or a key
outside `verify_keys`). With `required: false`, an absent envelope is legacy behavior — the grant
still requires every check described above, just not a signature.

A verifying signature attests only that the exact bytes of the sealed authorization file were
signed by one of the configured keys at some point. It does not attest that the underlying
economics or quality evidence is correct, current, or was produced honestly; that the signer was
authorized to promote this route; or that the sidecar's own binding checks (workload, task,
protocol, digests) still hold, since those are verified independently as described above. Signing
does not change the deployment trust boundary: promotion configuration, organizational approval,
and privileged administrators inside the deployment security domain remain trusted exactly as
without signing.

## Model authority

`model_authority: preserve` selects the configured pre-dispatch fallback unless the requested model
already resolves to the promoted supply. `rewrite-to-canonical` may replace only the unique
top-level JSON `model` string with the registry canonical model. Every other request byte is
preserved. Missing, duplicated, malformed, or over-limit model input invokes the configured
pre-dispatch fallback. Observe and recommend bodies are unchanged.

## Dispatch and fallback

A request is dispatched to zero or one upstream target. Bowline never follows redirects, retries a
completion, or falls back after a candidate attempt. Redirect responses from the configured
upstream, actuator, or health probe are returned or classified at that first target; their
`Location` is not contacted.

Pre-dispatch fallback is exactly `bypass` or `fail-closed`. `bypass` sends the original request once
to the configured upstream. `fail-closed` returns a stable local response with no upstream call.
Pre-dispatch `fail-closed` returns HTTP 503 with stable code `enforcement-fail-closed`.
Fallback is chosen before dispatch for a disabled or invalid kill state, missing/stale grant,
selector or bucket miss, pinned-model preservation, open/half-open circuit, failed health,
candidate saturation, reader/writer failure, or other candidate unavailability. After candidate
dispatch: A candidate timeout before response headers returns local HTTP 504; another candidate
dispatch failure before response headers returns local HTTP 502. A received candidate HTTP
response, including 401, 403, or 5xx, is returned as the first target response and is not rewritten
as a local failure. These responses still affect circuit classification. A candidate stream failure
after response headers terminates that stream without retry or fallback to the original upstream.

Every converted request first durably flushes a content-free schema-v2 decision. Candidate dispatch
requires the matching fresh handle and a second lifecycle/kill/grant check. If candidate evidence
cannot be flushed, the exact zero-authority replacement decision must be flushed before bypass or a
local fail-closed response. Final pre-dispatch authority loss first records `pre-dispatch-rejected`,
then durably records the exact configured `bypass` or `fail-closed` replacement before any fallback.
The linked replacement carries the same request, route, protocol, runtime task, optional
application, canonical tags, bucket, supplies, and enforcement digests as the rejected candidate.
If either terminal transition or replacement cannot be durably flushed, Bowline makes zero
dispatches.
Replacement evidence failure returns HTTP 503 with stable code `evidence-unavailable`. An incomplete
authority run cannot regain allocation authority.

## Kill switch, circuits, and bounds

The private kill file is exactly `armed\n` or `bypass\n` beneath a dedicated effective-user-owned
mode-0700 trust root. The trust root is an absolute bounded path without control characters; the
regular file is mode 0600. It is read through descriptor-relative
no-follow operations at every converted decision. Startup never arms it. Use:

```sh
bowline kill bypass --enforcement /etc/bowline/enforcement.yaml
bowline kill arm --enforcement /etc/bowline/enforcement.yaml
```

Startup never arms authority automatically or rewrites an existing valid kill state. An existing
strict private `armed` state remains armed; missing, invalid, or `bypass` kill state removes
authority and each route applies its configured pre-dispatch fallback, which can be `bypass` or
`fail-closed`. An unsafe, unreadable, malformed, or reader-unavailable state is invalid. Observe and
recommend still use the original target because they have no allocation authority.

Actuators start circuit-open until a bounded independent GET probe returns HTTP 200 with strict JSON
containing the canonical model ID. Probes carry no customer request data, use separate admission,
and do not follow redirects. Connect/header/stream failures, proven incomplete protocols, 5xx, and
401/403 count toward the volatile per-process breaker; other 4xx outcomes do not. During open and
half-open states customer requests use pre-dispatch fallback. Candidate admission acquires the
global bound before the per-actuator bound and holds both through the response stream. Saturation
uses pre-dispatch fallback.

## Evidence, reports, and health

Authority evidence is content-free and pairs every decision with one terminal outcome. It records
exact selection facts, intended and actual dispatch count, target, circuit transition, completion,
cancellation/failure class, and costs only when supported. It excludes request/response content,
authorization values, and raw endpoint URLs.

Enforced modeled delta is approved counterfactual cost minus observed actual cost over identical
complete token counts; unavailable evidence remains unavailable. Modeled enforced delta is available
only for a successful candidate HTTP 2xx response with observed complete token counts and both
approved rates.
The value can be positive, zero, or negative. Informational responses, redirects, every 4xx or 5xx,
timeouts, incomplete streams, bypass, fail-closed, cancellation, estimates, stale evidence, missing
cost, unpriceable evidence, and incomplete runs do not produce that value. Reports keep enforced
observed cost, enforced modeled delta, bypass, failure, cancellation, and shadow opportunity
separate.

Public health exposes aggregate writer/kill/mode/circuit/grant/admission state without route, app,
tag, supply, model, endpoint, or environment-reference details. A failed probe leaves a bypass-only
deployment ready/degraded, but an active fail-closed route on the unavailable actuator is unready.
Invalid configuration/evidence or writer failure is globally unready. Detailed sanitized route
diagnostics are local CLI output.

## Deployment boundary and safe start

One deployment is one enterprise security domain. Use this sequence: kill bypass -> produce
evidence -> promotion seal -> preflight -> organizational approval -> kill arm. Confirm aggregate
readiness and local diagnostics before arming. Neither the sidecar nor preflight constitutes
organizational approval. The synthetic
[killed example](../examples/enforcement/README.md) can be syntax-validated offline without
contacting any endpoint. It contains placeholders only and is not promotion evidence.

Controlled enforcement does not inspect prompt or response content, authenticate operator-supplied
billing inputs, establish dataset representativeness, approve spend, or establish realized savings.
Operator approval, traffic selection, evidence ownership, endpoint governance, network controls,
and production acceptance remain external.
