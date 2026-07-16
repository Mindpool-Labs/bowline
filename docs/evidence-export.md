# Evidence export

Bowline exposes a versioned local-filesystem projection for dashboards and other read-only
consumers:

```sh
bowline export evidence \
  --config /etc/bowline/bowline.yaml \
  --run-id <run-id> \
  --out /private/path/evidence.json
```

`--run-id` is required. The configuration supplies the evidence root, policy, exact registry
source, attribution mapping, owned-cost inputs, and quality floors used to reproduce the selected
run-scoped report. Policy, registry, attribution, or owned-cost digest drift is a hard failure, and
Bowline does not create the output file on validation failure.

## V1 scope

Evidence schema version 1 exports one schema-v1 shadow or passive observation run. It does not
export authority-bearing schema-v2 records, promotion grants, approval material, or actuator
authorization. Controlled-enforcement evidence retains its existing diagnostic report surface
until a separate public export contract is specified.

The published schema is
[`schemas/evidence-bundle-v1.schema.json`](../schemas/evidence-bundle-v1.schema.json). Within one
major evidence schema version, compatibility changes are additive only. Consumers must select the
major version they support and reject an unknown `evidence_schema_version`.

## Bundle contract

The top-level object contains:

- `generated_from`: the selected run ID, registry feed version, and bound policy, registry,
  attribution, owned-cost, passive-profile, and passive-input digests.
- `disclosure`: overall completeness, stable integrity warnings, coverage gaps, and the complete
  confidence legend.
- `runs`: exactly one public run projection.
- `decisions`: allowlisted `EvidenceDecisionV1` rows.
- `coverage`: the exact run report protocol-coverage section plus per-decision coverage status.
- `aggregates`: the exact serialized `ShadowReport` returned by the run report computation. Export
  does not implement a second accounting or aggregation path.

The public run projection contains only schema/run identity, time bounds, clean-shutdown state,
accepted/recorded/dropped/truncated/unmapped/unpriceable counters, the optional records digest, and
segment count. It excludes segment filenames, filesystem paths, writer errors, endpoint values,
and configuration values.

Each public decision always contains the same fields:

```json
{
  "decision_ref": "fixture-run:1",
  "sequence": 1,
  "observed_at_ms": 1783785600123,
  "protocol": "responses",
  "observation_source": "passive",
  "coverage_status": "supported",
  "coverage_reason": null,
  "task_class": "mechanical",
  "actual_supply_id": "supply/actual",
  "shadow_supply_id": "supply/selected",
  "actual_est_cost_usd": 0.001,
  "shadow_est_cost_usd": 0.0004,
  "policy_exposure": "compliant"
}
```

`decision_ref` is derived only from the selected run ID and durable sequence. The source request or
decision ID is never exported. Nullable values remain explicit JSON `null`; fields are not omitted
conditionally.

## Projection and disclosure boundary

The export may disclose configured supply IDs because they are the public placement keys used by
the report. It does not serialize raw workload identity, routes, applications, tags, API-key
digests, upstream URLs, provider model identifiers or aliases, attribution references, prompts,
responses, headers, authorization values, local paths, or raw `DecisionRecord` objects.

`disclosure.complete` matches the embedded report. `integrity_warnings` names run/writer,
drop/sequence, truncation, mapping/priceability, recovery, or record-count conditions without
including source content. `coverage_gaps` summarizes non-supported coverage status and recorded
coverage reasons. Every rendered aggregate therefore has one source in the bundle and retains its
original confidence label.

The command reads local files only and adds no listener or network service. Output is published
atomically as a mode-0600 regular file.
