# Operations

## Health and capacity

`/health/live` proves the process loop is serving. `/health/ready` is 200 only while durable
recording is configured and healthy. `/health/status` includes run ID, ready/shutdown state, queue
depth/capacity, accepted, recorded, dropped, truncated, unmapped, unpriceable, untrusted identity
header count, writer error, and last flush time. Do not expose status publicly.

Alert on readiness false, any drop, writer error, sequence gap, truncation, unmapped/unpriceable
growth, sustained queue depth, disk usage, upstream 502/504, and latency. Capacity is bounded by
`ledger_segment_bytes * ledger_max_segments`; stop before exhausting it. Phase 1 supports one
replica and one writer only.

## Start, stop, bypass, rollback

Run preflight before start. Send SIGTERM and wait at least `shutdown_grace_ms`; do not use SIGKILL
for planned changes. Remove traffic before stopping. Bypass by restoring the ingress's previous
direct upstream, then retain Bowline evidence. Roll back image/config/policy/registry as one reviewed
set, rerun preflight, and start a new run. Never edit an existing manifest or segment.

## Backup and restore

For a portable backup, stop cleanly and copy the entire evidence directory, including
`writer.lock`, all `run-*.json` manifests, and all named `.bwl` segments. A storage snapshot is
acceptable only when crash-consistent; expect an unclean manifest if taken live. Encrypt backups,
restrict access, record checksums, and test restoration into a separate directory.

Restore with Bowline stopped. Verify ownership/mode, run `bowline report --run-id` for every restored
run, and compare archived checksums. Do not merge directories or remove a manifest's segments.

## Rotation and upgrades

Evidence rotation is run-based: stop cleanly, archive the completed run, provision a fresh evidence
directory if retention requires it, and start a new run. The runtime never deletes old segments.
Before upgrades: export config/evidence, read the release changelog, run standalone CI and
Docker smoke, stage against an echo or canary upstream, then deploy with `Recreate`. Downgrades must
be tested against copied evidence; unknown schema versions are rejected.

## Incident handling

Preserve logs, manifest, segments, configuration inputs, binary/image digest, host time, and ingress
change history. Bypass first if serving is affected. Treat untrusted identity header counters as a
proxy-boundary signal and writer failures as evidence-integrity incidents. Follow
[security](security.md) for private reporting.

## Quality-canary operations

Keep canary execution off the serving path. Review and validate the complete local file set first,
record planned candidate-plus-judge requests, endpoint owners, retention terms, authorization
references, concurrency, wall/request deadlines, observed continuation thresholds, possible
in-flight overshoot, and an abort owner. Run one foreground process and monitor its summary; do not
wrap it in an automatic retry loop.

A nonzero run or an unclean/cancelled/unreconciled manifest is retained as incomplete evidence, not
resumed or converted to a pass. Preserve the whole `quality-runs/<run-id>/` directory and the exact
reviewed input files separately. Report only after digest validation. Re-run with a new run ID after
correcting a failure; do not edit an old report or ledger. Real endpoint execution, data-processing
approval, spend authorization, dataset review, and acceptance sign-off remain operator procedures.

## Billing and economics operations

Normalize provider data outside Bowline, review it for the exact `inference-usage-net` basis, then
run `billing validate` before `billing import`. Keep `billing-runs/` and economics bundle parents
mode 0700 on private storage; preserve mode-0600 files, whole directories, and source checksums.
Never edit a completed run or report. Define retention/deletion separately for source invoices,
billing evidence, quality evidence, and reports. Validate economics before creating its absent
output directory, and use a new directory for every revision. Failed or incomplete evidence is not
resumed or relabeled.

## Controlled-enforcement operations

Create the dedicated kill trust root as the effective user with mode 0700 and its regular state
file with mode 0600. Startup never arms or rewrites a valid kill state: an existing `armed` file
remains armed. Missing, invalid, or `bypass` state removes authority, and each route applies its
configured pre-dispatch `bypass` or `fail-closed` fallback. Startup does not create a promotion
authorization sidecar.

Keep the kill state at `bypass`, produce the exact economics and quality evidence, then seal each
authority route:

```sh
bowline promotion seal --config /etc/bowline/bowline.yaml --route support-chat
```

The seal command writes only the configured private local sidecar. It neither arms authority nor
contacts an actuator. Validate the policy, exact registry source, normalized owned costs, private
promotion evidence, sealed authorization, exact enforcement bundle, writer, kill state, and
bounded actuator probe with `bowline preflight`. A probe failure starts the actuator
circuit-open/degraded. Readiness stays true only when every active fail-closed route can safely
serve.

Arm only after reviewing exact workload/route/grant digests and aggregate health:

```sh
bowline kill bypass --enforcement /etc/bowline/enforcement.yaml
bowline kill arm --enforcement /etc/bowline/enforcement.yaml
```

The complete order is kill bypass -> produce evidence -> promotion seal -> preflight ->
organizational approval -> kill arm. A changed bound configuration or evidence input requires a
new sidecar while the kill state remains `bypass`; seal creation and preflight are not approval.

Monitor aggregate kill, grant freshness, circuit, admission, writer, bypass, failure, and
cancellation state. During an incident, set the kill state to bypass first. Each authority route
then applies its configured fallback: bypass routes call the original upstream once; fail-closed
routes remain local failures. Do not expect a candidate request to retry or switch upstream after
dispatch. Preserve the incomplete run and begin a new run after repair; authority never recovers
inside an incomplete run.
