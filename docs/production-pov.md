# Production PoV runbook

This runbook first produces decision-grade shadow evidence. A separately approved controlled phase
may then grant exact, bounded Chat/Responses authority. Agree on the window, traffic scope,
integrity threshold, cost inputs, reviewers, and sign-off owner before deployment.

## Entry criteria

- One reviewed upstream and matching `actual_supply_id`.
- Reviewed policy, registry, quality floors, and optional TCO with named owners and effective dates.
- A single replica, a durable evidence volume sized from the configured segment bounds, and tested
  backup/restore.
- An ingress path whose immediate proxy CIDRs are known; no direct ungoverned access for in-scope
  clients during the observation window.
- Application logs and provider invoice data available for independent reconciliation.

## Execute

1. Build from a recorded commit and record image digest, configuration digests, host, and time.
2. Run `bowline preflight --config bowline.prod.yaml --json`; all eight stable checks must pass.
3. Start exactly one `bowline serve --config bowline.prod.yaml` process.
4. Confirm `bowline health --url http://127.0.0.1:8080/health/ready` prints `ready`; capture
   `/health/status` without publishing sensitive infrastructure details.
5. Shift only the agreed route, beginning with low-risk traffic. Compare response status, headers,
   body bytes, streaming completion, application errors, and upstream totals.
6. Watch readiness, queue depth, accepted/recorded/dropped/truncated/unmapped/unpriceable counters,
   disk capacity, upstream 502/504 rates, and p95 latency.
7. At the agreed end, remove traffic and send SIGTERM. Require exit 0 and clean shutdown.
8. Render the selected run with `bowline report --config bowline.prod.yaml --run-id UUID`.
9. Archive the full evidence bundle described in [reporting](reporting.md).

## Acceptance checklist

- No material response-semantic regression; streaming and non-streaming paths match the upstream.
- Added p95 proxy latency is below the agreed budget; the reference gate is less than 5 ms on the
  deterministic localhost path.
- Report says `Complete: true`; accepted equals recorded; dropped, missing, truncated, and recovery
  issues are zero; every known upstream model is mapped and priceability exceptions are explained.
- Actual request totals reconcile with application/provider sources for the same window.
- Policy and registry decisions are reviewed by security, platform, finance, and workload owners.
- Counterfactuals are labeled with their confidence and are not presented as realized savings.
- Bypass, rollback, evidence restoration, and the next-run change list are exercised and signed.

## Abort and rollback

Bypass Bowline at the ingress if readiness fails, proxy errors rise, latency breaches the agreed
threshold, evidence storage approaches its bound, or response parity fails. Keep the failed run
manifest and segments. Do not restart into the same logical run; correct the cause, rerun preflight,
and start a new run. See [operations](operations.md).

External completion requires real production traffic and reviewer signatures. Repository tests and
the Docker smoke prove readiness to run the PoV, not external operational acceptance.

## Optional offline quality evidence

An operator may add a separately approved canary run to the PoV evidence bundle. Before execution,
name the dataset owner, representativeness reviewer, endpoint/data-processing approver, spend owner,
quality thresholds, judge status, and acceptance signer. `bowline canary validate` must pass before
the run directory exists. The completed `bowline canary report` must be digest-bound, reconciled,
fresh for the review date, and interpreted only for its exact candidate and dataset.

An eligible advisory verdict is not deployment authorization and does not change the serving-path
acceptance checklist. Incomplete, stale, unknown-cost, or failed quality evidence stays disclosed;
operators decide whether it blocks the external PoV.

## Optional reconciled economics evidence

After the observation run is complete, an operator may normalize a matching billing export and run
`bowline billing validate` followed by `bowline billing import`. Name exact traffic, billing, and
quality run IDs in a reviewed analysis manifest. Require `bowline economics validate` to finish
before publishing a new private directory with `bowline economics report`. Review exact period
tiling, count/ppm gates, source checksums, exceptions, blocker codes, and cross-format parity.

An eligible row is still an advisory counterfactual. Finance owns source classification and
reconciliation acceptance; workload owners own representativeness; security owns retention and
access; governance owns any later serving decision. Bowline makes none of those approvals.

## Optional controlled phase

Do not configure authority until the shadow, quality, and economics evidence above is complete and
reviewed. Create a strict exact route grant, keep its private kill file at `bypass`, and require
preflight to validate every digest/source plus one bounded actuator probe. Confirm the workload
allowlist, deterministic ppm, pinned-model rule, candidate bounds, fallback mode, expiry, and local
operator diagnostics. A failed probe, stale grant, unsafe kill file, or writer failure must retain
the documented bypass/fail-closed result.

Begin with a bounded `canary-enforce` ppm only after organizational approval and `bowline kill arm`.
Re-run byte/status/stream checks, reconcile schema-v2 decisions and terminals, and monitor aggregate
kill/circuit/grant/admission/writer health plus bypass, failure, cancellation, and modeled-delta
counts. Abort with `bowline kill bypass`; a fail-closed route remains fail-closed when authority is
removed. A candidate attempt never retries or reaches the original upstream afterward.

Repository verification does not approve a grant, endpoint, dataset, economics input, route,
security boundary, or production result. Record external acceptance and any exception separately.
