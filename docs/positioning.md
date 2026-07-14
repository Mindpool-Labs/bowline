# Positioning

## Where Bowline sits

Bowline is the intelligence layer for enterprise AI. It sits between the agent and workflow value
layer and the execution foundation, turning task distribution into an evidenced placement
decision: which class of work runs on which supply, at what modeled cost, with what measured
quality.

**Routers move requests. Bowline decides where work belongs.** Existing control planes, schedulers,
gateways, and model routers beneath Bowline enact the resulting decision or narrowly scoped
authority.

## Layer ownership

| Layer or input | Responsibility |
| --- | --- |
| Agent and workflow systems | Originate task intent and workload identity. |
| Bowline | Evaluate policy, quality, economics, sovereignty, and supply evidence to produce an evidence-bound placement decision or narrowly scoped authority. |
| Control-plane and routing systems | Reconcile, schedule, and route work according to the decision they receive. |
| Inference runtimes and hardware | Execute the selected work on the selected supply. |
| Cross-cutting evidence sources | Provide operator-controlled policy, measured quality, modeled economics, sovereignty, supply capability, usage, and outcome evidence. |

## The unit is the task

The unit is the task, not the request. A task class represents a repeatable class of enterprise
work with a configured quality floor. In the current release, Bowline maps an observed request to
the workload identity and configured task class, filters exact supply entries whose ratings do not
clear that floor, and records the deterministic placement decision it would make.

Task classes are operator-declared context associated with workload identity. Bowline does not
infer them from request content.

## Evidence before authority

Evidence before authority is a deliberate operator-controlled ladder:

1. **Shadow** observes the serving path and records the decision Bowline would make.
2. **Report** renders the bounded observation evidence for review.
3. **Canary** measures exact-supply quality in a separate bounded offline workflow.
4. **Economics** reconciles named local traffic, billing, and quality evidence into a static private
   bundle.
5. **Seal** binds one exact eligible workload and its verified economics and quality evidence into
   a private authorization sidecar.
6. **Arm** explicitly enables the sealed authority through the private kill state.

No step advances automatically, and a report, canary verdict, or economics bundle is not authority
to change serving. The offline economics workflow produces deterministic arithmetic over named
local inputs. Annualized values are disclosed extrapolations of past modeled deltas, not
predictions, accounting results, achieved outcomes, or authorization to change serving.

Controlled authority requires a separately configured exact grant that matches the active policy,
registry source, owned-cost catalog, runtime task, application identity, canonical tags, and exact
quality and economics evidence. Startup never seals or arms authority automatically, and it never
rewrites an existing valid kill state.

## What Bowline is not

Bowline is not an agent harness or inference runtime. It is not a router and does not replace
yours. Existing control-plane, routing, runtime, and hardware infrastructure executes Bowline's
decisions. Its present serving component is an integration and observation surface, not the
product category.

## Current v0.1 deployment

Bowline v0.1 can deploy as a local OpenAI-compatible observation and evidence point for configured
owned supply, VPC-hosted open weights, VPC frontier endpoints, and public APIs. It observes traffic
in shadow mode, evaluates the policy and supply decision it would make, accounts the result, and
reports the economics.

Without an enforcement bundle it observes, accounts, and changes nothing. Its separate offline
canary workflow can add exact-supply quality evidence for operator review, but neither a canary
verdict nor a shadow report changes a route. Optional controlled enforcement is limited to exact
allowlisted Chat Completions and Responses workloads and requires a fresh verified promotion grant
plus explicit operator arming.

## Content boundary

Bowline evaluates workload-identity policy and records the resulting shadow decision. In shadow
mode it does not hold routing enforcement authority. It is not DLP. Policy binds to what a workload
*is* (key, route, app, tags), never to what a prompt *says*.

## Served-path boundary

Bowline governs only the route where it is deployed. It does not control traffic paths it is not
serving. The current release has no content-classification or egress-tripwire capability.

## Supply treatment

Bowline uses a supply-agnostic schema: owned supply, VPC open weights, VPC frontier, and public API
entries all use the same registry shape, policy filters, ratings fields, and report labels.

Bowline publishes the formulas for floors, ratings, confidence labels, TCO, and sovereignty ratio.
Seeded feeds are illustrative inputs, not hidden authority.

The published methodology applies the same formulas to public APIs and owned supply and reports
insufficient evidence explicitly.
