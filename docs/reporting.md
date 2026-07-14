# Reporting and evidence

`bowline report --config PATH` reads only local evidence. With one run it selects that manifest;
with multiple runs it requires `--run-id`. Use `--json`, `--out PATH`, and
`--frontier-reference SUPPLY_ID` for automation. An incomplete manifest-backed report renders but
exits 2 unless `--allow-incomplete` is explicit.

```sh
bowline report --config bowline.prod.yaml --run-id UUID --out report.md
bowline report --config bowline.prod.yaml --run-id UUID --json --out report.json
```

## Integrity contract

A complete report requires clean segment recovery, clean shutdown, a healthy writer, no drops,
no missing sequences, no accounting truncation, and reconciliation of accepted and recorded work.
The Data Integrity section discloses run ID, accepted, recorded, dropped, missing sequences,
truncated, unmapped, unpriceable, recovery issues, and clean shutdown.

The Protocol Coverage section discloses supported and unsupported inference-record totals, counts
in deterministic protocol and coverage-status order, observation source, and whether coverage is
complete. Inline decision evidence supports OpenAI-compatible Chat Completions, Responses, and
Embeddings.

The Attribution section reports `static-configured`, `attributed`, `missing`,
`unknown-reference`, `ambiguous`, and `model-mismatch` counts separately for inline and passive
observation sources. It never emits attribution namespace/value pairs or attribution reasons.

The Provenance section reports present SHA-256 values or `absent` for normalized attribution
configuration, owned-cost catalog, combined passive profile/source contract, and exact passive
input bytes. Legacy manifests show these fields as absent. These digests are reproducibility
bindings, not signatures or proof of who produced the input.
Passive metadata is not cryptographically authenticated.

The authoritative [v1 inference-route catalog](architecture.md#v1-inference-route-catalog) lists
all 12 exact method/path contracts in catalog version 1. Catalogued routes outside the three
supported protocols are forwarded unchanged and recorded as `unsupported-protocol` coverage.
Malformed or unsupported request envelopes on one of the three supported routes are recorded as
`unsupported-shape` coverage with a reason.

Coverage-only records carry no placement recommendation and are excluded from cost, sovereignty,
arbitrage, unplaceable, mapping, and priceability calculations. The report discloses the gap and
remains incomplete for portfolio-wide conclusions; this is not described as data loss.
Administrative/non-inference routes such as models, files, batches, uploads, and vector-store
management are forwarded and are not counted as inference traffic. Routes absent from catalog
version 1 are forwarded and not included in the denominator; the authoritative table defines the
coverage claim.

Dropped work is never silently converted to zero cost. Unmapped records degrade affected cells;
unpriceable or missing usage prevents a verified cost claim. Accounting capture truncation leaves
downstream bytes unchanged but makes cost cells incomplete. Segment corruption or schema drift
stops at the readable prefix and is reported.

## Metrics and confidence

The report contains actual/shadow owned cost share, class cost shares, all-frontier
counterfactual, tier-arbitrage rows, and unplaceable decisions. Confidence is `observed`,
`declared`, `canary-verified`, or `unverified`; quality parity without canary evidence remains
unverified. Shadow savings metrics are counterfactual because shadow mode does not route
differently; they are not realized savings.

Archive the config, policy, registry, TCO, run manifest, every named segment, report, and source
version together. Reviewers should reject a PoV result without an integrity-complete run or an
explicitly documented exception. See [methodology](methodology.md) and the [PoV runbook](production-pov.md).

## Dedicated quality reports

`bowline canary report --config PATH --run-id UUID` reads the private quality manifest, framed
outcomes, and stored completion report. It recomputes the canonical outcomes and completion-report
digests bound into the manifest before applying current or explicit `--as-of-ms` freshness. An
unbound pre-quality-report run, altered report, altered outcome, missing sequence, or permissive/
nonregular report file is rejected.

Supplying all of `--dataset`, `--evaluators`, and `--canary` enables current-input verification. It
requires exact policy, registry, owned-cost, dataset, evaluator, candidate, endpoint, model, rubric,
template, and authorization-reference provenance. Supplying only some is an error. Verification
does not contact a candidate or judge and does not rerun evaluation.

The JSON/Markdown report discloses immutable completion and freshness-adjusted effective verdicts,
all gate states and blockers, sample/pass counts, pass rate, Wilson lower bound, p95 latency,
candidate error rate, separate candidate/judge cost totals, integrity state, and content-free
provenance. It is not merged into the passive economics report. Archive the private quality input
files under the operator's content controls and archive the quality run directory/report together;
do not publish them solely because raw content is excluded.

## Actionable-economics bundle

`bowline economics report` renders one canonical analysis into `report.json`, `report.md`,
`report.html`, `dimensions.csv`, `opportunities.csv`, `reconciliation.csv`, and `manifest.json`.
The manifest binds the six payloads and excludes itself. Cross-format totals, verdicts, blockers,
and ordering derive from the same model. Treat the directory as private financial evidence and
archive it with the exact traffic, billing, quality, config, policy, registry, and owned-cost inputs
named by its checksums. See [actionable economics](actionable-economics.md).

Both `report.json` and `manifest.json` carry the same bounded selected-evidence identity: explicit
traffic/billing run IDs with separate content, manifest, and recovery digests, plus ordered quality
run bindings with schema and manifest/outcomes/report/projection digests. Markdown and HTML include
the canonical report; CSV remains scoped to its named row family.

## Controlled-enforcement reports

Schema-v2 authority reports accept only descriptor-anchored validated run reads. JSON, Markdown,
HTML, and CSV derive independently from one fallible canonical model. They separate observed
enforced cost, enforced modeled delta, bypass, local fail-closed, candidate failure, downstream
cancellation, and shadow opportunity. Missing applicable actual cost or modeled delta makes only
that total unavailable; checked arithmetic failure stops publication. Incomplete diagnostic runs
may be rendered only with both financial aggregates withheld and the CLI exits 2 unless
`--allow-incomplete` is explicit.

Authority records are content-free and retain sanitized target/config identities rather than raw
URLs or authorization. They are modeled operational evidence, not provider-reconciled financial
results. Archive the private grant inputs, schema-v2 run, exact config/policy/registry/TCO, and
rendered report together.
