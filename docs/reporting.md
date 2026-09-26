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

### Modeled context reprocessing

`bowline report --authority-manifest <manifest> --reprocessing <file>` adds an optional
`reprocessing` section to the controlled-enforcement report. Without `--reprocessing`, the report
has no such key and its bytes do not change. The flag is valid only with `--authority-manifest`.
The input file is strict YAML, at most 65536 bytes, with no unknown fields. A synthetic example is
at `examples/enforcement/reprocessing.yaml`:

| field | meaning | valid range |
|---|---|---|
| `schema_version` | input format version | `1` |
| `steady_cache_hit_ppm` | share of a non-switch step's input that the model reads from cache | 0 to 1000000 |
| `targets.capable`, `targets.efficient` | prices of the model behind each routing target | both required |
| `input_per_mtok_usd`, `output_per_mtok_usd` | list price per million tokens | finite, 0 to 1e9 |
| `cache_read_ppm` | cache-read price as a fraction of the input price | 0 to 1000000 |
| `cache_write_ppm` | cache-write price as a fraction of the input price | 1000000 to 4000000 |

The section covers authority outcomes that carry a routing decision. It groups them by task
reference and step, and prices each step at the model that served it: `Candidate` is efficient
and `Original` is capable. An outcome that never reached a model, because the candidate was
rejected before dispatch or the route failed closed, is left out and counted in
`excluded_undispatched_steps`. A replacement dispatch counts as the step it replaced: it has no
routing binding of its own, so the section links it through `replaces_decision_id`. It reports `manifest_digest`, `status`, `tasks`, `routed_steps`,
`cold_steps`, `switch_steps`, `steady_steps`, `switches_to_efficient`, `switches_to_capable`,
`excluded_undispatched_steps`, `reprocessing_cost_micros`, `cache_adjusted_enforced_cost_micros`,
`cache_adjusted_counterfactual_cost_micros`, and `cache_adjusted_delta_micros`. The delta is
counterfactual minus enforced, serialized as a decimal string. `manifest_digest` is a
domain-separated SHA-256 of the validated manifest values, serialized as canonical JSON. It does
not cover the file bytes: two files that differ only in comments or layout have the same digest.

`status` is `available` or `incomplete`. It is `incomplete` when the run is incomplete, or when
any dispatched routed outcome has no input or output token count. An incomplete section keeps its counts and
sets every cost field to `null`; it never shows a partial total. Checked arithmetic overflow stops
report construction. Markdown and HTML show the section, labeled modeled, with the manifest digest.
CSV does not change. The formula and its assumptions are in
[methodology](methodology.md#modeled-context-reprocessing).

To check a result, recompute each step by hand from the formula and the input file, then compare
with the JSON. The same run and the same input file produce the same bytes.
