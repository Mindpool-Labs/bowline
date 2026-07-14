# Actionable economics

Bowline can combine one explicitly named observation run, explicitly named quality runs, and
optional operator-normalized billing evidence into a deterministic private static report. The
report is advisory and offline: it does not contact a provider, candidate, judge, or billing
system, and it does not route, promote, enforce, or approve spend.

Billing evidence is operator-supplied input, not provider-authenticated truth. Opportunities are
counterfactual modeled evidence, not realized savings. Annualization is arithmetic over the
declared past window using 31,556,952,000 milliseconds per year; it is not a forecast.

## Commands

```sh
bowline billing validate --config bowline.yaml --billing examples/billing/canonical.jsonl
bowline billing validate --config bowline.yaml --billing examples/billing/mapped.csv --mapping examples/billing/mapping.yaml
bowline billing import --config bowline.yaml --billing billing.jsonl
bowline economics validate --config bowline.yaml --analysis analysis.yaml
bowline economics report --config bowline.yaml --analysis analysis.yaml --out-dir private/economics-report
```

`billing validate` parses and normalizes every row and writes nothing. `billing import` performs
the same complete preflight, then creates one private billing run. Supplying `--mapping` selects
mapped CSV; omitting it selects canonical JSONL. There is no format guessing. `economics validate`
resolves exact local run IDs, verifies their bindings, computes in memory, and writes nothing.
`economics report` requires an absent output directory under an existing private, non-symlink
parent and atomically publishes a complete bundle. `--json` on import or report emits only a
content-free summary.

The tracked files under `examples/billing/` and `examples/economics/` are synthetic. The analysis
file is a template whose explicit run IDs must be replaced with locally completed runs. No generated
billing run, traffic run, quality run, report, or bundle is tracked.

## Billing schema and normalization

Canonical JSONL uses one strict schema-v1 object per line. Required fields are `schema_version: 1`,
a unique safe `row_id`, positive half-open `period_start_ms`/`period_end_ms`, exact registry
`supply_id`, `currency: USD`, `charge_basis: inference-usage-net`, and a non-negative decimal
`charge_usd` with at most six fractional digits. Optional `request_count`, `input_tokens`, and
`output_tokens` are non-negative integers; absence stays absent rather than becoming zero.

`inference-usage-net` means inference usage after usage-line discounts, excluding tax, support,
commitment purchases, unrelated services, and credits not allocated to an inference line. The
operator owns this classification and acknowledgement. Bowline accepts at most 16 MiB of billing
input, 100,000 rows, 16 KiB per JSONL/CSV record, 128 CSV columns, 256 bytes per header, and 4 KiB
per CSV field. A mapping is at most 64 KiB. Identifiers are at most 128 bytes. Timestamps cannot
exceed `253402300799999`.

Mapped CSV is UTF-8/RFC 4180 with a unique header row. Its strict YAML mapping has `version: 1`,
`delimiter: comma`, exact source columns for all required canonical fields, and optional count
columns. Duplicate/missing headers, formulas as values, malformed quoting, unsafe numbers, and
oversized inputs are rejected. This generic mapping boundary performs no provider-specific
adaptation.

USD decimals normalize to checked integer micro-USD. Per-record modeled floating costs use IEEE
round-to-nearest, ties-to-even before checked aggregation. Ppm gates are bounded integers from 0 to
1,000,000 and compare checked cross-products; equality passes. Overflow and unknown denominators
fail closed instead of becoming zero.

## Private billing evidence

Imported rows live separately under `ledger_dir/billing-runs/<run-id>`. The mode-0700 directory and
mode-0600 files use a single writer, CRC-framed canonical rows, contiguous sequence numbers,
bounded segments, synchronization, recovery checks, and an atomic manifest. Source bytes,
normalized rows, optional mapping, registry, segment inventory, totals, and reconciliation are
bound by domain-separated SHA-256 checksums. Paths, raw CSV rows, prompts, responses, authorization
values, and arbitrary metadata are not copied into the manifest.

These are integrity and reproducibility checksums, not signatures or proof of provider origin.
Incomplete, corrupt, torn, undecodable, mismatched, or unreconciled runs cannot strengthen a
financial conclusion. Operators must restrict filesystem access, establish retention/deletion
periods, back up only when required, and handle row identifiers and financial amounts as private.

## Modes, window tiling, and matching

`modeled-only` forbids a billing run. It can display modeled rows, but annualized opportunity is
null and rows are neither billing-reconciled nor eligible. `billing-reconciled` requires one named
billing run and all configured financial gates.

In billing-reconciled mode, the economics and reconciliation windows are identical. Selected rows
for each exact supply must tile the full half-open window exactly: no gaps, overlaps, partial
boundaries, or proration. Every supported economics-eligible traffic record matches zero or one
billing row using exact supply and `start <= timestamp < end`. Missing attribution/rows become
Bowline exceptions; rows with no record become provider-row exceptions.

Required request/input/output counts are independently configured. Count variance uses provider
count as denominator; charge variance uses imported charge. Record coverage is matched supported
economics-eligible records divided by all supported economics-eligible records. Row-presence charge
coverage counts charges whose rows are present; qualified charge coverage counts only rows whose
required counts and ppm tolerances pass. A present row can therefore improve presence coverage
without improving qualified coverage. `0/0` variance is zero, nonzero over zero fails, and empty or
zero-charge portfolios remain incomplete.

## Dimensions, policy, and quality

Reports group the persisted application plus exact resolved `team:`, `environment:`, and
`cost-center:` tags, sorted remaining tags, task class, protocol, and exact supplies. Missing
reserved values are `unassigned`; conflicting values are `ambiguous` and degrade completeness.
Dimensions are reporting group keys, not tenant boundaries, authorization scopes, or secure
isolation.

Policy exposure is historical. It compares actual supply with the feasible IDs retained on that
decision and reports `compliant`, `violation`, or `unknown`; it does not re-run current policy or
invent an unrecorded reason.

Quality runs are named explicitly, integrity-checked, and projected for freshness at `as_of_ms`.
Quality report schema v1 remains verifiable but is non-joinable for economics; schema v2 requires
the exact workload, task, protocol, and candidate identity. Duplicate or mismatched overlays fail
closed. A joined canary verdict remains advisory and does not mutate registry ratings or policy.
It is evidence for a bounded dataset and evaluator configuration, not a universally applicable
quality conclusion.

## Opportunity and annualization semantics

Eligibility exists only in billing-reconciled mode and requires complete traffic/billing/price/
usage evidence, current eligible quality evidence, policy feasibility, known positive modeled
savings, and every configured reconciliation threshold. Unknown or incomplete inputs become
blocker codes. Candidate and actual cost are recomputed from the bound registry/owned-cost catalog
over the same observed input/output token pair; the pre-response shadow estimate is excluded.

For an explicitly acknowledged representative past window that satisfies minimum duration and
record gates, the formula is:

```text
annualized_opportunity_usd = observed_modeled_delta_usd
                           * 31_556_952_000 / analysis_window_ms
```

The representativeness acknowledgement records an operator assertion; Bowline does not prove it.
The value is a counterfactual arithmetic extrapolation, not demand modeling, a budget, a guarantee,
a forecast, an accounting result, or evidence of savings already achieved.

## Static bundle and source bindings

The private bundle contains exactly seven files: `report.json`, `report.md`, `report.html`,
`dimensions.csv`, `opportunities.csv`, `reconciliation.csv`, and `manifest.json`. JSON is the
canonical model. Markdown, escaped self-contained HTML, and formula-neutralized RFC 4180 CSVs are
views of that model. Each payload is bounded to 64 MiB. HTML has no script/external asset and carries
a restrictive CSP.

The bundle manifest binds six payload artifacts and excludes itself. It records ordered names,
sizes, SHA-256 digests, package version, compile-time source revision or `unavailable`, exact run/
input digests, and a domain-separated bundle digest over canonical manifest bytes.

Before eligibility or annualization, Bowline recomputes and checks selected traffic, traffic
manifest/recovery, framed billing rows, billing manifest/recovery, quality outcomes/report/
manifest, analysis, config, registry, owned-cost, and policy bindings. Registry equality is required
across applicable sources; owned-cost and policy equality are required wherever applicable. These
bindings establish internal consistency, not external authenticity.

The authoritative JSON report and bundle manifest both name the exact selected evidence. Traffic
records its run ID plus separate canonical records, manifest, and verified-recovery digests.
Billing, when selected, records its run ID plus separate normalized-rows, manifest, and
verified-recovery digests. Quality is an ordered list of explicit run IDs with schema version and
manifest, outcomes, report, join-projection, registry, owned-cost, and policy digests. The two
structures must agree exactly; unsafe IDs, invalid digests, duplicate/order drift, or more than 256
quality sources fail closed. Markdown and HTML embed the same canonical report source section.

## Deployment boundary

One deployment represents one enterprise security domain. Run one replica with one protected
ledger and private output root. Bowline does not provide secure multi-tenancy. Bowline has no
management plane. It also has no persistent analytics service, provider billing API, dashboard, or
spend-approval workflow. Bowline does not provide provider-native support.
