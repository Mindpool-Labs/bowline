# Bowline Methodology

This document describes the v0.1 implementation. When the CLI report and this document differ, the
code is the source of truth and this document should be fixed.

## Quality Floors

Bowline maps each request to a task class from `x-bowline-task-class` or from the matched policy
rule. If neither supplies a class, the task is `unclassified`.

Default floors in `bowline-core/src/decision.rs`:

| Task class | Floor |
| --- | ---: |
| `mechanical` | 0.30 |
| `heavy-lifting` | 0.55 |
| `taste-sensitive` | 0.70 |
| `judgment` | 0.85 |
| `unclassified` | 0.55 |

Rationale:

- `mechanical`: low floor for rote transforms, extraction, formatting, and simple routing tasks.
- `heavy-lifting`: moderate default for coding, synthesis, support, and longer knowledge work.
- `taste-sensitive`: higher floor for copy, design, and brand-sensitive outputs.
- `judgment`: highest floor for decisions where poor reasoning or weak calibration is costly.
- `unclassified`: moderate default until the workload is explicitly classified.

The allocator filters feasible supply by policy, removes unavailable entries, requires the
task-class rating to clear the floor, then chooses the lowest estimated cost. Ties sort by supply
ID.

Controlled enforcement consumes this result only through an exact verified promotion grant. It
does not infer authority from registry rank, seeded ratings, or a cheaper candidate.

## Ratings Provenance

Registry ratings are normalized `0.0` to `1.0` values per supply entry and task class. The seeded
Phase 1 feed is illustrative and should be verified before relying on counterfactuals. Ratings are
seeded from published benchmarks, public model documentation, provider price sheets, and local
operator declarations where applicable.

Bowline now runs explicit offline per-organization canaries against exact candidate supplies. Their
dedicated quality overlays do not recalibrate or mutate registry ratings and do not change the
allocator. The seeded ratings and portfolio report quality parity cells therefore remain
`unverified`; canary evidence is reviewed separately under the exact dataset, evaluator, candidate,
judge, and freshness provenance described in [customer quality evidence](customer-quality.md).

## Evidence completeness

Every accepted request receives a run-scoped sequence before upstream I/O. A report is complete
only when accepted work reconciles with recorded work, the writer remained healthy, shutdown was
clean, no sequence is missing, no record was dropped or accounting-truncated, and every segment
recovered cleanly. Unmapped and unpriceable records are disclosed and degrade affected economic
cells. Integrity failure never becomes a zero-cost assumption.

Actual serving location comes from either the exact static `actual_supply_id` or one exact
operator-reviewed attribution mapping. Inline fallback to the static supply is allowed only when
the configured response header is absent. A present unknown, ambiguous, malformed, or
model-mismatched reference never falls back. Passive evidence has no static fallback. Model names
are checked only against the mapped entry's canonical model and aliases; they are not location
authority.

Attribution status is reported as `static-configured`, `attributed`, `missing`,
`unknown-reference`, `ambiguous`, or `model-mismatch`, split by inline or passive observation
source. Incomplete passive observations remain in coverage and attribution denominators but are
excluded from every cost, sovereignty, arbitrage, unplaceable, mapping, and priceability cell.

## Protocol coverage

Inline decision evidence supports OpenAI-compatible Chat Completions, Responses, and Embeddings.
The authoritative [v1 inference-route catalog](architecture.md#v1-inference-route-catalog) lists
all 12 exact method/path contracts in catalog version 1. Catalogued routes outside the three
supported protocols are forwarded unchanged and recorded as `unsupported-protocol` coverage.
Malformed or unsupported request envelopes on supported routes are recorded as `unsupported-shape`
coverage with a reason.

Coverage-only records carry no placement recommendation and are excluded from cost, sovereignty,
arbitrage, unplaceable, mapping, and priceability calculations. Reports disclose the gap and remain
incomplete for portfolio-wide conclusions. Administrative/non-inference routes such as models,
files, batches, uploads, and vector-store management are forwarded and are not counted as inference
traffic. Routes absent from catalog version 1 are forwarded and not included in the denominator;
the authoritative table defines the coverage claim.

## Confidence Labels

Report cells use these labels:

| Label | Meaning in v0.1 |
| --- | --- |
| `observed` | Derived from observed response usage or list-price inputs. |
| `declared` | Depends on declared TCO inputs or estimated usage inputs. |
| `canary-verified` | Defined confidence rank; the dedicated v0.1 quality report does not assign it to or rewrite portfolio cells. |
| `unverified` | Missing usage, missing priceability, absent samples, or parity not proven. |

Combination rule: Bowline uses the weakest label among inputs. The rank is:

`unverified < declared < canary-verified < observed`

If any mapped cost cell depends on declared owned-supply TCO, the combined label cannot be stronger
than `declared`. Empty sample sets are `unverified`. If records are unmapped or unpriceable, the
affected sovereignty, counterfactual, and tier-arbitrage cost cells are degraded to `unverified`.

## TCO Formula

Declared owned-supply cost per million tokens:

```text
owned_cost_per_mtok =
  (monthly_amortization_usd + monthly_power_usd + monthly_ops_usd)
  / monthly_capacity_mtok
```

Owned-supply request cost:

```text
owned_request_cost_usd =
  ((input_tokens + output_tokens) / 1_000_000) * owned_cost_per_mtok
```

Priced-supply request cost:

```text
priced_request_cost_usd =
  (input_tokens / 1_000_000) * input_per_mtok_usd
  + (output_tokens / 1_000_000) * output_per_mtok_usd
```

Counterfactual savings:

```text
savings_vs_all_frontier_usd =
  all_frontier_reference_cost_usd - shadow_cost_usd
```

Declared inputs:

- `monthly_amortization_usd`
- `monthly_power_usd`
- `monthly_ops_usd`
- `monthly_capacity_mtok`

Version-2 TCO is keyed by exact supply ID under `supplies`; each owned supply is priced only by its
own entry. An unlisted owned supply is unpriceable, never zero-cost. The legacy unversioned TCO
shape binds only to the exact legacy `actual_supply_id`, and only when that registry entry is owned;
it is never propagated to dynamically attributed owned supplies.

Registry inputs:

- supply ID and model
- supply class
- jurisdiction
- retention
- training-use flag
- cloud-act-exposure flag
- input and output price per million tokens, when priced
- task-class ratings
- availability flag

Ledger inputs:

- actual model
- observed or estimated input tokens
- observed output tokens, when present
- actual estimated cost, when upstream provided enough information
- shadow placement
- policy digest
- task class and floor

Report input:

- `frontier_reference`, either supplied by `--frontier-reference` or selected as the highest
  input-price public API entry in the registry.

## Sovereignty Ratio

The v0.1 CLI report computes sovereignty ratio as cost-share on owned supply:

```text
sovereignty_ratio =
  owned_supply_cost_usd / total_priceable_cost_usd
```

It renders both actual and shadow ratios, plus actual and shadow cost-share by supply class.

Token-share is the companion view:

```text
owned_token_share =
  owned_supply_tokens / total_accounted_tokens
```

Use token-share alongside cost-share when comparing workload volume to spend impact. The current
CLI report renders cost-share; token-share is defined here so downstream reports use the same
denominator and naming when they add it.

Shadow placement is selected at request time from an input-token estimate because output length is
unknown before the request. The recorded shadow placement identity can therefore differ from a
full-information choice; report costs and tier-arbitrage are recomputed from actual observed usage.

## Customer-quality statistics and verdicts

The dedicated quality report uses exact candidate-level evidence. Capacity counts dispatched
attempts; candidate-attributable errors form the error numerator. Latency is nearest-rank p95 over
successful normalized responses. Required evaluator failures count as complete failed samples;
required evaluator or judge execution errors make evidence insufficient. Pass rate and the Wilson
lower 95% bound use only complete samples.

Gates are policy, capacity, evidence, cost, and quality. Completion precedence is policy failure,
capacity failure, insufficient evidence, unknown cost, quality/cost failure, then eligible. Stale
evidence preserves that completion verdict and changes the effective verdict to insufficient only
where the implementation's freshness rule applies. The exact formula, truth table, judge semantics,
and continuation limits are in [customer quality evidence](customer-quality.md).

## Reconciled opportunity arithmetic

Actionable economics recomputes actual and candidate modeled costs per record from the same observed
input/output token pair and bound rate catalogs. It rounds each finite non-negative value to
micro-USD with ties-to-even, aggregates with checked integers, and compares ppm thresholds by exact
cross-products. The pre-response shadow estimate is not an economics cost input. Reconciliation
uses provider counts for count-variance denominators and imported charge for charge variance; it
keeps row-presence and qualified-charge coverage separate.

Annualization multiplies the positive observed-window modeled delta by 31,556,952,000 and divides
by window milliseconds with final ties-to-even rounding. It is available only after all applicable
billing, evidence, quality, policy, duration, count, and acknowledgement gates. This is past-window
arithmetic, not a prediction. See [actionable economics](actionable-economics.md).

## Enforced modeled delta

For a successful candidate response, Bowline recomputes observed actual cost and the grant's
approved counterfactual over the same complete input/output token counts. Enforced modeled delta is
the signed counterfactual-minus-actual result. Positive, zero, and negative values are retained.
Any applicable missing or overflowing input makes that aggregate unavailable or aborts report
construction; it is never replaced by a partial subtotal or zero. Bypass, fail-closed, candidate
failure, cancellation, estimated usage, stale/unpriceable evidence, and incomplete authority runs
are separate counts and produce no enforced modeled delta.
