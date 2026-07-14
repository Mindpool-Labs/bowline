# Registry reference

The registry is a neutral model-by-location supply catalog. Every candidate uses the same schema
regardless of who operates it. Seed data is illustrative; operators own price, rating,
availability, retention, and jurisdiction verification.

Top-level fields are `feed_version` and `entries`. Each entry contains:

- unique `id`; canonical `model`; optional unique `aliases`; human-readable `location`;
- `attributes.class`, `jurisdiction`, `retention`, `training_use`, and `cloud_act_exposure`;
- optional `price.input_per_mtok_usd` and `price.output_per_mtok_usd`, both non-negative;
- `ratings` values from 0.0 through 1.0 by task class;
- optional `available`; only explicit `false` excludes an entry.

The same canonical model may appear at multiple locations. Resolution is therefore scoped:
`actual_supply_id` first selects the entry, then the upstream model identifier must equal that
entry's canonical model or one of its aliases. Aliases cannot be duplicated within an entry.

```sh
bowline registry show --config bowline.prod.yaml
bowline registry probe --config bowline.prod.yaml
```

`show` prints class, jurisdiction, price, and availability. `probe` checks `/v1/models` for each
configured local endpoint; `preflight` performs the stricter production check against the actual
upstream and requires exact scoped resolution.

For updates, keep a reviewed copy of the previous feed, validate with preflight, restart to create
a new run with a new registry digest, and never compare economics across digests without disclosing
the change. The schema and decision rules apply identically to every supply entry and do not
privilege an operator.
