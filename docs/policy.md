# Policy reference

Phase 1 policy classifies workload identity; it never evaluates prompt or response content. A
bundle contains `version: 1`, ordered `identities`, and ordered `rules`. Unknown keys, an absent
default rule, or invalid enum values fail parsing.

Identity match fields are API-key digest, route, and app. A matching identity attaches tags. Rule
subjects may match those tags; the first matching rule wins. A rule can set `task_class` and
`require` constraints:

- `supply_class`: `owned`, `vpc-open-weights`, `vpc-frontier`, or `public-api`.
- `jurisdiction`: allow-listed registry values.
- `retention`: allow-listed registry values.
- `training_use`: required boolean.
- `cloud_act_exposure`: required boolean.

The final rule must use `default: true`. After policy filtering, unavailable entries and entries
below the task-class quality floor are removed; the lowest estimated-cost feasible entry wins, with
supply ID as the deterministic tie-break.

```sh
bowline policy validate policies/default.yaml
# ok sha256:<64 hexadecimal characters>
```

The digest is content-addressed and stored in each run manifest. Treat policy updates as change
events: validate, review the diff, retain the prior file and digest, restart Bowline to begin a new
run, and compare reports. See [operations](operations.md).

Bowline evaluates workload-identity policy and records the resulting shadow decision. In shadow
mode it does not hold routing enforcement authority. It is not DLP. Policy binds to what a workload
*is* (key, route, app, tags), never to what a prompt *says*.

Controlled authority does not replace this policy result. A route grant must bind the current
policy digest and the runtime canonical workload digest must exactly match verified promotion
evidence; the route's app/tag selector only narrows that authority. Policy or identity mismatch
invokes the configured pre-dispatch fallback.
