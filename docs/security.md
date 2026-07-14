# Security

Bowline's Phase 1 security objective is byte-faithful default forwarding plus exact, bounded,
reversible controlled authority with local integrity-disclosed evidence. It is not a content
classifier or secret store.

## Trust boundaries

- Clients and the configured upstream are outside Bowline's trust boundary.
- Only the immediate peer address can establish proxy trust. `x-bowline-*` identity headers from
  untrusted peers are ignored and counted.
- Normal authorization is forwarded to the upstream but is excluded from the ledger. Optional
  preflight authorization is read only from `BOWLINE_PREFLIGHT_AUTHORIZATION`.
- Config, policy, registry, TCO, image, ingress, clock, and evidence-volume administration are
  privileged operator inputs.
- Enforcement bundle, promotion evidence, kill trust root, actuator authorization environment,
  and arming are privileged operator inputs. The kill file is descriptor-read at each converted
  decision and startup never arms it.
- Attribution mappings, response-header selection, passive emitters, transform profiles, and input
  files are privileged operator inputs. Passive evidence is not cryptographically authenticated.

Bowline strips hop-by-hop and internal identity headers upstream, disables automatic response
decompression to preserve bytes, bounds request and accounting bodies, uses connection/header/idle
timeouts, writes private atomic manifests, checks framed records, and rejects concurrent writers.
The hardened image runs as UID/GID 65532 with a read-only root, dropped capabilities, no privilege
escalation, and runtime-default seccomp.

## Retained data

Evidence contains digests of API keys rather than raw keys; route/app/tag identity, task class,
model/supply identifiers, token counts and provenance, timestamps, latency/error facts, costs,
policy/run identifiers, a sanitized upstream endpoint identity, and shadow decisions. The endpoint
identity has query and fragment removed; the raw configured upstream URL is not written to the
decision ledger. Request and response content and authorization values are not intentionally
recorded. Operational logs may contain upstream transport errors; route logs and access logs are
controlled by the surrounding platform.

Hashes of low-entropy identifiers can still be sensitive. Restrict, encrypt, retain, and delete
evidence according to organization policy. Keep `/health/status` internal.

Billing rows and economics reports contain financial amounts, opaque row IDs, workload dimensions,
supply IDs, and run/checksum relationships. They exclude prompt/response content, raw CSV rows,
source paths, arbitrary metadata, and authorization values, but remain private. Protect source
inputs, separate stores, output parents, backups, and deletion workflows. Checksums detect
inconsistent evidence; they do not authenticate a provider or resist a privileged attacker who
coherently rewrites every input.

Passive profiles accept only enumerated scalar fields and reject known content, body, header,
authorization, token, credential, cookie, password, and raw-URL pointer names.
The pointer denylist cannot detect a secret aliased under an innocuous key.
Operators must review the emitter and profile together; do not route unreviewed logs into the
importer. Reports aggregate attribution statuses and digests and do not expose reference values or
extracted source values.

Quality input is a separate privileged content boundary. During a canary, case requests and
expected values are read into bounded memory and sent to each configured candidate. When enabled,
the configured judge additionally receives the request, expected map, normalized candidate text and
tool calls, fixed instruction, and rubric. These endpoints and surrounding network/logging systems
are outside Bowline's evidence-retention guarantee. Remote candidate use and every judge require
separate explicit content-egress acknowledgments; authorization comes only from bounded named
environment values.

Quality manifests, framed outcomes, and reports exclude raw case/evaluator/rubric/response content,
authorization, and judge rationale. They retain opaque IDs, measurements, statuses, and content/
configuration digests. Low-entropy content may be guessable from a digest. Keep quality evidence
mode 0600 on a restricted encrypted volume, control backups/retention, and do not expose it as a
public artifact. The outcome/report digest bindings detect accidental or unprivileged mutation but
are not signatures and do not establish who ran a judge.

Authority evidence adds content-free route/mode/workload digests, selection reason, target,
dispatch count, circuit/fallback, grant/config bindings, completion, failure/cancellation, and
applicable cost fields. It excludes prompts, responses, tool arguments, authorization values, and
raw actuator URLs. Candidate authorization replaces rather than inherits original authorization;
Bowline and hop-by-hop headers are removed. Original, actuator, and probe clients reject redirects.
One flushed decision and a current lifecycle/kill/grant recheck precede any candidate dispatch.

## Deployment requirements

Terminate TLS at a reviewed proxy or use end-to-end TLS, authenticate ingress, restrict direct
upstream access for the observed route, allow only required egress, mount config read-only, use a
dedicated evidence volume, and monitor integrity counters. Review seeded price/rating inputs before
decision use.

One deployment represents one enterprise security domain. Application, team, environment, cost
center, route, and task-class dimensions do not create tenant isolation. Use separate deployments,
credentials, evidence volumes, and surrounding controls for separate security domains.

For vulnerabilities, use the repository's private security reporting process. See the [threat model](threat-model.md) and
[limitations](limitations.md).

Bowline evaluates workload-identity policy and records the resulting shadow decision. In shadow
mode it does not hold routing enforcement authority. It is not DLP. Policy binds to what a workload
*is* (key, route, app, tags), never to what a prompt *says*.
