# Threat model

## Assets and actors

Assets are response integrity, authorization confidentiality, policy/registry/TCO correctness,
run completeness, evidence confidentiality, and reviewer trust. Relevant actors include an
untrusted client, compromised workload, malicious immediate proxy, compromised upstream,
misconfigured operator, evidence-volume attacker, dependency attacker, and resource-exhaustion
attacker.

## Primary threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Identity spoofing | Immediate-peer CIDR trust; ignore/count untrusted headers | A compromised trusted proxy can assert identity. |
| Secret leakage | Authorization excluded from evidence; URL redaction; no content capture | Surrounding proxies/loggers and upstream still see traffic. |
| Response mutation | Byte-faithful streaming; no automatic decompression; parity tests | Protocol normalization of allowed headers remains. |
| Silent evidence loss | Pre-accept sequence, bounded managed queue, disclosed drops, readiness failure | Process/host loss can leave a cleanly unreadable tail, disclosed on recovery. |
| Concurrent corruption | Directory-wide single-writer lock; single replica | Misconfigured storage lock semantics can undermine exclusivity. |
| Evidence tampering | CRC-framed records, atomic manifest, recovery disclosure | CRC is not a signature; a privileged volume attacker can rewrite coherent evidence. |
| Resource exhaustion | Request/accounting bounds, timeouts, queue/segment limits, resources | High valid traffic can fill the evidence allocation or upstream capacity. |
| Biased economics | Published schema/methodology, confidence degradation, operator-owned inputs | Price/rating/TCO inputs may be stale or strategically chosen. |
| False billing authority | Strict generic schema, basis acknowledgement, source/binding checksums, reconciliation disclosure | Operator-normalized billing is not authenticated provider truth; upstream classification can be wrong. |
| Misleading extrapolation | Past-window gates, exact formula, blocker codes, counterfactual labels | Representativeness and future demand remain outside Bowline. |
| Private financial disclosure | Separate private stores, no-follow reads, mode-0600 files, atomic private bundle | Row IDs, dimensions, charges, and reports remain sensitive operator data. |
| Canary content egress | Explicit candidate/judge endpoints, HTTPS for remote URLs, environment-only auth, bounded transient memory | Configured endpoints and surrounding logs can retain customer-controlled content. |
| Biased quality evidence | Strict inputs, deterministic evaluators, Wilson/sample/freshness disclosure, subjective judge label | Dataset selection, expected values, rubric, thresholds, and judge can be strategically chosen. |
| Quality evidence tampering | CRC-framed outcomes plus atomic manifest-bound outcome/report digests | Bindings are not signatures; a privileged volume attacker can rewrite a coherent bundle. |
| Supply-chain compromise | Locked Rust graph, deny/audit CI, pinned builder digest, minimal image | Registry, CI runner, signing, and publication controls remain operator duties. |
| Unauthorized candidate selection | Exact workload/grant/digest binding, private per-decision kill read, flush-gated handle, freshness recheck | A privileged operator controlling every trusted input remains trusted. |
| Duplicate billable work | Zero-or-one target construction, no redirects/retries/post-attempt fallback | Transport ambiguity can hide whether the single candidate attempt executed remotely. |
| Candidate outage or overload | Startup-open volatile circuit, bounded probe, global/per-actuator admission, configured pre-dispatch fallback | Circuit state is per process and resets on restart. |
| Authority evidence loss | Durable decision before dispatch, exact replacement decision, irreversible incomplete-run lifecycle | Host loss after remote execution can leave outcome evidence incomplete. |
| Promotion authority tampering | Optional, bring-your-own-key standard-Minisign signature over the exact bounded authorization file (`authority_signing`); missing/invalid signatures are a typed, fail-closed, durably recorded rejection | Off by default; a verifying signature attests only exact-byte authenticity of the sealed authorization at signing time, not the correctness or freshness of the evidence it binds, or organizational approval. |

## Non-goals

Bowline does not provide prompt-content policy or high availability. Evidence signing is optional,
bring-your-own-key, and scoped to promotion/authority evidence (see
[controlled enforcement](controlled-enforcement.md#optional-authority-signing)); it is not a
general evidence-signing or transparency-log capability, and it attests exact-byte authenticity
only, never correctness or organizational approval. Bowline does not provide tenant isolation
inside one process. It also does not provide authenticated billing truth, dataset
representativeness, independent judge trust, spend approval, or control of traffic that bypasses
the gateway. Controlled authority is limited to exact Chat/Responses grants and volatile local
circuit state. Offline quality canaries provide advisory evidence only. Review
[limitations](limitations.md) before interpreting a PoV.
