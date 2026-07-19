# Phase 1 limitations

- Shadow is the default. Controlled authority exists only for exact verified Chat/Responses grants;
  all other traffic retains the original upstream or configured local failure behavior.
- Inline decision evidence supports OpenAI-compatible Chat Completions, Responses, and Embeddings.
  Streaming evidence is supported for Chat Completions and Responses; Embeddings is non-streaming.
- The authoritative [v1 inference-route catalog](architecture.md#v1-inference-route-catalog)
  lists all 12 exact method/path contracts in catalog version 1. Catalogued routes outside the
  three supported protocols are forwarded unchanged and recorded as `unsupported-protocol`
  coverage. Malformed or unsupported request envelopes on supported routes are recorded as
  `unsupported-shape` coverage with a reason.
- Coverage-only records carry no placement recommendation and are excluded from cost, sovereignty,
  arbitrage, unplaceable, mapping, and priceability calculations; reports disclose the gap and
  remain incomplete for portfolio-wide conclusions.
- Administrative/non-inference routes such as models, files, batches, uploads, and vector-store
  management are forwarded and are not counted as inference traffic. Routes absent from catalog
  version 1 are forwarded and not included in the denominator; the authoritative table defines the
  coverage claim.
- Dynamic attribution is exact and operator-configured. It does not infer location from model name,
  inspect provider control planes, or guess mappings. Present invalid evidence never falls back.
- Passive v1 is bounded offline file import only: no listener, collector, callback endpoint, OTLP
  receiver, log tailer, daemon, schema guessing, or automatic provider discovery.
- The LiteLLM fixture proves only Bowline's callback serializer contract with synthetic objects.
  The Envoy fixture proves formatter/profile key and scalar-type parity, not a live Envoy process or
  arbitrary Envoy access-log compatibility.
- Duplicate event IDs are rejected only within one input file. Cross-run duplicate suppression is
  not performed; rerunning a file creates a distinct run.
- Profile pointer vocabulary blocks known sensitive/content names, but an emitter can alias a
  secret under an innocuous field name. Operators must review emitter configuration and profiles.
- One deployment is one enterprise security domain; dimensions are not isolation boundaries.
- The optional file-lease backend provides active-passive supervision only when every replica
  participates in one reliable POSIX lock domain and shares one evidence root. The supported
  example is two processes or containers on one host. Multi-host and NFS deployments are not
  claimed, even if a particular filesystem advertises advisory locking.
- File-lease failover does not provide active-active serving, state replication, forced lock
  stealing, or shared concurrent writers. A paused holder that retains the OS lock blocks
  takeover. The new active starts a fresh run with startup-open circuit and admission state; a
  killed active leaves its prior run incomplete.
- Workload identity policy only: no prompt/response content classification or blocking.
- No DLP claim. The exact scope is documented in [security](security.md).
- Accounting depends on upstream model/usage fields; estimates, missing usage, aliases, truncation,
  unmapped models, and unpriceable entries degrade confidence or completeness.
- A candidate without known price or applicable owned-supply TCO is excluded from cost-optimized
  placement. Bowline reports missing cost evidence rather than treating it as zero.
- Registry prices, ratings, availability, jurisdiction, retention, training use, and TCO are
  operator inputs. Seed values are illustrative and can become stale.
- Offline organization-specific quality canaries are implemented only for non-streaming
  OpenAI-compatible Chat and Responses. They do not cover Embeddings, SSE, multimodal input,
  provider-specific bodies, distributed/resumable workers, or retries.
- Canary results apply to the exact operator dataset, evaluators, candidate supply, optional
  subjective judge, configuration, and evidence age. Bowline does not establish dataset
  representativeness or independent acceptance.
- Observed token/cost limits stop future dispatch after completed evidence crosses a threshold;
  already in-flight candidate/judge chains may overshoot. There is no pre-dispatch charge guarantee,
  invoice download, provider-specific billing adapter, or spend approval.
- Quality overlays do not update ratings, choose among candidates, or execute promotion. Controlled
  authority separately requires exact fresh quality and economics evidence plus explicit route
  configuration and an armed private kill state.
- Evidence uses checksummed frames and atomic manifests, not cryptographic signing or an external
  transparency log. Privileged storage administrators remain trusted.
- Identity headers are trustworthy only to the extent the configured immediate proxy is trusted.
- The 10 MiB request limit, accounting capture bound, timeouts, queue capacity, and segment capacity
  define the supported traffic envelope; tune and load-test them for the workload.
- Billing imports are operator-normalized canonical evidence, not invoice retrieval or provider
  authentication. Exact-window reconciliation can remain incomplete and cannot establish accounting
  correctness.
- Economics reports are static private bundles, not an analytics service, forecast, migration
  control, or proof of achieved savings.
- Controlled authority supports only OpenAI-compatible Chat Completions and Responses. Embeddings,
  provider-specific protocols, malformed/ambiguous bodies, and unmatched routes cannot receive
  authority. Embeddings observe/recommend routes retain the original upstream and record
  zero-authority evidence.
- Promotion configuration is not authorization by itself. Each authority route requires a private
  descriptor-protected local sidecar that binds exact source evidence, normalized route semantics,
  and active policy/registry-source/owned-cost provenance. It is not a signature or external
  approval, and privileged administrators inside the deployment security domain remain trusted.
- Candidate authority requires a resolved application plus exact runtime task and canonical tag
  binding. Missing or invalid application identity, task mismatch, and tag mismatch use the
  configured zero-authority fallback.
- Candidate traffic has zero-or-one dispatch. There is no redirect following, completion retry, or
  original-upstream fallback after a candidate attempt. This avoids Bowline-originated duplicate
  attempts but cannot prove whether an ambiguous remote transport executed.
- Circuit and admission state is volatile and local to each activation. It is not replicated and
  resets startup-open after process restart or file-lease takeover.
- Promotion inputs, the local authorization seal, kill state, and configuration are
  operator-controlled checksummed evidence, not third-party attestations. Arming and organizational
  approval remain external.
- Enforced modeled delta is limited to successful candidate HTTP 2xx outcomes with observed complete
  token counts and both approved rates. Non-2xx responses, estimates, and incomplete usage remain
  unavailable even when a response body contains a usage object.
- No built-in authentication, TLS termination, rate limiting, WAF, secret manager, backup service,
  or persistent dashboard. Deploy these controls around Bowline.
- A complete local smoke or test run proves implementation behavior, not an operator's
  operational acceptance. See the [production PoV runbook](production-pov.md).
