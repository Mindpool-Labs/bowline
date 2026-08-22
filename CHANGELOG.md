# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Production-PoV preflight, health, run manifests, bounded segmented evidence, integrity reports,
  graceful lifecycle, hardened deployments, load/latency gates, and repository validation.
- Public architecture, operator, security, methodology, governance, and release documentation.
- Cost-optimized placement now requires known price evidence or applicable owned-supply TCO;
  candidates without either are excluded and reported as unpriceable.
- Inline decision evidence for OpenAI-compatible Chat Completions, Responses, and Embeddings,
  including explicit unsupported-protocol and unsupported-shape coverage records for catalogued
  inference traffic. Reports disclose protocol coverage and exclude coverage-only records from
  placement and financial conclusions.
- Optional controlled enforcement for exact verified Chat/Responses workloads, with an explicit
  private kill state, deterministic ppm rollout, zero-or-one dispatch, pre-dispatch fallback,
  volatile circuits, bounded candidate admission, schema-v2 authority evidence, aggregate health,
  and modeled-delta reports. Startup preserves an existing valid kill state and never arms
  authority automatically.
- A pluggable state-backend seam for circuit-breaker and candidate-admission state, with the
  existing local, volatile, startup-open behavior as the default. A supervisor owns the serving
  lease and the whole active-runtime lifecycle, so every activation has an explicit run boundary.
- An optional file-lease backend providing active-passive supervision: an exclusive POSIX advisory
  lock is the sole ownership authority, standbys stay live but unready and reject inference with
  `standby-no-lease`, and only the holder opens evidence writers, creates runtime state, runs
  startup probes, and admits traffic. Supported where every replica participates in one reliable
  POSIX lock domain and shares one evidence root; state is not replicated across failover.
- `bowline export evidence`, publishing a versioned `evidence_schema_version: 1` bundle for one
  selected run against a published JSON Schema (`schemas/evidence-bundle-v1.schema.json`). The
  decision projection is allowlisted and content-free: no route, app, tag, key digest, upstream,
  model identifier, attribution reference, prompt, response, header, or authorization material is
  exported, and aggregates are the report's own numbers rather than a second accounting path.
- Optional signature verification for promotion and authority evidence. A versioned detached
  envelope wraps a standard Minisign signature verified against operator-configured keys; the key
  an envelope carries is never a trust root. Who signs is left entirely to the operator. A missing
  or invalid required signature yields zero authority on the affected route and a durable reason
  in decision evidence rather than a startup failure.
- Optional external-approval artifact binding for promotion. A strict `ApprovalArtifactV1` is bound
  to the exact authorization it approves, verified through the same envelope and bounded by a
  configured maximum age. Bowline checks binding and freshness only — it never interprets the
  approver string, roles, quorum, or organizational policy.
- A published canonical passive-event schema (`schemas/passive-event-v1.schema.json`) and an offline
  conformance runner: `bowline conformance canonical` and `bowline conformance collector` share the
  importer's own validation, stable reason codes, and whole-file atomicity, so a passing result
  means the same input will pass import. The shipped LiteLLM and Envoy profile/fixture pairs are the
  reference corpus and run in CI.
- Documentation for the new contracts: `docs/evidence-export.md`, `docs/external-approval.md`, and
  `docs/writing-a-collector.md`.
- A Contributor License Agreement (`CLA.md`), affirmed per pull request.
- A neutrality charter (`docs/neutrality-charter.md`) stating the commitments that govern how
  affiliated supply is treated, anchored in a public transparency log with the Sigstore bundle
  committed for offline verification (`docs/anchors.md`).
- Bounded task-stage routing on exact Chat Completions and Responses routes. Enforcement bundle
  version 2 carries `routing_profiles`; durable, content-free task state lives in a private
  exclusive-writer prefix below the ledger directory; and an optional loopback-only advisory
  listener answers `POST /v1/routing/decision`. Routing never creates authority, and every
  missing, untrusted, malformed, conflicting, capacity-exhausted, corrupt, or unavailable case
  retains the capable target. Authority decision and outcome records that carry a routing
  decision are written at evidence schema version 3; records without routing stay at version 2,
  and both remain readable.
- An optional observe-only adapter for the NVIDIA NeMo Relay 0.6.0 Switchyard decision API. It
  sends only a task-reference digest, protocol, step, and enumerated signals, and records
  agreement, latency, and error aggregates. It cannot change a plan, target, authority, dispatch,
  fallback, kill state, or the native result. NVIDIA ships `nemo-relay-switchyard` as an
  experimental plugin and removes it in NeMo Relay 0.8, so this adapter is a pilot against a
  moving external contract.

### Fixed

- Candidate circuit-breaker accounting: a non-streaming response that closes cleanly with an
  incomplete or invalid body now records a failure; a healthy response truncated only by the
  accounting limit now records success; SSE completion detection accepts the spec-legal
  `data:[DONE]` form without a space.
- An oversized or non-UTF-8 attribution response header now resolves as absent and uses the
  configured static attribution fallback instead of reporting an unknown reference.

### Security

- Trusted immediate-proxy identity boundary, bounded accounting, strict configuration validation,
  private atomic run state, single-writer locking, minimal non-root image, and dependency gates.
- Upstream validation rejects URL userinfo and credential-bearing query parameters.
- Decision evidence stores a sanitized upstream endpoint identity with query and fragment removed,
  rather than the raw configured upstream URL.
- Authority-evidence integrity inventory validates segment-file ownership and mode before sealing
  the records digest, and segmented authoritative reads validate the run directory's ownership and
  mode, matching the existing per-file read checks.
- A non-loopback HTTPS enforcement actuator requires an explicit `remote_acknowledged: true` in its
  configuration; an Enforce route with no configured fallback fails closed instead of bypassing.
- Canary input files are opened with `O_NOFOLLOW` and validated through the open handle, removing a
  symlink check-then-use window.
- Routing task references are now HMAC-SHA256 (`hmac-sha256:` prefix) keyed by a 32-byte per-install
  salt, rather than an unkeyed digest over the bounded, low-entropy, operator-chosen task ID; the
  prior form was reversible by dictionary. **This is a breaking on-disk change**: the routing state
  metadata schema is bumped to 4, and a directory recorded before the bump refuses to open and needs
  a one-time reset (stop the gateway, delete the routing state directory — safe only for a directory
  that predates this change; a directory written by a *newer* Bowline release fails closed with a
  distinct error and must not be deleted). The schema is classified before the salt is ever loaded
  or minted, so that classification never depends on whether a salt file also happens to be
  present. A fingerprint derived from the salt (also `hmac-sha256:`-prefixed) is recorded in
  `metadata.json` and detects a replaced or lost `salt` file, so losing or replacing it refuses to
  open rather than silently mint a second key over surviving history — but only over a directory
  that holds real history. A directory with **no** real history (zero segments, zero decisions)
  mints a fresh salt on its own even if its `salt` file is absent or all-zero; only a directory that
  already has real history and a missing or all-zero salt gets the distinct "restore the salt file"
  error, since deleting that directory would destroy history the salt would have recovered. The
  salt is read via `getrandom` rather than a raw `/dev/urandom` file read, and an all-zero salt is
  rejected both when generated and when loaded from disk over real history.

## [0.1.0] - Unreleased

Introduces the initial shadow-observer feature set.
