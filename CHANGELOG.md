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

## [0.1.0] - Unreleased

Introduces the initial shadow-observer feature set.
