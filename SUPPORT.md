# Support

## Community support

Use GitHub Discussions for usage questions and the bug template for reproducible defects. Include
version, operating system, deployment type, redacted configuration, expected/actual behavior, and
relevant integrity counters. Community support is best-effort with no response-time commitment.

Security reports must follow [SECURITY](SECURITY.md). Do not post credentials, customer content,
private evidence, or infrastructure identifiers.

For canary questions, include only synthetic reproduction files, redacted endpoint identities,
content-free run counters, stable error codes, and the exact CLI version. Never attach customer
datasets, expected values, candidate output, rubrics, authorization values, outcome ledgers, or
quality reports to a public issue. Dataset review, endpoint governance, spend approval, and
acceptance sign-off belong to the deploying organization.

For billing or economics defects, use only synthetic canonical rows/mappings, redacted content-free
manifests, blocker codes, and artifact digests. Do not attach invoice exports, row identifiers,
financial report bundles, ledgers, customer dimensions, or authorization material to a public
issue. Financial classification, retention, representativeness, and accounting acceptance remain
operator responsibilities.

For controlled-enforcement defects, begin from the shipped synthetic killed example. Include only
the version, stable error/reason, aggregate health fields, redacted configuration shape, and
content-free synthetic reproduction. Do not attach promotion bundles, quality runs, schema-v2
ledgers, workload identities, actuator URLs, authorization references/values, kill paths, or private
diagnostics. Keep the kill state at bypass while reproducing configuration or evidence failures.
