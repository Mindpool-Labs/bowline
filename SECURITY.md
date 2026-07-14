# Security policy

## Supported versions

Before the first stable release, only the latest `main` commit and newest published v0.x release
receive security fixes. After v1.0, the current minor line and its immediate predecessor will be
supported unless a release note states otherwise.

## Private reporting

Do not open a public issue for a suspected vulnerability. Email `security@mindpool.io` with:

- affected version/commit and deployment shape;
- reproduction steps or proof of concept;
- impact, prerequisites, and whether exploitation is active;
- suggested mitigation, if known; and
- a safe contact method.

Do not include real customer prompts, credentials, or ledger data. We aim to acknowledge reports
within three business days, provide a triage update within seven, coordinate remediation and
disclosure, and credit reporters who want attribution. Timelines vary with severity and dependency
coordination. Good-faith research that avoids privacy violations, service disruption, persistence,
and data destruction is welcome.

See [security architecture](docs/security.md) and the [threat model](docs/threat-model.md).
