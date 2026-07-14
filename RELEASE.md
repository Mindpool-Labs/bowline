# Release process

Bowline uses Semantic Versioning. Before v1.0, incompatible public configuration, CLI, evidence
schema, or report changes increment the minor version; fixes and compatible additions increment the
patch version. A release requires a clean checkout and reviewed changelog.

## v0.1.0 preparation checklist

- [ ] Confirm scope, Apache-2.0 notices, community files, and support/security contacts.
- [ ] Set workspace version, update `CHANGELOG.md`, and document migrations/non-claims.
- [ ] Run format, lint, test, dependency, documentation, repository, deployment, Docker smoke,
      benchmark, and security workflow gates.
- [ ] Review SBOM/dependency output and image/base digest; scan for secrets and internal content.
- [ ] Have two maintainers review the release commit and evidence.
- [ ] Build release artifacts from the reviewed commit; record checksums and provenance.
- [ ] After required reviews pass, have an authorized maintainer create an annotated signed tag and
      GitHub release.
- [ ] Verify installation and rollback from published artifacts, then announce.

Only authorized maintainers may publish signed tags, GitHub releases, or images. Releases must
follow branch protection and required review policies.
