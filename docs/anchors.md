# Transparency anchors

Public log: the Sigstore Rekor public instance (`rekor.sigstore.dev`). Each anchored artifact has
its Sigstore bundle committed under [`docs/anchors/`](anchors/) so verification also works offline
against a pinned entry.

| Artifact | SHA-256 | Rekor log index | Anchored (UTC) |
| --- | --- | --- | --- |
| `docs/neutrality-charter.md` (charter v1.0.0) | `1074b01bd979d2ea94459fd963c732b9fcc374ef54ec58b9ba94aba5421849ff` | `2200249672` | `2026-07-19` |

Verify an entry:

```sh
shasum -a 256 docs/neutrality-charter.md
cosign verify-blob docs/neutrality-charter.md \
  --bundle docs/anchors/neutrality-charter-v1.0.0.sigstore.json \
  --certificate-identity "murali.raju@mindpoollabs.net" \
  --certificate-oidc-issuer "https://accounts.google.com"
```

Data-feed release signatures and future charter versions are anchored the same way and appended
to this table.
