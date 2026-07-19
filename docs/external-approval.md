# External-approval artifact binding

`promotion_approval` is an optional, independent precondition on a route's promotion grant: bring
your own approval workflow, and Bowline checks that its output is bound to the exact evidence it
claims to approve and is still fresh. Off by default; configuring it changes nothing about
signature verification (`authority_signing`, see [controlled-enforcement](controlled-enforcement.md))
or any other evidence check — the two sections are unrelated and can be used independently or
together.

## What this is, and what it is not

An approval artifact is machine-checkable evidence that some externally produced process bound
itself to one exact, already-sealed promotion authorization before Bowline will treat the route's
grant as usable. Bowline verifies exactly three things about it: a standard
[Minisign](https://jedisct1.github.io/minisign/) signature over its exact bytes, that it names the
exact evidence digests it claims to approve, and that it is fresh. It is **not** organizational
authority, a role, a quorum, an approval process, or a claim about who signed it or why. The
artifact carries an `approver` field, but Bowline never parses, compares, or acts on its contents
beyond storing it as an opaque, byte-bounded string — building an actual approval workflow (who
may approve, how many approvers, what they reviewed) is entirely the operator's responsibility,
outside Bowline.

## Configuration

Configure it in the gateway config, never in the enforcement bundle:

```yaml
promotion_approval:
  version: 1
  required: true
  verify_keys:
    - |
      untrusted comment: minisign public key <KEY-ID>
      <standard minisign public key, base64>
  max_age_seconds: 86400
```

`verify_keys` names one or more standard minisign public keys in their usual two-line
`minisign.pub` format. `max_age_seconds` bounds both how old an artifact may be when checked and
how long a validity window it may claim for itself (see [Freshness](#freshness) below).

With `required: true`, a route with promotion evidence but no approval artifact present is a soft,
typed, durably recorded rejection — the gateway keeps running and the route falls to its
configured pre-dispatch fallback with zero allocation authority. With `required: false`, an absent
artifact is legacy behavior: the grant still requires every other check, just not an approval.

## Producing an artifact

Bowline never generates or holds a secret signing key. Produce the artifact and its signature as
part of your own approval pipeline, after the promotion authorization has been sealed. The
artifact sits alongside the sealed authorization at the deterministic path
`<authorization_path>.approval.json` (for example
`authorization/support-chat.json.approval.json`):

```json
{
  "artifact_version": 1,
  "descriptor_sha256": "sha256:<authorization_digest, from the sealed authorization file>",
  "source_evidence": {
    "economics_source_digest": "sha256:<economics bundle digest bound by that authorization>",
    "quality_source_digest": "sha256:<quality source digest bound by that authorization>"
  },
  "approver": "<opaque identifier — never interpreted>",
  "issued_at_ms": 0,
  "expires_at_ms": 0
}
```

`descriptor_sha256`, `economics_source_digest`, and `quality_source_digest` must be copied exactly
from the sealed authorization document Bowline already produced for this route (its
`authorization_digest`, `economics_bundle_digest`, and `quality_source_digest` fields,
respectively) — the whole point of the artifact is to name the precise evidence it approves, byte
for byte.

Sign the artifact with the standard `minisign` tool (or any implementation of the format):

```sh
minisign -Sm /etc/bowline/authorization/support-chat.json.approval.json -s /path/to/approval-signing.key
```

The resulting envelope is a small JSON document at
`<authorization_path>.approval.json.signature.json` (for example
`authorization/support-chat.json.approval.json.signature.json`), containing the envelope version,
algorithm, signing key id, a SHA-256 digest of the exact artifact bytes, and the complete
`.minisig` text:

```json
{
  "envelope_version": 1,
  "algorithm": "minisign-ed25519",
  "key_id": "<minisign-key-id>",
  "payload_sha256": "sha256:...",
  "minisign_signature": "<complete .minisig text>"
}
```

A complete worked example, end to end:

```sh
# 1. Generate a signing key once (skip if you already have one).
minisign -G -s ./approval-signing.key -p ./approval-signing.pub

# 2. Build the artifact JSON from the already-sealed authorization file, copying its exact
#    authorization_digest / economics_bundle_digest / quality_source_digest fields.
jq -n \
  --arg descriptor "$(jq -r .authorization_digest /etc/bowline/authorization/support-chat.json)" \
  --arg economics "$(jq -r .economics_bundle_digest /etc/bowline/authorization/support-chat.json)" \
  --arg quality "$(jq -r .quality_source_digest /etc/bowline/authorization/support-chat.json)" \
  --arg approver "release-manager@example.com" \
  --argjson issued "$(date +%s000)" \
  --argjson expires "$(($(date +%s000) + 3600000))" \
  '{
    artifact_version: 1,
    descriptor_sha256: $descriptor,
    source_evidence: { economics_source_digest: $economics, quality_source_digest: $quality },
    approver: $approver,
    issued_at_ms: $issued,
    expires_at_ms: $expires
  }' > /etc/bowline/authorization/support-chat.json.approval.json

# 3. Sign the exact artifact bytes just written.
minisign -Sm /etc/bowline/authorization/support-chat.json.approval.json -s ./approval-signing.key

# 4. minisign writes the .minisig sidecar; wrap it into Bowline's envelope schema.
minisig=$(cat /etc/bowline/authorization/support-chat.json.approval.json.minisig)
digest=$(sha256sum /etc/bowline/authorization/support-chat.json.approval.json | cut -d' ' -f1)
key_id=$(grep -o '[0-9A-F]\{16\}$' ./approval-signing.pub)
jq -n \
  --arg key_id "$key_id" \
  --arg digest "sha256:$digest" \
  --arg sig "$minisig" \
  '{
    envelope_version: 1,
    algorithm: "minisign-ed25519",
    key_id: $key_id,
    payload_sha256: $digest,
    minisign_signature: $sig
  }' > /etc/bowline/authorization/support-chat.json.approval.json.signature.json
```

## Freshness

Freshness requires all three of:

- `issued_at_ms <= now_ms <= expires_at_ms` — the artifact's own claimed window covers the moment
  it is checked.
- `now_ms - issued_at_ms <= max_age_seconds` (converted to milliseconds) — the artifact is not
  older than the configured maximum, regardless of how far in the future it claims to expire.
- `expires_at_ms - issued_at_ms <= max_age_seconds` (converted to milliseconds) — the artifact
  cannot claim a validity window longer than the configured maximum, regardless of when it is
  checked.

## Validation precedence

An approval check produces exactly one of four typed, durably recorded outcomes, checked in this
order — each is a soft rejection, never a startup failure:

1. **Missing** — the artifact or its signature envelope is absent while `required: true`.
2. **Signature invalid** — present, but the standard Minisign signature does not verify against a
   configured key.
3. **Unbound** — the signature verifies, but the artifact does not parse as the schema above, or
   its named digests do not exactly match the sealed authorization it sits beside.
4. **Expired / stale** — the signature verifies and the artifact is bound, but it fails the
   freshness check above.

Unsafe evidence (a symlinked, world-readable, or oversized artifact or envelope file) is a
different failure class entirely: it retains ordinary startup refusal, exactly like every other
piece of evidence Bowline reads, and never becomes one of the four typed outcomes above.
