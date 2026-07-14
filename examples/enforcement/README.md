# Synthetic killed enforcement example

`enforcement.killed.yaml` is a safe structural example. It starts with a private kill state of
`bypass`, points only at loopback-only port 9, and contains placeholder digests and
paths, including a nonexistent placeholder `authorization_path`. It contains no authorization
sidecar, is not a grant, and must not be armed or used with traffic.

The offline validator creates a temporary mode-0700 trust root and mode-0600 `bypass` file,
quotes its schema-valid absolute path as YAML without evaluating path bytes, and calls only
`bowline kill bypass`. The strict schema rejects control characters in `trust_root`; punctuation,
quotes, backslashes, shell metacharacters, and spaces remain literal. The command validates the
bundle and atomically confirms the killed state; it does not load promotion evidence, probe the
actuator, create a sidecar, or contact any endpoint. The validator also confirms that the
placeholder authorization path remains absent.

From the repository root after building Bowline:

```sh
BOWLINE_BIN=./target/debug/bowline ./examples/enforcement/validate-offline.sh
```

For a real deployment, generate fresh private evidence with the documented quality and economics
workflows, replace every placeholder, keep credentials in the named environment variable, and
create a dedicated private trust root. While the kill state remains `bypass`, run `bowline
promotion seal` to create the configured private sidecar, then run full `bowline preflight`.
Review [controlled enforcement](../../docs/controlled-enforcement.md) and obtain the deployment's
separate approval before any operator arms authority.
