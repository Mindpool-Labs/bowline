# Release process

Bowline uses Semantic Versioning. Before v1.0, incompatible public configuration, CLI, evidence
schema, or report changes increment the minor version; fixes and compatible additions increment the
patch version.

## What a release is

Bowline is distributed as source. A release is a **signed, annotated tag on `main` and a
corresponding GitHub release**; consumers build from source at a tag. No binaries, container images,
or registry packages are published. CI builds a container image and smoke-tests it as a gate, but
does not push it.

## Branch and merge policy

`main` is protected and every change reaches it through a pull request. Merges are **rebase merges**,
which preserve each commit's author and keep `main`'s history linear.

## Review

Every non-trivial change is reviewed before merge by **two independent reviewers working in separate
contexts under distinct lenses** — for example durability and crash-consistency against logical
correctness and test coverage. Neither reviewer sees the other's findings.

- A finding is acted on when it identifies a concrete failure scenario.
- A reviewer does not review a change against a specification they authored.
- Where an independent review cannot be obtained, that is recorded rather than assumed.

## Gates

Every gate must pass on the exact commit being tagged. Run them locally and confirm CI agrees on the
pull request.

```
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
./scripts/check-repo.sh
./scripts/check-docs.sh
./scripts/check-deployment.sh
./scripts/check-security-workflow.sh
./scripts/docker-smoke.sh          # requires a running Docker daemon; CI runs it regardless
```

CI additionally runs CodeQL, a full-history secret scan, and `rustsec`. Record only results a
command produced; if a gate did not run locally, say so on the pull request.

Unset proxy variables before running cargo locally — `ureq` honours `ALL_PROXY` and ignores
`NO_PROXY`, which causes loopback tests to fail spuriously:

```
unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy
```

## Cutting a release

1. Confirm scope, Apache-2.0 notices, community files, and support and security contacts are current.
2. On a release branch, set the workspace version in the root `Cargo.toml` and refresh `Cargo.lock`.
3. In `CHANGELOG.md`, promote the accumulated entries under a dated version heading and leave an
   empty `## [Unreleased]` section — `scripts/check-repo.sh` requires that heading. Document
   migrations and explicit non-claims in the same change.
4. Run every gate above and record the output on the pull request.
5. Open the pull request, confirm CI, and rebase-merge it.
6. Tag the merge commit as below, push the tag, and create the GitHub release from it.
7. Fast-forward `dev` to `main`, and delete branches whose work is fully incorporated.

When removing a branch, verify by content rather than ancestry: rebase and squash merges rewrite
commit hashes, so an incorporated branch is not an ancestor of `main`. Use `git cherry main <branch>`
and compare the files themselves before concluding a branch still holds unmerged work.

## Signing

Tags are annotated and signed. Signing is configured per repository, not globally:

```
git config --local gpg.format ssh
git config --local user.signingkey ~/.ssh/<signing-key>.pub
git config --local tag.gpgsign true
git config --local gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Setting `tag.gpgsign` means a tag cannot be created unsigned by accident. Verify before pushing:

```
git tag -v vX.Y.Z     # expect: Good "git" signature for <signing identity>
```

For GitHub to display a tag as Verified, the public key must be registered on the account as a
**signing key** — GitHub maintains authentication keys and signing keys as separate lists — and the
tagger address must be a verified account email. GitHub evaluates signatures when they are read, so
registering a key applies to existing tags; a tag does not need to be recreated.

## Verifying a release

Verify the signature on the tag you intend to build, for example the first release:

```
git verify-tag v0.1.0
```

The tag names the exact commit the gates above were run against. `CHANGELOG.md` records the schema
versions a release carries and any migration a deployment needs.

## Authority

Only an authorized maintainer publishes tags and GitHub releases, and releases follow branch
protection. Gates are not bypassed to publish: where a gate is incorrect, it is corrected and that
correction is reviewed as part of the change that depends on it.
