# Release process

Bowline uses Semantic Versioning. Before v1.0, incompatible public configuration, CLI, evidence
schema, or report changes increment the minor version; fixes and compatible additions increment the
patch version.

This document describes the process this project actually runs. Where a control is unavailable —
because Bowline is currently maintained by one person — that is stated rather than promised.

## What a release is

A release is a **signed tag on `main` plus a GitHub release**. Bowline publishes **no build
artifacts**: no binaries, no container images, no crates.io packages. CI builds a container image
and smoke-tests it, but never pushes it. Consumers build from source at a tag.

There is therefore nothing to checksum, sign as an artifact, or roll back to. If artifact publishing
is ever added, this section is the one that must change first.

## Review

`main` is a protected branch. Every change reaches it through a pull request; direct pushes are
rejected. Merges are **rebase merges**, which preserve each commit's author and keep the linear
history the branch requires. A merge commit would be authored with the GitHub account identity
rather than the committing identity, so it is not used.

**Two-maintainer review is not available.** With a single maintainer, no second human can approve a
release commit, and a process that claims otherwise is a process nobody follows. The substitute is
mandatory and stronger than a rubber stamp:

- Any non-trivial change is reviewed by **two independent adversarial reviewers**, in separate
  contexts, under **distinct lenses** — for example durability and crash-consistency versus logical
  correctness and test efficacy. Neither sees the other's findings.
- A finding is acted on when it names a **concrete failure scenario**, not a style preference.
- Reviewers may not review work they specified. If the only available reviewer authored the spec,
  the gate is recorded as not run rather than run hollow.

This is not theatre. On the v0.1.0 routing work it ran four times and found a rejection-level defect
or a Medium on every round, including on changes that looked mechanical, and twice both lenses
independently found the same defect.

## Gates

Every gate below must pass on the exact commit being tagged. Run them locally, and confirm CI agrees
on the pull request.

```
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
./scripts/check-repo.sh
./scripts/check-docs.sh
./scripts/check-deployment.sh
./scripts/check-security-workflow.sh
./scripts/docker-smoke.sh          # needs a running Docker daemon; CI runs it regardless
```

CI additionally runs CodeQL, a full-history secret scan, and `rustsec`. Report only what a command
proved: if a gate did not run, say so in the pull request rather than implying it passed.

Unset proxy variables before running cargo locally — `ureq` honours `ALL_PROXY` and ignores
`NO_PROXY`, which makes loopback tests fail spuriously:

```
unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy
```

## Cutting a release

1. Confirm the scope, Apache-2.0 notices, community files, and support/security contacts are current.
2. On a release branch, set the workspace version in the root `Cargo.toml` and refresh `Cargo.lock`.
3. In `CHANGELOG.md`, promote the accumulated entries under a dated version heading and leave an
   empty `## [Unreleased]` section behind — `scripts/check-repo.sh` requires that heading to exist.
   Document migrations and non-claims in the same edit.
4. Run every gate above. Record the verbatim output in the pull request.
5. Open the pull request, let CI confirm, and rebase-merge it.
6. Tag the merge commit (see Signing), push the tag, and create the GitHub release from it.
7. Fast-forward `dev` to `main` so the two do not drift, and delete merged branches.

Before deleting any branch, verify by **content**, not ancestry. Rebase and squash merges rewrite
commit hashes, so a fully incorporated branch is never an ancestor of `main`. Use
`git cherry main <branch>`, and where that reports commits with no equivalent, compare the files
themselves before concluding anything is unmerged.

## Signing

Tags are annotated and signed. Signing is configured **repo-local**, never globally:

```
git config --local gpg.format ssh
git config --local user.signingkey ~/.ssh/<signing-key>.pub
git config --local tag.gpgsign true
git config --local gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

`tag.gpgsign=true` means an unsigned tag cannot be produced by accident. Verify before pushing:

```
git tag -v vX.Y.Z     # expect: Good "git" signature for <signing identity>
```

For GitHub to display the tag as Verified, the **public key must be registered on the account as a
Signing Key** — GitHub keeps authentication keys and signing keys in separate lists, and adding it to
one does not add it to the other — and the tagger email must be a verified account email. GitHub
evaluates signatures on read, so registering a key later verifies existing tags retroactively; a tag
does not need to be recreated.

## Authority

Only an authorized maintainer publishes tags and GitHub releases. Releases follow branch protection.
Alert dismissals and merge gates are not worked around to get a release out: if a gate is wrong, the
gate is fixed and the fix is reviewed, in the same change that relies on it.

## History

`v0.1.0` was the first release. It was deliberately held until thirteen findings from an adversarial
review of an unreviewed routing drop were closed, because releasing earlier would have fossilised a
terminal, silent self-disable in routing state and five published claims that did not hold.
