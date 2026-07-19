#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

required='CONTRIBUTING.md CLA.md CODE_OF_CONDUCT.md SECURITY.md SUPPORT.md CHANGELOG.md RELEASE.md
.github/ISSUE_TEMPLATE/bug.yml .github/ISSUE_TEMPLATE/config.yml
.github/pull_request_template.md .github/workflows/ci.yml .github/workflows/security.yml
scripts/check-security-workflow.sh'

failures=0
for file in $required; do
  if [ ! -f "$file" ]; then
    printf '%s\n' "missing repository artifact: $file" >&2
    failures=$((failures + 1))
  fi
done
[ "$failures" -eq 0 ] || exit 1

require() {
  pattern=$1
  file=$2
  if ! grep -Fq -- "$pattern" "$file"; then
    printf '%s\n' "missing repository contract '$pattern' in $file" >&2
    failures=$((failures + 1))
  fi
}

require 'Apache-2.0' CONTRIBUTING.md
require '[Contributor License Agreement](CLA.md)' CONTRIBUTING.md
require 'Version 1.0' CLA.md
require 'made under its terms' .github/pull_request_template.md
require 'Contributor Covenant' CODE_OF_CONDUCT.md
require '2.1' CODE_OF_CONDUCT.md
require 'security@mindpool.io' SECURITY.md
require 'Do not open a public issue' SECURITY.md
require 'Community support' SUPPORT.md
require 'For controlled-enforcement defects' SUPPORT.md
require 'Keep a Changelog' CHANGELOG.md
require '## [Unreleased]' CHANGELOG.md
require 'Semantic Versioning' RELEASE.md
require 'v0.1.0' RELEASE.md
require 'controlled-enforcement.md' README.md
require 'examples/enforcement/validate-offline.sh' README.md

ci=.github/workflows/ci.yml
for gate in 'cargo fmt --check' 'cargo clippy --workspace --all-targets -- -D warnings' \
  'cargo +1.95.0 check --workspace --all-targets' 'cargo test --workspace' 'cargo deny check' 'cargo audit' './scripts/check-docs.sh' \
  './scripts/check-deployment.sh' './scripts/check-repo.sh' './scripts/docker-smoke.sh' \
  'python3 -m unittest integrations/litellm/test_bowline_callback.py -v'; do
  require "$gate" "$ci"
done

security=.github/workflows/security.yml
./scripts/check-security-workflow.sh "$security"
require 'cargo deny check' "$security"
require 'cargo audit' "$security"
require 'version=8.30.1' "$security"
require '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb' "$security"
require 'gitleaks" dir . --config .gitleaks.toml --redact --no-banner' "$security"

[ "$failures" -eq 0 ] || exit 1
printf '%s\n' 'repository contract: PASS'
